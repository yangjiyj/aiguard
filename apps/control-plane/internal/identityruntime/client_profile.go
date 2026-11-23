package identityruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const (
	defaultFirstBrokerLoginFlow = "first broker login"
	reviewProfileProviderID     = "idp-review-profile"
	reviewProfileConfigKey      = "update.profile.on.first.login"
	reviewProfileAlias          = "jjdguard-review-profile"
)

func userProfilePath() string { return "/admin/realms/" + RealmName + "/users/profile" }

func flowExecutionsPath(flowAlias string) string {
	return "/admin/realms/" + RealmName + "/authentication/flows/" + flowAlias + "/executions"
}

func flowAliasOrDefault(alias string) string {
	if strings.TrimSpace(alias) == "" {
		return defaultFirstBrokerLoginFlow
	}
	return alias
}

type reviewExecution struct {
	ID                   string `json:"id"`
	ProviderID           string `json:"providerId"`
	AuthenticationConfig string `json:"authenticationConfig"`
}

// profileState 是 realm 级「首登资料页」相关的运行态事实。
type profileState struct {
	reviewMode    string // on / missing / off；执行器或配置缺失时为空
	namesRequired bool   // firstName / lastName 任一仍为必填
}

func (s profileState) skipSatisfied() bool {
	return s.reviewMode == "off" && !s.namesRequired
}

func (c *Client) findReviewExecution(ctx context.Context, flowAlias string) (*reviewExecution, error) {
	var executions []reviewExecution
	if err := c.doJSON(ctx, http.MethodGet, flowExecutionsPath(flowAliasOrDefault(flowAlias)), nil, &executions, http.StatusOK); err != nil {
		return nil, err
	}
	for i := range executions {
		if executions[i].ProviderID == reviewProfileProviderID {
			return &executions[i], nil
		}
	}
	return nil, nil
}

type authenticatorConfig struct {
	ID     string            `json:"id,omitempty"`
	Alias  string            `json:"alias,omitempty"`
	Config map[string]string `json:"config"`
}

func (c *Client) readReviewMode(ctx context.Context, flowAlias string) (string, error) {
	exec, err := c.findReviewExecution(ctx, flowAlias)
	if err != nil || exec == nil || exec.AuthenticationConfig == "" || !validRuntimeObjectID(exec.AuthenticationConfig) {
		return "", err
	}
	var cfg authenticatorConfig
	path := "/admin/realms/" + RealmName + "/authentication/config/" + exec.AuthenticationConfig
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &cfg, http.StatusOK); err != nil {
		return "", err
	}
	return cfg.Config[reviewProfileConfigKey], nil
}

func (c *Client) readUserProfile(ctx context.Context) (map[string]any, error) {
	raw, err := c.doAuthorized(ctx, http.MethodGet, userProfilePath(), nil, "application/json", http.StatusOK)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber() // 原样回写，不让数字被 float64 化。
	var profile map[string]any
	if err := decoder.Decode(&profile); err != nil {
		return nil, ErrRuntimeRejected
	}
	return profile, nil
}

func isNameAttribute(attr map[string]any) bool {
	name, _ := attr["name"].(string)
	return name == "firstName" || name == "lastName"
}

func (c *Client) readProfileState(ctx context.Context, flowAlias string) (profileState, error) {
	mode, err := c.readReviewMode(ctx, flowAlias)
	if err != nil {
		return profileState{}, err
	}
	profile, err := c.readUserProfile(ctx)
	if err != nil {
		return profileState{}, err
	}
	state := profileState{reviewMode: mode}
	attributes, _ := profile["attributes"].([]any)
	for _, item := range attributes {
		if attr, ok := item.(map[string]any); ok && isNameAttribute(attr) {
			if _, required := attr["required"]; required {
				state.namesRequired = true
			}
		}
	}
	return state, nil
}

// applySkipProfileReview：把 first broker login 的 Review Profile 设为 off，并取消 firstName/lastName 必填。
// 两步都是幂等的；服务账号缺 manage-realm 时返回 ErrRuntimeUnauthorized。
func (c *Client) applySkipProfileReview(ctx context.Context, flowAlias string) error {
	err := c.applySkipProfileReviewUnchecked(ctx, flowAlias)
	if errors.Is(err, ErrRuntimeUnauthorized) {
		// token 已通过（身份源本身可写），只是没有 realm 级写权限。
		return ErrManageRealmRequired
	}
	return err
}

func (c *Client) applySkipProfileReviewUnchecked(ctx context.Context, flowAlias string) error {
	exec, err := c.findReviewExecution(ctx, flowAlias)
	if err != nil {
		return err
	}
	if exec == nil || !validRuntimeObjectID(exec.ID) {
		return ErrRuntimeRejected
	}
	if exec.AuthenticationConfig != "" {
		if !validRuntimeObjectID(exec.AuthenticationConfig) {
			return ErrRuntimeRejected
		}
		path := "/admin/realms/" + RealmName + "/authentication/config/" + exec.AuthenticationConfig
		var cfg authenticatorConfig
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &cfg, http.StatusOK); err != nil {
			return err
		}
		if cfg.Config == nil {
			cfg.Config = map[string]string{}
		}
		if cfg.Config[reviewProfileConfigKey] != "off" {
			cfg.Config[reviewProfileConfigKey] = "off"
			if err := c.doJSON(ctx, http.MethodPut, path, cfg, nil, http.StatusOK, http.StatusNoContent); err != nil {
				return err
			}
		}
	} else {
		path := "/admin/realms/" + RealmName + "/authentication/executions/" + exec.ID + "/config"
		body := authenticatorConfig{Alias: reviewProfileAlias, Config: map[string]string{reviewProfileConfigKey: "off"}}
		if err := c.doJSON(ctx, http.MethodPost, path, body, nil, http.StatusOK, http.StatusCreated, http.StatusNoContent); err != nil {
			return err
		}
	}
	return c.relaxNameRequirements(ctx)
}

func (c *Client) relaxNameRequirements(ctx context.Context) error {
	profile, err := c.readUserProfile(ctx)
	if err != nil {
		return err
	}
	changed := false
	attributes, _ := profile["attributes"].([]any)
	for _, item := range attributes {
		attr, ok := item.(map[string]any)
		if !ok || !isNameAttribute(attr) {
			continue
		}
		if _, required := attr["required"]; required {
			delete(attr, "required")
			changed = true
		}
	}
	if !changed {
		return nil
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		return ErrRuntimeRejected
	}
	_, err = c.doAuthorized(ctx, http.MethodPut, userProfilePath(), payload, "application/json",
		http.StatusOK, http.StatusNoContent)
	return err
}

// ObservedSettings 是对运行态的只读反推，用于「采纳运行态」。字段为空表示无法确定，调用方不得臆测。
type ObservedSettings struct {
	Exists            bool
	SignatureMode     string
	UsernameClaim     string
	SkipProfileReview bool
}

// Observe 只做 GET，绝不写 Keycloak。
func (c *Client) Observe(ctx context.Context, realm, alias string) (ObservedSettings, error) {
	if err := validateRuntimeCoordinates(realm, alias); err != nil {
		return ObservedSettings{}, err
	}
	snapshot, err := c.Snapshot(ctx, realm, alias)
	if err != nil {
		return ObservedSettings{}, err
	}
	if !snapshot.Exists {
		return ObservedSettings{}, nil
	}
	obs := ObservedSettings{Exists: true, SignatureMode: SignatureModeJWKS}
	if snapshot.Provider.Config["validateSignature"] != "true" {
		obs.SignatureMode = SignatureModeNone
	}
	obs.UsernameClaim = inferUsernameClaim(snapshot.Mappers)
	mode, modeErr := c.readReviewMode(ctx, snapshot.Provider.FirstBrokerLoginFlowAlias)
	if modeErr != nil {
		return ObservedSettings{}, modeErr
	}
	obs.SkipProfileReview = mode == "off"
	return obs, nil
}

// inferUsernameClaim：优先受管的 jjdguard-claim-username；否则取 oidc-username-idp-mapper 且模板恰为 ${CLAIM.x} 的 x。
func inferUsernameClaim(mappers []MapperRepresentation) string {
	for _, m := range mappers {
		if m.Name == managedMapperPrefix+"username" && m.Config["user.attribute"] == "username" && validMappingToken(m.Config["claim"]) {
			return m.Config["claim"]
		}
	}
	for _, m := range mappers {
		if m.IdentityProviderMapper != "oidc-username-idp-mapper" {
			continue
		}
		tpl := strings.TrimSpace(m.Config["template"])
		if strings.HasPrefix(tpl, "${CLAIM.") && strings.HasSuffix(tpl, "}") {
			claim := strings.TrimSuffix(strings.TrimPrefix(tpl, "${CLAIM."), "}")
			if validMappingToken(claim) {
				return claim
			}
		}
	}
	return ""
}
