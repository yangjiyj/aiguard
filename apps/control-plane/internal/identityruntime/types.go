package identityruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	RealmName                = "jjdguard"
	ProviderAlias            = "enterprise"
	digestConfigKey          = "jjdguardConfigDigest"
	structureDigestConfigKey = "jjdguardStructureDigest"
	managedMapperPrefix      = "jjdguard-claim-"
	// skipProfileMarkerKey 记录「首次登录不弹资料页」已由本平台发布。只有开启时才写入 provider config，
	// 默认值下 provider config 与摘要保持与旧版本完全一致。
	skipProfileMarkerKey = "jjdguardSkipProfileReview"
)

// id_token 验签方式。空串等价于 SignatureModeJWKS（默认，行为与旧版本完全一致）。
const (
	SignatureModeJWKS = "jwks"
	SignatureModeNone = "none"
)

// NormalizeSignatureMode 把空值归一为默认的 jwks；未知取值原样返回，交给调用方校验。
func NormalizeSignatureMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return SignatureModeJWKS
	}
	return strings.TrimSpace(mode)
}

var (
	ErrInvalidRuntimeTarget       = errors.New("invalid identity runtime target")
	ErrInvalidPublicURL           = errors.New("invalid public SSO URL")
	ErrRuntimeCredentialsRequired = errors.New("identity runtime credentials required")
	ErrInvalidDesiredSource       = errors.New("invalid desired identity source")
	ErrRuntimeUnavailable         = errors.New("identity runtime unavailable")
	ErrRuntimeUnauthorized        = errors.New("identity runtime unauthorized")
	ErrRuntimeNotFound            = errors.New("identity runtime object not found")
	ErrRuntimeRejected            = errors.New("identity runtime rejected request")
	ErrRuntimeResponseTooLarge    = errors.New("identity runtime response too large")
	ErrPublishConflict            = errors.New("identity publish conflict")
	ErrPublishVerification        = errors.New("identity publish verification failed")
	ErrRollbackFailed             = errors.New("identity runtime rollback failed")
	ErrRuntimeDrifted             = errors.New("identity runtime drifted")
	// ErrManageRealmRequired：启用「首次登录不弹资料页」需要修改 realm 级认证流与用户资料，
	// 身份运行服务账号缺少 manage-realm 时被拒绝。默认部署刻意不授予该权限，见升级文档与 bootstrap 开关。
	ErrManageRealmRequired = errors.New("identity runtime service account lacks manage-realm required by skip_profile_review")
	// ErrInsecureEndpoint：IdP 端点不是 https，且部署没有为私网 IdP 显式登记例外。
	// token 端点走 http 会把 client_secret 明文发到网络上。
	ErrInsecureEndpoint = errors.New("identity provider endpoint must use https")
)

type DiscoveryEndpoints struct {
	Issuer        string
	Authorization string
	Token         string
	JWKS          string
	UserInfo      string
	EndSession    string
}

type ClaimMapping struct {
	Name          string
	Claim         string
	UserAttribute string
}

type DesiredIdentitySource struct {
	Realm         string
	Alias         string
	DisplayName   string
	Endpoints     DiscoveryEndpoints
	ClientID      string
	ClientSecret  string
	Scopes        []string
	ClaimMappings []ClaimMapping
	Digest        string
	// SignatureMode：id_token 验签方式，"" / "jwks"（默认，按 IdP 公钥验签）或 "none"（不校验签名）。
	SignatureMode string
	// SkipProfileReview：首次登录不弹资料页。realm 级设置共享，发布只会开启，不会因关闭而回滚。
	SkipProfileReview bool
	// AllowPrivateHTTP 是部署侧的传输例外（私网 IdP 已由 JJD_IDP_ALLOW_CIDRS 显式登记），
	// 不属于已发布配置，不进入摘要。默认 false：所有端点必须是 https。
	AllowPrivateHTTP bool
}

type ProviderRepresentation struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName,omitempty"`
	InternalID                string            `json:"internalId,omitempty"`
	ProviderID                string            `json:"providerId"`
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail"`
	StoreToken                bool              `json:"storeToken"`
	AddReadTokenRoleOnCreate  bool              `json:"addReadTokenRoleOnCreate"`
	LinkOnly                  bool              `json:"linkOnly"`
	HideOnLogin               bool              `json:"-"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string `json:"config"`
}

type MapperRepresentation struct {
	ID                     string            `json:"id,omitempty"`
	Name                   string            `json:"name"`
	IdentityProviderAlias  string            `json:"identityProviderAlias"`
	IdentityProviderMapper string            `json:"identityProviderMapper"`
	Config                 map[string]string `json:"config"`
}

type RuntimeSnapshot struct {
	Realm            string
	Alias            string
	Exists           bool
	Digest           string
	StructureDrifted bool
	Provider         ProviderRepresentation
	Mappers          []MapperRepresentation
}

type RuntimeStatus struct {
	Exists  bool
	Enabled bool
	Digest  string
	Drifted bool
}

type Publication struct {
	Digest         string
	AlreadyCurrent bool
	Previous       RuntimeSnapshot
}

func (desired DesiredIdentitySource) String() string {
	return fmt.Sprintf("identityruntime.DesiredIdentitySource{Realm:%q Alias:%q DisplayName:%q ClientID:%q Digest:%q Credentials:[redacted]}",
		desired.Realm, desired.Alias, desired.DisplayName, desired.ClientID, desired.Digest)
}

func (desired DesiredIdentitySource) GoString() string {
	return desired.String()
}

func (provider ProviderRepresentation) String() string {
	return fmt.Sprintf("identityruntime.ProviderRepresentation{Alias:%q DisplayName:%q ProviderID:%q Enabled:%t Config:[redacted]}",
		provider.Alias, provider.DisplayName, provider.ProviderID, provider.Enabled)
}

func (provider ProviderRepresentation) GoString() string {
	return provider.String()
}

func (snapshot RuntimeSnapshot) String() string {
	return fmt.Sprintf("identityruntime.RuntimeSnapshot{Realm:%q Alias:%q Exists:%t Digest:%q StructureDrifted:%t Provider:[redacted] Mappers:%d}",
		snapshot.Realm, snapshot.Alias, snapshot.Exists, snapshot.Digest, snapshot.StructureDrifted, len(snapshot.Mappers))
}

func (snapshot RuntimeSnapshot) GoString() string {
	return snapshot.String()
}

type digestInput struct {
	Realm         string
	Alias         string
	DisplayName   string
	Endpoints     DiscoveryEndpoints
	ClientID      string
	ClientSecret  string
	Scopes        []string
	ClaimMappings []ClaimMapping
	// 以下两项取默认值（jwks / false）时必须省略，保证存量身份源摘要不变。
	SignatureMode     string `json:",omitempty"`
	SkipProfileReview bool   `json:",omitempty"`
}

type runtimeStructureProvider struct {
	Alias                    string
	DisplayName              string
	ProviderID               string
	Enabled                  bool
	TrustEmail               bool
	StoreToken               bool
	AddReadTokenRoleOnCreate bool
	LinkOnly                 bool
	HideOnLogin              bool
	Config                   map[string]string
}

type runtimeStructureMapper struct {
	Name                   string
	IdentityProviderAlias  string
	IdentityProviderMapper string
	Config                 map[string]string
}

func isManagedProviderConfigKey(key string) bool {
	switch key {
	case "issuer", "authorizationUrl", "tokenUrl", "jwksUrl", "userInfoUrl", "logoutUrl",
		"clientId", "defaultScope", "useJwksUrl", "validateSignature", "syncMode",
		"pkceEnabled", "pkceMethod", skipProfileMarkerKey:
		return true
	default:
		return false
	}
}

func computeRuntimeStructureDigest(provider ProviderRepresentation, mappers []MapperRepresentation) (string, error) {
	providerConfig := make(map[string]string, len(provider.Config))
	for key, value := range provider.Config {
		if isManagedProviderConfigKey(key) {
			providerConfig[key] = value
		}
	}
	structureMappers := make([]runtimeStructureMapper, 0, len(mappers))
	for _, mapper := range mappers {
		if !strings.HasPrefix(mapper.Name, managedMapperPrefix) {
			continue
		}
		config := make(map[string]string, len(mapper.Config))
		for key, value := range mapper.Config {
			config[key] = value
		}
		structureMappers = append(structureMappers, runtimeStructureMapper{
			Name: mapper.Name, IdentityProviderAlias: mapper.IdentityProviderAlias,
			IdentityProviderMapper: mapper.IdentityProviderMapper, Config: config,
		})
	}
	sort.Slice(structureMappers, func(i, j int) bool {
		if structureMappers[i].Name != structureMappers[j].Name {
			return structureMappers[i].Name < structureMappers[j].Name
		}
		if structureMappers[i].IdentityProviderMapper != structureMappers[j].IdentityProviderMapper {
			return structureMappers[i].IdentityProviderMapper < structureMappers[j].IdentityProviderMapper
		}
		left, _ := json.Marshal(structureMappers[i].Config)
		right, _ := json.Marshal(structureMappers[j].Config)
		return string(left) < string(right)
	})
	canonical, err := json.Marshal(struct {
		Provider runtimeStructureProvider
		Mappers  []runtimeStructureMapper
	}{
		Provider: runtimeStructureProvider{
			Alias: provider.Alias, DisplayName: provider.DisplayName, ProviderID: provider.ProviderID,
			Enabled: provider.Enabled, TrustEmail: provider.TrustEmail, StoreToken: provider.StoreToken,
			AddReadTokenRoleOnCreate: provider.AddReadTokenRoleOnCreate, LinkOnly: provider.LinkOnly,
			HideOnLogin: provider.HideOnLogin, Config: providerConfig,
		},
		Mappers: structureMappers,
	})
	if err != nil {
		return "", ErrRuntimeRejected
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ComputeDesiredDigest(desired DesiredIdentitySource) (string, error) {
	if err := ValidateDesired(desired); err != nil {
		return "", err
	}
	scopes := append([]string(nil), desired.Scopes...)
	sort.Strings(scopes)
	mappings := append([]ClaimMapping(nil), desired.ClaimMappings...)
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].Name != mappings[j].Name {
			return mappings[i].Name < mappings[j].Name
		}
		if mappings[i].Claim != mappings[j].Claim {
			return mappings[i].Claim < mappings[j].Claim
		}
		return mappings[i].UserAttribute < mappings[j].UserAttribute
	})
	canonical, err := json.Marshal(digestInput{
		Realm: desired.Realm, Alias: desired.Alias, DisplayName: strings.TrimSpace(desired.DisplayName),
		Endpoints: desired.Endpoints, ClientID: desired.ClientID, ClientSecret: desired.ClientSecret,
		Scopes: scopes, ClaimMappings: mappings,
		SignatureMode: nonDefaultSignatureMode(desired.SignatureMode), SkipProfileReview: desired.SkipProfileReview,
	})
	if err != nil {
		return "", ErrInvalidDesiredSource
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// nonDefaultSignatureMode 默认值返回空串，使其在摘要里被 omitempty 省略。
func nonDefaultSignatureMode(mode string) string {
	if NormalizeSignatureMode(mode) == SignatureModeJWKS {
		return ""
	}
	return NormalizeSignatureMode(mode)
}

// allowInsecureNoneSignature 仅供同包测试把 http mock IdP 当作 https 使用，生产路径恒为 false。
var allowInsecureNoneSignature = false

func ValidateDesired(desired DesiredIdentitySource) error {
	if err := validateRuntimeCoordinates(desired.Realm, desired.Alias); err != nil {
		return err
	}
	if strings.TrimSpace(desired.DisplayName) == "" || len(desired.DisplayName) > 128 ||
		strings.TrimSpace(desired.ClientID) == "" || strings.TrimSpace(desired.ClientSecret) == "" {
		return ErrInvalidDesiredSource
	}
	for _, endpoint := range []struct {
		value    string
		required bool
	}{
		{desired.Endpoints.Issuer, true},
		{desired.Endpoints.Authorization, true},
		{desired.Endpoints.Token, true},
		{desired.Endpoints.JWKS, NormalizeSignatureMode(desired.SignatureMode) == SignatureModeJWKS},
		{desired.Endpoints.UserInfo, false},
		{desired.Endpoints.EndSession, false},
	} {
		if endpoint.value == "" && !endpoint.required {
			continue
		}
		if err := validateEndpoint(endpoint.value, desired.AllowPrivateHTTP); err != nil {
			return err
		}
	}
	switch NormalizeSignatureMode(desired.SignatureMode) {
	case SignatureModeJWKS:
	case SignatureModeNone:
		// 不校验签名只有在服务端经 HTTPS 直连 token 端点换取 token 时才成立；
		// 私网 http 例外（AllowPrivateHTTP）不对 none 放行。
		if !allowInsecureNoneSignature && !strings.HasPrefix(strings.ToLower(desired.Endpoints.Token), "https://") {
			return fmt.Errorf("%w: %w", ErrInvalidDesiredSource, ErrInsecureEndpoint)
		}
	default:
		return ErrInvalidDesiredSource
	}
	if len(desired.Scopes) == 0 {
		return ErrInvalidDesiredSource
	}
	hasOpenID := false
	for _, scope := range desired.Scopes {
		if strings.TrimSpace(scope) == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return ErrInvalidDesiredSource
	}
	seenAttributes := make(map[string]struct{}, len(desired.ClaimMappings))
	for _, mapping := range desired.ClaimMappings {
		if !validMappingToken(mapping.Claim) || !validMappingToken(mapping.UserAttribute) {
			return ErrInvalidDesiredSource
		}
		if _, exists := seenAttributes[mapping.UserAttribute]; exists {
			return ErrInvalidDesiredSource
		}
		seenAttributes[mapping.UserAttribute] = struct{}{}
	}
	return nil
}

func validateEndpoint(raw string, allowPrivateHTTP bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.User != nil || parsed.Fragment != "" {
		return ErrInvalidDesiredSource
	}
	if parsed.Scheme == "http" && !allowPrivateHTTP {
		return fmt.Errorf("%w: %w", ErrInvalidDesiredSource, ErrInsecureEndpoint)
	}
	return nil
}

// ValidClaimToken 供上层校验用户可输入的 claim 名称。
func ValidClaimToken(value string) bool { return validMappingToken(value) }

func validMappingToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') &&
			c != '_' && c != '-' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

func validateRuntimeCoordinates(realm, alias string) error {
	if realm != RealmName || !ValidProviderAlias(alias) {
		return ErrInvalidRuntimeTarget
	}
	return nil
}

// sourceAliasPrefix：9.2 多身份源并存。除历史默认 alias（ProviderAlias）外，每个身份源
// 按自己的 source id 派生独立 alias，互不覆盖。alias 只能由服务端派生，不接受外部输入。
const sourceAliasPrefix = "jjd-"

// AliasForSource 为身份源派生运行态 alias。legacyDefault=true 时沿用历史 alias
// "enterprise"（兼容已发布的回调地址与门户 kc_idp_hint）。
func AliasForSource(sourceID string, legacyDefault bool) (string, error) {
	if legacyDefault {
		return ProviderAlias, nil
	}
	alias := sourceAliasPrefix + strings.ToLower(strings.TrimSpace(sourceID))
	if !ValidProviderAlias(alias) {
		return "", ErrInvalidRuntimeTarget
	}
	return alias, nil
}

// ValidProviderAlias：历史 alias，或 jjd- 前缀 + [a-z0-9_-]{1,56}（URL 路径安全，不含 . / %）。
func ValidProviderAlias(alias string) bool {
	if alias == ProviderAlias {
		return true
	}
	rest := strings.TrimPrefix(alias, sourceAliasPrefix)
	if rest == alias || len(rest) == 0 || len(rest) > 56 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// CallbackURLForAlias 返回该身份源在运行态上的 broker 回调地址。
func CallbackURLForAlias(publicBase, alias string) string {
	return strings.TrimSuffix(publicBase, "/") + "/sso/realms/" + RealmName + "/broker/" + alias + "/endpoint"
}

func verifyDesiredDigest(desired DesiredIdentitySource) (string, error) {
	computed, err := ComputeDesiredDigest(desired)
	if err != nil {
		return "", err
	}
	if desired.Digest != "" && desired.Digest != computed {
		return "", fmt.Errorf("%w: digest mismatch", ErrInvalidDesiredSource)
	}
	return computed, nil
}
