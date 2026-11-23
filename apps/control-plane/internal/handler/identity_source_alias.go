package handler

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// W9 9.2：多身份源并存。
//
// 身份源以运行态 alias 为稳定标识：历史默认身份源是 "enterprise"，其余是服务端派生的
// "jjd-<id>"。现有身份源接口新增可选查询参数 ?source=<alias>；不带参数时作用于默认
// 身份源，行为与 9.2 之前完全一致。alias 永远不由客户端生成，只能从已存在的身份源中选取
// （新建身份源时由服务端派生）。

// sourceAliasFromRequest 读取 ?source=；缺省为默认身份源。非法值返回 ok=false。
func sourceAliasFromRequest(r *http.Request) (string, bool) {
	alias := strings.TrimSpace(r.URL.Query().Get("source"))
	if alias == "" {
		return repository.DefaultRuntimeAlias, true
	}
	if !identityruntime.ValidProviderAlias(alias) {
		return "", false
	}
	return alias, true
}

func writeInvalidSourceAlias(w http.ResponseWriter) {
	writeErrorWithStatus(w, http.StatusBadRequest, "invalid_source", "身份源标识无效")
}

// newSourceAlias 为新建的身份源派生 alias。
func newSourceAlias() (string, error) {
	return identityruntime.AliasForSource(strings.ReplaceAll(uuid.NewString(), "-", "")[:12], false)
}

// callbackURLForAlias 由部署公布的默认回调地址推出任一身份源的回调地址
// （各身份源在运行态上是独立的 broker 端点，IdP 侧需分别登记）。
func callbackURLForAlias(deps *Dependencies, alias string) string {
	base := deps.IdentityRuntimeConfig.CallbackURL
	suffix := "/broker/" + identityruntime.ProviderAlias + "/endpoint"
	if base == "" || !strings.HasSuffix(base, suffix) {
		return base
	}
	return strings.TrimSuffix(base, suffix) + "/broker/" + alias + "/endpoint"
}

func sourceAlias(src *repository.IdentitySource) string {
	if src == nil || src.RuntimeAlias == "" {
		return repository.DefaultRuntimeAlias
	}
	return src.RuntimeAlias
}
