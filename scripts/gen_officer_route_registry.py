import re,sys
import os
base=os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","apps","control-plane")+"/"
sod=open(base+"internal/permission/sod_routes.go").read()
tbl={}
for m in re.finditer(r'"(GET|POST|PUT|PATCH|DELETE) (/(?:admin/v1|api)/[^"]+)":\s*(SoD\w+)',sod): tbl[(m.group(1),m.group(2))]=m.group(3)
# SoD 常量名 -> 类别值，供注册表按「值」记录
consts=dict(re.findall(r'(SoD\w+)\s+SoDClass\s*=\s*"(\w+)"',open(base+"internal/permission/sod.go").read()))
officer_ok={"SoDCommon","SoDSecurityRecordRead","SoDSecurityConfigRead","SoDSecurityWrite","SoDAlertHandle","SoDEvidence","SoDRawEvidence","SoDDirectoryRead"}
auditor_only={"SoDAuditRead","SoDAuditExport","SoDLoginHistory"}
reg={}
pat=re.compile(r'^\s*r\.(With\((?P<w>[^\n]*?)\)\.)?(?P<m>Get|Post|Put|Patch|Delete)\("(?P<p>/(?:admin/v1|api)/[^"]+)",\s*(?P<e>.+)\)\s*$')
for line in open(base+"cmd/server/main.go"):
    m=pat.match(line.rstrip("\n"))
    if m: reg[(m['m'].upper(),m['p'])]=(m['w'],m['e'].strip())
out=[];skipped=[]
for k in sorted(tbl):
    c=tbl[k]
    if c not in officer_ok|auditor_only: continue
    if k not in reg: skipped.append(k); continue
    w,e=reg[k]
    e2=e[len("handler."):] if e.startswith("handler.") else e
    wrap = w=="handler.RequireFullTenantContentEvidence"
    if w and not wrap: print("UNKNOWN WITH",k,w,file=sys.stderr)
    inner=f"RequireFullTenantContentEvidence(asHandler({e2}))" if wrap else e2
    ex=e.replace('"','\\"')
    out.append(f'\t\t"{k[0]} {k[1]}": {{class: "{consts[c]}", expr: "{ex}", build: func() http.Handler {{ return asHandler({inner}) }}}},')
hdr='''package handler

// 本文件由 scripts/gen_officer_route_registry.py 根据 cmd/server/main.go 与 permission.sodRouteTable 生成，请勿手改。
// 收录 SoD 对安全员/审计员放行的全部已注册路由，以及它们在 main.go 里的注册表达式。
//   - officer_routes_role_gate_test.go 用它们真实调用 handler，断言不是 handler 层的角色拒绝；
//   - TestOfficerRouteRegistryMatchesSoDTable 反向核对注册表与 SoD 表一致：路由新增、改类别而这里没重新生成，测试失败。
// 重新生成：python3 scripts/gen_officer_route_registry.py（在仓库根目录执行），然后 gofmt。

import (
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
)

type officerRouteEntry struct {
	class string // SoD 类别的取值（如 "security_write"），与 permission.SoDClass 一致
	expr  string // 与 main.go 注册处完全一致的表达式
	build func() http.Handler
}

func officerRouteRegistry() map[string]officerRouteEntry {
	// 桩依赖：repo 全部为 nil，只用于走到 handler 的角色判定；之后访问 nil 仓库 panic 视为「已通过角色判定」。
	deps := &Dependencies{}
	agentAdminAPI := NewAgentAdminAPI(nil, deps)
	agentUnifiedAssetAPI := NewAgentUnifiedAssetAPI(nil, deps)
	agentDestinationApprovalAPI := NewAgentDestinationApprovalAPI(nil, deps)
	nativeEventAPI := NewNativeEventAPI(nil)
	agentAuthorizationAPI := NewAgentAuthorizationAPI(nil, deps)
	agentAuthorizationApprovalAPI := NewAgentAuthorizationApprovalAPI(nil, deps)
	agentDelegationAPI := NewAgentDelegationAPI(nil, nil)
	agentDelegationInvestigationAPI := NewAgentDelegationInvestigationAPI(nil)
	agentEndpointAPI := NewAgentEndpointAPI(nil)
	kubernetesSnapshotAPI := NewAgentKubernetesSnapshotAPI(nil)
	var mcpRedlineSettingsStore mcpRedlineSettingsStore
	// 诊断引擎为 nil：handler 先做角色判定，之后返回 503，不算角色拒绝。
	var diagEngine *diagnostics.Engine
	_, _, _, _, _, _, _, _, _, _, _ = deps, agentAdminAPI, agentUnifiedAssetAPI, agentDestinationApprovalAPI, nativeEventAPI, agentAuthorizationAPI, agentAuthorizationApprovalAPI, agentDelegationAPI, agentDelegationInvestigationAPI, agentEndpointAPI, kubernetesSnapshotAPI
	_ = mcpRedlineSettingsStore
	_ = diagEngine
	// 训练语料扫描：store 为 nil，handler 先做角色判定，之后返回 503，不算角色拒绝。
	corpusScanHTTP := NewCorpusScanHandler(deps, nil, nil)
	return map[string]officerRouteEntry{
'''
ftr='''	}
}

func asHandler(v any) http.Handler {
	switch h := v.(type) {
	case http.Handler:
		return h
	case func(http.ResponseWriter, *http.Request):
		return http.HandlerFunc(h)
	}
	panic("unsupported handler type")
}
'''
open(base+"internal/handler/officer_routes_registry_test.go","w").write(hdr+"\n".join(out)+"\n"+ftr)
print("生成",len(out),"条；SoD 表预留但 main.go 未注册:",skipped,file=sys.stderr)
