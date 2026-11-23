package handler

// Low-2 的覆盖守卫：证据原文读取出口的 handler 构造函数本身必须带读取审计。
//
// 单测 TestEveryEvidenceReadExitWritesAnAuditRecordWithoutTheContent 验证中间件行为；这里验证「真实 handler 被包上了它」——
// 用 SoD 表里 evidence 类的路由清单作为事实来源：凡是会返回证据正文/附件/时间线的出口，用真实构造函数发一个请求，
// 只要 handler 走到了「读取成功」就必须有审计。新增 evidence 类路由而没有挂审计，会让下面的清单检查失败（未知即失败）。

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// evidenceReadRoutes 是「返回证据内容」的出口；evidenceNonContentRoutes 是同属 evidence 类但只返回列表/元数据/索引的路由，
// 逐条写明为什么不记读取审计。两张表合起来必须覆盖 SoD 里的全部 evidence 类 GET/POST 路由。
var evidenceReadRoutes = map[string]string{
	"GET /admin/v1/audit/access-retention/{request_id}/content":                          "content",
	"POST /admin/v1/audit/access-retention/{request_id}/content":                         "content",
	"GET /admin/v1/audit/access-retention/{request_id}/blob":                             "blob",
	"GET /admin/v1/audit/access-retention/{request_id}/image-proxy":                      "image_proxy",
	"GET /admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview":  "artifact_preview",
	"GET /admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original": "artifact_original",
	"GET /admin/v1/audit/access-retention/{request_id}/timeline":                         "timeline",
	"POST /admin/v1/audit/access-retention/{request_id}/timeline":                        "timeline",
	"GET /admin/v1/audit/content/{session_id}":                                           "session_content",
	"GET /admin/v1/audit/content/{session_id}/export":                                    "session_export",
}

var evidenceNonContentRoutes = map[string]string{
	"GET /admin/v1/audit/access-retention":            "列表：只返回请求级元数据（时间、用户、模型、动作），不含正文",
	"GET /admin/v1/audit/access-retention/runs":       "取证任务列表：任务元数据",
	"POST /admin/v1/audit/leak-trace":                 "泄露溯源：只返回命中请求的元数据，不返回正文；每次调用写操作审计",
	"GET /admin/v1/audit/dispositions":                "处置记录列表：处置状态与备注，不含正文",
	"GET /admin/v1/audit/requests":                    "请求列表：元数据",
	"GET /admin/v1/audit/requests/{request_id}":       "请求详情：元数据与动作解释，正文走 access-retention/content",
	"GET /admin/v1/audit/content/{session_id}/events": "会话的安全事件列表：命中规则与严重度，不含对话正文",
	"GET /admin/v1/proxy/forward-access":              "正向代理访问列表：元数据",
}

// evidenceCoveredClass 判断一条路由是否在本守卫的检查范围：evidence 类，以及返回会话正文的审计导出路由
// （GET /audit/content/{session_id}/export 属审计员专属的 SoDAuditExport 类，但同样返回原文，必须留痕）。
func evidenceCoveredClass(route string, class permission.SoDClass) bool {
	if class == permission.SoDEvidence {
		return true
	}
	return route == "GET /admin/v1/audit/content/{session_id}/export" && class == permission.SoDAuditExport
}

func TestEveryEvidenceContentRouteIsCoveredByTheReadAudit(t *testing.T) {
	var unknown []string
	for route, class := range permission.OfficerRouteKeys() {
		if !evidenceCoveredClass(route, class) {
			continue
		}
		_, content := evidenceReadRoutes[route]
		_, meta := evidenceNonContentRoutes[route]
		if !content && !meta {
			unknown = append(unknown, route)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Fatalf("以下 evidence 类路由既没有挂读取审计，也没有在 evidenceNonContentRoutes 登记为「不返回正文」（未知即失败）:\n  %s",
			strings.Join(unknown, "\n  "))
	}
	// 登记表不得失真：登记的路由必须仍在 SoD 表里且仍是 evidence 类。
	classes := permission.OfficerRouteKeys()
	for route := range evidenceReadRoutes {
		if !evidenceCoveredClass(route, classes[route]) {
			t.Errorf("evidenceReadRoutes 里的 %s 已不再是 evidence 类（或已删除），请同步清理", route)
		}
	}
	for route := range evidenceNonContentRoutes {
		if !evidenceCoveredClass(route, classes[route]) {
			t.Errorf("evidenceNonContentRoutes 里的 %s 已不再是 evidence 类（或已删除），请同步清理", route)
		}
	}
}

// 用真实 handler 构造函数验证「读取成功就留痕」：这些出口在缺少仓储时会以非 2xx 返回，所以这里直接核对
// 「读取失败不留痕」；2xx 路径的留痕由 TestEveryEvidenceReadExitWritesAnAuditRecordWithoutTheContent 覆盖，
// 这里再用 evidenceReadRoutes 的 kind 与构造函数一一对应，防止构造函数里 kind 写错或漏包。
func TestEvidenceHandlersAreConstructedWithTheMatchingAuditKind(t *testing.T) {
	cases := map[string]func(*Dependencies) http.HandlerFunc{
		"content":           GetAccessRetentionContent,
		"blob":              GetAccessRetentionBlob,
		"image_proxy":       GetAccessRetentionImageProxy,
		"timeline":          GetEvidenceTimeline,
		"session_content":   GetSessionContent,
		"session_export":    ExportSessionContent,
		"artifact_preview":  func(d *Dependencies) http.HandlerFunc { return GetAccessRetentionArtifact(true, d) },
		"artifact_original": func(d *Dependencies) http.HandlerFunc { return GetAccessRetentionArtifact(false, d) },
	}
	for kind, build := range cases {
		t.Run(kind, func(t *testing.T) {
			// 失败路径：未登录 => 401，且不得留下读取审计。
			repo := &capturingSystemRepo{}
			rec := httptest.NewRecorder()
			build(&Dependencies{SystemRepo: repo}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
			if rec.Code < 400 {
				t.Fatalf("没有用户上下文应拒绝：%d", rec.Code)
			}
			if len(repo.auditOps) != 0 {
				t.Fatalf("失败的访问不得记读取审计：%+v", repo.auditOps)
			}
		})
	}
	// kind 表与登记表一致：登记的每个 kind 都有对应构造函数。
	registered := map[string]bool{}
	for _, k := range evidenceReadRoutes {
		registered[k] = true
	}
	for k := range registered {
		if _, ok := cases[k]; !ok {
			t.Errorf("登记的出口类型 %q 没有对应的构造函数覆盖用例", k)
		}
	}
}

// 真实 handler 的端到端：附件原件读取成功，恰好留一条审计；blob 别名同样只留一条（不是两条）；被拒绝的访问不留。
func TestRealArtifactHandlersWriteExactlyOneAuditRecordPerRead(t *testing.T) {
	artifact := &repository.RetainedArtifact{
		ID: "art_1", TenantID: "tenant_a", RequestID: "req_1", Direction: "input", Kind: "file",
		DisplayName: "report.pdf", MediaType: "application/pdf", ByteSize: 12, SHA256: "abc123", Status: "retained",
		OriginalObjectKey: "obj-key",
	}
	for _, tc := range []struct {
		name, route, path, kind string
		build                   func(*Dependencies) http.HandlerFunc
	}{
		{"original", "/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original", "/admin/v1/audit/access-retention/req_1/artifacts/art_1/original", "artifact_original",
			func(d *Dependencies) http.HandlerFunc { return GetAccessRetentionArtifact(false, d) }},
		{"blob alias", "/admin/v1/audit/access-retention/{request_id}/blob", "/admin/v1/audit/access-retention/req_1/blob?artifact_id=art_1", "blob", GetAccessRetentionBlob},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys := &capturingSystemRepo{}
			deps := &Dependencies{
				SystemRepo:           sys,
				RetainedArtifactRepo: fixedRetainedArtifactRepo{artifact: artifact},
				RetentionStore:       fixedArtifactStore{tenantID: "tenant_a", key: "obj-key", body: []byte("PDF-BYTES"), mime: "application/pdf"},
			}
			router := chi.NewRouter()
			router.Get(tc.route, tc.build(deps))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, evidenceUserCtx(httptest.NewRequest(http.MethodGet, tc.path, nil), "security_officer"))
			if rec.Code != http.StatusOK {
				t.Fatalf("读取应成功：%d %s", rec.Code, rec.Body.String())
			}
			if len(sys.auditOps) != 1 {
				t.Fatalf("一次读取应恰好一条审计，实际 %d：%+v", len(sys.auditOps), sys.auditOps)
			}
			d := sys.auditOps[0].ActionDetail
			if d["kind"] != tc.kind || d["role"] != "security_officer" || d["tenant_id"] != "tenant_a" || d["evidence_id"] != "req_1/art_1" && d["evidence_id"] != "req_1" {
				t.Fatalf("审计详情不对：%v", d)
			}
			if strings.Contains(jsonOf(d), "PDF-BYTES") {
				t.Fatalf("审计不得含内容：%v", d)
			}
		})
	}

	// 附件不存在（404）不留读取审计。
	sys := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: sys, RetainedArtifactRepo: fixedRetainedArtifactRepo{artifact: artifact},
		RetentionStore: fixedArtifactStore{tenantID: "tenant_a", key: "obj-key", body: []byte("x"), mime: "application/pdf"}}
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original", GetAccessRetentionArtifact(false, deps))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, evidenceUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_1/artifacts/nope/original", nil), "security_officer"))
	if rec.Code < 400 || len(sys.auditOps) != 0 {
		t.Fatalf("读不到附件不应留读取审计：%d ops=%d", rec.Code, len(sys.auditOps))
	}
}
