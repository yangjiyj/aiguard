package handler

// 证据原文读取留痕（Low-2）。
//
// 证据原文的读取出口（view=raw、/content、/blob、/image-proxy、/artifacts/.../original|preview、会话正文及导出）
// 之前只有一道角色闸门，读取行为完全不留痕。三员分立下「安全员看原文必须可追溯」：这里统一在路由上挂一个审计中间件，
// 读取成功（2xx）后写一条 audit_operations（evidence.read）：读取人、角色、租户、证据 ID、出口类型；绝不记内容。
//
// 设计取舍：
//   - 只在读取成功时记：被角色闸门拒绝（404）或失败的访问并没有读到内容，记了反而制造不存在的读取；
//   - 审计写入失败不影响读取返回：读取已经发生，且这是取证场景，不能因审计库抖动让合法读取失败（失败只记日志）；
//   - 用 ResponseWriter 包装取状态码，必须保留 http.Flusher，否则图片/附件的流式下载会被破坏。

import (
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

type evidenceAuditWriter struct {
	http.ResponseWriter
	status int
}

func (w *evidenceAuditWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *evidenceAuditWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *evidenceAuditWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 让 http.ResponseController 能穿透到底层 Writer（SetWriteDeadline 等）。
func (w *evidenceAuditWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// evidenceReadID 取证据标识：请求 ID，带附件时为 "request/artifact"，会话类为会话 ID。
func evidenceReadID(r *http.Request) string {
	rc := chi.RouteContext(r.Context())
	param := func(name string) string {
		if rc == nil {
			return ""
		}
		return strings.TrimSpace(rc.URLParam(name))
	}
	if req := param("request_id"); req != "" {
		if art := param("artifact_id"); art != "" {
			return req + "/" + art
		}
		return req
	}
	return param("session_id")
}

// AuditEvidenceRead 返回一个路由中间件：被包装的 handler 以 2xx 返回后，写一条证据读取审计。
// kind 是出口类型（content、content_raw、blob、image_proxy、artifact_original、artifact_preview、
// session_content、session_export、timeline ……）；content 出口在 view=raw 时记为 content_raw。
func AuditEvidenceRead(deps *Dependencies, kind string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			aw := &evidenceAuditWriter{ResponseWriter: w}
			next.ServeHTTP(aw, r)
			if aw.status != 0 && (aw.status < 200 || aw.status >= 300) {
				return
			}
			user := auth.GetUser(r.Context())
			if user == nil || deps == nil || deps.SystemRepo == nil {
				return
			}
			k := kind
			if k == "content" && r.URL.Query().Get("view") == "raw" {
				k = "content_raw"
			}
			id := evidenceReadID(r)
			detail := map[string]interface{}{
				"kind": k, "role": user.Role, "tenant_id": user.TenantID, "evidence_id": id,
			}
			// logAudit 内部已处理写入失败（只记日志）；这里不向上传播，保证读取不受审计影响。
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("component=evidence_read_audit stage=panic kind=%s", k)
					}
				}()
				logAudit(r, deps, "evidence.read", detail, "evidence", id)
			}()
		})
	}
}

// auditedEvidenceHandler 把一个证据读取 handler 包上读取审计，供路由注册处与 handler 构造函数共用。
func auditedEvidenceHandler(deps *Dependencies, kind string, h http.HandlerFunc) http.HandlerFunc {
	wrapped := AuditEvidenceRead(deps, kind)(h)
	return func(w http.ResponseWriter, r *http.Request) { wrapped.ServeHTTP(w, r) }
}
