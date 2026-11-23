package main

import (
	"net/http"
	"testing"
	"time"
)

// 语料扫描的分片上传与下载不受 30 秒全局超时约束（规格 5.5）；其余语料接口保持 30 秒。
func TestCorpusScanTransferRoutesHaveExtendedTimeout(t *testing.T) {
	id := "corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10"
	extended := []struct{ method, path string }{
		{http.MethodPut, "/admin/v1/security/corpus-scans/" + id + "/chunks/0"},
		{http.MethodGet, "/admin/v1/security/corpus-scans/" + id + "/report"},
		{http.MethodGet, "/admin/v1/security/corpus-scans/" + id + "/masked"},
	}
	for _, c := range extended {
		req, _ := http.NewRequest(c.method, c.path, nil)
		if got := controlPlaneRequestTimeout(req); got != corpusScanTransferRequestTimeout {
			t.Errorf("%s %s timeout=%s want %s", c.method, c.path, got, corpusScanTransferRequestTimeout)
		}
	}
	standard := []struct{ method, path string }{
		{http.MethodGet, "/admin/v1/security/corpus-scans"},
		{http.MethodGet, "/admin/v1/security/corpus-scans/" + id},
		{http.MethodPost, "/admin/v1/security/corpus-scans/" + id + "/start"},
		{http.MethodPost, "/admin/v1/security/corpus-scans/" + id + "/report"},
		{http.MethodGet, "/admin/v1/security/corpus-scans/" + id + "/chunks/0"},
	}
	for _, c := range standard {
		req, _ := http.NewRequest(c.method, c.path, nil)
		if got := controlPlaneRequestTimeout(req); got != standardControlPlaneRequestTimeout {
			t.Errorf("%s %s timeout=%s want standard", c.method, c.path, got)
		}
	}
	server := newControlPlaneHTTPServer("127.0.0.1:0", http.NewServeMux())
	if server.ReadTimeout != 30*time.Second {
		// 全局读取超时不为语料上传放宽；分片 handler 自己用 ResponseController 延长读取期限。
		t.Fatalf("read timeout = %s, want unchanged 30s", server.ReadTimeout)
	}
}
