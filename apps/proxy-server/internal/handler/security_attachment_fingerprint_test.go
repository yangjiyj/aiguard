package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

func TestProxyFingerprintDoesNotSkipNewAttachment(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	attachmentScans := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, _ := payload["context"].(map[string]interface{})
		attachments, _ := ctx["attachments"].([]interface{})
		w.Header().Set("Content-Type", "application/json")
		if len(attachments) > 0 {
			attachmentScans++
			_, _ = w.Write([]byte(`{"action":"block","findings":[{"type":"file","action":"block"}],"semantic_status":"completed","engine_build":"b1","rule_pack_version":"rp1","raw_findings":[{"type":"file","action":"block"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"action":"allow","findings":[],"semantic_status":"completed","engine_build":"b1","rule_pack_version":"rp1","raw_findings":[]}`))
	}))
	defer server.Close()
	client := NewSecurityClient(server.URL)
	client.WithFingerprintStore(scanfp.NewStore(nil, 16))
	for _, file := range []bool{false, true} {
		content := `{"type":"input_text","text":"summarize this file"}`
		if file {
			content += `,{"type":"input_file","filename":"instructions.txt","file_data":"bm90ZQ=="}`
		}
		body := `{"model":"m","input":[{"role":"user","content":[` + content + `]}]}`
		req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		action, _, _ := client.CheckInput(context.Background(), "tenant", "probe", req)
		if file && (action != "block" || attachmentScans != 1) {
			t.Fatalf("new file bypassed engine using cached plain text: action=%s attachment_scans=%d", action, attachmentScans)
		}
	}
}
