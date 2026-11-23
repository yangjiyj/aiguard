package security

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDLPTransportOverwritesUntrustedContext(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "record_only")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Context map[string]any `json:"context"`
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 && body[0] == '[' {
			var batch []struct {
				Context map[string]any `json:"context"`
			}
			json.Unmarshal(body, &batch)
			payload.Context = batch[0].Context
		} else {
			json.Unmarshal(body, &payload)
		}
		if payload.Context["key_id"] != "key1" || payload.Context["effective_dlp_enforcement"] != "record" || payload.Context["integration_credential"] != true {
			t.Errorf("可信档位未传达：%v", payload.Context)
		}
		ids, _ := payload.Context["integration_dlp_block_key_ids"].([]any)
		if len(ids) != 2 || ids[0] != "key1" || ids[1] != "key2" {
			t.Errorf("全部绑定凭据的可信状态未传达：%v", ids)
		}
		if len(body) > 0 && body[0] == '[' {
			json.NewEncoder(w).Encode([]CheckInputResponse{{RequestID: "测试", Action: "audit"}})
			return
		}
		json.NewEncoder(w).Encode(CheckInputResponse{Action: "audit"})
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), auth.KeyIDKey, "key1")
	ctx = context.WithValue(ctx, auth.AgentInstanceIDKey, "agent1")
	ctx = context.WithValue(ctx, auth.KeyDLPEnforcementKey, "block")
	ctx = context.WithValue(ctx, auth.IntegrationDLPBlockKeysKey, []string{"key1", "key2"})
	client := NewClient(server.URL)
	request := &CheckInputRequest{RequestID: "测试", Content: "测试内容", Context: map[string]any{"key_id": "伪造", "effective_dlp_enforcement": "block", "integration_dlp_block_key_ids": []string{"伪造"}}}
	_, err := client.CheckInput(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.CheckOutput(ctx, request.RequestID, request.Content, request.Context); err != nil {
		t.Fatal(err)
	}
	if _, err = client.CheckInputBatch(ctx, []*CheckInputRequest{request}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ApplyContext(ctx, &ApplyContextRequest{TenantID: "tenant-a", Context: ApplyContextContext{IntegrationDLPBlockKeyIDs: []string{"伪造"}}}); err != nil {
		t.Fatal(err)
	}
}
