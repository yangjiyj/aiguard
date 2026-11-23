package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 行为矩阵 8.2：端侧 decide 的工具日志是这次判定唯一的留痕。阻断要写下决定处置的防护项；
// 告警放行要标“要告警”；仅记录、全局观察留痕下不标。
func TestDecide2922ToolLogCarriesProtectionItemAndAlert(t *testing.T) {
	decide := func(t *testing.T, protections string, globalRecord bool) map[string]any {
		t.Helper()
		var logs []map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/v1/internal/agentguard/effective-policy":
				_, _ = w.Write([]byte(`{"data":{"id":"p","mode":"audit","default_action":"audit","confirm_channel_enabled":true,"rules":[],"exceptions":[]` + protections + `}}`))
			case "/admin/v1/internal/tools/logs":
				var payload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&payload)
				logs = append(logs, payload)
				_, _ = w.Write([]byte(`{"id":"tool-log"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)
		client := NewToolRiskClient(server.URL, "internal-secret")
		setToolGuardTestPosture(t, client, globalRecord, false)
		g, _ := endpointPolicyTestGateway(t, endpointTestBundle(nil, nil))
		g.runtime, g.toolClient = client, client
		w := callEndpointDecide(g, strings.Replace(hookdDecideRequestFixture, "/tmp/fixture", "/home/u/.ssh/id_rsa", 1), "ep_fixture01", "block")
		if w.Code != http.StatusOK || len(logs) != 1 {
			t.Fatalf("status=%d logs=%d body=%s", w.Code, len(logs), w.Body.String())
		}
		return logs[0]
	}
	item := func(payload map[string]any) any {
		evidence, _ := payload["evidence_json"].(map[string]any)
		return evidence["protection_item"]
	}
	if got := decide(t, `,"protections":{"agent.ssh_private_key":{"action":"block","params":{}}}`, false); got["status"] != "blocked" || item(got) != "agent.ssh_private_key" || got["notification_required"] == true {
		t.Fatalf("a block must name the deciding protection item: %v", got)
	}
	if got := decide(t, ``, false); got["effective_decision"] != "audit" || got["notification_required"] != true || item(got) != "agent.ssh_private_key" {
		t.Fatalf("the default alert-and-allow must ask for an alert: %v", got)
	}
	if got := decide(t, `,"protections":{"agent.ssh_private_key":{"action":"record","params":{}}}`, false); got["notification_required"] == true {
		t.Fatalf("record must not alert: %v", got)
	}
	if got := decide(t, ``, true); got["notification_required"] == true {
		t.Fatalf("global record mode must not alert: %v", got)
	}
}
