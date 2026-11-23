package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestCapacityMCPSSEStopsAfterSafeTerminalError(t *testing.T) {
	progress := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1}}`
	late := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"uninspected-late-frame","progress":2}}`
	for _, test := range []struct {
		name              string
		auditOnly, closed bool
	}{
		{"default", false, false}, {"closed", false, true}, {"record", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", strconv.FormatBool(test.closed))
			body := "event: message\ndata: " + progress + "\n\n" +
				"event: message\ndata: " + ws1CleanResult + "\n\n" +
				"event: message\ndata: " + late + "\n\n"
			env := ws1ResultEnv(t, test.auditOnly, body, "text/event-stream", &ws1FakeResultChecker{err: capacityStreamTestError{}})
			response := env.post(t, ws1ToolCallRequest)
			if response.Code != http.StatusOK {
				t.Fatalf("committed SSE status must remain200: %d", response.Code)
			}
			if !ws1LogsContain(env, "mcp_tool_result_unverified") {
				t.Fatalf("inspection failure must retain gap: %v", env.logs())
			}
			payloads := parseMCPSSEDataPayloads(response.Body.Bytes())
			if test.closed && !test.auditOnly {
				if len(payloads) != 2 || string(payloads[0]) != progress || strings.Contains(response.Body.String(), "uninspected-late-frame") || strings.Contains(response.Body.String(), "sunny") {
					t.Fatalf("closed capacity must stop after rewritten error: %s", response.Body.String())
				}
				var terminal struct {
					ID    json.RawMessage `json:"id"`
					Error struct {
						Code int `json:"code"`
					} `json:"error"`
				}
				if err := json.Unmarshal(payloads[1], &terminal); err != nil || string(terminal.ID) != "9" || terminal.Error.Code != -32000 {
					t.Fatalf("terminal frame must carry correlated JSON-RPC error: %s", payloads[1])
				}
				interrupted := false
				for _, entry := range env.logs() {
					interrupted = interrupted || entry["status"] == "stream_aborted"
				}
				if !interrupted {
					t.Fatalf("SSE audit must record actual interrupted delivery: %v", env.logs())
				}
			} else if len(payloads) != 3 || string(payloads[1]) != ws1CleanResult || string(payloads[2]) != late {
				t.Fatalf("open or Record capacity must preserve all events: %s", response.Body.String())
			}
		})
	}
}
