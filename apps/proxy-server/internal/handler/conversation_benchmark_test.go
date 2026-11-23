package handler

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// This isolates decode and conversation attribution cost, excluding network,
// security inference and persistence. It is not gateway throughput.
func BenchmarkCopilotConversationProjection(b *testing.B) {
	for _, turns := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("turns_%d", turns), func(b *testing.B) {
			messages := make([]map[string]any, 0, turns)
			for i := 0; i < turns; i++ {
				messages = append(messages, map[string]any{"role": "user", "content": []map[string]string{{"type": "input_text", "text": "<userRequest>检查项目 " + strings.Repeat("业务上下文", 50) + "</userRequest>"}}})
			}
			body, _ := json.Marshal(map[string]any{"input": messages})
			req := httptest.NewRequest("POST", "https://api.individual.githubcopilot.com/responses", nil)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, ok := decodeVSCodeXWebRequest(req, body, "application/json")
				if !ok {
					b.Fatal("decoder failed")
				}
				enrichAPIConversationKey("benchmark-tenant", "github-copilot", &got, req)
				if got.ConversationID == "" {
					b.Fatal("conversation missing")
				}
			}
		})
	}
}
