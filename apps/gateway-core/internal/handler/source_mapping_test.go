package handler

import "testing"

func TestMessageRoleToSource(t *testing.T) {
	cases := map[string]string{
		"system":    "system_prompt",
		"System":    "system_prompt",
		"developer": "system_prompt",
		"user":      "user",
		"assistant": "assistant_history",
		"tool":      "tool_result",
		"function":  "tool_result",
		"":          "",
		"weird":     "",
	}
	for role, want := range cases {
		if got := messageRoleToSource(role); got != want {
			t.Fatalf("messageRoleToSource(%q) = %q, want %q", role, got, want)
		}
	}
}
