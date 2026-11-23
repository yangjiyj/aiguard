// Package inspectionscope defines dialogue alert targets independently of detector layers.
package inspectionscope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type Policy struct {
	InspectUserInput      bool `json:"inspect_user_input"`
	InspectModelOutput    bool `json:"inspect_model_output"`
	InspectBuiltinContext bool `json:"inspect_builtin_context"`
	InspectHistory        bool `json:"inspect_history"`
	InspectToolResults    bool `json:"inspect_tool_results"`
}

func Default() Policy {
	return Policy{InspectUserInput: true, InspectModelOutput: true, InspectToolResults: true}
}

// Allows accepts only protocol-derived sources. Content markers never establish provenance.
func (p Policy) Allows(source string, latestUser bool) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "user":
		if latestUser {
			return p.InspectUserInput
		}
		return p.InspectHistory
	case "model_output":
		return p.InspectModelOutput
	case "system_prompt", "system", "developer", "developer_instruction", "tool_def", "agent_runtime_context", "agent_analysis_context":
		return p.InspectBuiltinContext
	case "assistant_history", "user_history":
		return p.InspectHistory
	case "tool_result", "rag", "rag_context", "retrieval", "retrieval_result", "web_content":
		return p.InspectToolResults
	default:
		return true
	}
}

// IsUntrustedSource reports content produced outside the operator's trust
// boundary: tool output, retrieval, and fetched web pages. A verdict on such a
// segment depends on what the user is asking the model to do with it, so the
// gateway may not reuse it across different tasks.
func IsUntrustedSource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "tool_result", "rag", "rag_context", "retrieval", "retrieval_result", "web_content":
		return true
	default:
		return false
	}
}

// Includes requires both source and history selection for an older tool/RAG turn.
// Unknown sources remain in scope even if an unrecognized parser marks them historical.
func (p Policy) Includes(source string, latestUser, history bool) bool {
	if !p.Allows(source, latestUser) {
		return false
	}
	if IsUntrustedSource(source) {
		return !history || p.InspectHistory
	}
	return true
}

func (p Policy) Fingerprint() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Fields preserves absence for the signed pre-scope configuration contract.
// A partial policy is invalid; an entirely absent policy uses the documented defaults.
type Fields struct {
	InspectUserInput      *bool `json:"inspect_user_input,omitempty"`
	InspectModelOutput    *bool `json:"inspect_model_output,omitempty"`
	InspectBuiltinContext *bool `json:"inspect_builtin_context,omitempty"`
	InspectHistory        *bool `json:"inspect_history,omitempty"`
	InspectToolResults    *bool `json:"inspect_tool_results,omitempty"`
}

func (f Fields) values() map[string]*bool {
	return map[string]*bool{"inspect_user_input": f.InspectUserInput, "inspect_model_output": f.InspectModelOutput,
		"inspect_builtin_context": f.InspectBuiltinContext, "inspect_history": f.InspectHistory, "inspect_tool_results": f.InspectToolResults}
}
func (f Fields) AddCanonical(values map[string]any) {
	for key, value := range f.values() {
		if value != nil {
			values[key] = *value
		}
	}
}
func (f Fields) Resolve() (Policy, error) {
	n := 0
	for _, value := range f.values() {
		if value != nil {
			n++
		}
	}
	if n == 0 {
		return Default(), nil
	}
	if n != 5 {
		return Policy{}, fmt.Errorf("incomplete inspection source policy")
	}
	return Policy{*f.InspectUserInput, *f.InspectModelOutput, *f.InspectBuiltinContext, *f.InspectHistory, *f.InspectToolResults}, nil
}
