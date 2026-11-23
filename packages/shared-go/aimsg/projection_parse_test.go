package aimsg

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

const projectionPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

func TestParseOpenAIRequestProjection(t *testing.T) {
	parsed, ok := ParseOpenAIChatRequest([]byte(`{
		"model":"gpt-5",
		"messages":[
			{"role":"system","content":"hidden system"},
			{"role":"user","content":[
				{"type":"text","text":"inspect these artifacts"},
				{"type":"image_url","image_url":{"url":"data:image/png;base64,` + projectionPNG + `"}},
				{"type":"input_file","file":{"file_data":"data:text/plain;base64,aGVsbG8=","filename":"note.txt"}}
			]}
		]
	}`))
	if !ok {
		t.Fatal("chat request should parse")
	}
	if parsed.Projection.UserInput != "inspect these artifacts" || parsed.Projection.ModelOutput != "" {
		t.Fatalf("projection = %#v", parsed.Projection)
	}
	if parsed.Projection.Status != ParseComplete {
		t.Fatalf("status = %q", parsed.Projection.Status)
	}
	if len(parsed.Projection.Artifacts) != 2 {
		t.Fatalf("artifacts = %#v", parsed.Projection.Artifacts)
	}
	for _, artifact := range parsed.Projection.Artifacts {
		if artifact.Direction != retentionartifact.DirectionInput || artifact.Payload == nil {
			t.Fatalf("input artifact was not retained as a candidate: %#v", artifact)
		}
	}
}

func TestParseResponsesRequestProjection(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
		"model":"gpt-5",
		"instructions":"hidden system",
		"input":[{"type":"message","role":"user","content":[
			{"type":"input_text","text":"summarize the file"},
			{"type":"input_file","file_data":"data:text/plain;base64,aGVsbG8=","filename":"draft.txt"},
			{"type":"input_image","image_url":"data:image/png;base64,` + projectionPNG + `"}
		]}]
	}`))
	if !ok {
		t.Fatal("responses request should parse")
	}
	if parsed.Projection.UserInput != "summarize the file" || parsed.Projection.Status != ParseComplete {
		t.Fatalf("projection = %#v", parsed.Projection)
	}
	if len(parsed.Projection.Artifacts) != 2 {
		t.Fatalf("artifacts = %#v", parsed.Projection.Artifacts)
	}
}

func TestParseAnthropicRequestProjection(t *testing.T) {
	parsed, ok := ParseAnthropicMessagesRequest([]byte(`{
		"model":"claude",
		"system":"hidden system",
		"messages":[{"role":"user","content":[
			{"type":"text","text":"review the attachments"},
			{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + projectionPNG + `"}},
			{"type":"document","source":{"type":"base64","media_type":"text/plain","data":"aGVsbG8="},"title":"note.txt"}
		]}]
	}`))
	if !ok {
		t.Fatal("anthropic request should parse")
	}
	if parsed.Projection.UserInput != "review the attachments" || parsed.Projection.Status != ParseComplete {
		t.Fatalf("projection = %#v", parsed.Projection)
	}
	if len(parsed.Projection.Artifacts) != 2 {
		t.Fatalf("artifacts = %#v", parsed.Projection.Artifacts)
	}
}

func TestParseOpenAIResponseProjection(t *testing.T) {
	jsonProjection, ok := ParseOpenAIChatResponse([]byte(`{
		"model":"gpt-5",
		"choices":[{"message":{"role":"assistant","content":"final answer","tool_calls":[{"id":"call_1"}]}}]
	}`))
	if !ok || jsonProjection.ModelOutput != "final answer" {
		t.Fatalf("json projection = %#v, ok=%v", jsonProjection, ok)
	}

	sseProjection, ok := ParseOpenAIChatResponse([]byte(`data: {"choices":[{"index":0,"delta":{"content":"hello "}}]}

data: {"choices":[{"index":0,"delta":{"content":"world"}}]}

data: [DONE]

`))
	if !ok || sseProjection.ModelOutput != "hello world" {
		t.Fatalf("sse projection = %#v, ok=%v", sseProjection, ok)
	}
}

func TestParseResponsesResponseProjection(t *testing.T) {
	projection, ok := ParseOpenAIResponsesResponse([]byte(`{
		"model":"gpt-5",
		"output":[
			{"type":"reasoning","summary":[{"type":"summary_text","text":"hidden thought"}]},
			{"type":"function_call","name":"shell","arguments":"{\"cmd\":\"secret\"}"},
			{"type":"message","role":"assistant","content":[
				{"type":"output_text","text":"final response"},
				{"type":"image_generation_call","result":"data:image/png;base64,` + projectionPNG + `"},
				{"type":"file","file_id":"file_private","filename":"report.txt"}
			]}
		]
	}`))
	if !ok || projection.ModelOutput != "final response" {
		t.Fatalf("projection = %#v, ok=%v", projection, ok)
	}
	if len(projection.Artifacts) != 2 ||
		projection.Artifacts[0].Direction != retentionartifact.DirectionOutput ||
		projection.Artifacts[0].Kind != retentionartifact.KindImage ||
		projection.Artifacts[1].Payload != nil {
		t.Fatalf("output artifacts = %#v", projection.Artifacts)
	}

	sseProjection, ok := ParseOpenAIResponsesResponse([]byte(`event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"hello "}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"world"}

event: response.completed
data: {"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello world"}]}]}}

`))
	if !ok || sseProjection.ModelOutput != "hello world" {
		t.Fatalf("sse projection = %#v, ok=%v", sseProjection, ok)
	}
}

func TestParseAnthropicResponseProjection(t *testing.T) {
	projection, ok := ParseAnthropicMessagesResponse([]byte(`{
		"model":"claude",
		"content":[
			{"type":"thinking","thinking":"hidden thought"},
			{"type":"tool_use","name":"Bash","input":{"command":"secret"}},
			{"type":"text","text":"visible result"}
		]
	}`))
	if !ok || projection.ModelOutput != "visible result" {
		t.Fatalf("projection = %#v, ok=%v", projection, ok)
	}

	sseProjection, ok := ParseAnthropicMessagesResponse([]byte(`event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"visible "}}

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"result"}}

`))
	if !ok || sseProjection.ModelOutput != "visible result" {
		t.Fatalf("sse projection = %#v, ok=%v", sseProjection, ok)
	}
}

func TestParseKnownRequestDoesNotExposeUnknownContentInProjection(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
		"model":"gpt-5",
		"input":[{"type":"message","role":"user","content":[{"type":"runtime_blob","payload":"hidden machine envelope"}]}]
	}`))
	if !ok {
		t.Fatal("known request must remain available to the security parser")
	}
	if parsed.Projection.UserInput != "" || parsed.Projection.Status != ParseAmbiguous {
		t.Fatalf("unknown content leaked into projection: %#v", parsed.Projection)
	}
	if strings.Contains(parsed.Projection.UserInput, "runtime_blob") {
		t.Fatalf("projection leaked raw JSON: %#v", parsed.Projection)
	}
}
