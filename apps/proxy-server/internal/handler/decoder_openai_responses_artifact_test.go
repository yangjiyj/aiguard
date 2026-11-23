package handler

import (
	"strings"
	"testing"
)

func TestDecodeOpenAIResponsesRequestKeepsSharedArtifactCandidate(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5",
		"input":[{"role":"user","content":[
			{"type":"input_text","text":"summarize this file"},
			{"type":"input_file","filename":"notes.txt","file_data":"aGVsbG8="}
		]}]
	}`)
	extracted, ok := decodeOpenAIResponsesRequest(body)
	if !ok || !strings.Contains(extracted.Text, "summarize this file") {
		t.Fatalf("shared Responses parser lost user turn: ok=%v extracted=%+v", ok, extracted)
	}
	if len(extracted.Attachments) != 1 {
		t.Fatalf("shared Responses parser lost artifact: %+v", extracted.Attachments)
	}
	attachment := extracted.Attachments[0]
	if attachment.FileName != "notes.txt" || attachment.DataBase64 == "" || attachment.ReferenceID != "" {
		t.Fatalf("unexpected artifact adapter result: %+v", attachment)
	}
}
