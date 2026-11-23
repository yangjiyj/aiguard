package aicontentlabel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

var testKey = DeriveKey("internal-secret-for-test")

func TestWatermarkRoundTrip(t *testing.T) {
	for _, requestID := range []string{
		"req_6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
		"6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
	} {
		frame, ok := Encode(requestID, testKey)
		if !ok {
			t.Fatalf("Encode(%q) failed", requestID)
		}
		if n := utf8.RuneCountInString(frame); n != FrameRunes {
			t.Fatalf("frame runes = %d, want %d", n, FrameRunes)
		}
		text := "第一段回答。\n\n第二段回答" + frame + "（以上内容由 AI 生成）"
		frames := Find(text)
		if len(frames) != 1 {
			t.Fatalf("Find returned %d frames", len(frames))
		}
		got, ok := Verify(frames[0], testKey)
		if !ok || got != requestID {
			t.Fatalf("Verify = %q, %v; want %q", got, ok, requestID)
		}
		if stripped := Strip(text); stripped != "第一段回答。\n\n第二段回答（以上内容由 AI 生成）" {
			t.Fatalf("Strip = %q", stripped)
		}
	}
}

func TestWatermarkRejectsForgeryAndWrongKey(t *testing.T) {
	frame, _ := Encode("req_6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", testKey)
	if _, ok := Verify(Find(frame)[0], DeriveKey("another-secret")); ok {
		t.Fatal("frame verified under a different key")
	}
	// 把第一个数据符号换成另一个合法符号：格式仍完整，HMAC 必须失败。
	runes := []rune(frame)
	for i, s := range symbols {
		if runes[2+4] == s {
			runes[2+4] = symbols[(i+1)%4]
			break
		}
	}
	tampered := Find(string(runes))
	if len(tampered) != 1 {
		t.Fatalf("tampered frame should still be well-formed, found %d", len(tampered))
	}
	if _, ok := Verify(tampered[0], testKey); ok {
		t.Fatal("tampered frame verified")
	}
}

func TestWatermarkRefusesUnsupportedRequestIDs(t *testing.T) {
	for _, id := range []string{"", "req_", "keepalive-123", "req_6F1C2A3B-4D5E-4F60-8A7B-9C0D1E2F3A4B", "{6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b}"} {
		if _, ok := Encode(id, testKey); ok {
			t.Fatalf("Encode(%q) should refuse", id)
		}
	}
	if _, ok := Encode("req_6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", nil); ok {
		t.Fatal("Encode without key should refuse")
	}
	if DeriveKey("  ") != nil {
		t.Fatal("blank secret should derive no key")
	}
}

func TestFindIgnoresTruncatedAndStrayZeroWidth(t *testing.T) {
	frame, _ := Encode("req_6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", testKey)
	truncated := string([]rune(frame)[:FrameRunes-1])
	cases := map[string]string{
		"截断":       "回答" + truncated,
		"零散零宽字符":   "零" + string(symbols[0]) + "宽" + string(symbols[1]) + "字" + string(symbols[2]) + "符",
		"只有起点":     "a" + frameStart + "b",
		"终点缺失后接正文": strings.Replace(frame, frameEnd, "x", 1),
	}
	for name, text := range cases {
		if got := Find(text); len(got) != 0 {
			t.Fatalf("%s: Find returned %d frames", name, len(got))
		}
		if Strip(text) != text {
			t.Fatalf("%s: Strip changed text", name)
		}
	}
	// 多一个起点符号在前面也要能找到后面的完整帧。
	if got := Find(string(markRune) + frame); len(got) != 1 {
		t.Fatalf("leading extra marker: found %d frames", len(got))
	}
	// 两个帧都能找到。
	if got := Find(frame + "中间" + frame); len(got) != 2 {
		t.Fatalf("two frames: found %d", len(got))
	}
}

func TestSettingsDefaultsAndParsing(t *testing.T) {
	d := ParseSettings(nil)
	if d.ExplicitEnabled || d.WatermarkEnabled || d.ExplicitText != DefaultExplicitText ||
		len(d.AgentTypes) != 1 || d.AgentTypes[0] != PortalAgentType {
		t.Fatalf("defaults = %+v", d)
	}
	if d.AppliesTo(PortalAgentType) {
		t.Fatal("disabled settings must not apply")
	}

	s := ParseSettings(map[string]string{
		KeyExplicitEnabled:  "true",
		KeyWatermarkEnabled: "TRUE",
		KeyExplicitText:     "  本回答由人工智能生成  ",
		KeyAgentTypes:       `["Enterprise_Portal","customer-desk","enterprise-portal"]`,
	})
	if !s.ExplicitEnabled || !s.WatermarkEnabled || s.ExplicitText != "本回答由人工智能生成" {
		t.Fatalf("parsed = %+v", s)
	}
	if len(s.AgentTypes) != 2 || s.AgentTypes[0] != PortalAgentType || s.AgentTypes[1] != "customer-desk" {
		t.Fatalf("agent types = %v", s.AgentTypes)
	}
	if !s.AppliesTo("enterprise-portal") || !s.AppliesTo("Customer Desk") || s.AppliesTo("claude-code") || s.AppliesTo("") {
		t.Fatal("AppliesTo mismatch")
	}
	if s.ExplicitLine() != "（本回答由人工智能生成）" {
		t.Fatalf("ExplicitLine = %q", s.ExplicitLine())
	}

	bad := ParseSettings(map[string]string{KeyExplicitText: "含\n换行", KeyAgentTypes: "not-json"})
	if bad.ExplicitText != DefaultExplicitText || len(bad.AgentTypes) != 1 {
		t.Fatalf("invalid values should fall back to defaults: %+v", bad)
	}
}

func TestNormalizeSettingValue(t *testing.T) {
	cases := []struct {
		key, raw, want string
		wantErr        bool
	}{
		{KeyExplicitEnabled, " True ", "true", false},
		{KeyWatermarkEnabled, "yes", "", true},
		{KeyExplicitText, "", DefaultExplicitText, false},
		{KeyExplicitText, strings.Repeat("长", 41), "", true},
		{KeyExplicitText, "带" + string(symbols[0]) + "零宽", "", true},
		{KeyAgentTypes, `[" enterprise_portal ",""]`, `["enterprise-portal"]`, false},
		{KeyAgentTypes, `[]`, `[]`, false},
		{KeyAgentTypes, `{"a":1}`, "", true},
	}
	for _, c := range cases {
		got, ok, err := NormalizeSettingValue(c.key, c.raw)
		if !ok {
			t.Fatalf("%s should be recognised", c.key)
		}
		if (err != nil) != c.wantErr || got != c.want {
			t.Fatalf("NormalizeSettingValue(%s, %q) = %q, %v", c.key, c.raw, got, err)
		}
	}
	if _, ok, _ := NormalizeSettingValue("block_response_mode", "x"); ok {
		t.Fatal("unrelated key should not be recognised")
	}
}

// watermarkVector 是跨语言测试向量；安全引擎的 Python 测试读同一份文件。
type watermarkVector struct {
	Name      string `json:"name"`
	Text      string `json:"text"`
	Frames    int    `json:"frames"`
	Stripped  string `json:"stripped"`
	RequestID string `json:"request_id,omitempty"`
}

func TestWatermarkVectorsMatchImplementation(t *testing.T) {
	raw, err := os.ReadFile("testdata/watermark_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Secret  string            `json:"secret"`
		Vectors []watermarkVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	key := DeriveKey(file.Secret)
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		frames := Find(v.Text)
		if len(frames) != v.Frames {
			t.Fatalf("%s: frames = %d, want %d", v.Name, len(frames), v.Frames)
		}
		if got := Strip(v.Text); got != v.Stripped {
			t.Fatalf("%s: stripped = %q, want %q", v.Name, got, v.Stripped)
		}
		if v.RequestID != "" {
			got, ok := Verify(frames[0], key)
			if !ok || got != v.RequestID {
				t.Fatalf("%s: verify = %q, %v", v.Name, got, ok)
			}
			if frame, _ := Encode(v.RequestID, key); !strings.Contains(v.Text, frame) {
				t.Fatalf("%s: vector text does not contain the encoded frame", v.Name)
			}
		}
	}
}
