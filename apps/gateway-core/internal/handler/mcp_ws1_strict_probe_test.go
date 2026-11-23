package handler

// 独立探针：直接对严格解析器喂正/负样本，不依赖 HTTP 夹具。

import (
	"errors"
	"strings"
	"testing"
)

func TestWS1StrictParserProbe(t *testing.T) {
	reject := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","NAME":"b","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{"x":{"k":1,"K":2}}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":[{"k":1,"k":2}]}}`,
		`{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","ID":1,"id":2,"method":"ping"}`,
		`{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		`{"id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"Name":"a","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"URI":"file:///x"}}`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"a\xff\"}}",
		`{"jsonrpc":"2.0","id":1,"method":"ping"} {"x":1}`,
	}
	for _, body := range reject {
		_, _, err := parseMCPStrictMessage([]byte(body))
		if err == nil {
			t.Errorf("应拒绝: %q", body)
			continue
		}
		if code := mcpParseErrorCode(err); code != -32600 && code != -32700 {
			t.Errorf("错误码异常 %d: %q", code, body)
		}
	}
	accept := map[string]string{
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a<b>&c"}}}`: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a<b>&c"}}}`,
		`{ "jsonrpc" : "2.0", "id" : "s", "method":"resources/read", "params":{"uri":"file:///x","extra":1}}`:         `{"jsonrpc":"2.0","id":"s","method":"resources/read","params":{"uri":"file:///x"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`:                                                      `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":3,"result":{"roots":[]}}`:                                                              `{"jsonrpc":"2.0","id":3,"result":{"roots":[]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"x"},"Ref":null}}`:            "",
	}
	for body, want := range accept {
		msg, canonical, err := parseMCPStrictMessage([]byte(body))
		if want == "" {
			if err == nil {
				t.Errorf("未知方法 params 内大小写重复键也要拒: %q", body)
			}
			continue
		}
		if err != nil {
			t.Errorf("应接受: %q err=%v", body, err)
			continue
		}
		if string(canonical) != want {
			t.Errorf("规范化转发体不符\n in=%s\nout=%s\nwant=%s", body, canonical, want)
		}
		if strings.Contains(body, "tools/call") && msg.Params.Name != "read_file" {
			t.Errorf("name 投影错误: %q", msg.Params.Name)
		}
	}
	if !errors.Is(mcpStrictValidate([]byte(`{"a":1,"A":2}`)), errMCPAmbiguousPayload) {
		t.Fatal("大小写折叠重复键应归类为歧义载荷")
	}
}
