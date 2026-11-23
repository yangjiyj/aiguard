package diagnostics

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	pemBegin := "-----BEGIN " + "PRIVATE KEY-----"
	pemEnd := "-----END " + "PRIVATE KEY-----"
	cases := []struct {
		name, in string
		gone     []string // 输出中不得出现
		keep     []string // 输出中必须出现
	}{
		{"Bearer", "header Bearer abc.def-123 end", []string{"abc.def-123"}, []string{"Bearer <redacted>"}},
		{"bearer小写", "bearer abcdef123456", []string{"abcdef123456"}, nil},
		{"sk密钥", "key is sk-proj_AbCd1234xyz ok", []string{"AbCd1234xyz"}, []string{"sk-<redacted>"}},
		{"sk短", "sk-xxxx", []string{"sk-xxxx"}, nil},
		{"Basic", "Authorization-less Basic dXNlcjpwYXNz", []string{"dXNlcjpwYXNz"}, []string{"Basic <redacted>"}},
		{"password行首", "password=xx", []string{"xx"}, []string{"password=<redacted>"}},
		{"password行中", "conn failed password=hunter2 retry", []string{"hunter2"}, []string{"retry"}},
		{"大写KEY", "JWT_SECRET=abc123\nDB_PASSWORD=p@ss\nHMAC_KEY=zzz\nAPI_TOKEN=ttt", []string{"abc123", "p@ss", "zzz", "ttt"}, nil},
		{"普通键不动", "WEB_PORT=3000\nCONTROL_PORT=8081", nil, []string{"WEB_PORT=3000", "CONTROL_PORT=8081"}},
		{"max_tokens不动", "max_tokens=4096", nil, []string{"max_tokens=4096"}},
		{"URL口令", "postgres://u:p@h:5432/db", []string{"u:p@"}, []string{"postgres://<redacted>@h:5432/db"}},
		{"URL无口令不动", "http://host:8080/path", nil, []string{"http://host:8080/path"}},
		{"Authorization头", "Authorization: Token secretvalue\nHost: x", []string{"secretvalue"}, []string{"Authorization: <redacted>", "Host: x"}},
		{"Cookie头", "Cookie: sid=abc; k=v", []string{"sid=abc"}, []string{"Cookie: <redacted>"}},
		{"Set-Cookie头", "set-cookie: a=b", []string{"a=b"}, nil},
		{"JSON键", `{"api_key":"abc999","name":"ok"}`, []string{"abc999"}, []string{`"name":"ok"`}},
		{"JSON key_prefix不动", `{"key_prefix":"sk-ab"}`, nil, []string{"key_prefix"}},
		{"PEM块", "x\n" + pemBegin + "\nMIIEvQIBADANBg\nabcdef\n" + pemEnd + "\ny", []string{"MIIEvQIBADANBg", "abcdef"}, []string{"x", "y"}},
		{"PEM未闭合", pemBegin + "\nSECRETBODY", []string{"SECRETBODY"}, nil},
		{"中文与请求编号不动", "请求 req_0a1b2c3d-1111-2222-3333-444455556666 返回 502，原因：上游超时", nil,
			[]string{"req_0a1b2c3d-1111-2222-3333-444455556666", "502", "上游超时"}},
		{"Basic普通英文不动", "Basic information about the system", nil, []string{"Basic information"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.in)
			for _, g := range c.gone {
				if strings.Contains(got, g) {
					t.Errorf("输出不应含 %q：%q", g, got)
				}
			}
			for _, k := range c.keep {
				if !strings.Contains(got, k) {
					t.Errorf("输出应含 %q：%q", k, got)
				}
			}
		})
	}
}

func TestRedactIdempotent(t *testing.T) {
	in := "Authorization: Bearer abc\npassword=x\npostgres://u:p@h/db"
	once := Redact(in)
	if twice := Redact(once); twice != once {
		t.Fatalf("不幂等：%q vs %q", once, twice)
	}
}
