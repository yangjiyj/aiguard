package inspectionscope

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// signMixedRuntimeFixture 与控制面 semanticCanonicalPayload 同编码：布尔 b:0/1，字符串 s:长度:内容。
func signMixedRuntimeFixture(config map[string]any) {
	var keys []string
	for key := range config {
		if key != "revision" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&canonical, "%d:%s=", len(key), key)
		switch value := config[key].(type) {
		case bool:
			if value {
				canonical.WriteString("b:1;")
			} else {
				canonical.WriteString("b:0;")
			}
		case string:
			fmt.Fprintf(&canonical, "s:%d:%s;", len(value), value)
		}
	}
	mac := hmac.New(sha256.New, []byte(runtimeTestKey))
	mac.Write([]byte("jjdguard:semantic-config:gateway-core\n" + canonical.String()))
	config["revision"] = hex.EncodeToString(mac.Sum(nil)[:16])
}

// 2.9.22：网关投影带上故障处理与检测执行的字符串键，独立代理共用这份投影，必须照常接受并读出。
// 用控制面真端点产出的签名夹具（control-plane TestGetInternalSemanticGatewayConfigWritesRuntimeFixture）。
func TestProxyReaderAcceptsControlPlaneRuntimeFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "apps", "gateway-core", "internal", "handler", "testdata", "semantic_gateway_runtime_config.json"))
	if err != nil {
		t.Fatalf("读不到控制面产出的夹具：%v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(raw) }))
	defer server.Close()
	// 与控制面夹具测试里网关签名密钥一致。
	reader := NewGatewayReader(server.URL, "test-internal-token", "semantic-gateway-test-key-32-bytes")
	if err := reader.Refresh(context.Background()); err != nil {
		t.Fatalf("控制面产出的签名投影被拒：%v", err)
	}
	for key, want := range map[string]string{
		"security_capacity_fail_mode": "closed", "upload_inspection_failure_action": "block", "output_strict_max_bytes": "2097152",
	} {
		if value, ok := reader.RuntimeOption(key); !ok || value != want {
			t.Fatalf("%s=%q ok=%v，期望 %q", key, value, ok, want)
		}
	}
}

// 不认识的取值只让该键按未下发处理，不连累整份投影（与网关同口径）。
func TestProxyReaderIgnoresUnknownRuntimeOptionValue(t *testing.T) {
	config := signedRuntimeFixture()
	config["security_capacity_fail_mode"] = "maybe"
	config["upload_inspection_failure_action"] = "block"
	signMixedRuntimeFixture(config)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(config) }))
	defer server.Close()
	reader := NewGatewayReader(server.URL, "test-internal-token", runtimeTestKey)
	if err := reader.Refresh(context.Background()); err != nil {
		t.Fatalf("单个不认识的取值不应让整份投影被拒：%v", err)
	}
	if _, ok := reader.RuntimeOption("security_capacity_fail_mode"); ok {
		t.Fatal("不认识的取值应按未下发处理")
	}
	if value, _ := reader.RuntimeOption("upload_inspection_failure_action"); value != "block" {
		t.Fatalf("其他键照常生效：%q", value)
	}
}

func TestProxyReaderRejectsUnsignedOrUnknownRuntimeOptions(t *testing.T) {
	unsigned := signedRuntimeFixture()
	unsigned["security_capacity_fail_mode"] = "closed"
	signRuntimeFixture(unsigned) // 只按布尔编码签名：字符串值没有被签进去
	unknown := signedRuntimeFixture()
	unknown["not_a_runtime_key"] = "x"
	signMixedRuntimeFixture(unknown)
	for name, config := range map[string]map[string]any{"unsigned": unsigned, "unknown": unknown} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(config) }))
		reader := NewGatewayReader(server.URL, "test-internal-token", runtimeTestKey)
		if err := reader.Refresh(context.Background()); err == nil {
			t.Fatalf("%s projection accepted", name)
		}
		server.Close()
	}
}

// 复审第四轮：不认识的取值只在变化时打日志，且只在验签通过后打。
func TestProxyReaderLogsUnknownRuntimeOptionValueOnlyOnChange(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	config := signedRuntimeFixture()
	config["security_capacity_fail_mode"] = "maybe"
	signMixedRuntimeFixture(config)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(config) }))
	defer server.Close()
	reader := NewGatewayReader(server.URL, "test-internal-token", runtimeTestKey)
	for i := 0; i < 3; i++ {
		if err := reader.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "security_capacity_fail_mode"); n != 1 {
		t.Fatalf("同一个不认识的取值应只记一次，实际 %d 次：%s", n, buf.String())
	}
	buf.Reset()
	forged := signedRuntimeFixture()
	forged["security_capacity_fail_mode"] = "other"
	forged["revision"] = strings.Repeat("0", 32)
	forgedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(forged) }))
	defer forgedServer.Close()
	if err := NewGatewayReader(forgedServer.URL, "test-internal-token", runtimeTestKey).Refresh(context.Background()); err == nil {
		t.Fatal("签名不符应拒收")
	}
	if strings.Contains(buf.String(), "security_capacity_fail_mode") {
		t.Fatalf("验签没通过时不应记取值日志：%s", buf.String())
	}
}
