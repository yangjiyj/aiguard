package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 控制面可切换成功/故障的测试桩：tenant 以请求体里的 tenant_id 区分币种不在这里做，
// 调用方通过 currencyBody 控制成功响应带什么币种。
type switchableBillingServer struct {
	server       *httptest.Server
	failStatus   atomic.Int32 // 0 表示成功
	currencyBody atomic.Value // string，成功响应体
}

func newSwitchableBillingServer(t *testing.T, successBody string) *switchableBillingServer {
	t.Helper()
	s := &switchableBillingServer{}
	s.currencyBody.Store(successBody)
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status := int(s.failStatus.Load()); status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"code":"billing_internal_error","message":"x"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(s.currencyBody.Load().(string)))
	}))
	t.Cleanup(s.server.Close)
	return s
}

func billingCurrencyEnvelope(tenant, requestID string) *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{TenantID: tenant, UserID: "user-a", RequestID: requestID, Model: "model-a"}
}

// 先从控制面成功拿到一次币种，之后控制面各类早返回路径（5xx、AllowanceRequired 报错、
// baseURL 为空）都要把缓存的租户币种写回信封，限额提示才不会退回默认符号。
func TestBillingClientEarlyReturnPathsReuseCachedTenantCurrency(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		degrade func(c *BillingClient, s *switchableBillingServer)
		wantErr bool
	}{
		{"metering 控制面 500 放行", "metering", func(c *BillingClient, s *switchableBillingServer) { s.failStatus.Store(500) }, false},
		{"prepaid 控制面 500 断流", "prepaid", func(c *BillingClient, s *switchableBillingServer) { s.failStatus.Store(500) }, true},
		{"AllowanceRequired 报错", "prepaid", func(c *BillingClient, s *switchableBillingServer) {
			c.AllowanceRequired = func(context.Context, string, string) (bool, error) { return false, errors.New("db down") }
		}, true},
		{"baseURL 为空", "prepaid", func(c *BillingClient, s *switchableBillingServer) { c.baseURL = "" }, true},
		{"已知未定价放行", "metering", func(c *BillingClient, s *switchableBillingServer) {
			s.failStatus.Store(500)
			c.ModelPriceConfigured = func(context.Context, string, string) (bool, error) { return false, nil }
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newSwitchableBillingServer(t, `{"billable_amount_micros":10,"reserved_micros":10,"currency":" usd ","price_id":"p1","admitted_at":"2026-10-22T00:00:00Z"}`)
			client := NewBillingClientWithMode(server.server.URL, "internal-secret", "", tc.mode)

			first := billingCurrencyEnvelope("tenant-a", "req-ok")
			if err := client.ReserveUsage(context.Background(), first, BillingUsage{PromptTokens: 1}); err != nil {
				t.Fatalf("首次成功响应不应报错：%v", err)
			}
			if first.QuotaCostCurrency != "USD" {
				t.Fatalf("成功响应应记录规范化币种 USD：%q", first.QuotaCostCurrency)
			}

			tc.degrade(client, server)
			second := billingCurrencyEnvelope("tenant-a", "req-degraded")
			err := client.ReserveUsage(context.Background(), second, BillingUsage{PromptTokens: 1})
			if tc.wantErr && err == nil {
				t.Fatal("该路径应返回 billing_unavailable")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("该路径应放行：%v", err)
			}
			if second.QuotaCostCurrency != "USD" {
				t.Fatalf("早返回路径应沿用缓存币种 USD：%q", second.QuotaCostCurrency)
			}
		})
	}
}

// 租户从没从控制面拿到过币种：不猜币种，信封保持为空（沿用历史的 ¥ 默认符号）。
func TestBillingClientEarlyReturnWithoutCachedCurrencyStaysEmpty(t *testing.T) {
	server := newSwitchableBillingServer(t, `{}`)
	server.failStatus.Store(500)
	client := NewBillingClientWithMode(server.server.URL, "internal-secret", "", "metering")
	envelope := billingCurrencyEnvelope("tenant-a", "req-nocache")
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 1}); err != nil {
		t.Fatalf("metering 控制面故障应放行：%v", err)
	}
	if envelope.QuotaCostCurrency != "" {
		t.Fatalf("没有缓存时不应猜币种：%q", envelope.QuotaCostCurrency)
	}

	// 成功响应没带币种（老版本控制面）也不会写缓存。
	server.failStatus.Store(0)
	server.currencyBody.Store(`{"billable_amount_micros":10}`)
	if err := client.ReserveUsage(context.Background(), billingCurrencyEnvelope("tenant-a", "req-oldcp"), BillingUsage{PromptTokens: 1}); err != nil {
		t.Fatal(err)
	}
	server.failStatus.Store(500)
	again := billingCurrencyEnvelope("tenant-a", "req-nocache-2")
	_ = client.ReserveUsage(context.Background(), again, BillingUsage{PromptTokens: 1})
	if again.QuotaCostCurrency != "" {
		t.Fatalf("老版本控制面不返回币种时不应出现缓存币种：%q", again.QuotaCostCurrency)
	}
}

// 币种缓存按租户隔离：A 租户的美元不能漏给 B 租户，B 租户的人民币也不能覆盖 A。
func TestBillingClientCachedCurrencyIsPerTenant(t *testing.T) {
	server := newSwitchableBillingServer(t, `{"billable_amount_micros":10,"currency":"USD"}`)
	client := NewBillingClientWithMode(server.server.URL, "internal-secret", "", "metering")
	if err := client.ReserveUsage(context.Background(), billingCurrencyEnvelope("tenant-a", "req-a"), BillingUsage{PromptTokens: 1}); err != nil {
		t.Fatal(err)
	}

	server.failStatus.Store(500)
	other := billingCurrencyEnvelope("tenant-b", "req-b-down")
	_ = client.ReserveUsage(context.Background(), other, BillingUsage{PromptTokens: 1})
	if other.QuotaCostCurrency != "" {
		t.Fatalf("B 租户不应拿到 A 租户的币种：%q", other.QuotaCostCurrency)
	}

	server.failStatus.Store(0)
	server.currencyBody.Store(`{"billable_amount_micros":10,"currency":"CNY"}`)
	if err := client.ReserveUsage(context.Background(), billingCurrencyEnvelope("tenant-b", "req-b"), BillingUsage{PromptTokens: 1}); err != nil {
		t.Fatal(err)
	}

	server.failStatus.Store(500)
	a := billingCurrencyEnvelope("tenant-a", "req-a-down")
	b := billingCurrencyEnvelope("tenant-b", "req-b-down-2")
	_ = client.ReserveUsage(context.Background(), a, BillingUsage{PromptTokens: 1})
	_ = client.ReserveUsage(context.Background(), b, BillingUsage{PromptTokens: 1})
	if a.QuotaCostCurrency != "USD" || b.QuotaCostCurrency != "CNY" {
		t.Fatalf("两个租户应各用各的币种：a=%q b=%q", a.QuotaCostCurrency, b.QuotaCostCurrency)
	}
}

// 租户 ID 为空不写缓存（否则所有无租户请求会共用一个币种）；nil client / nil envelope 不 panic。
func TestBillingClientCurrencyCacheIsNilSafe(t *testing.T) {
	var nilClient *BillingClient
	if err := nilClient.ReserveUsage(context.Background(), billingCurrencyEnvelope("tenant-a", "req-nil"), BillingUsage{}); err != nil {
		t.Fatalf("nil client 应直接放行：%v", err)
	}

	server := newSwitchableBillingServer(t, `{"billable_amount_micros":10,"currency":"USD"}`)
	client := NewBillingClientWithMode(server.server.URL, "internal-secret", "", "metering")
	if err := client.ReserveUsage(context.Background(), nil, BillingUsage{}); err != nil {
		t.Fatalf("nil envelope 应直接放行：%v", err)
	}

	if err := client.ReserveUsage(context.Background(), billingCurrencyEnvelope("", "req-notenant"), BillingUsage{PromptTokens: 1}); err != nil {
		t.Fatal(err)
	}
	server.failStatus.Store(500)
	anon := billingCurrencyEnvelope("", "req-notenant-2")
	_ = client.ReserveUsage(context.Background(), anon, BillingUsage{PromptTokens: 1})
	if anon.QuotaCostCurrency != "" {
		t.Fatalf("空租户 ID 不应读写币种缓存：%q", anon.QuotaCostCurrency)
	}
}
