package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
)

func shanghaiTime(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.FixedZone("CST", 8*3600))
}

// 断流开启后的金额超限：统一 429 + error.code=budget_exhausted，中文提示写明哪一层、已用/额度、何时重置。
func TestWriteQuotaAdmissionErrorBudgetCutoffMessageIsChineseWithLayerAndReset(t *testing.T) {
	cases := []struct {
		name string
		err  *governor.AdmissionLimitError
		want []string
	}{
		{"部门月预算", &governor.AdmissionLimitError{
			Metric: "month_cost_micros", Scope: "team", ScopeName: "研发部", Limit: 5_000_000_000, Used: 5_000_000_000,
			BudgetCutoff: true, RequestID: "req-team", ResetAt: shanghaiTime(2026, 11, 1),
		}, []string{"本月部门预算已用完", "研发部", "¥5,000.00 / ¥5,000.00", "11 月 1 日自动恢复", "请联系管理员"}},
		{"组织日预算", &governor.AdmissionLimitError{
			Metric: "day_cost_micros", Scope: "tenant", Limit: 100_000_000, Used: 100_000_000,
			BudgetCutoff: true, RequestID: "req-day", ResetAt: shanghaiTime(2026, 10, 12),
		}, []string{"今日组织预算已用完", "¥100.00 / ¥100.00", "10 月 12 日自动恢复"}},
		{"项目月预算含预占", &governor.AdmissionLimitError{
			Metric: "month_cost_micros", Scope: "project", Limit: 2_000_000, Used: 1_500_000, Reserved: 500_000,
			BudgetCutoff: true, RequestID: "req-proj", ResetAt: shanghaiTime(2026, 11, 1),
		}, []string{"本月项目预算已用完", "¥2.00 / ¥2.00"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeQuotaAdmissionError(w, tc.err, "req-fallback")
			var body ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusTooManyRequests || body.Error.Code != "budget_exhausted" {
				t.Fatalf("status=%d code=%q", w.Code, body.Error.Code)
			}
			for _, want := range tc.want {
				if !strings.Contains(body.Error.Message, want) {
					t.Fatalf("message %q missing %q", body.Error.Message, want)
				}
			}
		})
	}
}

// 开关关闭（BudgetCutoff=false）：错误码仍是 quota_exceeded，但文案也改成中文，不再露出英文。
func TestWriteQuotaAdmissionErrorLegacyQuotaMessageIsChinese(t *testing.T) {
	w := httptest.NewRecorder()
	writeQuotaAdmissionError(w, &governor.AdmissionLimitError{Metric: "month_cost_micros", Scope: "tenant", Limit: 10, Used: 10, RequestID: "r"}, "r")
	var body ErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusTooManyRequests || body.Error.Code != "quota_exceeded" {
		t.Fatalf("status=%d code=%q", w.Code, body.Error.Code)
	}
	if regexp.MustCompile(`[A-Za-z]{4,}`).MatchString(body.Error.Message) || body.Error.Message == "" {
		t.Fatalf("legacy message must be Chinese: %q", body.Error.Message)
	}
}

func TestBudgetMessageMoneyFormatting(t *testing.T) {
	cases := map[int64]string{0: "¥0.00", 1_000_000: "¥1.00", 5_000_000_000: "¥5,000.00", 1_234_567_890: "¥1,234.57", 999: "¥0.00"}
	for micros, want := range cases {
		if got := formatBudgetMicros(micros, ""); got != want {
			t.Fatalf("formatBudgetMicros(%d) = %q, want %q", micros, got, want)
		}
	}
}

// 员工月额度用尽（控制面返回）→ 网关原样透传中文提示并统一成 budget_exhausted。
func TestBillingAdmissionResponseMapsAllowanceExhaustedToBudgetExhaustedOnlyWhenCutoffIsOn(t *testing.T) {
	message := "本月个人额度已用完（张三，已用 ¥1.00 / ¥1.00），11 月 1 日自动恢复，如需追加请联系管理员"
	// 断流开启：统一成 429 + budget_exhausted。
	status, code, got := billingAdmissionResponse(&BillingAdmissionError{Code: "monthly_allowance_exhausted", HTTPStatus: 429, Message: message, cutoff: true})
	if status != 429 || code != budgetExhaustedCode || !strings.Contains(got, "本月个人额度已用完") {
		t.Fatalf("cutoff on: status=%d code=%s message=%s", status, code, got)
	}
	// 断流关闭：错误码、状态码保持改造前的样子。
	status, code, _ = billingAdmissionResponse(&BillingAdmissionError{Code: "monthly_allowance_exhausted", HTTPStatus: 429, Message: message})
	if status != 429 || code != "monthly_allowance_exhausted" {
		t.Fatalf("cutoff off must keep the legacy code: status=%d code=%s", status, code)
	}
	if got := billingAdmissionOutcome(&BillingAdmissionError{Code: "monthly_allowance_exhausted", HTTPStatus: 429}); got != "" {
		t.Fatalf("cutoff off must not tag a billing outcome, got %q", got)
	}
	if got := billingAdmissionOutcome(&BillingAdmissionError{Code: "monthly_allowance_exhausted", HTTPStatus: 429, cutoff: true}); got != billingOutcomeBudgetExhausted {
		t.Fatalf("cutoff on outcome = %q", got)
	}
	// 其他计费错误码不被改写。
	status, code, _ = billingAdmissionResponse(&BillingAdmissionError{Code: "insufficient_balance", HTTPStatus: 402, Message: "余额不足，请充值"})
	if status != 402 || code != "insufficient_balance" {
		t.Fatalf("status=%d code=%s", status, code)
	}
}

// Message snapshots use fixed dates; backoff behavior uses relative deadlines.
func TestWriteQuotaAdmissionErrorBudgetResetRetryAfter(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		reset time.Time
		retry int64
		want  int64
	}{
		{name: "future reset", reset: now.Add(time.Hour), want: -1},
		{name: "expired reset", reset: now.Add(-time.Hour)},
		{name: "explicit backoff", reset: now.Add(-time.Hour), retry: 37, want: 37},
		{name: "no reset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeQuotaAdmissionError(recorder, &governor.AdmissionLimitError{
				Metric: "month_cost_micros", Scope: "tenant", Limit: 100, Used: 100,
				BudgetCutoff: true, ResetAt: tc.reset, RetryAfter: tc.retry,
			}, "request")
			value := recorder.Header().Get("Retry-After")
			if tc.want == 0 {
				if value != "" {
					t.Fatalf("expired or absent reset must omit backoff, got %q", value)
				}
				return
			}
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				t.Fatalf("invalid Retry-After %q: %v", value, err)
			}
			if tc.want > 0 {
				if seconds != tc.want {
					t.Fatalf("backoff=%d want=%d", seconds, tc.want)
				}
			} else if seconds <= 0 || seconds > int64(time.Hour.Seconds()) {
				t.Fatalf("future reset backoff out of range: %d", seconds)
			}
		})
	}
}
