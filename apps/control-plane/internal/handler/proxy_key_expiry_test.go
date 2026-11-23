package handler

import (
	"testing"
	"time"
)

// 任务 3.4：Key 过期生效（P1-9，支柱⑤凭据生命周期）。
//
// 现状根因：repository.Create 本就把 k.ExpiresAt 写进 INSERT（struct 有 ExpiresAt
// 字段、INSERT 写 expires_at 列），gateway-core 数据面 verifier（proxy_key_verifier.go）
// 查询带 (expires_at IS NULL OR expires_at > now()) 已强制校验过期——「auth 校验过期」
// 这一半本就成立。真缺点只在 CreateProxyAccessKey 的请求体 struct 不收任何过期字段，
// 故 k.ExpiresAt 永远 nil → 每把 API 签发的 key 永不过期。
//
// 设计（reject-not-coerce，与 3.1/3.2/3.3 一致；相对 TTL 与 3.3 grace_seconds 同构，
// 避开客户端时钟/时区，服务端用权威 now() 算绝对时刻）：
// resolveIssueExpiry(expiresInSeconds, now)：nil→nil（永不过期，向后兼容默认）；
// >0→now+ttl；≤0→拒绝（签发即过期无意义）；>10 年上限→拒绝（防单位笔误）。
// 纯函数直测，绕开 ProxyAccessKeyRepo 具体类型 nil-panic。

func TestResolveIssueExpiry(t *testing.T) {
	sec := func(n int) *int { return &n }
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	// nil（未传 expires_in_seconds）→ nil，永不过期，向后兼容不报错。
	if got, err := resolveIssueExpiry(nil, now); err != nil || got != nil {
		t.Fatalf("nil 应回永不过期(nil) 不报错，实际 got=%v err=%v", got, err)
	}

	// 合法值（1 小时）→ now+1h。
	if got, err := resolveIssueExpiry(sec(3600), now); err != nil || got == nil || !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("3600s 应为 now+1h=%v，实际 got=%v err=%v", now.Add(time.Hour), got, err)
	}

	// 10 年上限边界（上限本身）→ 合法不报错。
	maxSec := 10 * 365 * 24 * 3600
	if got, err := resolveIssueExpiry(sec(maxSec), now); err != nil || got == nil || !got.Equal(now.Add(time.Duration(maxSec)*time.Second)) {
		t.Fatalf("10 年上限应合法，实际 got=%v err=%v", got, err)
	}

	// 0 → 拒绝（签发即过期=出生即死，绝不静默纠正）。
	if got, err := resolveIssueExpiry(sec(0), now); err == nil {
		t.Fatalf("0 应返回 error（签发即过期无意义），实际 got=%v err=nil", got)
	}

	// 负数 → 拒绝（reject-not-coerce）。
	if got, err := resolveIssueExpiry(sec(-1), now); err == nil {
		t.Fatalf("负数应返回 error，实际 got=%v err=nil", got)
	}

	// 超过 10 年上限 → 拒绝（防把毫秒当秒之类单位笔误造出近乎永不过期的 key）。
	if got, err := resolveIssueExpiry(sec(maxSec+1), now); err == nil {
		t.Fatalf(">10 年应返回 error，实际 got=%v err=nil", got)
	}
}
