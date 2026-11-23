package handler

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// 任务 3.3：Proxy Key 轮换（双 key 灰度窗口，P1-8，支柱⑤凭据生命周期）。
//
// 现状根因：main.go 只挂了 List/Create/Update/Delete /admin/v1/proxy-access-keys，
// 没有 rotate 端点；repository.Update 能改 status 却改不了 expires_at（expires_at
// 只在 Create 的 INSERT 写一次）。gateway-core 数据面校验（proxy_key_verifier.go）
// 的查找是纯粹的 proxy_key_hash + status='active' + (expires_at IS NULL OR > now())，
// 故同一逻辑 key 只要存在两行 active 且未过期记录就会同时通过——双 key 灰度天然成立，
// verifier 零改动。
//
// 设计（reject-not-coerce，与 3.1/3.2 一致）：rotate = 复用 Create+generateSecureKey
// 发新 active 行 + 把旧行 expires_at=now+grace 进入灰度（新增 SetExpiry repo 方法）。
// 两个纯函数 resolveRotationGrace/computeOldKeyExpiry 承载全部可判定逻辑，直测绕开
// ProxyAccessKeyRepo 具体类型 nil-panic。

func TestResolveRotationGrace(t *testing.T) {
	sec := func(n int) *int { return &n }

	// nil（未传 grace_seconds）→ 默认 24h，向后兼容不报错。
	if d, err := resolveRotationGrace(nil); err != nil || d != 24*time.Hour {
		t.Fatalf("nil 应回退默认 24h，实际 d=%v err=%v", d, err)
	}

	// 0 → 立即吊销（无窗口，安全应急），合法不报错。
	if d, err := resolveRotationGrace(sec(0)); err != nil || d != 0 {
		t.Fatalf("0 应为立即吊销 0，实际 d=%v err=%v", d, err)
	}

	// 合法值（30 分钟）→ 透传对应 duration。
	if d, err := resolveRotationGrace(sec(1800)); err != nil || d != 30*time.Minute {
		t.Fatalf("1800s 应为 30m，实际 d=%v err=%v", d, err)
	}

	// 30d 边界内合法（上限本身）→ 不报错。
	if d, err := resolveRotationGrace(sec(30 * 24 * 3600)); err != nil || d != 30*24*time.Hour {
		t.Fatalf("30d 上限应合法，实际 d=%v err=%v", d, err)
	}

	// 负数 → 拒绝（reject-not-coerce，绝不静默截断为 0）。
	if d, err := resolveRotationGrace(sec(-1)); err == nil {
		t.Fatalf("负数应返回 error，实际 d=%v err=nil", d)
	}

	// 超过 30d 上限 → 拒绝（绝不静默截断为 30d）。
	if d, err := resolveRotationGrace(sec(30*24*3600 + 1)); err == nil {
		t.Fatalf(">30d 应返回 error，实际 d=%v err=nil", d)
	}
}

func TestComputeOldKeyExpiry(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	grace := 24 * time.Hour

	// existing=nil（旧 key 本永不过期）→ now+grace。
	if got := computeOldKeyExpiry(now, grace, nil); !got.Equal(now.Add(grace)) {
		t.Fatalf("existing=nil 应为 now+grace=%v，实际 %v", now.Add(grace), got)
	}

	// existing 晚于 now+grace（旧 key 本来很久才过期）→ 收紧到 now+grace，不延长授权。
	later := now.Add(72 * time.Hour)
	if got := computeOldKeyExpiry(now, grace, &later); !got.Equal(now.Add(grace)) {
		t.Fatalf("existing 晚于窗口应收紧到 now+grace=%v，实际 %v", now.Add(grace), got)
	}

	// existing 早于 now+grace（旧 key 本就快过期）→ 维持 existing，绝不把它延长到 now+grace。
	earlier := now.Add(1 * time.Hour)
	if got := computeOldKeyExpiry(now, grace, &earlier); !got.Equal(earlier) {
		t.Fatalf("existing 早于窗口应维持 existing=%v（不延长），实际 %v", earlier, got)
	}

	// grace=0（立即吊销）→ 旧 key 立刻过期（now），即便它本来永不过期。
	if got := computeOldKeyExpiry(now, 0, nil); !got.Equal(now) {
		t.Fatalf("grace=0 应立即过期=now=%v，实际 %v", now, got)
	}
}

func TestGenerateSecureKeyUsesJJDGuardPrefixWithoutEntropyRegression(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		key := generateSecureKey()
		if !strings.HasPrefix(key, "jjd_") {
			t.Fatalf("generated key prefix is not jjd_; length=%d", len(key))
		}
		body := strings.TrimPrefix(key, "jjd_")
		if len(body) != 48 {
			t.Fatalf("generated random body length=%d, want 48", len(body))
		}
		decoded, err := hex.DecodeString(body)
		if err != nil {
			t.Fatal("generated random body is not hex")
		}
		if len(decoded) != 24 {
			t.Fatalf("generated random byte length=%d, want 24", len(decoded))
		}
		if _, exists := seen[key]; exists {
			t.Fatal("duplicate generated key")
		}
		seen[key] = struct{}{}
	}
}
