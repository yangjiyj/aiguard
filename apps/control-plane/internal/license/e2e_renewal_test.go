package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2ERenewalLicenseVerifies 端到端验证 Phase 0 密钥收口：
// 一张由生产签发身份(keyId lse-lic-2026, issuer huoxianbao-license-authority-prod)
// 签发、绑定到 deploymentId 的 v2 续费 license，必须能被网关真实验签链接受，
// 且部署绑定匹配。这是历史"单复数断链"雷区的回归护栏。
func TestE2ERenewalLicenseVerifies(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_gateway_license.json"))
	if err != nil {
		t.Fatalf("读取夹具失败: %v", err)
	}
	legacySHA := sha256.Sum256(raw)
	if got := hex.EncodeToString(legacySHA[:]); got != "728cc83f10d02d87203a082a1feb6d2676e2acbd4194fcf37e71c58d52aeda42" {
		t.Fatalf("旧签名夹具被改写: sha256=%s", got)
	}

	const (
		signingKeyID  = "lse-lic-2026"
		signingPubKey = "WxiAqCV0BUqVnopcPSrOWcVlowUoz1JQtGyEUCZ2f_Y"
		deploymentID  = "dep_e2e_fixture"
		prodIssuer    = "huoxianbao-license-authority-prod"
	)
	sum := sha256.Sum256([]byte("license.v2.deployment|" + deploymentID))
	localFP := Fingerprint{Scope: "deployment", Algorithm: "sha256", Value: hex.EncodeToString(sum[:])}

	baseOpts := func() VerificationOptions {
		return VerificationOptions{
			PublicKeysV2:     map[string]string{signingKeyID: signingPubKey},
			AcceptedProducts: []string{ProductJJDGuardEnterprise, ProductLegacyEnterprise},
			TrustedIssuers:   map[string]struct{}{prodIssuer: {}},
			Now:              time.Now().UTC(),
		}
	}

	// 正路径：匹配的部署指纹 → 验签通过 + 绑定匹配。
	opts := baseOpts()
	opts.DeploymentFingerprints = []Fingerprint{localFP}
	_, status, err := VerifyAny(string(raw), opts)
	if err != nil {
		t.Fatalf("续费 license 应验签通过, got err=%v", err)
	}
	if status == nil || !status.Valid || status.Status != StatusActive {
		t.Fatalf("应为有效 active, got %+v", status)
	}
	if status.Binding == nil || !status.Binding.Matched {
		t.Fatalf("部署绑定应匹配, got %+v", status.Binding)
	}

	// 反路径：错误的部署指纹（换台机器）→ 绑定不匹配，必须被拒。
	wrong := Fingerprint{Scope: "deployment", Algorithm: "sha256", Value: "deadbeef"}
	optsWrong := baseOpts()
	optsWrong.DeploymentFingerprints = []Fingerprint{wrong}
	_, statusWrong, errWrong := VerifyAny(string(raw), optsWrong)
	if errWrong == nil && (statusWrong != nil && statusWrong.Binding != nil && statusWrong.Binding.Matched) {
		t.Fatalf("换机(指纹不匹配)应被拒, got err=%v status=%+v", errWrong, statusWrong)
	}
}

func TestE2EJJDGuardFixtureVerifiesAndTamperingFailsSignatureFirst(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_jjdguard_license.json"))
	if err != nil {
		t.Fatalf("读取 JJDGuard 夹具失败: %v", err)
	}
	const (
		keyID        = "jjdguard-test-lic-2026"
		deploymentID = "dep_jjdguard_e2e_fixture"
		issuer       = "huoxianbao-license-authority-prod"
	)
	// 只用于仓库测试夹具；绝不是正式发布签名私钥。
	publicKey := base64.RawURLEncoding.EncodeToString(testV2PrivateKey(t).Public().(ed25519.PublicKey))
	sum := sha256.Sum256([]byte("license.v2.deployment|" + deploymentID))
	opts := VerificationOptions{
		PublicKeysV2:     map[string]string{keyID: publicKey},
		AcceptedProducts: []string{"jjdguard-enterprise", "newapi-enterprise"},
		TrustedIssuers:   map[string]struct{}{issuer: {}},
		DeploymentFingerprints: []Fingerprint{{
			Scope: "deployment", Algorithm: "sha256", Value: hex.EncodeToString(sum[:]),
		}},
		Now: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
	}
	_, status, err := VerifyAny(string(raw), opts)
	if err != nil {
		t.Fatalf("JJDGuard license 应验签通过: %v", err)
	}
	if status == nil || !status.Valid || len(status.Products) != 1 || status.Products[0] != "jjdguard-enterprise" {
		t.Fatalf("status = %+v, want JJDGuard-only product", status)
	}

	tampered := strings.Replace(string(raw), "jjdguard-enterprise", "third-product", 1)
	_, _, err = VerifyAny(tampered, opts)
	if err != ErrInvalidSignature {
		t.Fatalf("tampered JJDGuard fixture err = %v, want ErrInvalidSignature", err)
	}
}

func TestE2ELegacyFixtureTamperingFailsSignatureBeforeProductPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_gateway_license.json"))
	if err != nil {
		t.Fatalf("读取旧夹具失败: %v", err)
	}
	tampered := strings.Replace(string(raw), "newapi-enterprise", "third-product", 1)
	_, _, err = VerifyAny(tampered, VerificationOptions{
		PublicKeysV2:     map[string]string{"lse-lic-2026": "WxiAqCV0BUqVnopcPSrOWcVlowUoz1JQtGyEUCZ2f_Y"},
		AcceptedProducts: []string{"jjdguard-enterprise", "newapi-enterprise"},
		TrustedIssuers:   map[string]struct{}{"huoxianbao-license-authority-prod": {}},
		Now:              time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != ErrInvalidSignature {
		t.Fatalf("tampered legacy fixture err = %v, want ErrInvalidSignature", err)
	}
}
