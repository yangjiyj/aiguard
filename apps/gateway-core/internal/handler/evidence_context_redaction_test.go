package handler

import (
	"encoding/json"
	"strings"
	"testing"
)

func credFinding(category, typ, raw, ctx string) SecurityFinding {
	return SecurityFinding{
		Type: typ, Category: category, RawEvidence: raw, EvidenceContext: ctx,
		MatchedTextPreview: raw[:2] + "****" + raw[len(raw)-2:], RedactedEvidence: category + ":<MASKED>",
		MatchedLocation: "content[0:1]",
	}
}

// 凭据类命中：落库的上下文必须保留周围文字，但凭据本体绝不出现。
func TestCredentialEvidenceContextKeepsSurroundingTextButNeverTheSecret(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	ctx := "export AWS_ACCESS_KEY_ID=" + secret + " # used by the deploy script"
	for _, tc := range []struct{ category, typ string }{
		{"cloud_credential", "secret"}, {"plain_password", "secret"}, {"openai_key", "secret"},
		{"code_leak_database_url", "data_leak"}, {"code_leak_password_in_code", "data_leak"},
	} {
		got := redactedEvidenceContext(credFinding(tc.category, tc.typ, secret, ctx))
		if strings.Contains(got, secret) {
			t.Fatalf("%s: secret leaked into stored context: %q", tc.category, got)
		}
		if !strings.Contains(got, "export AWS_ACCESS_KEY_ID=") || !strings.Contains(got, "used by the deploy script") {
			t.Fatalf("%s: surrounding text lost: %q", tc.category, got)
		}
		if !strings.Contains(got, "已隐藏") {
			t.Fatalf("%s: masked span must be marked: %q", tc.category, got)
		}
	}
}

// 同一凭据在上下文里出现多次，每一处都要打码，不能只替换第一处。
func TestCredentialEvidenceContextMasksEveryOccurrence(t *testing.T) {
	secret := "s3cr3t-Value-0123456789"
	ctx := "a=" + secret + "; b=" + secret + "; c=" + secret
	got := redactedEvidenceContext(credFinding("plain_password", "secret", secret, ctx))
	if strings.Contains(got, secret) || strings.Count(got, "已隐藏") != 3 {
		t.Fatalf("every occurrence must be masked: %q", got)
	}
}

// 上下文太长时只保留命中点附近，且仍不含明文。
func TestCredentialEvidenceContextIsBounded(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	ctx := strings.Repeat("x", 3000) + secret + strings.Repeat("y", 3000)
	got := redactedEvidenceContext(credFinding("cloud_credential", "secret", secret, ctx))
	if strings.Contains(got, secret) || len([]rune(got)) > 400 {
		t.Fatalf("context must be bounded and clean, len=%d", len([]rune(got)))
	}
}

// 非凭据类（邮箱、涉密词等）行为保持不变：沿用原来的脱敏占位，不扩大落库内容。
func TestNonCredentialEvidenceContextKeepsLegacyPlaceholder(t *testing.T) {
	f := credFinding("pii_email", "pii", "alice@example.com", "contact alice@example.com for details")
	if got := redactedEvidenceContext(f); got != "pii_email:<MASKED>" {
		t.Fatalf("non-credential finding must keep legacy placeholder, got %q", got)
	}
}

// 没有原文可定位时，退回占位，宁可信息少也不猜。
func TestCredentialEvidenceContextFallsBackWhenRawMissing(t *testing.T) {
	f := credFinding("cloud_credential", "secret", "AKIAIOSFODNN7EXAMPLE", "some context")
	f.RawEvidence = ""
	if got := redactedEvidenceContext(f); got != "cloud_credential:<MASKED>" {
		t.Fatalf("missing raw evidence must fall back, got %q", got)
	}
}

// 凭据太短（<6）不做替换，避免把正常单词整批打码；回退占位。
func TestCredentialEvidenceContextSkipsTrivialSecrets(t *testing.T) {
	f := credFinding("plain_password", "secret", "abcdef", "password is abcdef ok")
	f.RawEvidence = "abc"
	if got := redactedEvidenceContext(f); got != "plain_password:<MASKED>" {
		t.Fatalf("trivial secret must fall back, got %q", got)
	}
}

// 端到端：经真实序列化后的整份 summary（落库内容）里，任何字段都不得出现凭据明文。
// 2.9.22 起（用户 11-17 定）“凭据明文不进告警库”作废：凭据命中的原文和前后文按原样落库，
// 打码函数 redactedEvidenceContext 只用来算升级前口径的证据身份。
func TestStoredSummaryKeepsCredentialPlaintextForEvidenceReaders(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	ctx := "export AWS_ACCESS_KEY_ID=" + secret + " # deploy"
	f := credFinding("cloud_credential", "secret", secret, ctx)
	f.Severity, f.RuleID = "critical", "rule_cloud"
	f.MatchedLocation = "content[25:45]" // 位置可用时按位置取原文，夹具给真实位置
	items := securityFindingsToSummary([]SecurityFinding{f})
	if items[0]["raw_evidence"] != secret {
		t.Fatalf("凭据命中原文入库: %#v", items[0]["raw_evidence"])
	}
	got, _ := items[0]["evidence_context"].(string)
	if got != ctx || strings.Contains(got, "已隐藏") {
		t.Fatalf("前后文按原样落库、不打码: %q", got)
	}
	if _, ok := items[0]["raw_evidence_sha256"]; !ok {
		t.Fatal("digest of the original evidence must still be stored for exact recovery")
	}
}

func TestEvidenceContextHidesPrivateKeyBodyAndKeepsHeader(t *testing.T) {
	header := "-----BEGIN RSA PRIVATE KEY-----"
	body := "\nMIIEowIBAAKCAQEA" + strings.Repeat("Zz9y", 20) + "\n"
	ctx := "帮我看看这个密钥\n" + header + body + "-----END RSA PRIVATE KEY-----\n谢谢"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "ssh_private_key", MatchedTextPreview: "--****--",
		RawEvidence: header, EvidenceContext: ctx, SecretText: body,
	})
	if strings.Contains(got, "MIIEow") || strings.Contains(got, "Zz9y") {
		t.Fatalf("私钥正文进了前后文: %q", got)
	}
	for _, want := range []string{"帮我看看这个密钥", header, "<已隐藏 96 字>", "-----END RSA PRIVATE KEY-----"} {
		if !strings.Contains(got, want) {
			t.Fatalf("前后文缺少 %q: %q", want, got)
		}
	}
}

func TestEvidenceContextFromOldEngineNeverStoresPrivateKeyContext(t *testing.T) {
	header := "-----BEGIN RSA PRIVATE KEY-----"
	ctx := header + "\nMIIEowIBAAKCAQEA-----END RSA PRIVATE KEY-----"
	for _, category := range []string{"ssh_private_key", "openssh_private_key", "private_key"} {
		got := redactedEvidenceContext(SecurityFinding{
			Category: category, MatchedTextPreview: "--****--", RawEvidence: header, EvidenceContext: ctx,
		})
		if got != "--****--" {
			t.Fatalf("%s：旧引擎不给秘密本体时只能存占位，得到 %q", category, got)
		}
	}
}

func TestEvidenceContextUsesSecretTextForAnyCategory(t *testing.T) {
	got := redactedEvidenceContext(SecurityFinding{
		Category: "some_new_credential", MatchedTextPreview: "to****56",
		RawEvidence:     "token=example-value-123456",
		EvidenceContext: "配置 token=example-value-123456 结束",
		SecretText:      "example-value-123456",
	})
	if got != "配置 token=<已隐藏 20 字> 结束" {
		t.Fatalf("得到 %q", got)
	}
}

func TestEvidenceContextSkipsTrivialSecretText(t *testing.T) {
	got := redactedEvidenceContext(SecurityFinding{
		Category: "plain_password", MatchedTextPreview: "pw****bc",
		RawEvidence: "pwd=abc", EvidenceContext: "这里 pwd=abc 以及 abc 这个词", SecretText: "abc",
	})
	if got != "pw****bc" {
		t.Fatalf("过短的秘密不做替换，得到 %q", got)
	}
}

// secret_text 字段本身仍不落库；2.9.22 起私钥正文作为前后文原文入库（用户 11-17 定，前后文不打码）。
func TestStoredSummaryNeverSerializesSecretTextField(t *testing.T) {
	body := "MIIEowIBAAKCAQEA" + strings.Repeat("Zz9y", 20)
	summary := securityFindingsToSummary([]SecurityFinding{{
		Type: "code_config", Category: "ssh_private_key", Severity: "critical", MatchedTextPreview: "--****--",
		RedactedEvidence: "-----BEGIN RSA PRIVATE KEY-----（后续正文 96 字已隐藏）",
		RawEvidence:      "-----BEGIN RSA PRIVATE KEY-----",
		EvidenceContext:  "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----",
		SecretText:       "\n" + body + "\n",
	}})
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret_text") {
		t.Fatalf("secret_text 字段进了落库内容: %s", encoded)
	}
	if ctx, _ := summary[0]["evidence_context"].(string); !strings.Contains(ctx, "-----BEGIN RSA PRIVATE KEY-----\n"+body) {
		t.Fatalf("前后文按原样落库: %q", ctx)
	}
}

func fakeKeyBody(seed string, n int) string {
	return "\n" + strings.Repeat(seed, n) + "\n"
}

func TestEvidenceContextTwoShortPrivateKeysFallsBack(t *testing.T) {
	h := "-----BEGIN EC PRIVATE KEY-----"
	e := "-----END EC PRIVATE KEY-----"
	b1 := fakeKeyBody("MHcCAQEEIAAA", 12)
	b2 := fakeKeyBody("K9k8Qw3ZxBBB", 12)
	f := SecurityFinding{
		Category: "ssh_private_key", MatchedTextPreview: "--****--", RawEvidence: h,
		EvidenceContext: h + b1 + e + "\n" + h + b2 + e, SecretText: b1,
	}
	got := redactedEvidenceContext(f)
	if got != "--****--" {
		t.Fatalf("应退回占位，得到 %q", got)
	}
	if strings.Contains(got, "K9k8Qw3ZxBBB") {
		t.Fatal("第二把正文泄露")
	}
}

func TestEvidenceContextEndLineBeforeMaskFallsBack(t *testing.T) {
	h := "-----BEGIN EC PRIVATE KEY-----"
	b := fakeKeyBody("MHcCAQEEIAAA", 12)
	ctx := "-----END EC PRIVATE KEY-----\n前文 " + h + b + "-----END EC PRIVATE KEY-----"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "ssh_private_key", MatchedTextPreview: "--****--", RawEvidence: h,
		EvidenceContext: ctx, SecretText: b,
	})
	if got != "--****--" {
		t.Fatalf("应退回占位，得到 %q", got)
	}
}

func TestEvidenceContextHidesNearbyAPIKeyAfterPrivateKey(t *testing.T) {
	h := "-----BEGIN EC PRIVATE KEY-----"
	b := fakeKeyBody("MHcCAQEEIAAA", 12)
	ctx := "请看密钥\n" + h + b + "-----END EC PRIVATE KEY-----\n另外我的 key 是 sk-proj-EXAMPLEexampleEXAMPLE0123456789 谢谢"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "ssh_private_key", MatchedTextPreview: "--****--", RawEvidence: h,
		EvidenceContext: ctx, SecretText: b,
	})
	if strings.Contains(got, "MHcCAQEEIAAA") || strings.Contains(got, "EXAMPLEexample") {
		t.Fatalf("泄露: %q", got)
	}
	for _, want := range []string{"请看密钥", h, "谢谢"} {
		if !strings.Contains(got, want) {
			t.Fatalf("缺少 %q: %q", want, got)
		}
	}
}

func TestEvidenceContextUUIDTailDigitsMaskedRestKept(t *testing.T) {
	got := redactedEvidenceContext(SecurityFinding{
		Category: "some_new_credential", MatchedTextPreview: "to****56",
		RawEvidence:     "token=example-value-123456",
		EvidenceContext: "请求 id 550e8400-e29b-41d4-a716-446655440000 配置 token=example-value-123456 结束",
		SecretText:      "example-value-123456",
	})
	// UUID 末段的纯数字会被数字串规则遮掉（宁可多遮）；周围文字和前面的段保留。
	if strings.Contains(got, "446655440000") || !strings.Contains(got, "550e8400-e29b-41d4-a") || !strings.Contains(got, "结束") {
		t.Fatalf("得到 %q", got)
	}
}

func TestSecurityFindingSecretTextNeverSerialized(t *testing.T) {
	b, err := json.Marshal(SecurityFinding{Category: "x", SecretText: "must-not-appear-123456"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "must-not-appear") || strings.Contains(string(b), "SecretText") {
		t.Fatalf("序列化带出了秘密本体: %s", b)
	}
	base := SecurityFinding{Category: "x", Severity: "high"}
	withSecret := base
	withSecret.SecretText = "must-not-appear-123456"
	k1 := fingerprintDetectionContextKey(nil, "block", []SecurityFinding{base}, "user", "human", "complete")
	k2 := fingerprintDetectionContextKey(nil, "block", []SecurityFinding{withSecret}, "user", "human", "complete")
	if k1 == "" || k1 != k2 {
		t.Fatalf("折叠键受 SecretText 影响: %q %q", k1, k2)
	}
}

func TestEvidenceContextRSAThenOpenSSHFallsBack(t *testing.T) {
	h := "-----BEGIN OPENSSH PRIVATE KEY-----"
	body := fakeKeyBody("b3BlbnNzaC1rZXk", 8)
	ctx := "mNn7oPp8qQq9rRr0sS\nTt5uVv6wXx==\n-----END RSA PRIVATE KEY-----\n" + h + body + "-----END OPENSSH PRIVATE KEY-----"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "openssh_private_key", MatchedTextPreview: "--****--", RawEvidence: h,
		EvidenceContext: ctx, SecretText: body,
	})
	if got != "--****--" {
		t.Fatalf("应退回占位，得到 %q", got)
	}
}
func TestEvidenceContextTokenBesideECKeyFallsBack(t *testing.T) {
	ctx := "token=ghp_exampleExampleExample0123 后面\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\nAbC1==\n-----END EC PRIVATE KEY-----"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "github_token", MatchedTextPreview: "gh****23",
		RawEvidence: "ghp_exampleExampleExample0123", EvidenceContext: ctx, SecretText: "ghp_exampleExampleExample0123",
	})
	if got != "gh****23" {
		t.Fatalf("应退回占位，得到 %q", got)
	}
}

func TestEvidenceContextTokenWithoutPrivateKeyStillMasked(t *testing.T) {
	got := redactedEvidenceContext(SecurityFinding{
		Category: "github_token", MatchedTextPreview: "gh****23",
		RawEvidence: "ghp_exampleExampleExample0123", EvidenceContext: "令牌 ghp_exampleExampleExample0123 结束", SecretText: "ghp_exampleExampleExample0123",
	})
	if got != "令牌 <已隐藏 29 字> 结束" {
		t.Fatalf("得到 %q", got)
	}
}

func TestHandlerFindingsToSecurityDropsSecretText(t *testing.T) {
	out := handlerFindingsToSecurity([]SecurityFinding{{Category: "x", SecretText: "must-not-go-back-123456"}})
	if len(out) != 1 || out[0].SecretText != "" {
		t.Fatalf("SecretText 被带回: %#v", out)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret_text") || strings.Contains(string(b), "must-not-go-back") {
		t.Fatalf("复核请求带出秘密本体: %s", b)
	}
}

func TestEvidenceContextScrubsSecondConnectionStringPassword(t *testing.T) {
	first := "postgresql://a:Ex4mplePass1@db1.example.com/x"
	ctx := first + "\npostgresql://b:Ex4mplePass2@db2.example.com/y"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "code_leak_database_url", MatchedTextPreview: "po****/x",
		RawEvidence: first, EvidenceContext: ctx, SecretText: "Ex4mplePass1",
	})
	if strings.Contains(got, "Ex4mplePass") || !strings.Contains(got, "db2.example.com") {
		t.Fatalf("得到 %q", got)
	}
}

func TestEvidenceContextScrubsPlainDigitsAndShortPasswords(t *testing.T) {
	secret := "Example-Passw0rd-123"
	got := redactedEvidenceContext(SecurityFinding{
		Category: "plain_password", MatchedTextPreview: "pa****23",
		RawEvidence:     "password=" + secret,
		EvidenceContext: "客户 张三 卡号 6222000000000009 手机 13800138000 password=" + secret + " pwd=Sh0rtPw1",
		SecretText:      secret,
	})
	for _, bad := range []string{"6222000000000009", "13800138000", "Sh0rtPw1", secret} {
		if strings.Contains(got, bad) {
			t.Fatalf("泄露 %q: %q", bad, got)
		}
	}
	if !strings.Contains(got, "客户 张三") {
		t.Fatalf("周围文字丢失: %q", got)
	}
}

func TestEvidenceContextMergesTruncatedKeyTail(t *testing.T) {
	got := redactedEvidenceContext(SecurityFinding{
		Category: "generic_api_key", MatchedTextPreview: "EX****",
		RawEvidence: "EXAMPLEa1b2c3d4e5f6", EvidenceContext: "api_key=EXAMPLEa1b2c3d4e5f6.g7h8i9j0k1 结束",
		SecretText: "EXAMPLEa1b2c3d4e5f6",
	})
	if strings.Contains(got, "g7h8i9j0k1") || strings.Contains(got, "EXAMPLE") || !strings.Contains(got, "结束") {
		t.Fatalf("得到 %q", got)
	}
}

func TestScrubContextSecretsSideEffects(t *testing.T) {
	cases := map[string]string{
		"Authorization: Bearer abc123xyz": "Authorization: Bearer <已隐藏 9 字>",
		"口令：Abc12345 好":                   "口令：<已隐藏 8 字> 好",
		"端口 8080 版本 1.2.3 时间 12:30:45":    "端口 8080 版本 1.2.3 时间 12:30:45",
		"+86 138 0013 8000":               "<已隐藏 17 字>",
	}
	for in, want := range cases {
		if got := scrubContextSecrets(in); got != want {
			t.Errorf("%q -> %q, 期望 %q", in, got, want)
		}
	}
}

func TestScrubContextSecretsCommonConfigForms(t *testing.T) {
	cases := []struct {
		name, in string
		gone     []string
	}{
		{"redis 空用户名", "redis://:Sh0rt9pw@cache:6379/0", []string{"Sh0rt9pw"}},
		{"PHP 数组", "'password' => 'Sh0rt9',", []string{"Sh0rt9"}},
		{"全角等号", "密码＝Sh0rt9", []string{"Sh0rt9"}},
		{"XML 标签", "<password>Sh0rt9</password>", []string{"Sh0rt9"}},
		{"引号值含空格", `{"password":"my pass 9"}`, []string{"my pass 9", "pass 9"}},
		{"单引号值含空格", `pwd = 'my pass 9' next`, []string{"pass 9"}},
		{"命令行空白分隔", "mysql --password Sh0rt9 db", []string{"Sh0rt9"}},
		{"Authorization token", "Authorization: token Sh0rt9tok", []string{"Sh0rt9tok"}},
		{"id 前缀的卡号", "客户 id-6222000000000009", []string{"6222000000000009"}},
		{"ID 前缀的手机号", "ID13800138000", []string{"13800138000"}},
	}
	for _, c := range cases {
		got := scrubContextSecrets(c.in)
		for _, bad := range c.gone {
			if strings.Contains(got, bad) {
				t.Errorf("%s: 泄露 %q: %q", c.name, bad, got)
			}
		}
	}
}

func TestScrubContextSecretsMarkerTailStopsAtDashes(t *testing.T) {
	got := scrubContextSecrets("<已隐藏 20 字>-----END EC PRIVATE KEY-----")
	if !strings.Contains(got, "-----END EC PRIVATE KEY-----") {
		t.Fatalf("END 行被并入标记: %q", got)
	}
}

// 顺序：先扫长串、再补遮。反过来时 10 位数字会先被切走，留下 sk-proj-EXAMPLEexampleEXAMPLE 前半段。
func TestEvidenceContextLongTokenWithDigitsHiddenWholeNotSplit(t *testing.T) {
	got := redactedEvidenceContext(SecurityFinding{
		Category: "some_new_credential", MatchedTextPreview: "to****56",
		RawEvidence: "token=example-value-123456", SecretText: "example-value-123456",
		EvidenceContext: "token=example-value-123456 另有 sk-proj-EXAMPLEexampleEXAMPLE0123456789 结束",
	})
	if strings.Contains(got, "EXAMPLEexample") {
		t.Fatalf("前半段残留: %q", got)
	}
}

func TestScrubContextSecretsDSNSetterAndDashTail(t *testing.T) {
	cases := []struct {
		name, in string
		gone     []string
	}{
		{"单连字符尾巴", "api_key=<已隐藏 19 字>-g7h8i9j0k1 结束", []string{"g7h8i9j0k1"}},
		{"Go MySQL DSN", `sql.Open("mysql", "root:Sh0rt9@tcp(db:3306)/x")`, []string{"Sh0rt9"}},
		{"setter", `ds.setPassword("Sh0rt9");`, []string{"Sh0rt9"}},
		{"Setenv", `os.Setenv("DB_PASSWORD", "Sh0rt9")`, []string{"Sh0rt9"}},
		{"XML 带属性", `<password type="plain">Sh0rt9</password>`, []string{"Sh0rt9"}},
		{"XML CDATA", `<password><![CDATA[Sh0rt9]]></password>`, []string{"Sh0rt9"}},
		{"XML 前缀标签", `<db_password>Sh0rt9</db_password>`, []string{"Sh0rt9"}},
		{"XML 点号标签", `<jdbc.password>Sh0rt9</jdbc.password>`, []string{"Sh0rt9"}},
	}
	for _, c := range cases {
		got := scrubContextSecrets(c.in)
		for _, bad := range c.gone {
			if strings.Contains(got, bad) {
				t.Errorf("%s: 泄露 %q: %q", c.name, bad, got)
			}
		}
	}
	for _, keep := range []string{"user, password, token 都要填", `<input type="password">`, "getPassword() 返回", "-----END EC PRIVATE KEY-----"} {
		if got := scrubContextSecrets(keep); got != keep {
			t.Errorf("普通文字被遮: %q -> %q", keep, got)
		}
	}
	if got := scrubContextSecrets("<已隐藏 20 字>-----END EC PRIVATE KEY-----"); !strings.Contains(got, "-----END EC PRIVATE KEY-----") {
		t.Errorf("END 行被并入: %q", got)
	}
}

func anyChunkOf(s, token string, n int) (string, bool) {
	r := []rune(token)
	for i := 0; i+n <= len(r); i++ {
		if strings.Contains(s, string(r[i:i+n])) {
			return string(r[i : i+n]), true
		}
	}
	return "", false
}

func TestBoundAroundMaskDropsTokenFragmentAtLeftEdge(t *testing.T) {
	token := "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Q"
	masked := token + strings.Repeat("字", 110) + "<已隐藏 5 字>结尾"
	got := hideLongTokenRuns(boundAroundMask(masked))
	if frag, ok := anyChunkOf(got, token, 6); ok {
		t.Fatalf("左边界残段 %q 留了下来: %q", frag, got)
	}
	if !strings.HasPrefix(got, "…") || !strings.Contains(got, "<已隐藏 5 字>") {
		t.Fatalf("省略号或标记丢失: %q", got)
	}
}

func TestBoundAroundMaskDropsTokenFragmentAtRightEdge(t *testing.T) {
	token := "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Q"
	masked := "开头<已隐藏 5 字>" + strings.Repeat("字", 110) + token
	got := hideLongTokenRuns(boundAroundMask(masked))
	if frag, ok := anyChunkOf(got, token, 6); ok {
		t.Fatalf("右边界残段 %q 留了下来: %q", frag, got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("省略号丢失: %q", got)
	}
}

func TestBoundAroundMaskUnchangedWhenEdgesNotInsideToken(t *testing.T) {
	masked := strings.Repeat("字", 200) + "<已隐藏 5 字>" + strings.Repeat("字", 200)
	r := []rune(masked)
	at := 200
	want := "…" + string(r[at-evidenceContextWindow:at+evidenceContextWindow+12]) + "…"
	if got := boundAroundMask(masked); got != want {
		t.Fatalf("边界不在令牌中间时结果应不变: %q", got)
	}
}
