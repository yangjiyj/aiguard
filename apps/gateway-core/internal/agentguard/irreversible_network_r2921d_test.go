package agentguard

import (
	"context"
	"strings"
	"testing"
)

// 2.9.21 第四轮（只收紧）：例外 (a) 的前提从“参数里没有高可信密钥”扩成“参数看起来不带凭据”
// （egressArgumentsLookCredentialLike）。参数全文（含嵌套、键名和值、[]string，不截断）命中
// 任一条，例外 (a) 不适用，按 2.9.20 算外发。规则编号见 egressCredentialLikeRule。

func TestEgressCredentialLikeRulesR2921d(t *testing.T) {
	cases := []struct {
		label string
		args  map[string]any
		want  string // 第一条命中的规则；"" 表示不像凭据
	}{
		// 1. DetectHighConfidenceSecrets 有任何发现，confirm 级（邮箱、手机号、身份证号）也算。
		{"pem", map[string]any{"description": "-----BEGIN RSA PRIVATE KEY-----\nMIIE"}, egressRuleDetector},
		{"email", map[string]any{"description": "联系 dev@example.com"}, egressRuleDetector},
		{"phone", map[string]any{"description": "电话 13800138000"}, egressRuleDetector},
		{"cn id", map[string]any{"description": "身份证 11010119900307123X"}, egressRuleDetector},
		{"phone as number", map[string]any{"contact": 13800138000.0}, egressRuleDetector},
		{"high entropy", map[string]any{"description": "TestTaintedEgressCredentialPayloadsMatch2920R2921d"}, egressRuleDetector},

		// 2. 键值形式的凭据。
		{"aws credfile spaced", map[string]any{"description": "aws_secret_access_key = wJalrXUtnF"}, egressRuleKeyValue},
		{"dotenv", map[string]any{"description": "DB_PASSWORD=Pr0d-S3cret!"}, egressRuleKeyValue},
		{"json quoted key", map[string]any{"description": `{"client_secret": "abcdef12"}`}, egressRuleKeyValue},
		{"camel PrivateKey", map[string]any{"description": "PrivateKey: abcdefgh"}, egressRuleKeyValue},
		{"export quoted", map[string]any{"description": "export GITLAB_TOKEN='abcdefgh'"}, egressRuleKeyValue},
		{"passwd colon no space", map[string]any{"description": "passwd:hunter22"}, egressRuleKeyValue},
		{"pwd", map[string]any{"description": "PWD=hunter22"}, egressRuleKeyValue},
		{"passphrase", map[string]any{"description": "passphrase: correct-horse"}, egressRuleKeyValue},
		{"api-key header", map[string]any{"description": "X-Api-Key: abcdef123"}, egressRuleKeyValue},
		{"api key spaced", map[string]any{"description": "API Key: abcdef123"}, egressRuleKeyValue},
		{"accesskey", map[string]any{"description": "AccessKey=abcdef123"}, egressRuleKeyValue},
		{"credential", map[string]any{"description": "credentials: abcdef123"}, egressRuleKeyValue},
		{"auth", map[string]any{"description": "AUTH_MODE=oauth2"}, egressRuleKeyValue},
		{"cookie", map[string]any{"description": "Cookie: sid=abcdef"}, egressRuleKeyValue},
		{"session", map[string]any{"description": "SESSION_KEY: abcdef"}, egressRuleKeyValue},
		{"yaml next line", map[string]any{"description": "token:\n  abcdefgh"}, egressRuleKeyValue},
		{"value too short", map[string]any{"description": "token: abc12"}, ""},
		{"word only", map[string]any{"description": "token 过期后自动刷新，password 字段加了校验"}, ""},
		// 参数本身的键名含凭据词且值非空。
		{"arg key private_token", map[string]any{"private_token": "x"}, egressRuleKeyName},
		{"arg key nested", map[string]any{"opts": map[string]any{"api_key": "x"}}, egressRuleKeyName},
		{"arg key in array", map[string]any{"items": []any{map[string]any{"Password": "x"}}}, egressRuleKeyName},
		{"arg key number value", map[string]any{"session_ttl": 0}, egressRuleKeyName},
		{"arg key spaced", map[string]any{"API Key": "x"}, egressRuleKeyName},
		{"arg key empty value", map[string]any{"password": "  ", "title": "fix"}, ""},
		{"arg key in typed map", map[string]any{"headers": map[string]string{"X-Auth": "x"}}, egressRuleKeyName},
		{"arg key in typed slice", map[string]any{"items": []map[string]any{{"Password": "x"}}}, egressRuleKeyName},
		{"typed map empty value", map[string]any{"headers": map[string]string{"X-Auth": ""}}, ""},
		{"bytes value", map[string]any{"description": []byte("glpat-Ex4mpleT0ken")}, egressRuleTokenPrefix},

		// 3. Bearer 或 Basic 后接 16 个以上字符的令牌。
		{"bearer", map[string]any{"description": "use Bearer abcdefghijklmnop1234 for tests"}, egressRuleBearer},
		{"basic", map[string]any{"description": "header Basic YWRtaW46cGFzc3dvcmQ="}, egressRuleBearer},
		{"bearer short", map[string]any{"description": "Bearer abc"}, ""},

		// 4. 已知令牌前缀与 JWT。
		{"glpat", map[string]any{"description": "glpat-Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"gldt", map[string]any{"description": "gldt-Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"glrt", map[string]any{"description": "glrt-Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"glptt", map[string]any{"description": "glptt-Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"glsoat", map[string]any{"description": "glsoat-Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"runner", map[string]any{"description": "GR1348941Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"xoxa", map[string]any{"description": "xoxa-2-1234567890"}, egressRuleTokenPrefix},
		{"xoxb", map[string]any{"description": "xoxb-1234567890"}, egressRuleTokenPrefix},
		{"xoxp", map[string]any{"description": "xoxp-1234567890"}, egressRuleTokenPrefix},
		{"xoxo", map[string]any{"description": "xoxo-1234567890"}, egressRuleTokenPrefix},
		{"xoxs", map[string]any{"description": "xoxs-1234567890"}, egressRuleTokenPrefix},
		{"xoxr", map[string]any{"description": "xoxr-1234567890"}, egressRuleTokenPrefix},
		{"stripe live", map[string]any{"description": "sk_live_Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"stripe restricted", map[string]any{"description": "rk_live_Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"google api key", map[string]any{"description": "AIzaSyEx4mpleT0kenAbCdEfGhIjKlMnOpQrS"}, egressRuleTokenPrefix},
		{"google oauth", map[string]any{"description": "ya29.Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"npm", map[string]any{"description": "npm_Ex4mpleT0kenAbCd"}, egressRuleTokenPrefix},
		{"pypi", map[string]any{"description": "pypi-AgEIcHlwaS5vcmc"}, egressRuleTokenPrefix},
		{"huggingface", map[string]any{"description": "hf_Ex4mpleT0kenAbCd"}, egressRuleTokenPrefix},
		{"digitalocean", map[string]any{"description": "dop_v1_0123456789abcdef"}, egressRuleTokenPrefix},
		{"shopify", map[string]any{"description": "shpat_0123456789abcdef"}, egressRuleTokenPrefix},
		{"sendgrid", map[string]any{"description": "SG.Ex4mpleT0ken.AbCdEf"}, egressRuleTokenPrefix},
		{"prefix after underscore", map[string]any{"description": "my_hf_Ex4mpleT0ken"}, egressRuleTokenPrefix},
		{"jwt", map[string]any{"description": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl"}, egressRuleTokenPrefix},
		{"jwt unsigned", map[string]any{"description": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}, egressRuleTokenPrefix},
		{"prefix inside word", map[string]any{"description": "shelf_lifecycle and msg.length"}, ""},
		{"prefix tail too short", map[string]any{"description": "hf_hub npm_ci"}, ""},

		// 5. 私钥材料迹象。
		{"PRIVATE KEY", map[string]any{"description": "RSA PRIVATE KEY omitted"}, egressRulePrivateKey},
		{"openssh-key-v1", map[string]any{"description": "magic openssh-key-v1"}, egressRulePrivateKey},
		{"openssh base64 magic", map[string]any{"description": "b3BlbnNzaC1rZXktdjE"}, egressRulePrivateKey},
		{"putty", map[string]any{"description": "PuTTY-User-Key-File-3: ssh-ed25519"}, egressRulePrivateKey},
		{"jwk", map[string]any{"description": `{"kty":"RSA","d":"abc"}`}, egressRulePrivateKey},
		{"privateExponent", map[string]any{"description": "privateExponent:"}, egressRulePrivateKey},
		{"wireguard", map[string]any{"description": "PrivateKey = abc"}, egressRulePrivateKey},
		{"jwk without d", map[string]any{"description": `{"kty":"RSA","n":"abc","e":"AQAB"}`}, ""},

		// 6. 带口令的连接串。
		{"mysql url", map[string]any{"description": "mysql://root:rootpw@db:3306/app"}, egressRuleURLPassword},
		{"redis empty user", map[string]any{"description": "redis://:s3cr3t@cache:6379"}, egressRuleURLPassword},
		{"url without password", map[string]any{"description": "https://jira.example.com/browse/EVAL-2921"}, ""},

		// 7. 十六进制材料。
		{"md5", map[string]any{"description": "d41d8cd98f00b204e9800998ecf8427e"}, egressRuleHex},
		{"0x eth", map[string]any{"description": "0x4c0883a69102937d6231471b5dbb6204fe512961"}, egressRuleHex},
		{"commit sha", map[string]any{"description": "9ef666c2a1b0c3d4e5f60718293a4b5c6d7e8f90"}, egressRuleHex},
		{"colon hex", map[string]any{"description": "5c:0b:1f:7a:3e:91:d4:22:8c:6f:0a:b3:47:e2:19:d8"}, egressRuleHex},
		{"colon hex wrapped", map[string]any{"description": "5c:0b:1f:7a:3e:91:d4:22:\n    8c:6f:0a:b3:47:e2:19:d8"}, egressRuleHex},
		{"hex 31", map[string]any{"description": "d41d8cd98f00b204e9800998ecf8427"}, ""},
		{"short commit", map[string]any{"description": "commit 9ef666c2"}, ""},
		{"colon hex 15", map[string]any{"description": "5c:0b:1f:7a:3e:91:d4:22:8c:6f:0a:b3:47:e2:19"}, ""},

		// 8. base64 类长串（40 字以上，大写、小写、数字都有）。
		{"aws secret bare", map[string]any{"description": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, egressRuleBase64},
		{"base64url 43", map[string]any{"description": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}, egressRuleBase64},
		{"no upper", map[string]any{"description": "abcdefghij0123456789abcdefghij0123456789"}, ""},
		{"39 chars", map[string]any{"description": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE"}, ""},

		// 覆盖面：嵌套、数组、[]string、键名本身。
		{"nested value", map[string]any{"opts": map[string]any{"notes": map[string]any{"text": "glpat-Ex4mpleT0ken"}}}, egressRuleTokenPrefix},
		{"array value", map[string]any{"files": []any{"README.md", "DB_PASSWORD=Pr0d-S3cret!"}}, egressRuleKeyValue},
		{"string slice", map[string]any{"labels": []string{"docs", "glpat-Ex4mpleT0ken"}}, egressRuleTokenPrefix},
		{"secret as key text", map[string]any{"labels": map[string]any{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true}}, egressRuleBase64},
		{"long value not truncated", map[string]any{"description": strings.Repeat("重试评测任务前先清理临时目录。", 2000) + "glpat-Ex4mpleT0ken"}, egressRuleTokenPrefix},

		// 现场原写法：不像凭据。
		{"site create", map[string]any{"project_path": "rd/devhub-agent-platform", "source_branch": "feat/egress-fix-2921", "target_branch": "main",
			"target": "main", "title": "修复评测任务重试前未清理临时目录",
			"description": "https://jira.example.com/browse/EVAL-2921 重试评测任务前先清理临时目录，避免残留文件影响下一轮结果。"}, ""},
		{"site view", map[string]any{"project_path": "rd/devhub-agent-platform", "merge_request_iid": 1234.0, "target": "main"}, ""},
	}
	for _, tc := range cases {
		if got := egressCredentialLikeRule(tc.args); got != tc.want {
			t.Errorf("%s: egressCredentialLikeRule=%q want %q", tc.label, got, tc.want)
		}
		if got := egressArgumentsLookCredentialLike(tc.args); got != (tc.want != "") {
			t.Errorf("%s: egressArgumentsLookCredentialLike=%v want %v", tc.label, got, tc.want != "")
		}
	}
}

// 嵌套超出扫描深度时无法确认，按像凭据算（例外不适用）。
func TestEgressCredentialLikeBeyondScanDepthR2921d(t *testing.T) {
	deep := map[string]any{"text": "fine"}
	for i := 0; i < maxScannedArgumentDepth+2; i++ {
		deep = map[string]any{"n": deep}
	}
	if got := egressCredentialLikeRule(deep); got != egressRuleScanBound {
		t.Fatalf("beyond scan depth must count as credential-like, got %q", got)
	}
}

// 现场两个 devhub 工具的原写法（中文 description、jira 链接、分支名 feat/egress-fix-2921、
// project_path、title、target=main、不带凭据）仍放开：直接调用和租户 strict 策略两条路径都不拦。
func TestTaintedEgressSiteOriginalShapesReleasedR2921d(t *testing.T) {
	const description = "https://jira.example.com/browse/EVAL-2921 重试评测任务前先清理临时目录，避免残留文件影响下一轮结果。"
	const siteOutput = `{"project":"rd/devhub-agent-platform","default_branch":"main","target":"main",` +
		`"merge_requests":[{"iid":1234,"source_branch":"feat/egress-fix-2921","target_branch":"main",` +
		`"title":"修复评测任务重试前未清理临时目录","description":"` + description + `"}]}`
	cases := []struct {
		name string
		args map[string]any
	}{
		{"mcp__devhub__create_gitlab_ce_merge_request", map[string]any{
			"project_path": "rd/devhub-agent-platform", "source_branch": "feat/egress-fix-2921", "target_branch": "main",
			"target": "main", "title": "修复评测任务重试前未清理临时目录", "description": description, "content": description,
		}},
		{"mcp__devhub__create_gitlab_ce_merge_request", map[string]any{
			"project_path": "rd/devhub-agent-platform", "source_branch": "feat/egress-fix-2921", "target_branch": "main",
			"target": "main", "title": "修复评测任务重试前未清理临时目录", "description": description,
		}},
		{"mcp__devhub__get_gitlab_ee_merge_request_detail", map[string]any{
			"project_path": "rd/devhub-agent-platform", "merge_request_iid": 1234, "target": "main",
		}},
		{"mcp__devhub__get_gitlab_ee_merge_request_detail", map[string]any{
			"project_path": "rd/devhub-agent-platform", "merge_request_iid": "1234", "target": "main", "content": "feat/egress-fix-2921",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isIrreversibleNetworkTool(tc.name, tc.args) {
				t.Fatalf("site shape must stay released (rule %q): %v", egressCredentialLikeRule(tc.args), tc.args)
			}
			for _, policy := range []*EffectivePolicy{nil, {Mode: ModeStrict, RuleMode: ModeStrict}} {
				got := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
					ToolName: tc.name, ToolType: ToolTypeMCP, Arguments: tc.args, Mode: ModeStrict, Policy: policy,
					ContextFragments: []ContextFragment{{ID: "tool-result-1", Trust: ProvenanceUntrusted, Text: siteOutput}},
				})
				if got.Provenance != ProvenanceTainted {
					t.Fatalf("fixture must carry tainted arguments, got %s", got.Provenance)
				}
				if got.Reason == "tainted_irreversible_network_egress" || got.RawDecision == DecisionBlock || got.EffectiveDecision == DecisionBlock {
					t.Fatalf("site shape must not block (policy=%v): raw=%s eff=%s reason=%s", policy != nil, got.RawDecision, got.EffectiveDecision, got.Reason)
				}
			}
		})
	}
}

// 典型合并请求说明（中英文）在新前提下的结果：want 为第一条命中的规则，"" 表示仍放开。
// 写进现场工具的 description 和 content，看例外 (a) 是否还适用。
func TestMergeRequestDescriptionCorpusR2921d(t *testing.T) {
	corpus := []struct {
		id, text, want string
	}{
		{"zh-jira", "修复评测任务重试前未清理临时目录的问题。\n\nJira: https://jira.example.com/browse/EVAL-2921", ""},
		{"zh-short-commit", "关联 EVAL-2921，提交 a1b2c3d：重试前调用 cleanupTempDir()。", ""},
		{"zh-long-path", "改动文件：apps/gateway-core/internal/agentguard/network_egress_tool.go，新增 egressArgumentsLookCredentialLike。", egressRuleDetector},
		{"zh-token-word", "token 过期后自动刷新，不再需要手动重新登录。", ""},
		{"zh-secret-word", "配置项 secret 改为从 Vault 读取，代码里不再写死密码。", ""},
		{"zh-password-word", "password 字段加了长度校验（8–64 位），见 UserService.validatePassword。", ""},
		{"zh-test-name", "补充单测：TestTaintedEgressCredentialPayloadsMatch2920R2921d 覆盖 23 种载荷。", egressRuleDetector},
		{"zh-rollback", "合并后需在 staging 上执行 `make migrate`，回滚步骤见 docs/rollback.md。", ""},
		{"zh-cve", "升级 gin 到 v1.10.0，修复 CVE-2024-12345。", ""},
		{"zh-session-word", "修复会话超时：session_timeout 由 30m 调整为 2h。", ""},
		{"zh-env-auth", "新增环境变量 AUTH_MODE=oauth2，默认关闭。", egressRuleKeyValue},
		{"zh-go-snippet", "代码片段：\n```go\nif err := cleanup(ctx); err != nil {\n    return fmt.Errorf(\"cleanup: %w\", err)\n}\n```", ""},
		{"zh-image-digest", "镜像 registry.example.com/rd/devhub-agent:2.9.21，digest sha256:3f5a9c0e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a", egressRuleHex},
		{"zh-full-commit", "回滚到提交 9ef666c2a1b0c3d4e5f60718293a4b5c6d7e8f90 之前的版本。", egressRuleHex},
		{"zh-mention-email", "@zhangsan 帮忙看下，有问题联系 zhangsan@example.com。", egressRuleDetector},
		{"zh-env-name", "数据库连接改为读环境变量 DATABASE_URL，不再写在 config.yaml。", ""},
		{"zh-co-author", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", egressRuleDetector},
		{"zh-authorization-word", "修复 Authorization 头缺失时返回 500 的问题，改为返回 401。", ""},
		{"zh-cookie-word", "新增 `cookie` 解析：读取 `sessionid`，过期则跳转登录页。", ""},
		{"zh-redacted-password", "测试用例使用占位符 password: <redacted>（非真实口令）。", egressRuleKeyValue},
		{"en-jira", "Fix retry cleanup for eval tasks.\n\nCloses https://jira.example.com/browse/EVAL-2921", ""},
		{"en-short-commits", "Refs EVAL-2921. Squashed commits: a1b2c3d, 4e5f6a7.", ""},
		{"en-token-word", "Rotate the API token via Vault; no secrets are stored in this repo.", ""},
		{"en-function", "Add `validatePassword()` to UserService; passwords must be 8-64 chars.", ""},
		{"en-ci", "Update `.gitlab-ci.yml`: cache node_modules between stages.", ""},
		{"en-bump", "Bump golang.org/x/net from 0.23.0 to 0.33.0.", ""},
		{"en-auth-path", "Move auth middleware to internal/http/middleware/auth.go and add tests.", ""},
		{"en-config-keys", "Set `session.timeout: 2h` and `auth.provider: keycloak`.", egressRuleKeyValue},
		{"en-signed-off", "Signed-off-by: Zhang San <zhangsan@example.com>", egressRuleDetector},
		{"en-mr-link", "See rd/devhub-agent-platform!1234 and https://gitlab.example.com/rd/devhub-agent-platform/-/merge_requests/1234", egressRuleDetector},
		{"en-py-snippet", "Snippet:\n```python\nresp = requests.get(url, headers={\"Accept\": \"application/json\"}, timeout=10)\n```", ""},
		{"en-basic-auth-word", "Add Basic auth support for the internal metrics endpoint (credentials read from env).", ""},
		{"en-base64-fixture", "Base64 sample in test fixture: dGhpcyBpcyBhIHRlc3QgZml4dHVyZSBmb3IgdW5pdCB0ZXN0cw==", egressRuleDetector},
	}
	const site = "mcp__devhub__create_gitlab_ce_merge_request"
	blocked := 0
	for _, tc := range corpus {
		args := map[string]any{"project_path": "rd/devhub-agent-platform", "source_branch": "feat/egress-fix-2921", "target_branch": "main",
			"target": "main", "title": "修复评测任务重试前未清理临时目录", "description": tc.text, "content": tc.text}
		rule := egressCredentialLikeRule(args)
		if rule != tc.want {
			t.Errorf("%s: rule=%q want %q", tc.id, rule, tc.want)
		}
		if got := isIrreversibleNetworkTool(site, args); got != (tc.want != "") {
			t.Errorf("%s: isIrreversibleNetworkTool=%v want %v", tc.id, got, tc.want != "")
		}
		if rule != "" {
			blocked++
		}
	}
	t.Logf("merge request description corpus: %d samples, %d back to 2.9.20 egress", len(corpus), blocked)
}
