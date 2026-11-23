package agentguard

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22 任务 2.1：原“敏感本地文件”一个原因码拆成五个防护项，各自可配动作和例外。
// 精确类（.env、系统口令与进程环境、密钥挂载目录、git 口令文件）按文件名或完整路径
// 判定；其余靠名字猜的规则都落在“名字像敏感文件”。
func TestTargetClasses2922(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   string // 空串表示不命中
	}{
		{"/app/.env", "blocked_env_file"},
		{".env.example", ""},
		{"/etc/shadow", "blocked_system_secret_file"},
		{"/etc/shadow.bak", "sensitive_name_hint"},
		{"/etc/gshadow", "blocked_system_secret_file"},
		{"/proc/1234/environ", "blocked_system_secret_file"},
		{"/proc/self/environ", "blocked_system_secret_file"},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", "blocked_secret_mount_path"},
		{"/run/secrets/db_password", "blocked_secret_mount_path"},
		{"/etc/secrets/db-password", "blocked_secret_mount_path"},
		{"~/.git-credentials", "blocked_git_credentials_file"},
		{"/home/u/.config/git/credentials", "blocked_git_credentials_file"},
		// 2026-11-21 用户决定：源码文件名像敏感文件不算（客户现场 wc -l .../keep_secrets.go）。
		{"pkg/secrets/manager.go", ""},
		{"pkg/secrets/manager.yaml", "sensitive_name_hint"},
		{"/var/run/docker.sock", "sensitive_name_hint"},
		{"/etc/passwd", "sensitive_name_hint"},
		{"process.env", "sensitive_name_hint"},
		{"/host/etc/shadow", "sensitive_name_hint"},
		{"~/.ssh/id_rsa", "blocked_ssh_private_key_path"},
		{"~/.aws/credentials", "blocked_cloud_credential_path"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			got := AnalyzeTarget(tc.target)
			if tc.want == "" {
				if got.Hit {
					t.Fatalf("%s must not hit, got %s", tc.target, got.Reason)
				}
				return
			}
			if !got.Hit || got.Reason != tc.want {
				t.Fatalf("%s: want %s, got hit=%v reason=%s", tc.target, tc.want, got.Hit, got.Reason)
			}
			if _, ok := protection.ItemForReason(got.Reason); !ok {
				t.Fatalf("%s: reason %s must be a registered protection item", tc.target, got.Reason)
			}
		})
	}
}

// ~/.gnupg 整个目录（含通配和变量）落在“名字像敏感文件”。
func TestGnupgStoreIsNameHint2922(t *testing.T) {
	d := analyzeSiteBash(t, "tar czf /tmp/g.tgz ~/.gnupg")
	if d.EffectiveDecision != DecisionBlock || d.Reason != "sensitive_name_hint" {
		t.Fatalf("~/.gnupg must be a sensitive_name_hint hit, got effective=%s reason=%s", d.EffectiveDecision, d.Reason)
	}
}

// 旧原因码 blocked_sensitive_local_file_path 写的例外（升级前被底线忽略）升级后照字面生效：
// 拆出来的五个新原因码都算它点名的对象（用户决定 D4）。
func TestLegacySensitiveLocalFileExceptionCoversSplitReasons2922(t *testing.T) {
	for _, tc := range []struct{ path, item string }{
		{"/srv/app/.env", "agent.env_file"},
		{"/etc/shadow", "agent.system_secret_file"},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", "agent.secret_mount"},
		{"/home/u/.git-credentials", "agent.git_credential"},
		{"/srv/app/pkg/secrets/manager.yaml", "agent.sensitive_name"},
	} {
		evaluate := func(exceptions []PolicyException) Decision {
			return analyzeMatrix(ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
				Arguments: map[string]any{"file_path": tc.path},
				Policy:    policyWith(blockingProtections(protection.GroupAgentTarget), nil, exceptions)})
		}
		if d := evaluate(nil); d.EffectiveDecision != DecisionBlock || d.ProtectionItem != tc.item {
			t.Fatalf("%s: configured block must block on %s, got effective=%s item=%s", tc.path, tc.item, d.EffectiveDecision, d.ProtectionItem)
		}
		legacy := []PolicyException{{ID: "e-legacy", RuleID: "blocked_sensitive_local_file_path", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}}
		if d := evaluate(legacy); d.EffectiveDecision != DecisionAudit || len(d.ProtectionExceptionIDs()) != 1 {
			t.Fatalf("%s: legacy exception must release %s, got effective=%s exceptions=%v", tc.path, tc.item, d.EffectiveDecision, d.ProtectionExceptionIDs())
		}
	}
}
