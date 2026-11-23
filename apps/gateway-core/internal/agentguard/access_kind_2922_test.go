package agentguard

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22 任务 2.2：读、写、使用分开判定（设计 5.1）。
// - .env 只算读：source / . / --env-file 加载它、写和改它（Write、Edit、>、>>、tee）都不算命中；
// - kubeconfig 被 --kubeconfig、KUBECONFIG= 拿来认证不算命中，kubectl config view --raw 把
//   凭据打出来，算云凭据；
// - 私钥和云凭据被写（覆盖、追加、拷入）也算命中。
// 全部在“所有敏感目标防护项设为阻断”的现场策略下断言。

func siteWrite(path, content string) ToolCallAnalysisInput {
	return ToolCallAnalysisInput{ToolName: "Write", ToolType: "file", Mode: ModeStrict,
		Arguments: map[string]any{"file_path": path, "content": content}}
}

func siteEdit(path, oldText, newText string) ToolCallAnalysisInput {
	return ToolCallAnalysisInput{ToolName: "Edit", ToolType: "file", Mode: ModeStrict,
		Arguments: map[string]any{"file_path": path, "old_string": oldText, "new_string": newText}}
}

func TestUsingOrWritingEnvFileIsNotAHit2922(t *testing.T) {
	for _, command := range []string{
		"source .env",
		". .env",
		"set -a && source .env && set +a && go run ./cmd/server",
		"source ./.env.local",
		"docker compose -f deploy/docker-compose.yml --env-file .env up -d",
		"docker run --rm --env-file .env.dev -p 8080:8080 app:dev",
		"docker run --env-file=.env alpine true",
		"echo A=1 > .env",
		"echo A=1 >> .env",
		"echo A=1 | tee .env",
		"printf 'A=1\\n' | tee -a .env.local",
		"cp .env.example .env",
	} {
		t.Run(command, func(t *testing.T) {
			requireRecordedNotBlocked(t, command, analyzeSiteBash(t, command))
		})
	}
	all := blockingProtections(protection.GroupAgentTarget)
	for label, in := range map[string]ToolCallAnalysisInput{
		"Write .env":       siteWrite("/srv/app/.env", "A=1\n"),
		"Write .env.local": siteWrite("/srv/app/.env.local", "A=1\n"),
		"Edit .env":        siteEdit("/srv/app/.env", "A=1", "A=2"),
		// write_to_file 会把写完的文件内容回传给模型，复核员乙 11-18 定为照算命中
		// （TestReviewBToolArgumentExemptions2922）。
	} {
		t.Run(label, func(t *testing.T) {
			requireRecordedNotBlocked(t, label, analyzeSiteInput(in, all))
		})
	}
}

func TestUsingKubeconfigIsNotAHit2922(t *testing.T) {
	for _, command := range []string{
		"kubectl --kubeconfig ~/.kube/config get nodes -o wide",
		"kubectl --kubeconfig=/home/dev/.kube/config-npu-test get pods -n npu-system",
		"KUBECONFIG=~/.kube/config kubectl get pods -A",
		"export KUBECONFIG=~/.kube/config && kubectl get pods",
		"helm --kubeconfig ~/.kube/config list -A",
		"kubectl config view",
	} {
		t.Run(command, func(t *testing.T) {
			requireRecordedNotBlocked(t, command, analyzeSiteBash(t, command))
		})
	}
}

func TestEnvAndCredentialReadsStillHit2922(t *testing.T) {
	for _, tc := range []struct{ command, reason string }{
		{"cat .env", targetReasonEnvFile},
		{"grep -r API .env", targetReasonEnvFile},
		{"cp .env /tmp/x", targetReasonEnvFile},
		{"tar czf x.tgz .env", targetReasonEnvFile},
		{"base64 .env", targetReasonEnvFile},
		{`python -c "print(open('.env').read())"`, targetReasonEnvFile},
		{"source .env; cat .env", targetReasonEnvFile},
		{"kubectl config view --raw", targetReasonCloudCredential},
		{"kubectl --kubeconfig ~/.kube/prod config view --raw", targetReasonCloudCredential},
		{"kubectl config view --raw=true -o jsonpath='{.users[0].user.token}'", targetReasonCloudCredential},
		// 命令行里另有 $KUBECONFIG 时，赋值不再当“只拿来认证”。
		{"KUBECONFIG=~/.kube/config cat $KUBECONFIG", targetReasonCloudCredential},
		// 使用位置上的其他类凭据照旧算读。
		{"kubectl --kubeconfig ~/.ssh/id_rsa get pods", targetReasonSSHPrivateKey},
		{"source ~/.ssh/id_rsa", targetReasonSSHPrivateKey},
		{"docker run --env-file ~/.aws/credentials alpine env", targetReasonCloudCredential},
		// 私钥和云凭据的写算命中。
		{"echo x > ~/.ssh/id_rsa", targetReasonSSHPrivateKey},
		{"echo x >> ~/.aws/credentials", targetReasonCloudCredential},
		{"cp /tmp/k ~/.ssh/id_ed25519", targetReasonSSHPrivateKey},
		{"echo x | tee ~/.ssh/id_rsa", targetReasonSSHPrivateKey},
	} {
		t.Run(tc.command, func(t *testing.T) {
			requireProtectionBlockAndDefaultAlert(t, tc.command, siteBash(tc.command), tc.reason)
		})
	}
	for label, tc := range map[string]struct {
		in     ToolCallAnalysisInput
		reason string
	}{
		"Write ~/.ssh/id_rsa":      {siteWrite("/home/u/.ssh/id_rsa", "x"), targetReasonSSHPrivateKey},
		"Write ~/.aws/credentials": {siteWrite("/home/u/.aws/credentials", "x"), targetReasonCloudCredential},
		"Read .env":                {siteRead("/srv/app/.env"), targetReasonEnvFile},
	} {
		t.Run(label, func(t *testing.T) {
			requireProtectionBlockAndDefaultAlert(t, label, tc.in, tc.reason)
		})
	}
}
