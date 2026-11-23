package agentguard

import "testing"

func TestAnalyzeTargetBlocksDecimalLoopbackURL(t *testing.T) {
	result := AnalyzeTarget("http://2130706433/admin")

	if result.Reason != "blocked_loopback_or_private_ip" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
	if result.NormalizedTarget != "http://127.0.0.1/admin" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}

func TestAnalyzeTargetBlocksHexDottedLoopbackURL(t *testing.T) {
	result := AnalyzeTarget("http://0x7f.0.0.1/admin")

	if result.NormalizedTarget != "http://127.0.0.1/admin" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}

func TestAnalyzeTargetBlocksIPv4MappedIPv6LoopbackURL(t *testing.T) {
	result := AnalyzeTarget("http://[::ffff:127.0.0.1]/admin")

	if result.NormalizedTarget != "http://127.0.0.1/admin" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}

func TestAnalyzeTargetBlocksCloudMetadataAddress(t *testing.T) {
	result := AnalyzeTarget("http://169.254.169.254/latest/meta-data/iam/security-credentials")

	if result.Reason != "blocked_cloud_metadata" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
}

func TestAnalyzeTargetAllowsPublicURLWithoutDNS(t *testing.T) {
	result := AnalyzeTarget("https://api.example.com/v1/chat")

	if result.NormalizedTarget != "https://api.example.com/v1/chat" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}

func TestAnalyzeTargetBlocksSSHPrivateKeyPath(t *testing.T) {
	result := AnalyzeTarget("/srv/app/../app/.ssh/id_rsa")

	if result.Reason != "blocked_ssh_private_key_path" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
	if result.NormalizedTarget != "/srv/app/.ssh/id_rsa" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}

func TestAnalyzeTargetBlocksURLEncodedCloudCredentialPath(t *testing.T) {
	result := AnalyzeTarget("/home/service/%2eaws/credentials")

	if result.Reason != "blocked_cloud_credential_path" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
	if result.NormalizedTarget != "/home/service/.aws/credentials" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}

func TestAnalyzeTargetBlocksBareEnvFile(t *testing.T) {
	result := AnalyzeTarget(".env")

	// 2.9.22 任务 2.1：.env 从“敏感本地文件”拆出，归 .env 文件防护项。
	if result.Reason != "blocked_env_file" || !result.Hit {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
}

func TestAnalyzeTargetBlocksEtcPasswd(t *testing.T) {
	result := AnalyzeTarget("/etc/passwd")

	// 2.9.22 任务 2.1：/etc/passwd 不含口令散列，归“名字像敏感文件”。
	if result.Reason != "sensitive_name_hint" || !result.Hit {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
}

func TestAnalyzeTargetBlocksLocalhostHostname(t *testing.T) {
	result := AnalyzeTarget("http://localhost:8080/admin")

	if result.Reason != "blocked_loopback_or_private_ip" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
	if result.NormalizedTarget != "http://localhost:8080/admin" {
		t.Fatalf("unexpected normalized target: %q", result.NormalizedTarget)
	}
}
