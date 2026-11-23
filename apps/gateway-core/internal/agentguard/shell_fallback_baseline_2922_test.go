package agentguard

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 兜底不比 a5785e9a（2.9.21 的做法）宽（代码质量第三轮复审）：testdata/fallback_baseline_2922.jsonl 是在
// a5785e9a 上，把本包、handler 包测试文件里的全部字符串字面量与探针 1–14 当 Bash 命令、敏感目标组
// 防护项全配成阻断时被拦下的 1206 条（命令、当时的原因码）。这里把上限设成 0 强制走兜底，逐条再判：
// 基线拦而兜底不拦的，只许是下面清单里原样列出的 20 条（2.9.22 与 11-21 有意调整的目标类别），新的放行必须
// 人工加进清单；清单里的每条也必须仍被放行。

// fallbackBaselineAllowed lists, verbatim, the baseline blocks the fallback
// may release, each with why 2.9.22 judges it differently on purpose. Any new
// release must be added here by hand.
var fallbackBaselineAllowed = map[string]string{
	// SSH 公钥（*.pub）是公开文件（2.9.22 设计：~/.ssh 下的 .pub 不算私钥）
	"cat ~/.ssh/*.pub":                   "SSH 公钥是公开文件",
	"cat ~/.ssh/id_*.pub":                "SSH 公钥是公开文件",
	"cat ~/.ssh/{id_rsa,id_ed25519}.pub": "SSH 公钥是公开文件",
	"cat ~/.ssh/{id_rsa,x}.pub":          "SSH 公钥是公开文件",
	"tar czf pubs.tgz ~/.ssh/*.pub":      "SSH 公钥是公开文件",
	// kubectl JSONPath / custom-columns 里的 .env 字段不是环境文件（2.9.22 目标分类：.env 只认文件名）
	"kubectl get pod -o jsonpath='{.spec.containers[*].env[*].name}'":                                                              "JSONPath 里的 .env 字段",
	"kubectl get pods -n npu-system -o jsonpath='{.items[*].spec.containers[0].env[*].name}'":                                      "JSONPath 里的 .env 字段",
	"kubectl get pod p -n ns -o jsonpath='{.spec.containers[0].env[?(@.name==\"LOG_LEVEL\")].value}'":                              "JSONPath 里的 .env 字段",
	"ssh npu-master \"kubectl -n npu-system get pods -o jsonpath='{.items[*].spec.containers[*].env[*].name}'\"":                   "JSONPath 里的 .env 字段",
	"kubectl get pods -o custom-columns=NAME:.metadata.name,ENV:.spec.containers[*].env":                                           "custom-columns 里的 .env 字段",
	"kubectl get pods -o jsonpath='{.items[*].spec.containers[*].env[*].name}'":                                                    "JSONPath 里的 .env 字段",
	"kubectl get pod npu-exporter-7d9f -n npu-system -o jsonpath='{.spec.containers[0].env[?(@.name==\"TOPS_LOG_LEVEL\")].value}'": "JSONPath 里的 .env 字段",
	"ssh npu-master \"kubectl get pods -n npu-system -o jsonpath='{.items[*].spec.containers[0].env[*].value}'\"":                  "JSONPath 里的 .env 字段",
	// yq / jq 表达式里的 .aws 字段不是凭据路径（2.9.22 目标分类：云凭据只认文件路径）
	"yq '.spec[0].aws' values.yaml": "yq 表达式里的 .aws 字段",
	// 源码文件名或所在目录像敏感文件（2026-11-21 用户决定：只是名字像，源码不算；客户现场
	// wc -l internal/provider/keep_secrets.go 被拦）
	"Show status of src/credential_store.go changes": "源码文件名像敏感文件",
	"Review src/credential_store.go changes":         "源码文件名像敏感文件",
	"sed -n '1,80p' pkg/secrets/vault.go":            "源码文件名像敏感文件",
	"head -50 internal/credential/store.go":          "源码文件名像敏感文件",
	"pytest tests/test_credentials.py -q":            "源码文件名像敏感文件",
	"git diff HEAD~1 -- internal/secrets/manager.go": "源码文件名像敏感文件",
}

func TestShellFallbackNotLooserThanBaseline2922(t *testing.T) {
	file, err := os.Open("testdata/fallback_baseline_2922.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	withShellWorkLimit(t, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	total, released := 0, map[string]string{}
	for scanner.Scan() {
		var row struct {
			Command string `json:"command"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		total++
		decision := analyzeSiteInput(siteBash(row.Command), blockingProtections(protection.GroupAgentTarget))
		if decision.EffectiveDecision == DecisionBlock || decision.EffectiveDecision == DecisionConfirm {
			continue
		}
		allowed, ok := fallbackBaselineAllowed[row.Command]
		if !ok {
			t.Errorf("blocked by a5785e9a (%s) but not by the fallback: %q", row.Reason, row.Command)
			continue
		}
		released[row.Command] = allowed
	}
	if total < 1000 {
		t.Fatalf("only %d baseline rows", total)
	}
	// 清单里每一条都还得真的被放行（判定收紧后要从清单里删掉）。
	for command := range fallbackBaselineAllowed {
		if _, ok := released[command]; !ok {
			t.Errorf("listed as released but blocked (or no longer in the baseline): %q", command)
		}
	}
}
