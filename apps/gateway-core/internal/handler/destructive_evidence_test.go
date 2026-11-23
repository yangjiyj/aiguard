package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func destructiveDecision(subcategory string) agentguard.Decision {
	return agentguard.Decision{
		RiskCategory:     agentguard.DestructiveRiskCategory,
		RiskSubcategory:  subcategory,
		NormalizedTarget: subcategory + ":1-targets",
	}
}

// destructiveEvidenceDecision 走真实的闸门分析取决策（触发段随 Decision 透传）；分析器不判破坏性时，
// 用手工构造的破坏性决策代替（模拟兜底策略给出的判定），此时没有触发段。
func destructiveEvidenceDecision(name, arguments, subcategory string) agentguard.Decision {
	args, rejected := parseToolCallArguments(arguments)
	decision := evaluateStructuredToolCall(structuredToolCallInput{
		ToolName: name, ToolType: inferToolTypeFromName(name), Arguments: args,
		RawArguments: arguments, ArgumentsParseRejected: rejected, Mode: agentguard.ModeStrict,
	}).Decision
	if decision.RiskCategory != agentguard.DestructiveRiskCategory {
		return destructiveDecision(subcategory)
	}
	return decision
}

func destructiveEvidenceFor(name, arguments, subcategory string) string {
	tc := ToolCall{ID: "c1", Function: ToolCallFunc{Name: name, Arguments: arguments}}
	return agentGuardSecurityFinding(tc, destructiveEvidenceDecision(name, arguments, subcategory), 0).RedactedEvidence
}

type evidenceProbe struct {
	ID             string          `json:"id"`
	Tool           string          `json:"tool"`
	Arguments      json.RawMessage `json:"arguments"`
	Subcategory    string          `json:"subcategory"`
	MustNotContain []string        `json:"must_not_contain"`
	MustContain    []string        `json:"must_contain"`
	Note           string          `json:"note"`
}

func loadEvidenceProbes(t *testing.T, file string, minimum int) []evidenceProbe {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// 样本里形似平台令牌的假值在中间插了 {{JOIN}}，读入后去掉，
	// 免得仓库里出现完整令牌字面量被代码托管平台的密钥扫描拦下。
	raw = []byte(strings.ReplaceAll(string(raw), "{{JOIN}}", ""))
	var probes []evidenceProbe
	if err := json.Unmarshal(raw, &probes); err != nil {
		t.Fatal(err)
	}
	if len(probes) < minimum {
		t.Fatalf("%s shrank: %d", file, len(probes))
	}
	return probes
}

func (probe evidenceProbe) arguments() string {
	args := string(probe.Arguments)
	if len(args) > 0 && args[0] == '[' {
		args = `{"command":` + args + `}`
	}
	return args
}

// 表驱动：每条探针走真实分析路径取触发段，断言 must_not_contain 一个都不出现、must_contain 全部出现。
// 分析器不判破坏性的探针没有触发段，证据只剩“子类（N 个目标）”，只断言不泄漏、证据里没有命令；
// 不为过测试去改分析器判定。must_contain 与骨架口径冲突的，在 overrides 里改断言并写明原因。
func runEvidenceProbeTable(t *testing.T, file string, minimum int, noTrigger map[string]bool, overrides map[string][]string, known map[string]string) {
	probes := loadEvidenceProbes(t, file, minimum)
	leaks, withoutSegments := 0, 0
	for _, probe := range probes {
		decision := destructiveEvidenceDecision(probe.Tool, probe.arguments(), probe.Subcategory)
		evidence := agentGuardFindingEvidence(decision)
		if reason, ok := known[probe.ID]; ok {
			t.Logf("%s: known limitation, not asserted (%s): %q", probe.ID, reason, evidence)
			continue
		}
		for _, secret := range probe.MustNotContain {
			if strings.Contains(evidence, secret) {
				leaks++
				t.Errorf("%s: credential %q leaked: %q", probe.ID, secret, evidence)
			}
		}
		if noTrigger[probe.ID] {
			withoutSegments++
			if len(decision.EvidenceSegments) > 0 || strings.Contains(evidence, "：") {
				t.Errorf("%s: listed as no-trigger but the analyzer produced a trigger segment: %q", probe.ID, evidence)
			}
			continue
		}
		if len(decision.EvidenceSegments) == 0 {
			t.Errorf("%s: no trigger segment, add it to the no-trigger list if that is the analyzer's verdict: %q", probe.ID, evidence)
			continue
		}
		want := probe.MustContain
		if override, ok := overrides[probe.ID]; ok {
			want = override
		}
		for _, fragment := range want {
			if !strings.Contains(evidence, fragment) {
				t.Errorf("%s: want %q in %q (%s)", probe.ID, fragment, evidence, probe.Note)
			}
		}
	}
	t.Logf("%s probes=%d leaks=%d noTrigger=%d", file, len(probes), leaks, withoutSegments)
}

// 分析器不判这些探针为破坏性（没有触发段），证据只剩“子类（N 个目标）”，必须不泄漏、不含命令。不为过测试去改分析器判定。
var evidenceProbeNoTrigger = map[string]bool{
	"07":  true,
	"08":  true,
	"09":  true,
	"10":  true,
	"11":  true,
	"12":  true,
	"16":  true,
	"17":  true,
	"24":  true,
	"27":  true,
	"29":  true,
	"37":  true,
	"38":  true,
	"39":  true,
	"40":  true,
	"43":  true,
	"48":  true,
	"54":  true,
	"56":  true,
	"59":  true,
	"60":  true,
	"63":  true,
	"64":  true,
	"65":  true,
	"66":  true,
	"67":  true,
	"68":  true,
	"69":  true,
	"70":  true,
	"71":  true,
	"72":  true,
	"73":  true,
	"75":  true,
	"78":  true,
	"80":  true,
	"80b": true,
	"81b": true,
	"89":  true,
	"91":  true,
	"93":  true,
	"94":  true,
	"98":  true,
	"101": true,
	"103": true,
	"106": true,
	"107": true,
	"110": true,
	"111": true,
	"114": true,
	"M03": true,
	"M13": true,
	"M14": true,
	"M15": true,
	"M17": true,
	"M18": true,
	"M23": true,
	// 2.9.22：SQL 解析失败（美元引号里的口令）改为兜底防护项 agent.parse_rejected，不再按“删除与破坏”
	// 出触发段（原先走破坏性兜底，带 DROP TABLE 的触发段）。
	"83b": true,
}

// 写 /tmp 的非破坏性对照：分析器不判破坏性，没有触发段。
var evidenceAdversarialNoTrigger = map[string]bool{
	"R055": true,
	"R056": true,
	"R057": true,
	"R058": true,
	"R059": true,
	"R060": true,
	"R061": true,
	"R062": true,
	"R063": true,
	"R064": true,
	"R065": true,
	"R066": true,
	"R067": true,
}

// 旧表里与骨架口径冲突的 must_contain 改断言，分三类写明原因。
var evidenceProbeContainOverrides = map[string][]string{
	// 命令里要求出现的片段在触发段之外（前置登录、cd、管道左侧、前一条命令、后一条命令），只断言触发段本身
	"13":  {"rm -rf repo/.git"},
	"14":  {"git push -f"},
	"18":  {"rm -rf data"},
	"19":  {"rm -rf data"},
	"28":  {"rm -rf ~/.aws/cli/cache"},
	"30":  {"rm -f db.sql"},
	"32":  {"rm -f db.sql"},
	"33":  {"rm -f db.sql"},
	"53":  {"rm -f /etc/nologin"},
	"82":  {"DROP TABLE t"},
	"83":  {"DROP TABLE t"},
	"83b": {"DROP TABLE t"},
	"87":  {"del x"},
	"90":  {"helm uninstall app"},
	"92":  {"docker rm -f c"},
	"113": {"rm -rf /home/bob/x"},
	"M16": {"rm -rf ckpt"},
	"M20": {"rm -rf .github"},
	"31":  {"rm a"},
	"95":  {"git reset --hard"},
	// POSIX 解析下 /s、/q 是普通位置参数，骨架写 …；单横线长选项（-Recurse）按“更长的短选项”写首字母加 …；Windows 路径目标保持原写法
	"41":  {"del", "C:\\data"},
	"42":  {"Remove-Item C:\\data"},
	"44":  {"Remove-Item C:\\x"},
	"55":  {"del", "\\\\srv\\share\\x"},
	"86":  {"del", "C:\\data"},
	"104": {"Remove-Item C:\\x"},
	// 要求显示的是普通位置参数或选项值（echo 的参数、git reset 的提交号、kubectl 的 -n 值、子命令之后的第三个词、-c 的值），骨架写 …；删除目标、可执行文件、重定向目标仍然出现
	"84b": {"echo", "> t"},
	"M01": {"git reset --hard"},
	"M12": {"echo", "notes.txt"},
	"M21": {"kubectl delete secret db-password"},
	"M24": {"git push --force"},
	"100": {"push -f"},
	"25":  {"kubectl create secret", "> s.yaml"},
	"26":  {"kubectl create secret", "> s.yaml"},
	"34":  {"mysqldump", "> /data/db.sql"},
	// 数据库命令行：-e/-c 的 SQL 是选项值，骨架写 …，触发的语句另起一段按 SQL 骨架显示；主机、用户等选项值写 …
	"01":  {"mysql -u… -p… … -e … ; drop table t"},
	"02":  {"mysql -u … --password … -e … ; DROP DATABASE x"},
	"03":  {"mysql -u… -p… -e … ; drop database x"},
	"04":  {"mysql -u… -p… -e … ; drop database x"},
	"05":  {"mysql -h … -u… -p… -e … ; drop database x"},
	"06":  {"PGPASSWORD=… psql -h … -c … ; drop table t"},
	"35":  {"psql … -c … ; drop table t"},
	"79":  {"PGPASSWORD=… psql -h … -c … ; drop table t"},
	"81":  {"mysql -u… -p… -e … ; drop database x"},
	"83c": {"mysql -u… -p… -e … ; drop database x"},
	"96":  {"MYSQL_PWD=… mysql -e … ; drop database x"},
	"105": {"PGPASSWORD=… psql -c … ; drop table t"},
	"108": {"mysql -p… -h … -e … ; drop database x"},
	"M22": {"mysql -h … -P … -u… -p -e … ; drop database x"},
	// redis-cli：连接选项的值写 …，破坏命令照样显示
	"36": {"redis-cli -u … FLUSHALL"},
	"61": {"redis-cli -h … --pass … FLUSHALL"},
	"62": {"redis-cli -h … -a … FLUSHALL"},
	// 前一条命令不在触发段里；rsync 的源目录是普通位置参数，骨架写 …，删除目标（目的目录）照样显示
	"84": {"PGPASSWORD=… psql -c … ; drop table t"},
	"99": {"rsync -e … -a --delete … root@10.0.0.5:/dst/"},
}

func TestDestructiveAlertEvidenceProbeTable(t *testing.T) {
	runEvidenceProbeTable(t, "testdata/destructive_evidence_probes.json", 141, evidenceProbeNoTrigger, evidenceProbeContainOverrides, nil)
}

// 对抗用例：echo/printf 写文件内容、PowerShell 括号内联凭据、SQL 函数包裹与注释、-ec 别名与带 / 的 base64、
// 令牌前缀、Cookie 与请求头、查询参数、argv 空格拼接。must_contain 已按骨架口径写，不需要改断言。
func TestDestructiveAlertEvidenceAdversarialTable(t *testing.T) {
	runEvidenceProbeTable(t, "testdata/destructive_evidence_adversarial.json", 154, evidenceAdversarialNoTrigger, nil, nil)
}

// 分析器不判破坏性的命令没有触发段，上面的表测不到渲染规则本身。这里对两张表的每条探针解析出的每一段
// （含管道左侧的 echo、前置登录、PowerShell 与 cmd 的词法兜底段）逐段渲染，凭据一个都不能出现。
func TestDestructiveEvidenceRenderingOnEveryParsedSegment(t *testing.T) {
	segments := 0
	for _, file := range []string{"testdata/destructive_evidence_probes.json", "testdata/destructive_evidence_adversarial.json"} {
		for _, probe := range loadEvidenceProbes(t, file, 1) {
			if probe.Tool == "run_sql" {
				continue
			}
			parsed, _ := parseToolCallArguments(probe.arguments())
			for _, segment := range agentguard.ParsedEvidenceSegments(agentguard.DestructiveInput{
				ToolName: probe.Tool, ToolType: structuredExecutionToolType(inferToolTypeFromName(probe.Tool), parsed), Arguments: parsed,
			}) {
				segments++
				rendered := renderEvidenceSegment(segment, 0)
				for _, secret := range probe.MustNotContain {
					if strings.Contains(rendered, secret) {
						t.Errorf("%s: credential %q leaked: %q", probe.ID, secret, rendered)
					}
				}
			}
		}
	}
	if segments < 200 {
		t.Fatalf("too few parsed segments, the walk is not exercising the parsers: %d", segments)
	}
}

func TestDestructiveAlertEvidenceShowsTheCommandSkeleton(t *testing.T) {
	cases := []struct {
		name, arguments, subcategory, want string
	}{
		{"Bash", `{"command":"cat template.txt > config.yaml"}`, "filesystem_overwrite", "覆盖文件：cat … > config.yaml"},
		// 前后的其它命令、管道左侧不进证据。
		{"Bash", `{"command":"cd /srv/app && make clean && rm -rf build/cache && echo done"}`, "filesystem_delete", "删除文件：rm -rf build/cache"},
		{"Bash", `{"command":"echo 'S3cretPipe' | sudo rm -rf /srv/x"}`, "filesystem_delete", "删除文件：sudo rm -rf /srv/x"},
		{"Bash", `{"command":"sudo rm -rf /srv/x <<< 'S3cretHere'"}`, "filesystem_delete", "删除文件：sudo rm -rf /srv/x <<< …"},
		// heredoc 正文不进证据。
		{"Bash", "{\"command\":\"cat > app.yaml <<'EOF'\\nkey: value\\nother: value\\nEOF\"}", "filesystem_overwrite", "覆盖文件：cat > app.yaml <<'EOF'（正文已省略 2 行）"},
		// 嵌套 bash -c 取内层触发段。
		{"Bash", `{"command":"bash -c \"cd /srv; rm -rf /srv/x\""}`, "filesystem_delete", "删除文件：rm -rf /srv/x"},
		// 前置赋值只写变量名；选项的值不显示。
		{"Bash", `{"command":"DB_PASSWORD='my S3cret' rm -rf /srv/x"}`, "filesystem_delete", "删除文件：DB_PASSWORD=… rm -rf /srv/x"},
		{"Bash", `{"command":"terraform destroy -auto-approve -var token=S3cret"}`, "infrastructure_destroy", "销毁基础设施：terraform destroy -auto-approve -v… …"},
		{"Bash", `{"command":"kubectl --token=S3cret delete ns prod"}`, "cluster_destroy", "删除集群资源：kubectl --token=… delete ns prod"},
		// Codex 数组形态：取 -lc 后面的脚本里的触发段；argv 按元素渲染，含空格的元素就是一个目标。
		{"shell", `{"command":["bash","-lc","cd /srv/app && rm -rf build/cache"]}`, "filesystem_delete", "删除文件：rm -rf build/cache"},
		{"exec", `{"argv":["rm","-rf","/opt/My Dir"]}`, "filesystem_delete", "删除文件：rm -rf '/opt/My Dir'"},
		{"shell", `{"command":["powershell","-Command","Remove-Item C:\\data -Recurse"]}`, "filesystem_delete", `删除文件：Remove-Item C:\data -Recurse`},
		// 带选项的 sudo、env 包装、数据库命令行、云存储删除、PowerShell 字符串形态的 EncodedCommand、Set-Content、cp 覆盖
		{"Bash", `{"command":"echo S3cretPipe | sudo -S -u root rm -rf /opt/app"}`, "filesystem_delete", "删除文件：sudo -S -u … rm -rf /opt/app"},
		{"exec", `{"argv":["env","DB_PASSWORD=S3cret x","rm","-rf","/opt/app"]}`, "filesystem_delete", "删除文件：env DB_PASSWORD=… rm -rf /opt/app"},
		{"Bash", `{"command":"MYSQL_PWD=S3cret mysql -h 10.0.0.5 -e \"UPDATE users SET password='S3cret'\""}`, "database_unscoped_mutation", "无条件批量修改数据库：MYSQL_PWD=… mysql -h … -e … ; UPDATE users SET password=?"},
		{"Bash", `{"command":"aws s3 rm s3://bucket/data --recursive"}`, "cloud_resource_destroy", "删除云资源：aws s3 rm s3://bucket/data --recursive"},
		{"Bash", `{"command":"powershell -ec JABwAD0AJwBTADMAYwByAGUAdABUADUAMgAnADsAIABSAGUAbQBvAHYAZQAtAEkAdABlAG0AIABDADoAXABkAGEAdABhACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUA"}`, "filesystem_delete", `删除文件：powershell -EncodedCommand <已解码：Remove-Item C:\data -Recurse -Force>`},
		{"powershell", `{"command":"Set-Content -Path C:\\app\\x.txt -Value 'S3cret'"}`, "filesystem_overwrite", `覆盖文件：Set-Content -Path C:\app\x.txt -Value …`},
		{"Bash", `{"command":"cp /dev/null /etc/app/config.yaml"}`, "filesystem_overwrite", "覆盖文件：cp … /etc/app/config.yaml"},
		{"exec_command", `{"cmd":"terraform destroy -auto-approve"}`, "infrastructure_destroy", "销毁基础设施：terraform destroy -auto-approve"},
		// SQL：只写触发的那几条语句，字面量换成 ?。
		{"run_sql", `{"query":"SELECT 1; DROP TABLE users; SELECT 2"}`, "database_destroy", "删除数据库对象：DROP TABLE users"},
		{"run_sql", `{"query":"UPDATE t SET note='a;b'; DELETE FROM t"}`, "database_unscoped_mutation", "无条件批量修改数据库：UPDATE t SET note=? ; DELETE FROM t"},
		// 拿不到触发段时只写“做了什么（N 个目标）”，不写命令。
		{"delete_file", `{"path":"/srv/a.txt"}`, "filesystem_delete", "删除文件（1 个目标）"},
		{"Bash", `{"command":"ls"}`, "no_such_subcategory", "破坏性操作（1 个目标）"},
	}
	for _, c := range cases {
		if got := destructiveEvidenceFor(c.name, c.arguments, c.subcategory); got != c.want {
			t.Errorf("%s %s: evidence=%q want %q", c.name, c.arguments, got, c.want)
		}
	}
	if got := agentGuardFindingEvidence(agentguard.Decision{RiskCategory: agentguard.DestructiveRiskCategory, RiskSubcategory: "filesystem_delete"}); got != "删除文件" {
		t.Errorf("without a target count the evidence is the label only: %q", got)
	}
}

// 闸门没做破坏性分析的兜底决策（参数解析失败），证据不写命令。2.9.22 起身份异常不再跳过破坏性
// 分析（另记 agent.identity_rejected 命中），用例改用参数解析失败的写法。
func TestDestructiveAlertEvidenceHasNoCommandWhenTheGateDidNotAnalyze(t *testing.T) {
	arguments := `{"command":"rm -rf /srv/x"`
	args, rejected := parseToolCallArguments(arguments)
	decision := evaluateStructuredToolCall(structuredToolCallInput{
		ToolName: "Bash", ToolType: "shell", Arguments: args, RawArguments: arguments, ArgumentsParseRejected: rejected,
		ProtocolIdentityRejected: true, AgentType: "unknown-agent", Mode: agentguard.ModeStrict,
	}).Decision
	if len(decision.EvidenceSegments) != 0 || strings.Contains(agentGuardFindingEvidence(decision), "rm") {
		t.Fatalf("evidence=%q segments=%v", agentGuardFindingEvidence(decision), decision.EvidenceSegments)
	}
}

func TestDestructiveAlertEvidenceIsRedactedBeforeItIsTruncated(t *testing.T) {
	token := "ghp_" + strings.Repeat("A1b2C3d4E5", 4)[:36]
	long := "rm -rf /srv/" + strings.Repeat("中", 185) + "/" + token + "/x"
	evidence := destructiveEvidenceFor("Bash", `{"command":`+mustJSONString(long)+`}`, "filesystem_delete")
	if strings.Contains(evidence, "ghp_") || strings.Contains(evidence, "A1b2C3") {
		t.Fatalf("token straddling the cut leaked: %q", evidence)
	}
	body := strings.TrimPrefix(evidence, "删除文件：")
	if n := len([]rune(body)); n != destructiveEvidenceMaxRunes+1 || !strings.HasSuffix(body, "…") {
		t.Fatalf("command must be cut to %d runes plus an ellipsis, got %d: %q", destructiveEvidenceMaxRunes, n, evidence)
	}
	exact := "rm -rf /" + strings.Repeat("a", destructiveEvidenceMaxRunes-len("rm -rf /"))
	if got := destructiveEvidenceFor("Bash", `{"command":`+mustJSONString(exact)+`}`, "filesystem_delete"); strings.HasSuffix(got, "…") {
		t.Fatalf("a command of exactly the limit must not be cut: %q", got)
	}
}

// 分析器认定的目标本身含凭据的极端情况由纵深检测兜底。
func TestDestructiveEvidenceDefenseCatchesCredentialsInsideTargets(t *testing.T) {
	for target, secret := range map[string]string{
		"https://admin:S3cretUserinfo@host.invalid/x": "S3cretUserinfo",
		"/srv/sk-AbCdEf1234567890AbCdEf12":            "AbCdEf1234567890",
		"/srv/pypi-AgEIcHlwaS5vcmcCJDabcdefghijklmn":  "AgEIcHlwaS5v",
		"/srv/LTAI5tAbCdEfGhIjKlMnOp":                 "LTAI5tAbCd",
		"/srv/zhang.san@corp.example.invalid/x":       "zhang.san",
	} {
		segment := agentguard.EvidenceSegment{Words: []agentguard.EvidenceWord{
			{Kind: agentguard.EvidenceArg, Text: "rm"}, {Kind: agentguard.EvidenceArg, Text: "-rf"},
			{Kind: agentguard.EvidenceArg, Text: target, Target: true},
		}}
		if got := renderEvidenceSegment(segment, 0); strings.Contains(got, secret) || !strings.HasPrefix(got, "rm -rf ") {
			t.Errorf("%s -> %q", target, got)
		}
	}
}

func TestDestructiveEvidenceDecodesEncodedCommand(t *testing.T) {
	encode := func(script string) string {
		units := utf16.Encode([]rune(script))
		raw := make([]byte, 0, len(units)*2)
		for _, unit := range units {
			raw = append(raw, byte(unit), byte(unit>>8))
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	words := func(option, value string) agentguard.EvidenceSegment {
		return agentguard.EvidenceSegment{Lexical: true, Words: []agentguard.EvidenceWord{
			{Kind: agentguard.EvidenceArg, Text: "powershell"}, {Kind: agentguard.EvidenceArg, Text: option}, {Kind: agentguard.EvidenceArg, Text: value},
			{Kind: agentguard.EvidenceRedirectOp, Text: ">"}, {Kind: agentguard.EvidenceRedirectTarget, Text: "out.txt"},
		}}
	}
	// 解码出的 ? 编码成 base64 后含 /，旧规则的高熵兜底会放过它。
	encoded := encode("$p='S3cretEnc?'; Remove-Item C:\\data -Recurse")
	for _, option := range []string{"-e", "-ec", "-enc", "-EncodedCommand"} {
		got := renderEvidenceSegment(words(option, encoded), 0)
		want := "powershell -EncodedCommand <已解码：Remove-Item C:\\data -Recurse> > out.txt"
		if got != want {
			t.Errorf("%s: %q want %q", option, got, want)
		}
	}
	if got := renderEvidenceSegment(words("-ec", "!!!not-base64!!!"), 0); got != "powershell -EncodedCommand … > out.txt" {
		t.Errorf("undecodable value must be hidden: %q", got)
	}
}

func TestDestructiveEvidenceSQLSkeleton(t *testing.T) {
	for statement, want := range map[string]string{
		"UPDATE users SET password = crypt('S3cret', gen_salt('bf'))": "UPDATE users SET password = crypt(?, gen_salt(?))",
		"UPDATE users SET password=md5('S3cret')":                     "UPDATE users SET password=md5(?)",
		`UPDATE users SET "password" = 'S3cret'`:                      `UPDATE users SET "password" = ?`,
		"UPDATE users SET `password` = 'S3cret'":                      "UPDATE users SET `password` = ?",
		`UPDATE users SET passwd = "S3cret"`:                          "UPDATE users SET passwd = ?",
		"ALTER ROLE root PASSWORD $$S3cret$$":                         "ALTER ROLE root PASSWORD ?",
		"ALTER ROLE r PASSWORD $tag$S3cret$tag$ LOGIN":                "ALTER ROLE r PASSWORD ? LOGIN",
		"DELETE FROM users -- password S3cret\n":                      "DELETE FROM users",
		"/* token=S3cret */ DELETE FROM sessions":                     "DELETE FROM sessions",
		"DROP USER 'bob'@'%'":                                         "DROP USER ?@?",
		"DELETE FROM t WHERE id = 42 AND name = 'a''b'":               "DELETE FROM t WHERE id = ? AND name = ?",
		"SELECT * FROM mysql.user WHERE x = $1":                       "SELECT * FROM mysql.user WHERE x = $1",
		"UPDATE users SET password_hash = '$2b$12$S3cretabcdefgh'":    "UPDATE users SET password_hash = ?",
		"DELETE\n  FROM   t":                                          "DELETE FROM t",
	} {
		statement = strings.ReplaceAll(statement, "\\n", "\n")
		got := renderEvidenceSegment(agentguard.EvidenceSegment{SQL: statement}, 0)
		if got != want {
			t.Errorf("%q -> %q want %q", statement, got, want)
		}
	}
}

func TestNonDestructiveEvidenceKeepsTheNormalizedTarget(t *testing.T) {
	tc := ToolCall{Function: ToolCallFunc{Name: "Read", Arguments: `{"file_path":"~/.ssh/id_rsa"}`}}
	decision := agentguard.Decision{RiskCategory: "credential_access", NormalizedTarget: "~/.ssh/id_rsa"}
	if got := agentGuardSecurityFinding(tc, decision, 0).RedactedEvidence; got != "~/.ssh/id_rsa" {
		t.Fatalf("evidence=%q", got)
	}
}

func mustJSONString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// 子命令词只对已知有子命令的可执行文件显示；其它可执行文件后的位置参数一律写 …，口令不会被当成子命令。
func TestDestructiveEvidenceSubcommandsOnlyForKnownExecutables(t *testing.T) {
	render := func(command string) string {
		args := map[string]any{"command": command}
		segments := agentguard.ParsedEvidenceSegments(agentguard.DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: args})
		rendered := make([]string, 0, len(segments))
		for _, segment := range segments {
			rendered = append(rendered, renderEvidenceSegment(segment, 0))
		}
		return strings.Join(rendered, " ; ")
	}
	for command, want := range map[string]string{
		"htpasswd -b file user secretpw":        "htpasswd -b …",
		"mytool secretpw delete":                "mytool …",
		"./deploy.sh prodpass wipe":             "./deploy.sh …",
		"echo hunter > out.txt":                 "echo … > out.txt",
		"net user bob secretpw":                 "net …",
		"git push -f origin main":               "git push -f …",
		"GIT.EXE push --force":                  "GIT.EXE push --force",
		"/usr/bin/terraform destroy":            "/usr/bin/terraform destroy",
		"docker compose down -v":                "docker compose down -v",
		"docker-compose down":                   "docker-compose down",
		"docker --tlsverify rm -f c":            "docker --tlsverify rm -f …",
		"kubectl --namespace prod delete pod x": "kubectl --namespace … delete pod …",
		"kubectl --token secretpw delete pod x": "kubectl --token … delete pod …",
		"kubectl delete Prod9 pod":              "kubectl delete …",
		"git remote add origin-1 url x y":       "git remote add …",
		"aws s3 rm s3://b --recursive":          "aws s3 rm … --recursive",
		"docker --password hunter rm -f c":      "docker --password … rm -f …",
	} {
		if got := render(command); got != want {
			t.Errorf("%q -> %q want %q", command, got, want)
		}
	}
}

// 骨架对抗与可读性：K 组是骨架规则的对抗写法，V 组是管理员日常会看到的破坏性命令，要求读得懂。
// 检测缺口（nohup/time/exec 包装、不带 --recursive 的 aws s3 rm、zfs destroy 等）和构造写法分析器不判破坏性，没有触发段。
var evidenceSkeletonNoTrigger = map[string]bool{
	"K003": true,
	"K004": true,
	"K007": true,
	"K015": true,
	"K017": true,
	"K018": true,
	"K020": true,
	"K025": true,
	"K030": true,
	"V025": true,
	"V028": true,
	"V031": true,
	"V034": true,
	"V038": true,
	"V040": true,
	"V045": true,
	// 2.9.22：SQL 解析失败（美元引号里的口令）改为兜底防护项 agent.parse_rejected，不再按“删除与破坏”出触发段。
	"K054": true,
	"K061": true,
	"K062": true,
	"K072": true,
	"K073": true,
}

// 已知局限，不阻塞：
//   - 单横线选项总长不超过 3 个字符时整体原样显示（-pa 会露出 1 个字符）。
var evidenceSkeletonKnownLimitations = map[string]string{}

func TestDestructiveAlertEvidenceSkeletonTable(t *testing.T) {
	runEvidenceProbeTable(t, "testdata/destructive_evidence_skeleton.json", 138, evidenceSkeletonNoTrigger, nil, evidenceSkeletonKnownLimitations)
}

func TestDestructiveEvidenceReadableToolOptions(t *testing.T) {
	render := func(tool, command string) string {
		args := map[string]any{"command": command}
		segments := agentguard.ParsedEvidenceSegments(agentguard.DestructiveInput{ToolName: tool, ToolType: "shell", Arguments: args})
		rendered := make([]string, 0, len(segments))
		for _, segment := range segments {
			rendered = append(rendered, renderEvidenceSegment(segment, 0))
		}
		return strings.Join(rendered, " ; ")
	}
	for _, c := range []struct{ tool, command, want string }{
		// find 的谓词与值原样，-exec 之后的命令写 …
		{"Bash", `find /data/logs -name '*.log' -mtime +7 -type f -delete`, `find … -name '*.log' -mtime +7 -type f -delete`},
		{"Bash", `find . -maxdepth 2 -size +1M -exec rm -f {} \;`, `find … -maxdepth 2 -size +1M -exec … ;`},
		{"Bash", `find . -empty -execdir shred -u {} +`, `find … -empty -execdir … +`},
		// terraform：-auto-approve、-target=、-var-file= 原样，-var 的值写 …
		{"Bash", `terraform destroy -auto-approve -target=aws_instance.web -var-file=prod.tfvars -var token=x`, `terraform destroy -auto-approve -target=aws_instance.web -var-file=prod.tfvars -v… …`},
		{"Bash", `tofu apply -auto-approve`, `tofu apply -auto-approve`},
		// git clean 的短选项簇原样；-e 带值（排除模式），值写 …，不能当成第二个子命令
		{"Bash", `git clean -fdx`, `git clean -fdx`},
		{"Bash", `git clean -fdx -e keep`, `git clean -fdx -e …`},
		{"Bash", `git clean -fdxe keep`, `git clean -fdxe …`},
		{"Bash", `git clean -e keep -fdx`, `git clean -e … -fdx`},
		{"Bash", `git push -fu origin main`, `git push -fu …`},
	} {
		if got := render(c.tool, c.command); got != c.want {
			t.Errorf("%q -> %q want %q", c.command, got, c.want)
		}
	}
}

// 路径段里的纯数字文件名、目录名多是时间戳或编号，13–19 位的长数字不按银行卡遮；
// 手机号、身份证号形态在路径里照样遮，路径之外的长数字也照样遮。
func TestDestructiveEvidenceKeepsNumericPathSegments(t *testing.T) {
	for command, want := range map[string]string{
		`rm -f /var/log/app/1731484800123`:  "删除文件：rm -f /var/log/app/1731484800123",
		`rm -rf 1731484800123456/`:          "删除文件：rm -rf 1731484800123456/",
		`rm -rf /data/runs/1731484800123/x`: "删除文件：rm -rf /data/runs/1731484800123/x",
	} {
		if got := destructiveEvidenceFor("Bash", `{"command":`+mustJSONString(command)+`}`, "filesystem_delete"); got != want {
			t.Errorf("%s: %q want %q", command, got, want)
		}
	}
	for command, secret := range map[string]string{
		`rm -rf /data/user/13812345678`:        "13812345678",
		`rm -rf /archive/110101199003071234/x`: "110101199003071234",
		`rm -rf /archive/11010119900307123X`:   "11010119900307123X",
	} {
		got := destructiveEvidenceFor("Bash", `{"command":`+mustJSONString(command)+`}`, "filesystem_delete")
		if strings.Contains(got, secret) || !strings.Contains(got, "<redacted:digits>") {
			t.Errorf("%s: personal number must stay redacted, got %q", command, got)
		}
	}
	segment := agentguard.EvidenceSegment{Words: []agentguard.EvidenceWord{
		{Kind: agentguard.EvidenceArg, Text: "rm"}, {Kind: agentguard.EvidenceArg, Text: "6222021234567890123", Target: true},
	}}
	if got := renderEvidenceSegment(segment, 0); got != "rm <redacted:digits>" {
		t.Errorf("a long number outside a path stays redacted, got %q", got)
	}
}

func TestDestructiveEvidenceShowsTargetsAfterOptions(t *testing.T) {
	for _, c := range []struct{ name, arguments, want string }{
		{"Bash", `{"command":"dd if=/dev/zero of=/dev/sdb bs=1M count=100"}`, "破坏块设备：dd if=… of=/dev/sdb bs=… count=…"},
		{"Bash", `{"command":"wipefs -a /dev/sdb"}`, "破坏块设备：wipefs -a /dev/sdb"},
		{"Bash", `{"command":"shred -u /etc/app/secret.key"}`, "删除文件：shred -u /etc/app/secret.key"},
		{"Bash", `{"command":"parted -s /dev/sdb mklabel gpt"}`, "破坏块设备：parted -s /dev/sdb …"},
		{"Bash", `{"command":"rmdir -p /data/a/b"}`, "删除文件：rmdir -p /data/a/b"},
		{"powershell", `{"command":"Remove-Item -Path C:\\data -Recurse -Force"}`, `删除文件：Remove-Item -Path C:\data -Recurse -Force`},
		{"powershell", `{"command":"Remove-Item -LiteralPath C:\\data -Recurse"}`, `删除文件：Remove-Item -LiteralPath C:\data -Recurse`},
		{"cmd", `{"command":"rd /s /q \\\\10.0.0.5\\share\\x"}`, `删除文件：rd /s /q \\10.0.0.5\share\x`},
		// 斜杠开关先于目标判断，带冒号的整体按选项处理，值写 …。
		{"cmd", `{"command":"del /f /q C:\\data\\* /p:Secret1"}`, `删除文件：del /f /q C:\data\* /p:…`},
		// 凭据类选项后面的值不显示，即使分析器把它当目标；-id/-name/-file/-path 结尾的不算凭据。
		{"Bash", `{"command":"rm -rf /opt/app --token S3cretT90"}`, "删除文件：rm -rf /opt/app --token …"},
		{"Bash", `{"command":"rm -rf /data/x?token=hunter2pw"}`, "删除文件：rm -rf /data/x?token=***"},
	} {
		if got := destructiveEvidenceFor(c.name, c.arguments, "filesystem_delete"); got != c.want {
			t.Errorf("%s %s: %q want %q", c.name, c.arguments, got, c.want)
		}
	}
	for option, want := range map[string]bool{
		"--secret-id": false, "--token-file": false, "--key-name": false, "--role-arn": false, "--output-path": false,
		"--token": true, "--password": true, "-Credential": true, "-Path": false, "-LiteralPath": false, "-Destination": false,
	} {
		if got := evidenceCredentialOption(option); got != want {
			t.Errorf("%s credential=%v want %v", option, got, want)
		}
	}
	// 按可执行文件区分的短选项：已知工具只隐藏它自己的口令选项，破坏性工具一律显示目标。
	for _, c := range []struct {
		exe, option string
		want        bool
	}{
		{"mysql", "-p", false}, {"mysql", "-e", true}, {"curl", "-u", false}, {"curl", "-o", true},
		{"wipefs", "-a", true}, {"shred", "-u", true}, {"parted", "-s", true}, {"unknowntool", "-p", false}, {"unknowntool", "-x", true},
	} {
		if got := evidenceValueMayShow(c.exe, c.option, "/x"); got != c.want {
			t.Errorf("%s %s show=%v want %v", c.exe, c.option, got, c.want)
		}
	}
}

func TestDestructiveEvidenceSQLDollarQuoteTagsMayContainDigits(t *testing.T) {
	for statement, want := range map[string]string{
		"UPDATE users SET password = $a1$S3cret$a1$":  "UPDATE users SET password = ?",
		"UPDATE users SET pwd = $A1$S3cret$A1$":       "UPDATE users SET pwd = ?",
		"UPDATE users SET col = $tag_x$S3cret$tag_x$": "UPDATE users SET col = ?",
		"UPDATE users SET pwd = $1":                   "UPDATE users SET pwd = $1",
	} {
		if got := renderEvidenceSegment(agentguard.EvidenceSegment{SQL: statement}, 0); got != want {
			t.Errorf("%q -> %q want %q", statement, got, want)
		}
	}
}

// 阻断与确认事件（tool_attempt_blocked）的证据与告警同源：工具名 · 子类中文：命令骨架。
func TestToolAttemptBlockedEvidenceIsTheCommandSkeleton(t *testing.T) {
	for command, want := range map[string]string{
		"rm -rf /srv/sandbox-target":              "shell_command · 删除文件：rm -rf /srv/sandbox-target",
		"DB_PASSWORD=S3cretPw rm -rf /srv/target": "shell_command · 删除文件：DB_PASSWORD=… rm -rf /srv/target",
	} {
		h, _ := newDestructiveChatTestHandler(t, "light", "block")
		var blocked []SecurityFinding
		h.auditWriter = &MockAuditWriter{OnSecurityEvent: func(_ string, findings []SecurityFinding) {
			for _, finding := range findings {
				if finding.Type == "tool_attempt_blocked" {
					blocked = append(blocked, finding)
				}
			}
		}}
		envelope := &modelrouter.RequestEnvelope{RequestID: "req-block-evidence", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
		call := ToolCall{ID: "call-delete", Type: "function", Function: ToolCallFunc{Name: "shell_command", Arguments: `{"command":` + mustJSONString(command) + `}`}}
		if _, _, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", call)); err != nil {
			t.Fatal(err)
		}
		if len(blocked) != 1 || blocked[0].RedactedEvidence != want {
			t.Errorf("%q: blocked=%+v want evidence %q", command, blocked, want)
		}
		if strings.Contains(blocked[0].RedactedEvidence, "S3cretPw") || strings.Contains(blocked[0].RedactedEvidence, "-targets") {
			t.Errorf("block evidence leaks or keeps the internal code: %q", blocked[0].RedactedEvidence)
		}
	}
	// 拿不到触发段时写“工具名 · 子类中文（N 个目标）”。
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, destructiveDecision("filesystem_delete"))
	if operation.Detail != "Bash · 删除文件（1 个目标）" {
		t.Errorf("detail=%q", operation.Detail)
	}
}
