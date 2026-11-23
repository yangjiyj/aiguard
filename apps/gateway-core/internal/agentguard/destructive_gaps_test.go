package agentguard

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// 2.9.17 审查对抗测试发现的检测缺口。sub 为空表示必须不报（无类别、无兜底）；
// targets 不为 nil 时断言证据里被标为目标的词（按出现顺序）；risk 不为空时断言级别。
type destructiveGapCase struct {
	name    string
	tool    string
	args    map[string]any
	sub     string
	risk    string
	targets []string
}

func gapCmd(command string) map[string]any { return map[string]any{"command": command} }

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func evidenceTargetWords(analysis DestructiveAnalysis) []string {
	var targets []string
	for _, segment := range analysis.EvidenceSegments {
		for _, word := range segment.Words {
			if word.Target {
				targets = append(targets, word.Text)
			}
		}
	}
	return targets
}

func runDestructiveGapCases(t *testing.T, cases []destructiveGapCase) {
	t.Helper()
	for _, c := range cases {
		tool := c.tool
		if tool == "" {
			tool = "Bash"
		}
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: tool, ToolType: "shell", Arguments: c.args})
		if tool == "run_sql" {
			got = AnalyzeDestructiveOperation(DestructiveInput{ToolName: tool, Arguments: c.args})
		}
		if c.sub == "" {
			if got.Category != "" || got.ParseRejected {
				t.Errorf("%s: must stay quiet: %+v", c.name, got)
			}
			continue
		}
		if got.Subcategory != c.sub || got.ParseRejected {
			t.Errorf("%s: want %s, got %s/%s parseRejected=%v reason=%s", c.name, c.sub, got.Category, got.Subcategory, got.ParseRejected, got.Reason)
			continue
		}
		if c.risk != "" && got.RiskLevel != c.risk {
			t.Errorf("%s: want risk %s, got %s", c.name, c.risk, got.RiskLevel)
		}
		if c.targets != nil {
			if marked := evidenceTargetWords(got); !reflect.DeepEqual(marked, c.targets) {
				t.Errorf("%s: want targets %q, got %q (summary %s)", c.name, c.targets, marked, got.TargetSummary)
			}
		}
		if len(got.EvidenceSegments) == 0 {
			t.Errorf("%s: no trigger segment: %+v", c.name, got)
		}
	}
}

func TestDestructiveGapSudoAndEnvWrappers(t *testing.T) {
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "sudo -u", args: gapCmd(`sudo -u root rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo -S 管道", args: gapCmd(`echo 'pw' | sudo -S rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo -S here-string", args: gapCmd(`sudo -S rm -rf /opt/app <<< 'pw'`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo -E", args: gapCmd(`sudo -E rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo --", args: gapCmd(`sudo -- rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo 短选项簇带值", args: gapCmd(`sudo -Su root rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo -u 连写", args: gapCmd(`sudo -uroot rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo --user=", args: gapCmd(`sudo --user=root rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo 赋值", args: gapCmd(`sudo PASS=x rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo -u env", args: gapCmd(`sudo -u x env A=hunter2pw rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "env -i", args: gapCmd(`env -i PATH=/bin PASS=hunter2pw rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "env -u 带值", args: gapCmd(`env -u HOME rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "env 变量名", args: gapCmd(`env hunter2pw=1 rm -rf /opt/app`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "env git push -f", args: gapCmd(`env GH_TOKEN=x git push -f origin main`), sub: "vcs_destroy"},
		{name: "sudo sh -c", args: gapCmd(`sudo sh -c 'rm -rf /opt/app'`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "sudo -u bash -c", args: gapCmd(`sudo -u root bash -c "rm -rf /opt/app"`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "env bash -c", args: gapCmd(`env FOO=1 bash -c 'rm -rf /opt/app'`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "bash -c 带变量", args: gapCmd(`bash -c "rm -rf /opt/app $Y"`), sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "bash -c 变量目标", args: gapCmd(`bash -c "rm -rf $DIR"`), sub: "filesystem_delete"},
		// 包装后仍按非执行选项与非法写法处理
		{name: "sudo dry-run", args: gapCmd(`sudo -u root kubectl delete ns prod --dry-run=client`)},
		{name: "sudo 非法写法", args: gapCmd(`sudo hunter2pw rm -rf /opt/app`)},
		{name: "sudo -l", args: gapCmd(`sudo -l`)},
		{name: "env 只打印", args: gapCmd(`env | grep PATH`)},
	})
}

func TestDestructiveGapArgvShapes(t *testing.T) {
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "argv env rm", tool: "exec", args: map[string]any{"argv": []any{"env", "DB_PASSWORD=S3cret T68", "rm", "-rf", "/opt/app"}}, sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "argv sudo env rm", tool: "exec", args: map[string]any{"argv": []any{"sudo", "env", "A=x horsepw", "rm", "-rf", "/opt/app"}}, sub: "filesystem_delete", targets: []string{"/opt/app"}},
		{name: "command 数组 env git push -f", tool: "shell", args: map[string]any{"command": []any{"env", "GH_TOKEN=S3cret R55", "git", "push", "-f", "origin", "main"}}, sub: "vcs_destroy"},
		{name: "command 数组 sudo 赋值", tool: "shell", args: map[string]any{"command": []any{"sudo", "PASS=correct horsepw", "rm", "-rf", "/opt/app"}}, sub: "filesystem_delete", targets: []string{"/opt/app"}},
		// 元素含空格时整体是一个目标，不被拆开
		{name: "command 数组含空格目标", tool: "shell", args: map[string]any{"command": []any{"rm", "-rf", "/opt/My Dir"}}, sub: "filesystem_delete", targets: []string{"/opt/My Dir"}},
		{name: "command 数组 kubectl --token 值含空格", tool: "shell", args: map[string]any{"command": []any{"kubectl", "--token", "correct horsepw", "delete", "ns", "prod"}}, sub: "cluster_destroy", targets: []string{"prod"}},
	})
}

func TestDestructiveGapDatabaseCommandLines(t *testing.T) {
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "mysql -e", args: gapCmd(`mysql -uroot -pS3cret db -e 'drop table t'`), sub: "database_destroy"},
		{name: "mysql --password 空格", args: gapCmd(`mysql -u root --password S3cret -e 'DROP DATABASE x'`), sub: "database_destroy"},
		{name: "mysql -Ne 簇", args: gapCmd(`mysql -Ne 'DROP DATABASE x'`), sub: "database_destroy"},
		{name: "mysql --execute=", args: gapCmd(`mysql --execute='DROP DATABASE x'`), sub: "database_destroy"},
		{name: "mysql -p 交互", args: gapCmd(`mysql -h 10.0.0.5 -P 3306 -uroot -p -e 'drop database x'`), sub: "database_destroy"},
		{name: "mariadb -e 无条件删除", args: gapCmd(`mariadb -e 'DELETE FROM users'`), sub: "database_unscoped_mutation"},
		{name: "psql -c", args: gapCmd(`PGPASSWORD=x psql -h 10.0.0.5 -c "drop table t"`), sub: "database_destroy"},
		{name: "psql --command=", args: gapCmd(`psql --command="DELETE FROM users"`), sub: "database_unscoped_mutation"},
		{name: "dropdb", args: gapCmd(`PGPASSWORD=x dropdb -h 10.0.0.5 -U postgres prod`), sub: "database_destroy", targets: []string{"prod"}},
		{name: "mysqladmin drop", args: gapCmd(`mysqladmin -uroot -p'S3cret T15' -f drop prod`), sub: "database_destroy", targets: []string{"drop", "prod"}},
		{name: "redis-cli FLUSHALL", args: gapCmd(`redis-cli -h 10.0.0.6 --pass S3cret FLUSHALL`), sub: "database_destroy", targets: []string{"FLUSHALL"}},
		{name: "redis-cli flushdb", args: gapCmd(`redis-cli -n 3 flushdb async`), sub: "database_destroy", targets: []string{"flushdb"}},
		{name: "redis-cli -u", args: gapCmd(`redis-cli -u redis://:S3cret@10.0.0.6:6379 FLUSHALL`), sub: "database_destroy", targets: []string{"FLUSHALL"}},
		{name: "mysql 查询", args: gapCmd(`mysql -uroot -p -e 'select 1'`)},
		{name: "psql 有条件删除", args: gapCmd(`psql -c "DELETE FROM users WHERE id = 1"`)},
		{name: "mysqladmin status", args: gapCmd(`mysqladmin -uroot status`)},
		{name: "redis-cli get", args: gapCmd(`redis-cli -h 10.0.0.6 get flushall`)},
		{name: "redis-cli info", args: gapCmd(`redis-cli -n 0 info`)},
	})
}

func TestDestructiveGapSQLTautologyWhere(t *testing.T) {
	sql := func(query string) map[string]any { return map[string]any{"query": query} }
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "WHERE 1=1", tool: "run_sql", args: sql(`UPDATE settings SET v='S3cret' WHERE 1=1`), sub: "database_unscoped_mutation"},
		{name: "OR 1=1", tool: "run_sql", args: sql(`DELETE FROM users WHERE password = 'S3cret' OR 1=1`), sub: "database_unscoped_mutation"},
		{name: "括号", tool: "run_sql", args: sql(`DELETE FROM t WHERE (1=1)`), sub: "database_unscoped_mutation"},
		{name: "TRUE", tool: "run_sql", args: sql(`DELETE FROM t WHERE TRUE`), sub: "database_unscoped_mutation"},
		{name: "1 = 1 带空格", tool: "run_sql", args: sql(`UPDATE t SET a = 2 WHERE 1 = 1 RETURNING *`), sub: "database_unscoped_mutation"},
		{name: "1=1 AND 条件", tool: "run_sql", args: sql(`DELETE FROM t WHERE 1=1 AND id = 5`)},
		{name: "子查询里的 1=1", tool: "run_sql", args: sql(`DELETE FROM t WHERE id IN (SELECT id FROM x WHERE 1=1)`)},
		{name: "普通条件", tool: "run_sql", args: sql(`UPDATE t SET a = 1 WHERE id = 1`)},
		{name: "恒假", tool: "run_sql", args: sql(`DELETE FROM t WHERE 1 = 2`)},
	})
}

func TestDestructiveGapCloudStorageAndRsync(t *testing.T) {
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "aws s3 rm --recursive", args: gapCmd(`aws s3 rm s3://b --recursive`), sub: "cloud_resource_destroy", risk: "critical", targets: []string{"s3://b"}},
		{name: "aws 全局选项", args: gapCmd(`aws --profile prod s3 rm s3://b/x --recursive`), sub: "cloud_resource_destroy", targets: []string{"s3://b/x"}},
		{name: "az delete-batch", args: gapCmd(`az storage blob delete-batch --account-name a --account-key K3y== --source c`), sub: "cloud_resource_destroy", risk: "critical"},
		{name: "az container delete", args: gapCmd(`az storage container delete --name c --connection-string "AccountKey=K3y=="`), sub: "cloud_resource_destroy", risk: "critical"},
		{name: "az blob delete", args: gapCmd(`az storage blob delete --container-name c --name x.txt`), sub: "cloud_resource_destroy", risk: "high"},
		{name: "ossutil rm -r", args: gapCmd(`ossutil rm oss://b/x -r -f -i LTAI5tAbCdEfGhIjKlMn -k S3cret`), sub: "cloud_resource_destroy", risk: "critical", targets: []string{"oss://b/x"}},
		{name: "ossutil rm 单个", args: gapCmd(`ossutil rm oss://b/x`), sub: "cloud_resource_destroy", risk: "high", targets: []string{"oss://b/x"}},
		{name: "rclone purge", args: gapCmd(`rclone purge s3:bucket --s3-secret-access-key S3cret`), sub: "cloud_resource_destroy", risk: "critical", targets: []string{"s3:bucket"}},
		{name: "s3cmd del --recursive", args: gapCmd(`s3cmd del --recursive --force s3://b --secret_key=S3cret`), sub: "cloud_resource_destroy", risk: "critical", targets: []string{"s3://b"}},
		{name: "rsync --delete 远端", args: gapCmd(`rsync -a --delete -e "sshpass -p S3cret ssh" src/ root@10.0.0.5:/dst/`), sub: "filesystem_delete", targets: []string{"root@10.0.0.5:/dst/"}},
		{name: "rsync --delete-after", args: gapCmd(`rsync -av --delete-after --exclude .git src/ /srv/www/`), sub: "filesystem_delete", targets: []string{"/srv/www/"}},
		{name: "aws s3 rm 单个对象", args: gapCmd(`aws s3 rm s3://b/x`)},
		{name: "aws s3 ls", args: gapCmd(`aws s3 ls s3://b --recursive`)},
		{name: "az blob list", args: gapCmd(`az storage blob list --container-name c`)},
		{name: "ossutil ls", args: gapCmd(`ossutil ls oss://b`)},
		{name: "rclone ls", args: gapCmd(`rclone ls s3:bucket`)},
		{name: "s3cmd ls", args: gapCmd(`s3cmd ls s3://b`)},
		{name: "rsync 不删除", args: gapCmd(`rsync -a src/ dst/`)},
	})
}

func TestDestructiveGapPowerShellForms(t *testing.T) {
	plain := encodePowerShell(`$p='S3cretT52'; Remove-Item C:\data -Recurse -Force`)
	withParens := encodePowerShell(`Remove-Item \\srv\share\x -Recurse -Credential (New-Object PSCredential('corp\bob', (ConvertTo-SecureString 'S3cretT51' -AsPlainText -Force)))`)
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "字符串 -EncodedCommand", args: gapCmd(`powershell -EncodedCommand ` + plain), sub: "filesystem_delete"},
		{name: "字符串 -ec", args: gapCmd(`powershell -ec ` + plain), sub: "filesystem_delete"},
		{name: "字符串 -e 带括号", args: gapCmd(`powershell -e ` + withParens), sub: "filesystem_delete"},
		{name: "字符串 -Command", args: gapCmd(`pwsh -NoProfile -Command "Remove-Item C:\data -Recurse"`), sub: "filesystem_delete", targets: []string{`C:\data`}},
		{name: "数组 -Command 带括号", tool: "shell", args: map[string]any{"command": []any{"powershell", "-Command", `Remove-Item \\srv\share\x -Recurse -Credential (New-Object PSCredential('corp\bob', (ConvertTo-SecureString 'S3cretT51' -AsPlainText -Force)))`}}, sub: "filesystem_delete", targets: []string{`\srv\share\x`}},
		{name: "数组 -EncodedCommand 带括号", tool: "shell", args: map[string]any{"command": []any{"powershell", "-EncodedCommand", withParens}}, sub: "filesystem_delete", targets: []string{`\srv\share\x`}},
		{name: "Set-Content", tool: "powershell", args: gapCmd(`Set-Content -Path C:\app\secret.txt -Value 'S3cretR52'`), sub: "filesystem_overwrite", targets: []string{`C:\app\secret.txt`}},
		{name: "Set-Content 位置参数", tool: "powershell", args: gapCmd(`Set-Content C:\app\x.txt 'S3cret'`), sub: "filesystem_overwrite", targets: []string{`C:\app\x.txt`}},
		// Remove-Item 第二个位置参数是 -Filter，不是目标
		{name: "Remove-Item 多余位置参数", tool: "powershell", args: gapCmd(`Remove-Item C:\x -Recurse -Force -ErrorAction SilentlyContinue S3cretP10`), sub: "filesystem_delete", targets: []string{`C:\x`}},
		{name: "字符串 -EncodedCommand 非破坏", args: gapCmd(`powershell -enc ` + encodePowerShell(`Get-ChildItem C:\data`))},
		{name: "字符串 -Command 非破坏", args: gapCmd(`powershell -Command "Get-ChildItem C:\data"`)},
	})
	// 字符串形态的 EncodedCommand 证据仍是外层这条命令，渲染时再解码。
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: gapCmd(`powershell -ec ` + plain)})
	if len(got.EvidenceSegments) != 1 || len(got.EvidenceSegments[0].Words) == 0 || got.EvidenceSegments[0].Words[0].Text != "powershell" {
		t.Errorf("encoded command evidence must be the outer call: %+v", got.EvidenceSegments)
	}
}

func TestDestructiveGapRedirectAndWrites(t *testing.T) {
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: ">& 文件", args: gapCmd(`echo x >& /etc/app/conf`), sub: "filesystem_overwrite", risk: "critical"},
		{name: ">& 普通文件", args: gapCmd(`make >& build.log`), sub: "filesystem_overwrite", risk: "medium"},
		{name: "tee -a 敏感", args: gapCmd(`echo k | tee -a ~/.ssh/authorized_keys`), sub: "filesystem_overwrite", risk: "high", targets: []string{"~/.ssh/authorized_keys"}},
		{name: "sudo tee", args: gapCmd(`echo x | sudo tee /etc/hosts`), sub: "filesystem_overwrite", risk: "critical", targets: []string{"/etc/hosts"}},
		{name: "cp 覆盖 /etc", args: gapCmd(`cp /dev/null /etc/app/config.yaml`), sub: "filesystem_overwrite", risk: "critical", targets: []string{"/etc/app/config.yaml"}},
		{name: "cp -t", args: gapCmd(`cp -t /etc/cron.d job`), sub: "filesystem_overwrite", risk: "critical", targets: []string{"/etc/cron.d"}},
		{name: "install", args: gapCmd(`install -m 644 build/unit.service /etc/systemd/system/x.service`), sub: "filesystem_overwrite", risk: "critical", targets: []string{"/etc/systemd/system/x.service"}},
		{name: "sed -i /etc", args: gapCmd(`sed -i 's/a/b/' /etc/ssh/sshd_config`), sub: "filesystem_overwrite", risk: "critical", targets: []string{"/etc/ssh/sshd_config"}},
		{name: "sed -i.bak -e", args: gapCmd(`sed -i.bak -e 's/a/b/' ~/.bashrc`), sub: "filesystem_overwrite", risk: "high", targets: []string{"~/.bashrc"}},
		{name: "sed -ri", args: gapCmd(`sed -ri 's/a/b/' /etc/hosts`), sub: "filesystem_overwrite", risk: "critical", targets: []string{"/etc/hosts"}},
		// 不敏感的写法不报（现场降噪口径）
		{name: ">&2", args: gapCmd(`echo done >&2`)},
		{name: "1>&2", args: gapCmd(`echo done 1>&2`)},
		{name: ">&-", args: gapCmd(`echo done >&-`)},
		{name: ">& /dev/null", args: gapCmd(`make >& /dev/null`)},
		{name: ">& 变量", args: gapCmd(`echo x >&"$FD"`)},
		{name: "tee 普通文件", args: gapCmd(`npm test 2>&1 | tee test.log`)},
		{name: "tee -a 构建日志", args: gapCmd(`make 2>&1 | tee -a build.log`)},
		{name: "cp 普通文件", args: gapCmd(`cp a.txt b.txt`)},
		{name: "cp 到 /tmp", args: gapCmd(`cp -r src/ /tmp/x`)},
		{name: "install -d", args: gapCmd(`install -d /etc/foo`)},
		{name: "sed -i 源码", args: gapCmd(`sed -i 's/a/b/' src/main.go`)},
		{name: "sed 不带 -i", args: gapCmd(`sed 's/a/b/' /etc/hosts`)},
		{name: "sed -n", args: gapCmd(`sed -n '1p' /etc/passwd`)},
		{name: "sed -ie 是后缀", args: gapCmd(`sed -ie 's/a/b/' src/main.go`)},
	})
}

func TestDestructiveGapOptionValuesAreNotTargets(t *testing.T) {
	runDestructiveGapCases(t, []destructiveGapCase{
		{name: "helm --kube-token", args: gapCmd(`helm uninstall app --kube-token S3cretT25`), sub: "cluster_destroy", targets: []string{"app"}},
		{name: "helm --kube-as-user", args: gapCmd(`helm uninstall app -n prod --kube-as-user admin`), sub: "cluster_destroy", targets: []string{"app"}},
		{name: "kubectl --token 在后", args: gapCmd(`kubectl delete pod x --token S3cret`), sub: "cluster_destroy", targets: []string{"x"}},
		{name: "kubectl -o", args: gapCmd(`kubectl delete pod x -o name`), sub: "cluster_destroy", targets: []string{"x"}},
	})
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: gapCmd(`helm uninstall app --kube-token S3cretT25`)})
	if !strings.HasSuffix(got.TargetSummary, ":1-targets") {
		t.Errorf("option value counted as a target: %s", got.TargetSummary)
	}
}

// 现场降噪放行不能因为本轮补漏重新告警。
func TestDestructiveGapKeepsSiteNoiseSuppression(t *testing.T) {
	for _, command := range []string{
		`make >> build.log 2>&1`,
		`npm test > /dev/null 2>&1`,
		`echo x >> "$GITHUB_OUTPUT"`,
		`go test ./... 2>&1 | tee -a "$LOG"`,
		`sudo apt-get install -y jq > /dev/null 2>&1`,
		`env CI=1 npm test >> build.log 2>&1`,
		`sudo -u app make >> build.log 2>&1`,
		`mysql -e 'select 1' > /dev/null 2>&1`,
		`rsync -a src/ /srv/www/ >> deploy.log 2>&1`,
	} {
		got := productionShell(command)
		if got.Category != "" || got.ParseRejected {
			t.Errorf("%q must stay quiet: %+v", command, got)
		}
	}
}
