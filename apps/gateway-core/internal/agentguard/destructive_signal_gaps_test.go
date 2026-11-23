package agentguard

import "testing"

// 解析不完整时的信号闸门与本轮补上的检测用同一套词：数据库命令行、云存储删除、rsync --delete、Set-Content、-ec。
func TestDestructiveSignalCoversCommandLineGaps(t *testing.T) {
	for _, command := range []string{
		`mysql -uroot -e "drop table t`,
		`psql -c "TRUNCATE users`,
		`dropdb prod "`,
		`mysqladmin -f drop prod "`,
		`redis-cli -h 10.0.0.6 FLUSHALL "`,
		`aws s3 rm s3://b --recursive "`,
		`az storage blob delete-batch --source c "`,
		`ossutil rm oss://b/x -r "`,
		`rclone purge remote:bucket "`,
		`s3cmd del s3://b/x "`,
		`rsync -a --delete src/ /srv/www/ "`,
		`Set-Content -Path C:\app\x.txt -Value "`,
		`powershell -ec AAAA "`,
	} {
		if !DestructiveSignalPresent(command) {
			t.Errorf("command must keep the fail-safe in force: %s", command)
		}
	}
	for _, command := range []string{
		`mysql -uroot -e "select 1`,
		`aws s3 ls s3://b --recursive "`,
		`rsync -a src/ /srv/www/ "`,
		`redis-cli -h 10.0.0.6 info "`,
		`az storage blob list --container-name c "`,
	} {
		if DestructiveSignalPresent(command) {
			t.Errorf("read-only command must carry no destructive signal: %s", command)
		}
	}
}
