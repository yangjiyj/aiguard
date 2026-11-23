package handler

// M-1 守卫：users.role 的全部写入口清单。
// 角色一变，旧会话必须失效（否则带着新角色的权限，既不用重新登录也不用重新过 TOTP）。会话在 Redis，无法进数据库事务，
// 所以每个写入口都必须有人负责吊销。新增任何会写 users.role 的 SQL 都会让本测试失败，迫使作者回答「谁吊销会话」。
// 中间件另有「会话角色必须等于当前角色」的兜底（auth.Middleware），覆盖吊销失败、竞态与绕过本清单的写入。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var usersRoleWriters = map[string]string{
	// UserRepository.Update 写 role：handler.UpdateUser 在任何角色变化前已清空 req.Role（走事务化路径），
	// 其余调用方只有 bootstrap.ApplyAdminConfig（roleChanged 时吊销会话）。
	"internal/repository/users.go": "Update：UpdateUser 角色变化走事务化路径；bootstrap.ApplyAdminConfig 在角色改变时 DeleteByUser。Delete：DeleteUser 随后 DeleteByUser",
	// identitybinding 的 UpdatePlatformRole：TransitionTenantRole（applyManagedUserTenantRoleTransition 先吊销、后再吊销）
	// 与 TransitionPlatformRole（applyManagedUserRoleTransition 先吊销）。
	"internal/repository/user_identity_links.go": "UpdatePlatformRole：两条转换路径都先 DeleteByUser",
	// emergency 降级时的本地身份写入，位于 applyManagedUserRoleTransition 内，先 DeleteByUser。
	"internal/localidentity/provisioner.go": "emergency 降级：applyManagedUserRoleTransition 先 DeleteByUser",
}

// 能改变已存在账号角色的 SQL 写法，识别分两步（RE2 没有前瞻，单条正则无法把「SET 列表」与后面的 WHERE role = ... 区分开）：
//
//  1. usersWriteHead 找到每条「写 users 表」的语句头，并取出语句头之后到本条 SQL 字符串结束的文本：
//     - UPDATE [ONLY] [schema.]users ... SET            → SET 列表紧跟其后；
//     - INSERT INTO [schema.]users ... ON CONFLICT ... DO UPDATE SET   → upsert，冲突时改已有账号；
//     - MERGE INTO [schema.]users ... WHEN MATCHED ... UPDATE SET      → 同上。
//     纯 INSERT 与 ON CONFLICT DO NOTHING 只创建新账号，没有旧会话可失效，所以不算。
//  2. setListWritesRole 只在 SET 列表内找 role = ...：列表到 WHERE / FROM / RETURNING（或语句结束）为止，
//     之后的 "AND role = 'viewer'" 只是过滤条件，不是写入。role 可带表别名和引号（u.role、"role"）。
//
// 语句范围限定在同一个反引号字符串里，不会把相邻两条语句串起来。变更时同步更新 TestUsersRoleWriteStatementRegexp 的正反例。
var usersWriteHead = regexp.MustCompile("(?is)" +
	"(?:\\bUPDATE\\s+(?:ONLY\\s+)?(?:\\w+\\.)?\"?users\"?\\b[^`;]{0,300}?\\bSET\\b" +
	"|\\bINSERT\\s+INTO\\s+(?:\\w+\\.)?\"?users\"?\\b[^`;]{0,900}?\\bON\\s+CONFLICT\\b[^`;]{0,600}?\\bDO\\s+UPDATE\\s+SET\\b" +
	"|\\bMERGE\\s+INTO\\s+(?:\\w+\\.)?\"?users\"?\\b[^`;]{0,900}?\\bWHEN\\s+MATCHED\\b[^`;]{0,600}?\\bUPDATE\\s+SET\\b)")

var (
	setListEnd  = regexp.MustCompile("(?is)\\b(?:WHERE|FROM|RETURNING)\\b|`|;")
	setRoleAssn = regexp.MustCompile("(?is)(?:^|[\\s,])(?:\\w+\\.)?\"?role\"?\\s*=")
)

func writesUsersRole(src string) bool {
	for _, loc := range usersWriteHead.FindAllStringIndex(src, -1) {
		rest := src[loc[1]:]
		if end := setListEnd.FindStringIndex(rest); end != nil {
			rest = rest[:end[0]]
		}
		if setRoleAssn.MatchString(rest) {
			return true
		}
	}
	return false
}

func TestEveryUsersRoleWriterHasASessionRevocationOwner(t *testing.T) {
	found := map[string]bool{}
	for _, root := range []string{"..", "../../cmd"} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			if writesUsersRole(string(raw)) {
				// 规整为 internal/... 或 cmd/...：Walk 的根是 ".." 与 "../../cmd"。
				rel := filepath.ToSlash(filepath.Clean(path))
				switch {
				case strings.HasPrefix(rel, "../"):
					rel = "internal/" + strings.TrimPrefix(rel, "../")
				}
				found[rel] = true
			}
			return nil
		})
	}
	var unexpected []string
	for f := range found {
		if _, ok := usersRoleWriters[f]; !ok {
			unexpected = append(unexpected, f)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("发现未登记的 users.role 写入口 %v：角色一变旧会话必须失效，请确认由谁调用 SessionRepo.DeleteByUser，并登记到 usersRoleWriters", unexpected)
	}
	for f := range usersRoleWriters {
		if !found[f] {
			t.Fatalf("清单里的 %s 已不再写 users.role，请同步清理清单（避免清单失真）", f)
		}
	}
}

// 正则本身的自测：该抓的写法必须抓到，不该抓的（只读、纯新建、无关表）不能误报。
// 新增写法被漏掉时，先在这里加一条失败用例，再改正则。
func TestUsersRoleWriteStatementRegexp(t *testing.T) {
	mustMatch := map[string]string{
		"原写法":                 "UPDATE users SET role = $1 WHERE id = $2",
		"role 不在 SET 的第一列":    "UPDATE users SET status = $1, updated_at = NOW(), role = $2 WHERE id = $3",
		"换行与缩进":               "UPDATE users\n\t\tSET password_hash=$3,\n\t\t    role=$4,department_id=$5\n\tWHERE id=$2",
		"大小写混用":               "update Users set Role='viewer' where id=$1",
		"带 schema":            "UPDATE public.users SET role = $1 WHERE id = $2",
		"UPDATE ONLY":         "UPDATE ONLY users SET role = $1",
		"带别名":                 "UPDATE users AS u SET role = $1 FROM x WHERE u.id = x.id",
		"SET 里用别名限定 role":     "UPDATE users u SET u.role = $1 WHERE u.id = $2",
		"引号标识符":               "UPDATE \"users\" SET \"role\" = $1",
		"upsert 用 EXCLUDED":   "INSERT INTO users (id, tenant_id, username, role) VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id, username) DO UPDATE SET role = EXCLUDED.role",
		"upsert 多列 role 在后":   "INSERT INTO users (id, username, role, status) VALUES ($1,$2,$3,$4)\n ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = NOW(), role = $3",
		"upsert 带 schema 与换行": "INSERT INTO public.users (id, role)\nVALUES ($1, $2)\nON CONFLICT ON CONSTRAINT users_pkey\nDO UPDATE\nSET role = EXCLUDED.role",
		"upsert 条件冲突目标":       "INSERT INTO users (id, role) VALUES ($1,$2) ON CONFLICT (id) WHERE deleted_at IS NULL DO UPDATE SET role=$2",
		"MERGE":               "MERGE INTO users u USING src s ON u.id = s.id WHEN MATCHED THEN UPDATE SET role = s.role",
	}
	for name, sql := range mustMatch {
		if !writesUsersRole("`" + sql + "`") {
			t.Errorf("应当被识别为 users.role 写入口但没有：%s\n  %s", name, sql)
		}
	}
	mustNotMatch := map[string]string{
		"只读":                    "SELECT id, role FROM users WHERE role = 'admin'",
		"纯新建（无旧会话可失效）":          "INSERT INTO users (id, tenant_id, username, role) VALUES ($1,$2,$3,$4)",
		"冲突时什么也不做":              "INSERT INTO users (id, username, role) VALUES ($1,$2,$3) ON CONFLICT (tenant_id, username) DO NOTHING",
		"upsert 但不改 role":       "INSERT INTO users (id, username, role) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()",
		"UPDATE users 不改 role":  "UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2 AND role = 'viewer'",
		"其他表的 role":             "UPDATE team_members SET role = $1 WHERE team_id = $2",
		"其他表 upsert role":       "INSERT INTO project_users (project_id, user_id, role) VALUES ($1,$2,$3) ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role",
		"表名包含 users 前缀":         "UPDATE users_archive SET role = $1",
		"user_identity_links 表": "UPDATE user_identity_links SET role = $1",
		"两条语句相邻不得串联":            "UPDATE users SET status = $1 WHERE id = $2` + `UPDATE other SET role = $1",
	}
	for name, sql := range mustNotMatch {
		if writesUsersRole("`" + sql + "`") {
			t.Errorf("不应被识别为 users.role 写入口却被识别了：%s\n  %s", name, sql)
		}
	}
}
