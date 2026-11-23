package handler

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 文件内容 DLP 全局开关在 system_settings 中的键（与控制平面/security-engine/gateway 对齐）。
const (
	fileContentDLPSettingKey        = "file_content_dlp_enabled"
	securityAuditOnlySettingKey     = "security_audit_only"
	securityExecutionModeSettingKey = "security_execution_mode"
)

// fileDLPSettingTTL 是正向代理侧动态开关只读缓存的 TTL：每次请求只读一次快照，
// 既避免每请求查库的开销，也保证 UI 保存后短时间内热生效（与 spec 一致）。
const fileDLPSettingTTL = 10 * time.Second

// settingQueryTimeout 限制一次 system_settings 查库的时长：数据库卡住时按回落规则取值，
// 不把请求一起卡住（2.9.22 复审补充）。
const settingQueryTimeout = 2 * time.Second

// 控制平面库查询失败时默认关闭（节省资源 + fail-safe），不抛错。
var errDBUnavailable = errors.New("file dlp system_settings query unavailable")

// rowScanner 抽象 *pgx.Row 的 Scan，便于单测注入。
type rowScanner interface {
	Scan(dest ...any) error
}

// querierFunc 把一次 QueryRow 查询抽象成函数，使读取器可在单测中替换、
// 又能在生产用 *pgxpool.Pool（其 QueryRow 返回 *pgx.Row，与接口返回类型不兼容，故用函数适配）。
type querierFunc func(ctx context.Context, sql string, args ...any) rowScanner

// FileDLPSettingReader 读取文件内容 DLP 全局动态开关。Enabled 永不 panic、永不返回 error：
// 缺失/非法/查询失败一律默认关闭（节省资源、fail-safe），与 spec 的安全默认一致。
type FileDLPSettingReader interface {
	Enabled(ctx context.Context) bool
}

// DBFileDLPSettingReader 从 system_settings 读 file_content_dlp_enabled，带 fileDLPSettingTTL 只读缓存。
type DBFileDLPSettingReader struct {
	query              querierFunc
	ttl                time.Duration
	fallback           FileDLPSettingReader
	settingKey         string
	deploymentTrueWins bool
	// invalidValue 是库里存了非 true/false 的值时的取值，与控制面一致：执行模式旧键按记录
	// （resolveSecurityExecutionMode 的安全默认），其他开关按关闭（签名投影 semanticBool）。
	invalidValue bool

	// queryTimeout 为 0 时取 settingQueryTimeout（测试可调短）。
	queryTimeout time.Duration

	mu         sync.Mutex
	refreshing bool
	// refreshDone 在一次查库结束时关闭；首次读取在途时其他调用等它，不再各自查库。
	refreshDone chan struct{}
	value       bool
	hasValue    bool
	managed     bool
	lastReadOK  bool
	expireAt    time.Time
}

// NewDBFileDLPSettingReader 构造一个默认 10 秒 TTL 的 DB 读取器。
// query 必须返回 Scan 行为兼容 pgx.Row 的扫描器。
func NewDBFileDLPSettingReader(query querierFunc) FileDLPSettingReader {
	return newDBBooleanSettingReader(query, fileContentDLPSettingKey, EnvFileDLPSettingReader{})
}

// NewDBFileDLPSettingReaderFromPool 用 *pgxpool.Pool 构造默认 10 秒 TTL 的 DB 读取器，
// 内部适配 pgx.Row 到 rowScanner，供 cmd/server 注入。
func NewDBFileDLPSettingReaderFromPool(db *pgxpool.Pool) FileDLPSettingReader {
	if db == nil {
		return nil
	}
	return NewDBFileDLPSettingReader(func(ctx context.Context, sql string, args ...any) rowScanner {
		return db.QueryRow(ctx, sql, args...)
	})
}

// NewDBSecurityAuditOnlySettingReader 从同一配置源读取审计模式，避免代理和安全引擎
// 对同一请求作出相反的中断决定。
func NewDBSecurityAuditOnlySettingReader(query querierFunc) FileDLPSettingReader {
	reader := newDBBooleanSettingReader(query, securityAuditOnlySettingKey, staticBooleanSettingReader(true))
	reader.deploymentTrueWins = true
	reader.invalidValue = true
	return reader
}

func NewDBSecurityAuditOnlySettingReaderFromPool(db *pgxpool.Pool) FileDLPSettingReader {
	if db == nil {
		return nil
	}
	return NewDBSecurityAuditOnlySettingReader(func(ctx context.Context, sql string, args ...any) rowScanner {
		return db.QueryRow(ctx, sql, args...)
	})
}

func newDBBooleanSettingReader(query querierFunc, settingKey string, fallback FileDLPSettingReader) *DBFileDLPSettingReader {
	return &DBFileDLPSettingReader{
		query: query, ttl: fileDLPSettingTTL, settingKey: settingKey, fallback: fallback,
	}
}

func (r *DBFileDLPSettingReader) Enabled(ctx context.Context) bool {
	if r == nil || r.query == nil {
		return r != nil && r.deploymentTrueWins && (EnvSecurityAuditOnlySettingReader{}).Enabled(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	for {
		// 缓存未过期，或别的调用正在刷新而手里已有值：直接用缓存，不等查库。
		if time.Now().Before(r.expireAt) || (r.refreshing && r.hasValue) {
			value := r.effectiveValue(ctx)
			r.mu.Unlock()
			return value
		}
		if !r.refreshing {
			break
		}
		// 首次读取在途：等它读完（2.9.22 代码质量审查）。调用方先取消时按回落规则取值。
		done := r.refreshDone
		r.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			r.mu.Lock()
			value := r.provisionalValue(ctx)
			r.mu.Unlock()
			return value
		}
		r.mu.Lock()
	}
	r.refreshing = true
	done := make(chan struct{})
	r.refreshDone = done
	r.mu.Unlock()

	// 在锁外查库，带超时；查完再加锁写回（2.9.22 复审补充）。
	raw, mode, legacyExists, err := r.read(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	defer close(done)
	r.refreshing = false
	validRead := err == nil || errors.Is(err, pgx.ErrNoRows)
	if err == nil {
		r.managed = mode == "record" || mode == "protect"
		if r.managed {
			r.value = mode == "record"
			r.hasValue = true
		} else if !legacyExists {
			r.value = r.fallbackEnabled(ctx)
			r.hasValue = true
		} else {
			// 与控制面同一解析：只认 true/false（不分大小写、可带空白），空值当没存，
			// 其他取值按 invalidValue（仍记为未核实）。
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "true":
				r.value = true
			case "false":
				r.value = false
			case "":
				r.value = r.fallbackEnabled(ctx)
			default:
				validRead = false
				r.value = r.invalidValue
			}
			r.hasValue = true
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		r.managed = false
		r.value = r.fallbackEnabled(ctx)
		r.hasValue = true
	} else if !r.hasValue {
		r.value = r.fallbackEnabled(ctx)
	}
	r.lastReadOK = validRead

	r.expireAt = time.Now().Add(r.ttl)
	return r.effectiveValue(ctx)
}

// provisionalValue 在没能等到查库结果时取值（调用方持 mu）：读到过就用缓存，否则按回落规则。
func (r *DBFileDLPSettingReader) provisionalValue(ctx context.Context) bool {
	if r.hasValue {
		return r.effectiveValue(ctx)
	}
	if r.deploymentTrueWins && (EnvSecurityAuditOnlySettingReader{}).Enabled(ctx) {
		return true
	}
	return r.fallbackEnabled(ctx)
}

// read 查一次 system_settings，不持锁，超过 queryTimeout（缺省 2 秒）即放弃。查库与调用方的
// 取消脱钩：客户端断开不让读取失败，结果照样写进缓存供后续请求使用。
func (r *DBFileDLPSettingReader) read(ctx context.Context) (raw, mode string, legacyExists bool, err error) {
	timeout := r.queryTimeout
	if timeout <= 0 {
		timeout = settingQueryTimeout
	}
	queryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	settingKey := r.settingKey
	if settingKey == "" {
		settingKey = fileContentDLPSettingKey
	}
	legacyExists = true
	if r.deploymentTrueWins {
		// Read both keys in one statement so a mode transition cannot combine
		// values from different database snapshots. Missing values remain empty.
		err = r.query(queryCtx,
			`SELECT COALESCE(MAX(value) FILTER (WHERE key = $1), ''),
			        COALESCE(MAX(value) FILTER (WHERE key = $2), ''),
			        COUNT(*) FILTER (WHERE key = $1) > 0
			 FROM system_settings WHERE key IN ($1, $2)`,
			settingKey, securityExecutionModeSettingKey,
		).Scan(&raw, &mode, &legacyExists)
	} else {
		err = r.query(queryCtx, `SELECT value FROM system_settings WHERE key = $1`, settingKey).Scan(&raw)
	}
	return raw, mode, legacyExists, err
}

func (r *DBFileDLPSettingReader) runtimeValueVerified() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasValue && r.lastReadOK && time.Now().Before(r.expireAt)
}

// effectiveValue is called under mu; mode and value are one cached snapshot.
// 2.9.22（设计 D7）：部署变量 SECURITY_AUDIT_ONLY=true 只在库里没有显式执行模式时作初值，
// 控制台显式选了 record/protect 就按控制台。
func (r *DBFileDLPSettingReader) effectiveValue(ctx context.Context) bool {
	if r.deploymentTrueWins && !r.managed && (EnvSecurityAuditOnlySettingReader{}).Enabled(ctx) {
		return true
	}
	return r.value
}

// deploymentInitialValueActive 报告当前是否由部署变量作初值决定为记录模式（态势上报用）。
func (r *DBFileDLPSettingReader) deploymentInitialValueActive(ctx context.Context) bool {
	if r == nil || !r.deploymentTrueWins || !(EnvSecurityAuditOnlySettingReader{}).Enabled(ctx) {
		return false
	}
	r.Enabled(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.managed
}

// securityExecutionMode identifies the database reader that resolves explicit
// mode and the legacy deployment ceiling together, including on cache hits.
func (r *DBFileDLPSettingReader) securityExecutionMode(ctx context.Context) bool {
	if r == nil || !r.deploymentTrueWins {
		return (EnvSecurityAuditOnlySettingReader{}).Enabled(ctx) || r.Enabled(ctx)
	}
	return r.Enabled(ctx)
}

func (r *DBFileDLPSettingReader) fallbackEnabled(ctx context.Context) bool {
	if r.fallback == nil {
		return false
	}
	return r.fallback.Enabled(ctx)
}

// EnvFileDLPSettingReader 仅在 DB 不可用时作启动后备，默认关闭。
type staticBooleanSettingReader bool

func (r staticBooleanSettingReader) Enabled(context.Context) bool { return bool(r) }

type EnvFileDLPSettingReader struct{}

func (EnvFileDLPSettingReader) Enabled(context.Context) bool {
	switch strings.ToLower(strings.TrimSpace(fileContentDLPEnv())) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// EnvSecurityAuditOnlySettingReader 仅作为数据库不可用时的启动后备。
type EnvSecurityAuditOnlySettingReader struct{}

func (EnvSecurityAuditOnlySettingReader) Enabled(context.Context) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECURITY_AUDIT_ONLY"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// errNoRows 表示 system_settings 中缺失该键（默认关闭）。
var errNoRows = pgx.ErrNoRows
