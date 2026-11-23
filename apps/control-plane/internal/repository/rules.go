package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRuleNotFound                       = errors.New("rule not found")
	ErrRuleSetNotFound                    = errors.New("rule set not found")
	ErrNoRuntimeRules                     = errors.New("no runtime rules")
	ErrManagedSecurityPolicyReadOnly      = errors.New("managed security policy is read-only through legacy rule APIs")
	ErrInvalidContentAuditException       = errors.New("invalid content audit exception")
	ErrContentAuditExceptionLimitExceeded = errors.New("content audit exception limit exceeded")
)

// RuntimeMatcher is the normalized matcher shape consumed by both the control
// plane compiler and the security engine. Exactly one field is populated,
// according to the rule's executable runtime type.
type RuntimeMatcher struct {
	Regex      string
	Keywords   []string
	FieldNames []string
}

// executableRulePredicateSQL is the database equivalent of
// NormalizeRuntimeMatcher. Keep the two in lockstep: only the three runtime
// types are executable, their matcher field must agree with the type, string
// values are trimmed, arrays must contain strings only, and at least one array
// element must remain non-blank after trimming.
const executableRulePredicateSQL = `(
	(r.rule_type = 'regex'
	 AND jsonb_typeof(r.match_config_json->'regex') = 'string'
	 AND (r.match_config_json->>'regex') ~ '[^[:space:]]')
	OR
	(r.rule_type = 'keyword'
	 AND jsonb_typeof(r.match_config_json->'keywords') = 'array'
	 AND NOT EXISTS (
	   SELECT 1
	   FROM jsonb_array_elements(CASE
	     WHEN jsonb_typeof(r.match_config_json->'keywords') = 'array'
	     THEN r.match_config_json->'keywords' ELSE '[]'::jsonb END) AS item
	   WHERE jsonb_typeof(item) <> 'string'
	 )
	 AND EXISTS (
	   SELECT 1
	   FROM jsonb_array_elements(CASE
	     WHEN jsonb_typeof(r.match_config_json->'keywords') = 'array'
	     THEN r.match_config_json->'keywords' ELSE '[]'::jsonb END) AS item
	   WHERE jsonb_typeof(item) = 'string' AND (item #>> '{}') ~ '[^[:space:]]'
	 ))
	OR
	(r.rule_type = 'field_name'
	 AND jsonb_typeof(r.match_config_json->'field_names') = 'array'
	 AND NOT EXISTS (
	   SELECT 1
	   FROM jsonb_array_elements(CASE
	     WHEN jsonb_typeof(r.match_config_json->'field_names') = 'array'
	     THEN r.match_config_json->'field_names' ELSE '[]'::jsonb END) AS item
	   WHERE jsonb_typeof(item) <> 'string'
	 )
	 AND EXISTS (
	   SELECT 1
	   FROM jsonb_array_elements(CASE
	     WHEN jsonb_typeof(r.match_config_json->'field_names') = 'array'
	     THEN r.match_config_json->'field_names' ELSE '[]'::jsonb END) AS item
	   WHERE jsonb_typeof(item) = 'string' AND (item #>> '{}') ~ '[^[:space:]]'
	 ))
)`

// RuleRepository handles rule database operations
type RuleRepository struct {
	db *pgxpool.Pool
}

// NewRuleRepository creates a new rule repository
func NewRuleRepository(db *pgxpool.Pool) *RuleRepository {
	return &RuleRepository{db: db}
}

// GetByID retrieves a rule by ID
func (r *RuleRepository) GetByID(ctx context.Context, tenantID, id string) (*Rule, error) {
	query := `
		SELECT r.id, COALESCE(r.policy_code, ''), r.rule_set_id, r.rule_type, r.name,
		       r.priority, r.severity, r.scope_json, r.match_config_json, r.action, r.enabled, r.description, r.created_at
		FROM rules r
		JOIN rule_sets rs ON rs.id = r.rule_set_id
		WHERE r.id = $1 AND rs.tenant_id = $2
		  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
	`

	row := r.db.QueryRow(ctx, query, id, tenantID)
	var rule Rule
	err := row.Scan(
		&rule.ID,
		&rule.PolicyCode,
		&rule.RuleSetID,
		&rule.RuleType,
		&rule.Name,
		&rule.Priority,
		&rule.Severity,
		&rule.ScopeJSON,
		&rule.MatchConfigJSON,
		&rule.Action,
		&rule.Enabled,
		&rule.Description,
		&rule.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}
	return &rule, nil
}

// Create inserts a new rule
func (r *RuleRepository) Create(ctx context.Context, tenantID string, rule *Rule) error {
	if rule.ID == "" {
		rule.ID = "rule_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, scope_json, match_config_json, action, enabled, description)
		SELECT $1, rs.id, $3, $4, $5, $6, $7, $8, $9, $10, $11
		FROM rule_sets rs
		WHERE rs.id = $2 AND rs.tenant_id = $12
	`

	result, err := r.db.Exec(ctx, query,
		rule.ID,
		rule.RuleSetID,
		rule.RuleType,
		rule.Name,
		rule.Priority,
		rule.Severity,
		rule.ScopeJSON,
		rule.MatchConfigJSON,
		rule.Action,
		rule.Enabled,
		rule.Description,
		tenantID,
	)

	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrRuleSetNotFound
	}

	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}
	return nil
}

// Update updates rule fields by ID. Only non-zero/non-nil fields are applied.
func (r *RuleRepository) Update(ctx context.Context, tenantID, id string, action, severity string, priority int, enabled bool, name string) error {
	query := `
		UPDATE rules AS r
		SET action = $1, severity = $2, priority = $3, enabled = $4, name = $5
		FROM rule_sets AS rs
		WHERE r.id = $6 AND rs.id = r.rule_set_id AND rs.tenant_id = $7
		  AND NULLIF(BTRIM(r.policy_code), '') IS NULL
		  AND ` + ruleNotDeletedSQL + `
	`

	result, err := r.db.Exec(ctx, query, action, severity, priority, enabled, name, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	if result.RowsAffected() == 0 {
		return r.legacyRuleMutationError(ctx, tenantID, id, ErrRuleNotFound)
	}
	return nil
}

// Delete removes a rule by ID
func (r *RuleRepository) Delete(ctx context.Context, tenantID, id string) error {
	query := `
		DELETE FROM rules AS r
		USING rule_sets AS rs
		WHERE r.id = $1 AND rs.id = r.rule_set_id AND rs.tenant_id = $2
		  AND NULLIF(BTRIM(r.policy_code), '') IS NULL
		  AND ` + ruleNotDeletedSQL + `
	`

	result, err := r.db.Exec(ctx, query, id, tenantID)
	if err != nil {
		// security_events.rule_id references this row: a rule that has ever fired cannot be
		// removed without rewriting audit history, so it is retired instead of failing with a 500.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return r.retireLegacyRule(ctx, tenantID, id)
		}
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	if result.RowsAffected() == 0 {
		return r.legacyRuleMutationError(ctx, tenantID, id, ErrRuleNotFound)
	}
	return nil
}

func (r *RuleRepository) retireLegacyRule(ctx context.Context, tenantID, id string) error {
	var ownedID string
	err := r.db.QueryRow(ctx, `
		SELECT r.id FROM rules r JOIN rule_sets rs ON rs.id=r.rule_set_id
		WHERE r.id=$1 AND rs.tenant_id=$2 AND NULLIF(BTRIM(r.policy_code), '') IS NULL
		  AND `+ruleNotDeletedSQL, id, tenantID,
	).Scan(&ownedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return r.legacyRuleMutationError(ctx, tenantID, id, ErrRuleNotFound)
	}
	if err != nil {
		return fmt.Errorf("verify legacy rule retirement target: %w", err)
	}
	return tombstoneRule(ctx, r.db, ownedID)
}

// BatchUpdateByType updates runtime-capable rules of a given type in a tenant-owned rule set.
// Catalog-only rows without a supported matcher remain read-only and are never auto-created.
func (r *RuleRepository) BatchUpdateByType(ctx context.Context, tenantID, ruleSetID, ruleType string, enabled *bool, action *string, replyMessage *string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin batch update rules: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var ownedID string
	if err := tx.QueryRow(ctx, `
		SELECT id FROM rule_sets WHERE id=$1 AND tenant_id=$2 FOR UPDATE`,
		ruleSetID, tenantID,
	).Scan(&ownedID); errors.Is(err, pgx.ErrNoRows) {
		return ErrRuleSetNotFound
	} else if err != nil {
		return fmt.Errorf("lock rule set for batch update: %w", err)
	}
	var hasManagedPolicy bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
		  SELECT 1 FROM rules
		  WHERE rule_set_id=$1 AND rule_type=$2
		    AND NULLIF(BTRIM(policy_code), '') IS NOT NULL
		    AND NOT jsonb_exists(COALESCE(scope_json,'{}'::jsonb),'deleted_at')
		)`, ruleSetID, ruleType,
	).Scan(&hasManagedPolicy); err != nil {
		return fmt.Errorf("check managed policies for batch update: %w", err)
	}
	if hasManagedPolicy {
		return ErrManagedSecurityPolicyReadOnly
	}
	query := `
		UPDATE rules AS r
		SET enabled = COALESCE($3, enabled),
		    action = COALESCE($4, action),
		    match_config_json = CASE WHEN $5::text IS NOT NULL THEN
		        jsonb_set(COALESCE(match_config_json, '{}'::jsonb), '{reply_message}', to_jsonb($5::text))
		    ELSE match_config_json END
		FROM rule_sets AS rs
		WHERE r.rule_set_id = $1 AND r.rule_type = $2
		  AND rs.id = r.rule_set_id AND rs.tenant_id = $6
		  AND NULLIF(BTRIM(r.policy_code), '') IS NULL
		  AND ` + ruleNotDeletedSQL + `
		  AND ` + executableRulePredicateSQL

	result, err := tx.Exec(ctx, query, ruleSetID, ruleType, enabled, action, replyMessage, tenantID)
	if err != nil {
		return fmt.Errorf("failed to batch update rules: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNoRuntimeRules
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit batch update rules: %w", err)
	}
	return nil
}

// ToggleEnabled atomically flips a tenant-owned executable rule. The UPDATE
// changes enabled only, so concurrent toggles cannot lose one another or
// overwrite policy fields read from a stale snapshot.
func (r *RuleRepository) ToggleEnabled(ctx context.Context, tenantID, id string) (bool, error) {
	query := `
		UPDATE rules AS r
		SET enabled = NOT r.enabled
		FROM rule_sets AS rs
		WHERE r.id = $1 AND rs.id = r.rule_set_id AND rs.tenant_id = $2
		  AND NULLIF(BTRIM(r.policy_code), '') IS NULL
		  AND ` + ruleNotDeletedSQL + `
		  AND ` + executableRulePredicateSQL + `
		RETURNING r.enabled
	`

	var enabled bool
	if err := r.db.QueryRow(ctx, query, id, tenantID).Scan(&enabled); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("failed to toggle rule: %w", err)
		}

		var owned bool
		if verifyErr := r.db.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM rules r
				JOIN rule_sets rs ON rs.id = r.rule_set_id
				WHERE r.id = $1 AND rs.tenant_id = $2
				  AND `+ruleNotDeletedSQL+`
			)`, id, tenantID).Scan(&owned); verifyErr != nil {
			return false, fmt.Errorf("verify rule ownership: %w", verifyErr)
		}
		if !owned {
			return false, ErrRuleNotFound
		}
		if err := r.legacyRuleMutationError(ctx, tenantID, id, ErrNoRuntimeRules); err != nil {
			return false, err
		}
		return false, ErrNoRuntimeRules
	}
	return enabled, nil
}

// defaultSubRules defines all sub-rules per detector type with descriptions
var defaultSubRules = map[string][]struct {
	Name        string
	PolicyCode  string
	Severity    string
	Action      string
	Description string
}{
	"prompt_injection": {
		// Direct injection attacks
		{"经典注入指令检测", "builtin.prompt_injection.8894ce9a632bada9", "high", "block", "检测 'Ignore previous instructions'、'Disregard all above' 等经典越狱指令，识别直接覆写系统提示的攻击模式"},
		{"角色扮演注入检测", "builtin.prompt_injection.7396b867d7156f96", "high", "block", "检测通过虚构角色身份（如 'You are now in developer mode'）绕过安全限制的攻击"},
		{"特权提升检测", "builtin.prompt_injection.5e084cbc6cb3c32d", "high", "block", "检测伪装管理员、调试模式、特权用户等身份提升尝试"},
		{"Few-shot 攻击检测", "builtin.prompt_injection.344b93890cdccc3e", "medium", "block", "检测通过提供多个示例引导模型输出违规内容的攻击方式"},
		{"否定式注入", "builtin.prompt_injection.1ac9559c46501ff8", "high", "block", "检测 'Don't do X'、'Never refuse' 等否定式指令，识别限制规避"},
		{"假设场景绕过", "builtin.prompt_injection.fec82263fa576a55", "medium", "block", "检测 'Imagine a scenario where...'、'In a fictional world' 等假设性语境绕过"},
		{"对抗性后缀攻击", "builtin.prompt_injection.73644306e4dfbcf4", "high", "block", "检测特殊字符后缀攻击（如 '!?!?!?'），对抗模型的安全训练"},
		{"系统提示覆写检测", "builtin.prompt_injection.594c6d42965bb1d1", "high", "block", "检测 'You are no longer...'、'New instructions:' 等系统提示覆写尝试"},
		{"分隔符混淆攻击", "builtin.prompt_injection.d2484f0152f1f577", "high", "block", "检测利用特殊分隔符（如 '###'、'==='）分割上下文的注入攻击"},
		{"上下文截断攻击", "builtin.prompt_injection.ba9a8699a54af996", "medium", "block", "检测 '[END OF CONTEXT]' 等伪造上下文结束标记的攻击"},
		// Encoding & obfuscation
		{"Base64 编码注入", "builtin.prompt_injection.f4809d017dfbf3a6", "medium", "block", "检测 Base64 编码的恶意指令，识别通过编码绕过文本检测的攻击"},
		{"Base32/Base16 编码注入", "builtin.prompt_injection.9f67a6da54bce276", "medium", "block", "检测 Base32 和 Base16（Hex）编码的注入指令"},
		{"Hex 编码注入", "builtin.prompt_injection.ac6042efdf14b49c", "medium", "block", "检测十六进制编码（如 '0x48656c6c6f'）的恶意内容"},
		{"Unicode 编码绕过", "builtin.prompt_injection.8a4cfd4d54e80e99", "medium", "block", "检测 Unicode 转义序列（如 '\\u0048\\u0065'）编码的攻击内容"},
		{"URL 编码绕过", "builtin.prompt_injection.57767f0750a92dfa", "medium", "block", "检测 URL 编码（如 '%48%65%6c'）的注入指令"},
		{"双重编码检测", "builtin.prompt_injection.4fb2be0130d3f3f1", "medium", "block", "检测多重编码（Base64后再URL编码）的深度混淆攻击"},
		{"零宽字符注入", "builtin.prompt_injection.ba9bbb9f63e7b514", "medium", "block", "检测零宽空格（U+200B）、零宽连接符等不可见字符插入"},
		{"同形字符替换", "builtin.prompt_injection.3c2c8a296f39670e", "medium", "block", "检测利用视觉相似字符（如 Cyrillic 'а' 替代 Latin 'a'）的攻击"},
		{"自定义编码/莫尔斯电码", "builtin.prompt_injection.b167772e4c27e54b", "medium", "block", "检测非标准编码方式，包括莫尔斯电码、替换密码等"},
		{"二进制/八进制编码注入", "builtin.prompt_injection.5ab93c096487f735", "medium", "block", "检测二进制（'01001000'）或八进制编码的指令"},
		{"ROT13/Atbash 编码绕过", "builtin.prompt_injection.4b465e70a6377330", "medium", "block", "检测 ROT13、Atbash 等字母替换密码编码的内容"},
		{"Emoji 编码注入", "builtin.prompt_injection.467da79f0b886cd8", "medium", "block", "检测利用 Emoji 序列传递信息的隐写攻击"},
		{"ASCII 艺术注入", "builtin.prompt_injection.c2cc41c645d6e802", "medium", "block", "检测利用 ASCII 艺术图案隐藏指令的攻击"},
		// Semantic & social engineering
		{"逐步诱导检测", "builtin.prompt_injection.6e0c3ca0b2eaf8a8", "high", "block", "检测多轮对话中逐步增加敏感请求的诱导模式"},
		{"翻译绕过", "builtin.prompt_injection.752acd8e33f82f2d", "medium", "audit", "检测请求翻译敏感内容到其他语言的绕过尝试"},
		{"小语种注入", "builtin.prompt_injection.f45dc17b1e6725b7", "medium", "audit", "检测利用低资源语言（如威尔士语、斯瓦希里语）绕过安全检测"},
		{"混合语种绕过", "builtin.prompt_injection.cbadb8fba1cbd3ce", "medium", "block", "检测在请求中混合多种语言规避检测的攻击"},
		{"渐进式脱敏诱导", "builtin.prompt_injection.69e7baa759b6c503", "medium", "block", "检测逐步降低模型警惕性的多轮诱导攻击"},
		{"道德困境诱导", "builtin.prompt_injection.a74e7f1501822fc1", "medium", "block", "检测通过虚构道德困境迫使模型做出违规决策的攻击"},
		{"逻辑谜题绕过", "builtin.prompt_injection.8c29ec75bf9c8cc1", "medium", "block", "检测将违规请求包装为逻辑谜题或智力游戏的攻击"},
		{"对比示例攻击", "builtin.prompt_injection.af7e6ee3195516c6", "medium", "block", "检测 'What would happen if X vs Y' 对比式诱导"},
		{"情感操控诱导", "builtin.prompt_injection.b322a14e01c1d5d5", "medium", "block", "检测利用情感故事、悲伤叙述引发模型同情并绕过限制"},
		{"紧急语气绕过", "builtin.prompt_injection.b2a9904f92b79552", "medium", "block", "检测 'URGENT'、'Emergency'、'Time-sensitive' 等紧急语气的胁迫"},
		{"道德权威施压", "builtin.prompt_injection.4a2869c6bcc5351c", "medium", "block", "检测引用道德权威、伦理原则迫使模型妥协的攻击"},
		{"法律威胁诱导", "builtin.prompt_injection.5ce853ec8c7904ab", "high", "block", "检测声称法律后果、合规要求迫使模型配合的攻击"},
		{"虚假安全警报", "builtin.prompt_injection.ba1fbb4a4032dc78", "medium", "block", "检测伪造安全漏洞、紧急威胁迫使模型提供敏感信息的攻击"},
		{"技术支持冒充", "builtin.prompt_injection.d29c0062c05c6a04", "medium", "block", "检测冒充技术支持、系统管理员身份的欺骗"},
		{"协作借口绕过", "builtin.prompt_injection.13c78c8cb376da98", "medium", "block", "检测 'I'm working with...'、'We need this for...' 协作借口"},
		{"多轮铺垫攻击", "builtin.prompt_injection.c2bd08c27cf70ea1", "high", "block", "检测长时间多轮对话中建立信任后突然提出敏感请求的模式"},
		{"权威引用伪造", "builtin.prompt_injection.90324ca72fb4d87a", "high", "block", "检测伪造官方文档、权威机构声明迫使模型配合的攻击"},
		{"学术研究借口", "builtin.prompt_injection.51e37afc89cb1115", "medium", "block", "检测以学术研究、论文撰写为由请求敏感内容的攻击"},
		{"术语混淆绕过", "builtin.prompt_injection.c171230d59d1a27a", "medium", "block", "检测使用专业术语混淆违规内容真实意图的攻击"},
		// Structured injection
		{"伪代码注入", "builtin.prompt_injection.90eebdc9900c34be", "medium", "block", "检测利用伪代码、代码注释隐藏恶意指令的攻击"},
		{"JSON/XML 结构注入", "builtin.prompt_injection.7264c727a4fc2ed4", "high", "block", "检测利用 JSON、XML 数据结构注入恶意内容的攻击"},
		{"Markdown 渲染注入", "builtin.prompt_injection.75f29627a37e0d01", "medium", "block", "检测利用 Markdown 格式隐藏指令或触发异常渲染的攻击"},
		{"Payload 拆分注入", "builtin.prompt_injection.4326456f74d43796", "high", "block", "检测将攻击指令拆分到多个位置组合执行的攻击"},
		{"模板填充注入", "builtin.prompt_injection.bfbe6a1eccdb32ef", "medium", "block", "检测利用模板语法（如 '{{}}'）注入恶意内容的攻击"},
		{"排列组合注入", "builtin.prompt_injection.7730b3cbd5246f1f", "medium", "block", "检测通过生成大量排列组合文本绕过检测的攻击"},
		{"Token 走私攻击", "builtin.prompt_injection.f28adec4733f37d1", "high", "block", "检测利用特殊 Token 序列绕过模型解析的攻击"},
		{"多模态输入注入", "builtin.prompt_injection.15004e1e3fd53f86", "medium", "block", "检测在图像、音频等多模态输入中隐藏恶意指令的攻击"},
		{"GIF/图像隐写注入", "builtin.prompt_injection.839171ac2965425a", "high", "block", "检测 GIF 动画帧、图像像素中隐藏的恶意指令"},
	},
	"content_safety": {
		// Political security (TC260)
		{"领导人负面讨论", "builtin.content_safety.f1252b5fafaca83a", "critical", "block", "检测涉及国家领导人的负面评价、侮辱或不实信息，符合 TC260 政治安全要求"},
		{"敏感政治事件", "builtin.content_safety.d6d189ffdd19c725", "critical", "block", "检测敏感政治事件讨论，包括重大政策争议、政治动荡等话题"},
		{"领土主权检测", "builtin.content_safety.aeeb1eb209b9046e", "critical", "block", "检测涉及领土主权争议的不当表述，维护国家领土完整原则"},
		{"民族宗教问题", "builtin.content_safety.b0fa6eb641e7f1c5", "high", "block", "检测涉及民族、宗教的敏感内容，避免引发民族宗教矛盾"},
		{"历史虚无主义", "builtin.content_safety.295e1c9330cfd201", "high", "block", "检测歪曲历史、否定历史事实的历史虚无主义言论"},
		{"邪教宣传内容", "builtin.content_safety.430e892402c08738", "critical", "block", "检测邪教组织宣传、招募内容，符合反邪教法规要求"},
		{"恐怖主义宣传", "builtin.content_safety.3f07c132c798a867", "critical", "block", "检测恐怖主义思想传播、暴力极端主义宣传内容"},
		{"煽动颠覆内容", "builtin.content_safety.84b78c69bd854278", "critical", "block", "检测煽动颠覆国家政权、推翻社会主义制度的内容"},
		// Illegal & harmful
		{"色情低俗内容", "builtin.content_safety.58663e6bd52f1ade", "high", "block", "检测色情、低俗、性暗示内容，保护未成年人身心健康"},
		{"暴力恐怖内容", "builtin.content_safety.a33fdb67d98f1e9d", "critical", "block", "检测描述暴力恐怖行为、血腥场面的内容"},
		{"毒品制作指导", "builtin.content_safety.2e7c3d1811c916b4", "critical", "block", "检测毒品制作方法、使用指导等违法内容"},
		{"武器制作指导", "builtin.content_safety.2e163d09b9155752", "critical", "block", "检测武器、爆炸物制作方法的详细指导"},
		{"自杀方法指导", "builtin.content_safety.50e1338e3f0a2d02", "critical", "block", "检测自杀方法、方式的详细指导，防止生命伤害"},
		{"自残/自杀内容", "builtin.content_safety.8b77e51268536ced", "critical", "block", "检测鼓励、美化自残或自杀的内容"},
		{"人身攻击指导", "builtin.content_safety.94c8f6138ae0a180", "high", "block", "检测如何伤害他人的具体指导，包括物理和心理攻击"},
		{"人肉搜索指导", "builtin.content_safety.93a1f2312c974373", "critical", "block", "检测教唆进行人肉搜索、网络暴力攻击的指导内容"},
		{"性暴力内容", "builtin.content_safety.94cbba62575e32f9", "critical", "block", "检测性暴力、性侵害内容的描述"},
		{"虐待动物内容", "builtin.content_safety.4e2d6940ae0c8718", "high", "block", "检测虐待、伤害动物的指导或描述"},
		{"药品滥用指导", "builtin.content_safety.bb6ee23a359ce52e", "critical", "block", "检测处方药滥用、非法用药指导内容"},
		// Network security
		{"网络攻击教程", "builtin.content_safety.fc486a78d9176d14", "high", "block", "检测黑客技术、网络攻击方法的教程和指导"},
		{"违禁品检测", "builtin.content_safety.37e8337d76413856", "high", "block", "检测违禁物品交易、制作、获取的指导内容"},
		{"未成年人保护", "builtin.content_safety.972bcf8de3b4d32d", "high", "block", "检测涉及未成年人权益侵害的内容，符合未成年人保护法"},
		{"赌博/诈骗内容", "builtin.content_safety.3b524e3893a7da4f", "high", "block", "检测赌博方法、诈骗技术的指导和宣传"},
		// Other harmful
		{"敏感人物/组织", "builtin.content_safety.3cc66da68952eebe", "high", "audit", "检测涉及敏感人物、敏感组织的内容"},
		{"歧视内容", "builtin.content_safety.741b4225c2f0b108", "medium", "block", "检测种族、性别、年龄等歧视性言论"},
		{"骚扰/霸凌内容", "builtin.content_safety.dc547e0b41610cca", "medium", "block", "检测网络骚扰、霸凌行为的指导或描述"},
		{"辱骂脏话", "builtin.content_safety.ffbbdfb2e823022d", "medium", "block", "检测对人的辱骂、脏话与侮辱性称呼，覆盖谐音、拼音缩写、字间空格等变形；废物利用、垃圾分类等正常用语不会命中，引用或讨论某个脏话词不拦"},
		{"网络暴力内容", "builtin.content_safety.c529368da553e93d", "high", "block", "检测网络暴力攻击、群体霸凌的指导内容"},
		{"校园暴力内容", "builtin.content_safety.167af81998f1d9d8", "high", "block", "检测校园暴力、欺凌行为的指导或描述"},
		{"家庭暴力内容", "builtin.content_safety.e741adeb0f05ae95", "high", "block", "检测家庭暴力方法的指导或美化"},
		{"虚假信息/谣言", "builtin.content_safety.948316474cf587e1", "medium", "audit", "检测可能引发社会恐慌的虚假信息和谣言"},
		{"仇恨言论", "builtin.content_safety.130064bdc1ae51ab", "high", "block", "检测针对特定群体的仇恨言论和煽动性内容"},
		{"环境污染指导", "builtin.content_safety.66f2bb762e173339", "medium", "block", "检测环境污染、破坏生态环境的指导内容"},
		{"食品安全违规", "builtin.content_safety.9b130d27ba058baf", "medium", "block", "检测食品安全违规行为的指导或描述"},
		{"医疗欺诈内容", "builtin.content_safety.f658a2f524585da0", "high", "block", "检测医疗欺诈、虚假医疗宣传的内容"},
	},
	"agent_detect": {
		// Agent identification
		{"Claude Code 管控", "builtin.agent_detect.f93768ab6617606e", "low", "audit", "识别 Anthropic Claude Code CLI 客户端指纹，并按策略审计或阻断"},
		{"OpenAI Codex CLI 检测", "builtin.agent_detect.223c40ba05f83647", "low", "audit", "检测 OpenAI Codex CLI 特征：openai.com 引用、GPT-4 API 模式"},
		{"Cursor IDE 管控", "builtin.agent_detect.b620fc06d06c1fc7", "low", "audit", "识别 Cursor IDE 客户端指纹，并按策略审计或阻断"},
		{"Copilot Chat/CLI 检测", "builtin.agent_detect.53e522e6a7b8dac2", "medium", "audit", "检测 GitHub Copilot Chat 和 CLI 特征：github.com/copilot 引用"},
		{"GitHub Copilot 管控", "builtin.agent_detect.12438c4c568f8c24", "low", "audit", "识别 GitHub Copilot 客户端指纹，并按策略审计或阻断"},
		{"Amazon Q Developer 检测", "builtin.agent_detect.a5d24299196cf4f3", "low", "audit", "检测 Amazon Q Developer 特征：aws.amazon.com/q 引用"},
		{"Google Gemini Code Assist", "builtin.agent_detect.f539af0c43cb3787", "low", "audit", "检测 Google Gemini Code Assist 特征：gemini.google.com 引用"},
		{"Cline/Roo Code 管控", "builtin.agent_detect.60879276c451279a", "low", "audit", "识别 Cline/Roo Code 客户端指纹，并按策略审计或阻断"},
		{"Windsurf/Cascade 管控", "builtin.agent_detect.c1896e0995119428", "low", "audit", "识别 Windsurf/Cascade 客户端指纹，并按策略审计或阻断"},
		{"Continue.dev 管控", "builtin.agent_detect.1d449b7a84677bb2", "low", "audit", "识别 Continue.dev 客户端指纹，并按策略审计或阻断"},
		{"Aider 检测", "builtin.agent_detect.008356aa358e9978", "low", "audit", "检测 Aider CLI 特征：aider.chat 引用、git 操作模式"},
		{"Tabnine 检测", "builtin.agent_detect.6cada6a14d0a4263", "low", "audit", "检测 Tabnine IDE 插件特征：tabnine.com 引用"},
		{"Sourcegraph Cody 检测", "builtin.agent_detect.79ae5816a3bf3ee5", "low", "audit", "检测 Sourcegraph Cody 特征：sourcegraph.com/cody 引用"},
		{"Replit AI 检测", "builtin.agent_detect.3aa45df74b2de7a8", "low", "audit", "检测 Replit AI 特征：replit.com 引用、Replit 工作空间模式"},
		{"CodeRabbit 检测", "builtin.agent_detect.c1759598ed72a0d2", "low", "audit", "检测 CodeRabbit PR 审查工具特征：coderabbit.ai 引用"},
		{"LangChain/LlamaIndex SDK", "builtin.agent_detect.364d6d282e3fd912", "low", "audit", "检测 LangChain 和 LlamaIndex SDK 调用特征"},
		{"CrewAI/AutoGen 检测", "builtin.agent_detect.5a691bbd627d263a", "low", "audit", "检测 CrewAI 和 Microsoft AutoGen 多智能体框架特征"},
		{"Dify/Coze 平台检测", "builtin.agent_detect.6f490afdd7023369", "low", "audit", "检测 Dify 和 Coze 低代码平台特征：dify.ai、coze.cn 引用"},
		{"AutoGPT/BabyAGI 检测", "builtin.agent_detect.c124e717941b210c", "low", "audit", "检测 AutoGPT 和 BabyAGI 自主智能体特征"},
		// Behavioral controls
		{"请求频率限制", "builtin.agent_detect.6bb38a327f4ddadd", "high", "block", "检测异常高频请求模式，防止资源滥用"},
		{"高危工具调用检测", "builtin.agent_detect.2451a4aa92aae6c4", "high", "block", "检测 shell_exec 等高危工具动作，并按策略审计或阻断"},
		{"Session 超长检测", "builtin.agent_detect.3b83737794508b03", "low", "audit", "检测超长对话 Session，识别自动化持续交互"},
		{"多身份并发检测", "builtin.agent_detect.25c6ba2e41db01e3", "high", "block", "检测同一来源多身份并发请求，识别批量自动化"},
		{"批量请求模式检测", "builtin.agent_detect.4011bbc60f4c286d", "high", "block", "检测批量任务执行模式，防止自动化滥用"},
		{"异常时间窗口请求", "builtin.agent_detect.baf350658bb917ff", "high", "block", "检测非正常时间窗口的高频请求，识别自动化攻击"},
		{"格式化响应提取", "builtin.agent_detect.b9cbfe2be43132d0", "medium", "audit", "检测要求特定格式输出以便程序提取的请求模式"},
		{"API 直接调用检测", "builtin.agent_detect.e2d7dcc63727dab9", "low", "audit", "检测直接 API 调用特征，识别绕过 UI 的自动化请求"},
		{"代理轮换检测", "builtin.agent_detect.967c7b3cfd32049a", "high", "block", "检测代理 IP 轮换模式，识别分布式自动化攻击"},
		{"异常地理位置请求", "builtin.agent_detect.68cabce575a7dafa", "medium", "audit", "检测地理位置异常变化的请求模式"},
		{"设备指纹异常检测", "builtin.agent_detect.1ec9fa7c05668d6e", "high", "block", "检测设备指纹伪造或异常变化，识别自动化工具"},
	},
	"data_leak": {
		// Chinese PII
		{"手机号检测", "builtin.data_leak.e5821efde7585cbb", "medium", "mask", "检测中国手机号格式（11 位数字），脱敏处理为 '138****5678'"},
		{"身份证号检测", "builtin.data_leak.ee20059e4c9fbf2f", "high", "mask", "检测中国身份证号（18 位），脱敏处理为 '310***********1234'"},
		{"护照号检测", "builtin.data_leak.2348426d637af519", "high", "mask", "检测中国护照号格式（E + 8 位数字等），脱敏处理"},
		{"港澳台证件检测", "builtin.data_leak.63ae19f7cd1834bf", "high", "mask", "检测港澳台居民证件号格式，脱敏处理"},
		{"军官证检测", "builtin.data_leak.9a6811b786b7618f", "high", "mask", "检测军官证、武警证件号格式，脱敏处理"},
		{"驾驶证检测", "builtin.data_leak.86c5bbeff12d7c44", "medium", "mask", "检测驾驶证号格式（18 位身份证号或独立编号），脱敏处理"},
		{"社保卡号检测", "builtin.data_leak.e18afae0f9594164", "high", "mask", "检测社保卡号格式，脱敏处理"},
		{"银行卡号检测", "builtin.data_leak.a3048f2177b99395", "high", "mask", "检测银行卡号（16-19 位），脱敏处理为 '6222****1234'"},
		{"信用卡CVV检测", "builtin.data_leak.afa8b93679b66cb2", "critical", "block", "检测信用卡 CVV/CVC 安全码（3-4 位），直接阻断"},
		{"银行流水检测", "builtin.data_leak.d85734a727cce7b8", "high", "mask", "检测银行流水、账户明细中的敏感数据"},
		// Contact & address
		{"邮箱地址检测", "builtin.data_leak.261854a33ac6da17", "low", "audit", "检测邮箱地址格式，审计记录不脱敏"},
		{"家庭地址检测", "builtin.data_leak.aa6a72765f3d1d2b", "medium", "mask", "检测详细家庭地址，脱敏处理关键信息"},
		{"IP 地址检测", "builtin.data_leak.0cce2cce8b7bc217", "low", "audit", "检测 IPv4/IPv6 地址，审计记录"},
		{"出生日期检测", "builtin.data_leak.b37eae3f56e3d8f4", "low", "audit", "检测出生日期格式，审计记录"},
		{"通信记录检测", "builtin.data_leak.3512cd70e182c979", "high", "mask", "检测通话记录、短信内容等通信数据"},
		{"位置/GPS 数据", "builtin.data_leak.a9ac5ee3d220e157", "low", "audit", "检测 GPS 坐标、位置描述数据"},
		// Health & biometrics
		{"医疗记录检测", "builtin.data_leak.cd7cd3f962c8a7c1", "high", "mask", "检测医疗诊断、病历、用药记录"},
		{"基因数据检测", "builtin.data_leak.f21dc3ac3d94c0f3", "high", "block", "检测 DNA 序列、基因检测结果，直接阻断"},
		{"生物特征检测", "builtin.data_leak.65f151cdf48b5404", "high", "mask", "检测指纹、虹膜、人脸特征数据"},
		// Credentials & secrets
		{"API Key 检测", "builtin.data_leak.aa4bbf915707ff15", "critical", "block", "检测 API Key 格式（如 sk-xxx、AKIAxxx），直接阻断"},
		{"密码明文检测", "builtin.data_leak.98cc238bfbf6babb", "critical", "block", "检测明文密码、Passphrase，直接阻断"},
		{"JWT/Token 检测", "builtin.data_leak.87358f1a6d000590", "high", "block", "检测 JWT Token、Bearer Token 格式"},
		{"证书/私钥检测", "builtin.data_leak.a0891acf6ebc39c0", "critical", "block", "检测 SSL 证书私钥、SSH 私钥内容"},
		{"数据库连接串检测", "builtin.data_leak.67728f5a17e4a70a", "critical", "block", "检测数据库连接字符串（含密码）"},
		{"AWS/GCP 凭据检测", "builtin.data_leak.4cf7caaec6252ac7", "critical", "block", "检测 AWS Access Key、GCP Service Account Key"},
		{"SSH 密钥检测", "builtin.data_leak.db6cefda8798cab2", "critical", "block", "检测 SSH 私钥格式（" + "-----BEGIN OPENSSH " + "PRIVATE KEY-----" + "）"},
		// Enterprise data
		{"涉密文件标记检测", "builtin.data_leak.17723b156cfa7533", "high", "block", "检测 '机密'、'绝密'、'内部文件' 等涉密标记"},
		{"内部项目代号检测", "builtin.data_leak.e40d55f61d111133", "medium", "audit", "检测企业内部项目代号、产品代号"},
		{"敏感代码片段检测", "builtin.data_leak.85d7d239c670bab5", "medium", "mask", "检测可能包含凭据或敏感逻辑的代码片段"},
		{"教育背景检测", "builtin.data_leak.55e2d913ee8746b4", "low", "audit", "检测学历、学校等教育背景信息"},
		{"犯罪记录检测", "builtin.data_leak.1a873ce1a4f5e91e", "high", "mask", "检测犯罪记录、法律案件信息"},
		{"保险信息检测", "builtin.data_leak.7399a414eb30dbb9", "medium", "mask", "检测保险单号、保险理赔信息"},
	},
	"prompt_leak": {
		{"系统提示提取检测", "builtin.prompt_leak.00e21ecc7d791885", "high", "block", "检测 'Repeat your instructions'、'Show your system prompt' 等提取请求"},
		{"初始指令泄露检测", "builtin.prompt_leak.67489bdeaea0573a", "high", "block", "检测试图获取模型初始指令、训练数据的请求"},
		{"分隔符探测攻击", "builtin.prompt_leak.ebfe1cb42be3b070", "high", "block", "检测探测系统提示分隔符（如 '###'）的攻击"},
		{"提示词反转攻击", "builtin.prompt_leak.4fb9d9df2042df28", "high", "block", "检测 'Tell me what you were told not to do' 等反转攻击"},
		{"角色反转提取", "builtin.prompt_leak.adaf812b35c328aa", "high", "block", "检测 'You are now the user, I am the AI' 等角色反转攻击"},
		{"Base64 提示提取", "builtin.prompt_leak.4e51f1e57aa519c0", "high", "block", "检测通过 Base64 编码请求提取系统提示的攻击"},
		{"多语言提示提取", "builtin.prompt_leak.0fae073315d29973", "medium", "block", "检测使用多语言请求绕过检测提取系统提示"},
		{"编码方式提取", "builtin.prompt_leak.aa2cf7f9df399747", "high", "block", "检测使用各类编码方式提取系统提示的攻击"},
		{"渐进式提示提取", "builtin.prompt_leak.801e45f28d7a1758", "medium", "block", "检测多轮对话中逐步获取系统提示片段的攻击"},
		{"格式化导出要求", "builtin.prompt_leak.81c61518cc032dbd", "medium", "block", "检测 'Output in JSON/XML' 等格式化导出系统提示的请求"},
		{"提示词重构攻击", "builtin.prompt_leak.0dae0c3ea88dad80", "high", "block", "检测试图通过部分信息重构完整系统提示的攻击"},
		{"元指令泄露检测", "builtin.prompt_leak.4b4745b0d80aa02a", "high", "block", "检测试图获取模型元指令、安全规则的请求"},
		{"API 参数探测", "builtin.prompt_leak.c584e35e5a105858", "medium", "audit", "检测探测 API 参数（如 temperature、max_tokens）的请求"},
		{"系统配置探测", "builtin.prompt_leak.7e8a7b334134633b", "medium", "block", "检测探测系统配置、后端架构的请求"},
		{"内部指令查询", "builtin.prompt_leak.2dd388f0575b616c", "high", "block", "检测 'What rules do you follow' 等内部指令查询请求"},
	},
	"code_security": {
		{"SQL 注入代码生成", "builtin.code_security.d82567ae4c6cba2a", "medium", "block", "检测生成 SQL 注入攻击代码的请求"},
		{"命令注入代码生成", "builtin.code_security.2e8190e3871e45d6", "medium", "block", "检测生成 OS 命令注入攻击代码的请求"},
		{"SSRF 代码生成", "builtin.code_security.eea7475d95f58dd5", "medium", "block", "检测生成 SSRF（服务器端请求伪造）攻击代码的请求"},
		{"XSS 代码生成", "builtin.code_security.46a74885f15123bb", "medium", "block", "检测生成 XSS（跨站脚本攻击）代码的请求"},
		{"反序列化漏洞代码", "builtin.code_security.83c72801873c89c6", "medium", "block", "检测生成反序列化漏洞利用代码的请求"},
		{"路径遍历代码生成", "builtin.code_security.389ee9cb3cb7c789", "medium", "block", "检测生成路径遍历攻击代码的请求"},
		{"硬编码凭据示例", "builtin.code_security.9640acf0d1083905", "medium", "block", "检测代码中的硬编码凭据示例，阻断请求"},
		{"弱加密代码生成", "builtin.code_security.829c9fe3cbc3a792", "medium", "block", "检测生成弱加密（如 MD5、DES）代码的请求"},
		{"内存溢出代码", "builtin.code_security.d4bd0d8e0c6c9857", "medium", "block", "检测生成缓冲区溢出、内存攻击代码的请求"},
		{"权限绕过代码", "builtin.code_security.4f2a28590d7747f6", "medium", "block", "检测生成权限绕过、认证绕过代码的请求"},
		{"不安全的随机数", "builtin.code_security.3e1454b49ab95b46", "medium", "audit", "检测生成不安全随机数生成器的代码"},
		{"日志注入代码", "builtin.code_security.be648ff0048d7877", "medium", "block", "检测生成日志注入攻击代码的请求"},
		{"XML 外部实体注入", "builtin.code_security.d6121b4e9c6b3639", "medium", "block", "检测生成 XXE（XML 外部实体注入）攻击代码的请求"},
		{"不安全的文件处理", "builtin.code_security.0234e3099d41f98b", "medium", "block", "检测生成不安全文件操作代码的请求"},
		{"模板注入代码", "builtin.code_security.3f67649cc24121a3", "medium", "block", "检测生成模板注入（SSTI）攻击代码的请求"},
		{"LDAP 注入代码", "builtin.code_security.c0bf948ca3c9ebe2", "medium", "block", "检测生成 LDAP 注入攻击代码的请求"},
		{"NoSQL 注入代码", "builtin.code_security.2da958a010ca4303", "medium", "block", "检测生成 NoSQL 注入攻击代码的请求"},
	},
	"fraud_detect": {
		{"虚假投资话术", "builtin.fraud_detect.85094af4238a5149", "high", "block", "检测虚假投资理财话术，识别 '保本保息'、'高收益零风险' 等骗局"},
		{"钓鱼邮件生成", "builtin.fraud_detect.31114886164ee6ac", "high", "block", "检测生成钓鱼邮件、伪造银行通知的请求"},
		{"杀猪盘话术", "builtin.fraud_detect.5b7e940a2a8800b2", "high", "block", "检测杀猪盘诈骗话术，识别感情诱导后诈骗的模式"},
		{"虚假中奖信息", "builtin.fraud_detect.e6509942afa78488", "high", "block", "检测虚假中奖通知话术"},
		{"庞氏骗局话术", "builtin.fraud_detect.c99081d7ce4ae6de", "high", "block", "检测庞氏骗局、传销式投资话术"},
		{"虚假贷款推广", "builtin.fraud_detect.98e22b1a3a71ca52", "medium", "block", "检测虚假贷款、无门槛贷款推广话术"},
		{"假冒银行通知", "builtin.fraud_detect.6ff312032520747d", "high", "block", "检测伪造银行通知、短信验证码骗取话术"},
		{"加密货币骗局", "builtin.fraud_detect.7e0c55725773bdb8", "high", "block", "检测加密货币投资骗局、虚拟货币诈骗话术"},
		{"退款诈骗话术", "builtin.fraud_detect.8515194cb5e180de", "high", "block", "检测退款诈骗、假客服退款话术"},
		{"虚假众筹文案", "builtin.fraud_detect.5924fd3912c0e21c", "medium", "block", "检测虚假众筹、慈善诈骗文案"},
		{"冒充客服话术", "builtin.fraud_detect.9dbfbdb60934fd8e", "high", "block", "检测冒充客服、售后人员进行诈骗的话术"},
		{"虚假招聘诈骗", "builtin.fraud_detect.193da7504db91d7c", "medium", "block", "检测虚假招聘、收取费用诈骗话术"},
		{"假冒公检法话术", "builtin.fraud_detect.eafd99decc56bca2", "high", "block", "检测冒充公安、检察院、法院人员进行诈骗的话术"},
		{"虚假购物网站", "builtin.fraud_detect.5fdc9f9c064a22a1", "medium", "block", "检测虚假购物网站、钓鱼商城话术"},
		{"虚假投资平台", "builtin.fraud_detect.e8c52e0bae177488", "high", "block", "检测虚假投资平台、模拟交易平台话术"},
		{"刷单诈骗话术", "builtin.fraud_detect.9414bd270d35d512", "high", "block", "检测刷单兼职诈骗话术"},
		{"冒充领导诈骗", "builtin.fraud_detect.eadf367494293780", "high", "block", "检测冒充领导、老板要求转账的话术"},
	},
	"dos_protection": {
		{"递归展开攻击", "builtin.dos_protection.6f6907dfdbc2ee17", "medium", "block", "检测利用递归定义导致无限展开的攻击，如 'Define X as X+1'"},
		{"超长上下文消耗", "builtin.dos_protection.26b5a56593b2a884", "medium", "block", "检测故意生成超长文本消耗资源的攻击"},
		{"无限循环指令", "builtin.dos_protection.762fbe86a6615238", "medium", "block", "检测 'Repeat forever'、'Loop without end' 等无限循环指令"},
		{"指数膨胀请求", "builtin.dos_protection.4f43236bc20250dc", "medium", "block", "检测利用指数级增长消耗资源的请求"},
		{"批量并发请求", "builtin.dos_protection.1d26c44f7b71efac", "high", "block", "检测批量并发请求模式，防止资源耗尽"},
		{"大文件处理攻击", "builtin.dos_protection.1c7e9f9970f83177", "medium", "block", "检测请求处理超大文件消耗资源的攻击"},
		{"正则回溯攻击", "builtin.dos_protection.c49a1dd5605cb6d1", "medium", "block", "检测利用正则表达式回溯导致性能下降的攻击"},
		{"深层嵌套展开", "builtin.dos_protection.5f096e00aa599617", "medium", "block", "检测深层嵌套结构导致大量计算的请求"},
		{"资源耗尽指令", "builtin.dos_protection.4290e5f12c4f81a4", "medium", "block", "检测明确要求消耗大量计算资源的指令"},
		{"重复提交攻击", "builtin.dos_protection.e669fe2aeef676da", "medium", "block", "检测恶意重复提交相同请求的攻击"},
		{"递归函数调用", "builtin.dos_protection.6e61ea7c8d2d9a07", "medium", "block", "检测生成递归函数导致资源耗尽的请求"},
	},
	"plugin_security": {
		{"未授权工具调用", "builtin.plugin_security.5c66059903fe2cab", "high", "block", "检测未授权的工具、插件调用请求"},
		{"插件权限提升", "builtin.plugin_security.ba997217f9b54e40", "high", "block", "检测插件试图获取更高权限的请求"},
		{"文件系统越权", "builtin.plugin_security.e9d082e3a9566521", "high", "block", "检测插件越权访问文件系统的请求"},
		{"网络请求伪造", "builtin.plugin_security.2932cca214e98d4e", "high", "block", "检测插件伪造网络请求、绕过网络限制的攻击"},
		{"插件链式攻击", "builtin.plugin_security.fb49d223f677b0ac", "high", "block", "检测利用多个插件组合进行攻击的模式"},
		{"MCP 权限绕过", "builtin.plugin_security.450758fa39c93507", "high", "block", "检测 MCP（Model Context Protocol）权限绕过攻击"},
		{"工具窃取数据", "builtin.plugin_security.1aa5c9889e5f4e27", "critical", "block", "检测工具、插件窃取敏感数据的请求"},
		{"工具日志篡改", "builtin.plugin_security.b5f7907c68e5bf34", "medium", "block", "检测试图篡改工具日志、审计记录的请求"},
		{"插件数据泄露", "builtin.plugin_security.0e486a2f5576a9b0", "high", "block", "检测插件泄露敏感数据的请求"},
		{"恶意插件安装", "builtin.plugin_security.7f715200f0fa437d", "critical", "block", "检测安装恶意插件、有害扩展的请求"},
		{"工具拒绝执行", "builtin.plugin_security.1024164507834300", "medium", "block", "检测导致工具拒绝执行、服务中断的请求"},
	},
	"illegal_trade": {
		{"违禁品交易引导", "builtin.illegal_trade.36d483957d6bc246", "critical", "block", "检测违禁品交易方法、渠道引导"},
		{"假货制造指导", "builtin.illegal_trade.17afa89cca4e8954", "critical", "block", "检测假冒商品制作方法指导"},
		{"黑市交易引导", "builtin.illegal_trade.4f6d018cc6d7ee00", "high", "block", "检测黑市交易渠道、方法引导"},
		{"处方药违规销售", "builtin.illegal_trade.3a11e5702d46e089", "high", "block", "检测处方药违规销售、购买方法"},
		{"野生动物交易", "builtin.illegal_trade.3f55b904e1900e0d", "critical", "block", "检测野生动物及其制品交易引导"},
		{"假冒证件制作", "builtin.illegal_trade.41681caad5e30153", "critical", "block", "检测伪造证件、印章制作方法"},
		{"走私方法咨询", "builtin.illegal_trade.5ed755f877e035f9", "high", "block", "检测走私方法、渠道咨询"},
		{"非法武器交易", "builtin.illegal_trade.b5eab46d920f0a59", "critical", "block", "检测非法武器交易方法引导"},
		{"人口贩卖内容", "builtin.illegal_trade.b42c9e2d1d6a1cdb", "critical", "block", "检测人口贩卖相关内容"},
		{"毒品交易引导", "builtin.illegal_trade.103b0604b9ae8e51", "critical", "block", "检测毒品交易方法、渠道引导"},
		{"人体器官交易", "builtin.illegal_trade.2baa4f43c99678c0", "critical", "block", "检测人体器官非法交易内容"},
	},
	"copyright_protect": {
		{"受版权文本生成", "builtin.copyright_protect.8459d0184254fe69", "medium", "block", "检测请求生成明显受版权保护的完整文本"},
		{"盗版内容提取", "builtin.copyright_protect.5bc4433e74d45c13", "high", "block", "检测请求提取盗版书籍、电影等内容的摘要"},
		{"歌词批量导出", "builtin.copyright_protect.a77b346995352c2b", "medium", "block", "检测批量请求导出完整歌词"},
		{"开源许可绕过", "builtin.copyright_protect.e3ded2f4e7620f42", "medium", "block", "检测请求绕过开源许可证限制使用代码"},
		{"受保护角色再现", "builtin.copyright_protect.36cd5135e9429132", "medium", "block", "检测请求再现受版权保护的角色"},
		{"侵权图像描述", "builtin.copyright_protect.7123a899c2158bdb", "medium", "audit", "检测请求描述受版权保护的图像内容"},
		{"专利内容复制", "builtin.copyright_protect.9c0b04a17d008a0c", "high", "block", "检测请求复制专利文档的核心内容"},
		{"商业机密提取", "builtin.copyright_protect.1107170cb2c8407a", "high", "block", "检测请求提取企业商业机密"},
		{"学术论文盗用", "builtin.copyright_protect.d971cfcccc10c312", "high", "block", "检测请求盗用学术论文、研究成果"},
	},
	"rag_security": {
		{"外部知识投毒", "builtin.rag_security.af8adaef83896e2d", "high", "block", "检测向 RAG 知识库注入虚假信息的攻击"},
		{"检索上下文劫持", "builtin.rag_security.d42179890c2b8967", "high", "block", "检测劫持检索结果上下文的攻击"},
		{"虚假文档引用", "builtin.rag_security.1723128d6f171f69", "medium", "block", "检测伪造文档引用、虚假来源的请求"},
		{"知识库越权查询", "builtin.rag_security.0c2992f0a6665641", "high", "block", "检测越权访问知识库内容的请求"},
		{"RAG 数据泄露", "builtin.rag_security.467a622e0be8d906", "high", "block", "检测通过 RAG 泄露敏感数据的请求"},
		{"向量嵌入操纵", "builtin.rag_security.13154dbf8dc32f3f", "high", "block", "检测操纵向量嵌入结果的攻击"},
		{"文档源欺骗", "builtin.rag_security.659584df2cd2be3d", "medium", "block", "检测伪造文档来源欺骗检索系统的攻击"},
		{"检索结果篡改", "builtin.rag_security.08b9b614ab365989", "high", "block", "检测篡改检索结果的攻击"},
		{"RAG 缓存投毒", "builtin.rag_security.74a9f1e667ced7cf", "high", "block", "检测向 RAG 缓存注入恶意数据的攻击"},
	},
	"supply_chain": {
		{"模型版本漏洞探测", "builtin.supply_chain.e88a49da94a0a712", "medium", "audit", "检测探测模型版本、已知漏洞的请求"},
		{"未授权模型调用", "builtin.supply_chain.98c244cb0345cb0d", "high", "block", "检测调用未授权模型的请求"},
		{"模型行为探测", "builtin.supply_chain.cc3faf3e41ecaaa8", "medium", "audit", "检测探测模型内部行为、决策逻辑的请求"},
		{"合规标签绕过", "builtin.supply_chain.91151fe7a133df12", "high", "block", "检测绕过合规标签、安全标记的请求"},
		{"第三方依赖漏洞", "builtin.supply_chain.575265dc58c794c7", "medium", "audit", "检测利用第三方依赖漏洞的攻击"},
		{"模型权重窃取", "builtin.supply_chain.dd2a34c2c0d63125", "critical", "block", "检测窃取模型权重、参数的请求"},
		{"影子模型使用", "builtin.supply_chain.9e3f687b97ec8ae3", "high", "block", "检测使用影子模型、克隆模型的请求"},
		{"恶意模型加载", "builtin.supply_chain.26bc51020d532aaf", "critical", "block", "检测加载恶意模型、有害模型的请求"},
	},
}

// NormalizeRuntimeMatcher applies the single executable matcher contract used
// at every boundary. Domain detector types such as prompt_injection are
// capability catalog labels, not ad-hoc keyword rules.
func NormalizeRuntimeMatcher(ruleType string, raw []byte) (RuntimeMatcher, bool) {
	if len(raw) == 0 {
		return RuntimeMatcher{}, false
	}
	var cfg struct {
		Regex      json.RawMessage `json:"regex"`
		Keywords   json.RawMessage `json:"keywords"`
		FieldNames json.RawMessage `json:"field_names"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return RuntimeMatcher{}, false
	}

	trimmedStrings := func(values []string) []string {
		cleaned := make([]string, 0, len(values))
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				cleaned = append(cleaned, value)
			}
		}
		return cleaned
	}

	switch ruleType {
	case "regex":
		var regex string
		if err := json.Unmarshal(cfg.Regex, &regex); err != nil {
			return RuntimeMatcher{}, false
		}
		regex = strings.TrimSpace(regex)
		if regex == "" {
			return RuntimeMatcher{}, false
		}
		return RuntimeMatcher{Regex: regex}, true
	case "keyword":
		var rawKeywords []string
		if err := json.Unmarshal(cfg.Keywords, &rawKeywords); err != nil {
			return RuntimeMatcher{}, false
		}
		keywords := trimmedStrings(rawKeywords)
		if len(keywords) == 0 {
			return RuntimeMatcher{}, false
		}
		return RuntimeMatcher{Keywords: keywords}, true
	case "field_name":
		var rawFieldNames []string
		if err := json.Unmarshal(cfg.FieldNames, &rawFieldNames); err != nil {
			return RuntimeMatcher{}, false
		}
		fieldNames := trimmedStrings(rawFieldNames)
		if len(fieldNames) == 0 {
			return RuntimeMatcher{}, false
		}
		return RuntimeMatcher{FieldNames: fieldNames}, true
	default:
		return RuntimeMatcher{}, false
	}
}

// RuleHasSupportedMatcher reports whether the rule's type and normalized
// matcher form an executable runtime pair.
func RuleHasSupportedMatcher(rule *Rule) bool {
	if rule == nil {
		return false
	}
	_, ok := NormalizeRuntimeMatcher(rule.RuleType, rule.MatchConfigJSON)
	return ok
}

// RuleIsCapabilityCatalog recognizes only the built-in descriptive seed rows.
// Stable policy_code is authoritative so customer-facing renames never make a
// shipped policy deletable through the legacy rule endpoints. Migration 125 is
// mandatory for this binary, so names are never used as an identity fallback.
func RuleIsCapabilityCatalog(rule *Rule) bool {
	if rule == nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(rule.PolicyCode), "builtin.")
}

// RuleIsManagedSecurityPolicy identifies every rule owned by the unified
// policy center. The prefix describes origin only; any non-blank policy_code
// is an ownership boundary and must not be mutated through legacy /rules APIs.
func RuleIsManagedSecurityPolicy(rule *Rule) bool {
	return rule != nil && strings.TrimSpace(rule.PolicyCode) != ""
}

func (r *RuleRepository) legacyRuleMutationError(ctx context.Context, tenantID, id string, fallback error) error {
	var policyCode string
	err := r.db.QueryRow(ctx, `
		SELECT COALESCE(r.policy_code,'')
		FROM rules r
		JOIN rule_sets rs ON rs.id=r.rule_set_id
		WHERE r.id=$1 AND rs.tenant_id=$2
		  AND `+ruleNotDeletedSQL, id, tenantID,
	).Scan(&policyCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRuleNotFound
	}
	if err != nil {
		return fmt.Errorf("verify legacy rule mutation target: %w", err)
	}
	if strings.TrimSpace(policyCode) != "" {
		return ErrManagedSecurityPolicyReadOnly
	}
	return fallback
}

// SeedDefaultSubRules creates all default sub-rules if they don't exist
func newDefaultPolicyRuleID() string {
	return "rule_" + uuid.NewString()
}

func (r *RuleRepository) SeedDefaultSubRules(ctx context.Context, tenantID, ruleSetID string) (created int, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin seed rules transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID+":"+ruleSetID); err != nil {
		return 0, fmt.Errorf("lock default rule set: %w", err)
	}
	var owned bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM rule_sets WHERE id=$1 AND tenant_id=$2)`,
		ruleSetID, tenantID,
	).Scan(&owned); err != nil {
		return 0, fmt.Errorf("verify default rule set: %w", err)
	}
	if !owned {
		return 0, ErrRuleSetNotFound
	}

	for ruleType, subRules := range defaultSubRules {
		for _, sr := range subRules {
			policyCode := strings.TrimSpace(sr.PolicyCode)
			if policyCode == "" {
				return 0, fmt.Errorf("default policy identity is not registered: %s/%s", ruleType, sr.Name)
			}
			if isRetiredDefaultPolicy(policyCode) {
				continue
			}
			var ruleID string
			catalogedNow := false
			err := tx.QueryRow(ctx,
				`SELECT id FROM rules WHERE rule_set_id=$1 AND policy_code=$2`,
				ruleSetID, policyCode,
			).Scan(&ruleID)
			switch {
			case err == nil:
				// Existing catalog identity is authoritative even when the display
				// name was edited. Never recreate a renamed policy.
			case errors.Is(err, pgx.ErrNoRows):
				var legacyCount int
				if err := tx.QueryRow(ctx, `
					SELECT COUNT(*), COALESCE(MIN(id), '')
					FROM rules
					WHERE rule_set_id=$1 AND rule_type=$2 AND name=$3
					  AND NOT jsonb_exists(COALESCE(scope_json,'{}'::jsonb),'deleted_at')`,
					ruleSetID, ruleType, sr.Name,
				).Scan(&legacyCount, &ruleID); err != nil {
					return 0, fmt.Errorf("check legacy policy %s: %w", sr.Name, err)
				}
				if legacyCount > 1 {
					return 0, fmt.Errorf("ambiguous default policy %s/%s: %d rows", ruleType, sr.Name, legacyCount)
				}
				if legacyCount == 1 {
					result, err := tx.Exec(ctx,
						`UPDATE rules SET policy_code=$1 WHERE id=$2 AND rule_set_id=$3 AND policy_code IS NULL`,
						policyCode, ruleID, ruleSetID,
					)
					if err != nil {
						return 0, fmt.Errorf("assign policy code %s: %w", sr.Name, err)
					}
					if result.RowsAffected() != 1 {
						return 0, fmt.Errorf("assign policy code %s: concurrent catalog conflict", sr.Name)
					}
					catalogedNow = true
					break
				}

				ruleID = newDefaultPolicyRuleID()
				result, err := tx.Exec(ctx, `
					INSERT INTO rules (id,rule_set_id,policy_code,rule_type,name,priority,severity,scope_json,action,enabled,description)
					SELECT $1,rs.id,$3,$4,$5,0,$6,'{"catalog":"default_policy","catalog_version":1}'::jsonb,$7,true,$8
					FROM rule_sets rs
					WHERE rs.id=$2 AND rs.tenant_id=$9`,
					ruleID, ruleSetID, policyCode, ruleType, sr.Name,
					sr.Severity, sr.Action, sr.Description, tenantID,
				)
				if err != nil {
					return 0, fmt.Errorf("failed to create rule %s: %w", sr.Name, err)
				}
				if result.RowsAffected() != 1 {
					return 0, ErrRuleSetNotFound
				}
				catalogedNow = true
				created++
			default:
				return 0, fmt.Errorf("find policy code %s: %w", sr.Name, err)
			}

			// Bind only on initial catalog adoption. A later customer removal is
			// configuration and must not be silently undone on service restart.
			if !catalogedNow {
				continue
			}
			binding, exact := exactCapabilityBindingForPolicy(policyCode)
			if !exact {
				continue
			}
			for _, category := range binding.CapabilityCategories {
				var capabilityID string
				if err := tx.QueryRow(ctx,
					`SELECT id FROM security_capabilities WHERE category=$1`,
					category,
				).Scan(&capabilityID); err != nil {
					return 0, fmt.Errorf("resolve capability %s for %s: %w", category, sr.Name, err)
				}
				if _, err := tx.Exec(ctx, `
					INSERT INTO rule_capability_bindings (rule_id,capability_id,binding_mode,priority,config_json)
					VALUES ($1,$2,$3,0,'{}'::jsonb)
					ON CONFLICT (rule_id,capability_id) DO NOTHING`,
					ruleID, capabilityID, binding.BindingMode,
				); err != nil {
					return 0, fmt.Errorf("bind capability %s to %s: %w", category, sr.Name, err)
				}
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit seed rules transaction: %w", err)
	}
	return created, nil
}

// GetRulesByType retrieves all rules for a given type in a rule set
func (r *RuleRepository) GetRulesByType(ctx context.Context, tenantID, ruleSetID, ruleType string) ([]*Rule, error) {
	var owned bool
	if err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM rule_sets WHERE id=$1 AND tenant_id=$2)`,
		ruleSetID, tenantID,
	).Scan(&owned); err != nil {
		return nil, fmt.Errorf("verify rule set ownership: %w", err)
	}
	if !owned {
		return nil, ErrRuleSetNotFound
	}
	query := `
		SELECT r.id, r.rule_set_id, r.rule_type, r.name, r.priority, r.severity, r.scope_json, r.match_config_json, r.action, r.enabled, r.description, r.created_at
		FROM rules r
		JOIN rule_sets rs ON rs.id=r.rule_set_id
		WHERE r.rule_set_id = $1 AND r.rule_type = $2 AND rs.tenant_id=$3
		  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
		ORDER BY r.priority DESC, r.created_at
	`
	rows, err := r.db.Query(ctx, query, ruleSetID, ruleType, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		var rule Rule
		err := rows.Scan(
			&rule.ID, &rule.RuleSetID, &rule.RuleType, &rule.Name,
			&rule.Priority, &rule.Severity,
			&rule.ScopeJSON, &rule.MatchConfigJSON,
			&rule.Action, &rule.Enabled, &rule.Description, &rule.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate rules: %w", rows.Err())
	}
	return rules, nil
}

// SystemTenantID 是承载所有内置行业预置数据安全规则包的保留租户。
// rule_sets.tenant_id 是指向 tenants(id) 的 NOT NULL 外键，预置包必须挂在一个真实租户下，
// 故迁移 068 预置此租户专门承载 source_type='builtin' 的行业规则集。
const SystemTenantID = "tenant_system"

// buildCompilableRulesQuery 生成「某租户可编译规则」的查询与参数（纯函数，便于隔离单测）。
//
// 候选集合 = 本租户自有已发布规则（包含 disabled，由编译器分类并生成诊断）
//
//	∪ 系统内置包中（source_type='builtin' 且 industry∈{generic, 本租户行业}）的规则。
//
// 安全：tenantID / industry 全部以绑定参数下传（$1/$2/$3），绝不拼接进 SQL 文本，防注入。
func buildCompilableRulesQuery(tenantID, industry string) (string, []any) {
	query := `
		SELECT r.id, COALESCE(r.policy_code, ''), r.rule_set_id, r.rule_type, r.name, r.priority, COALESCE(bro.severity, r.severity),
		       CASE WHEN bro.semantic_action IS NULL THEN (CASE WHEN bro.redaction_json IS NULL THEN r.scope_json ELSE COALESCE(r.scope_json,'{}'::jsonb) || jsonb_build_object('redaction',bro.redaction_json) END) ELSE COALESCE((CASE WHEN bro.redaction_json IS NULL THEN r.scope_json ELSE COALESCE(r.scope_json,'{}'::jsonb) || jsonb_build_object('redaction',bro.redaction_json) END),'{}'::jsonb) || jsonb_build_object('semantic_action',bro.semantic_action) END, r.match_config_json, COALESCE(bro.action, r.action),
		       COALESCE(bro.enabled, r.enabled), r.description, r.created_at,
		       COALESCE(runtime_capabilities.items, '[]'::jsonb)
		FROM rules r
		JOIN rule_sets rs ON rs.id = r.rule_set_id
		LEFT JOIN builtin_rule_overrides bro ON bro.tenant_id = $1 AND bro.rule_id = r.id
		LEFT JOIN LATERAL (
		  SELECT jsonb_agg(
		    jsonb_build_object(
		      'category', selected.category,
		      'binding_mode', selected.binding_mode,
		      'enabled', selected.enabled,
		      'supported_stages', selected.supported_stages,
		      'allowed_actions', selected.allowed_actions,
		      'mask_capable', selected.mask_capable
		    )
		    ORDER BY selected.priority DESC, selected.category
		  ) AS items
		  FROM (
		    SELECT capability.category, binding.binding_mode, capability.enabled,
		           capability.supported_stages, capability.allowed_actions,
		           capability.mask_capable, binding.priority
		    FROM rule_capability_bindings binding
		    JOIN security_capabilities capability ON capability.id = binding.capability_id
		    WHERE binding.rule_id = r.id AND bro.capability_categories IS NULL
		    UNION ALL
		    SELECT capability.category, bro.binding_mode, capability.enabled,
		           capability.supported_stages, capability.allowed_actions,
		           capability.mask_capable, 0
		    FROM security_capabilities capability
		    WHERE bro.capability_categories IS NOT NULL
		      AND bro.capability_categories ? capability.category
		  ) selected
		) runtime_capabilities ON TRUE
		WHERE rs.published = TRUE
		  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
		  AND (
		        rs.tenant_id = $1
		        OR (rs.tenant_id = $2 AND rs.source_type = 'builtin' AND rs.industry IN ('generic', $3))
		      )
		ORDER BY r.priority DESC, r.created_at
		LIMIT 10001
	`
	return query, []any{tenantID, SystemTenantID, industry}
}

// ListCompilableRulesByTenant 返回某租户所有「可编译进运行时规则包」的规则：
// 取已发布规则集（rs.published=TRUE）下的全部规则候选（含 disabled），
// 并叠加系统内置包中匹配本租户 industry（或通用 generic）的行业预置数据安全规则。
// enabled 与 matcher 有效性统一由编译器分类，保证未下发规则有可观测诊断而非查询层静默消失。
// rules 表无 tenant_id 列，租户归属通过 rule_set_id → rule_sets.tenant_id 关联。
// 服务于「方案A：规则编译下发」的内部下发接口 GET /admin/v1/internal/rules/pack。
func (r *RuleRepository) ListCompilableRulesByTenant(ctx context.Context, tenantID, industry string) ([]*Rule, error) {
	query, args := buildCompilableRulesQuery(tenantID, industry)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list compilable rules: %w", err)
	}
	defer rows.Close()
	return scanCompilableRules(rows)
}

func scanCompilableRules(rows pgx.Rows) ([]*Rule, error) {
	var result []*Rule
	for rows.Next() {
		var rule Rule
		var capabilitiesJSON []byte
		if err := rows.Scan(
			&rule.ID, &rule.PolicyCode, &rule.RuleSetID, &rule.RuleType, &rule.Name,
			&rule.Priority, &rule.Severity, &rule.ScopeJSON, &rule.MatchConfigJSON,
			&rule.Action, &rule.Enabled, &rule.Description, &rule.CreatedAt,
			&capabilitiesJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan compilable rule: %w", err)
		}
		if err := json.Unmarshal(capabilitiesJSON, &rule.RuntimeCapabilities); err != nil {
			return nil, fmt.Errorf("failed to decode runtime capabilities for rule %s: %w", rule.ID, err)
		}
		result = append(result, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate compilable rules: %w", err)
	}
	return result, nil
}

// scanRules 把规则查询结果集逐行扫描为 []*Rule。
// 列顺序须与 buildCompilableRulesQuery / buildBuiltinDataSecurityQuery 的 SELECT 完全一致；
// 抽出共用以保证两条下发/展示路径扫描同一组字段，杜绝列错位导致的展示与引擎下发漂移。
func scanRules(rows pgx.Rows) ([]*Rule, error) {
	var rules []*Rule
	for rows.Next() {
		var rule Rule
		err := rows.Scan(
			&rule.ID, &rule.RuleSetID, &rule.RuleType, &rule.Name,
			&rule.Priority, &rule.Severity,
			&rule.ScopeJSON, &rule.MatchConfigJSON,
			&rule.Action, &rule.Enabled, &rule.Description, &rule.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate rules: %w", rows.Err())
	}
	return rules, nil
}

// buildBuiltinDataSecurityQuery 生成「某行业当前生效的内置数据安全预置包」的查询与参数（纯函数，便于隔离单测）。
//
// 它读取的是引擎按方案A实际编译下发的同一批内置规则，作为「内容和数据安全」配置页只读展示的单一事实源：
//
//	集合 = 系统租户 tenant_system 名下 source_type='builtin' 且 industry∈{generic, 本行业} 的已发布启用规则。
//
// 安全：固定收敛到系统租户（$1 绑定 SystemTenantID），绝不借此读到任意租户自有规则；
// industry 以绑定参数 $2 下传，绝不拼接进 SQL 文本，防注入。
// 行业过滤口径与 buildCompilableRulesQuery 的内置分支严格一致，保证展示=下发。
func buildBuiltinDataSecurityQuery(industry string) (string, []any) {
	query := `
		SELECT r.id, r.rule_set_id, r.rule_type, r.name, r.priority, r.severity,
		       r.scope_json, r.match_config_json, r.action, r.enabled, r.description, r.created_at
		FROM rules r
		JOIN rule_sets rs ON rs.id = r.rule_set_id
		WHERE r.enabled = TRUE AND rs.published = TRUE
		  AND rs.tenant_id = $1
		  AND rs.source_type = 'builtin'
		  AND rs.industry IN ('generic', $2)
		ORDER BY rs.industry, r.priority DESC, r.created_at
	`
	return query, []any{SystemTenantID, industry}
}

// ListBuiltinDataSecurityRules 返回某行业当前生效的内置数据安全预置包（通用 generic 之上叠加本行业）。
// 与 ListCompilableRulesByTenant 共用 scanRules 与同一行业过滤口径。
// 注意：本查询只读系统预置规则本身，不叠加租户覆盖（级别、动作、启停），
// 因此不等于某租户引擎实际生效的规则；租户生效视图以 ListCompilableRulesByTenant 为准。
func (r *RuleRepository) ListBuiltinDataSecurityRules(ctx context.Context, industry string) ([]*Rule, error) {
	query, args := buildBuiltinDataSecurityQuery(industry)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list builtin data security rules: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// ContentAuditException 是内容安全（数据安全 / 文件管控）的例外规则。
//
// 与 agentguard 的例外不同：RuleID 是对 rules.id 的真实外键（可为空表示作用域级例外）；
// 方案A 下例外随规则包一同编译下发。
type ContentAuditException struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	ScopeType       string     `json:"scope_type"`
	ScopeRef        string     `json:"scope_ref"`
	IncludeChildren bool       `json:"include_children"`
	RuleID          string     `json:"rule_id"`  // 旧：rules(id) 外键，仅自定义规则；保留兼容
	RuleRef         string     `json:"rule_ref"` // 新：统一命名空间引用（内置英文 ID 或 rules.id），读取优先
	Decision        string     `json:"decision"` // allow | audit
	Reason          string     `json:"reason"`
	ExpiresAt       *time.Time `json:"expires_at"` // nil = 永久（迁移 109）
	Enabled         bool       `json:"enabled"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
}

const (
	maxActiveContentAuditExceptions        = 10000
	contentAuditExceptionLimitProbe        = maxActiveContentAuditExceptions + 1
	maxContentAuditExceptionScopeTypeRunes = 32
	maxContentAuditExceptionScopeRefRunes  = 255
	maxContentAuditExceptionRuleIDRunes    = 64
	maxContentAuditExceptionRuleRefRunes   = 255
	maxContentAuditExceptionReasonRunes    = 2048
)

func invalidContentAuditException(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidContentAuditException, fmt.Sprintf(format, args...))
}

func contentAuditExceptionFieldTooLong(value string, maxRunes int) bool {
	return len([]rune(value)) > maxRunes
}

// ListActiveContentAuditExceptionsByTenant 拉取本租户当前生效（启用且未过期）的内容安全例外。
// content_audit_exceptions 自带 tenant_id 列，无需 JOIN rule_sets。
func (r *RuleRepository) ListActiveContentAuditExceptionsByTenant(ctx context.Context, tenantID string) ([]*ContentAuditException, error) {
	query := `
		SELECT id, tenant_id, scope_type, scope_ref, include_children, COALESCE(rule_id, ''),
		       COALESCE(NULLIF(rule_ref, ''), rule_id, '') AS rule_ref,
		       decision, reason, expires_at, enabled, COALESCE(created_by, ''), created_at
		FROM content_audit_exceptions
		WHERE tenant_id = $1 AND enabled = TRUE AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at
		LIMIT $2
	`
	rows, err := r.db.Query(ctx, query, tenantID, contentAuditExceptionLimitProbe)
	if err != nil {
		return nil, fmt.Errorf("failed to list content audit exceptions: %w", err)
	}
	defer rows.Close()

	var excs []*ContentAuditException
	for rows.Next() {
		var e ContentAuditException
		err := rows.Scan(
			&e.ID, &e.TenantID, &e.ScopeType, &e.ScopeRef, &e.IncludeChildren, &e.RuleID, &e.RuleRef,
			&e.Decision, &e.Reason, &e.ExpiresAt, &e.Enabled, &e.CreatedBy, &e.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan content audit exception: %w", err)
		}
		excs = append(excs, &e)
		if len(excs) > maxActiveContentAuditExceptions {
			return nil, ErrContentAuditExceptionLimitExceeded
		}
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate content audit exceptions: %w", rows.Err())
	}
	return excs, nil
}

// ListContentAuditExceptionsByTenant lists all content/data exception rules for management UI.
func (r *RuleRepository) ListContentAuditExceptionsByTenant(ctx context.Context, tenantID string) ([]*ContentAuditException, error) {
	query := `
		SELECT id, tenant_id, scope_type, scope_ref, include_children, COALESCE(rule_id, ''),
		       COALESCE(NULLIF(rule_ref, ''), rule_id, '') AS rule_ref,
		       decision, reason, expires_at, enabled, COALESCE(created_by, ''), created_at
		FROM content_audit_exceptions
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list content audit exceptions: %w", err)
	}
	defer rows.Close()

	var excs []*ContentAuditException
	for rows.Next() {
		var e ContentAuditException
		if err := rows.Scan(&e.ID, &e.TenantID, &e.ScopeType, &e.ScopeRef, &e.IncludeChildren, &e.RuleID, &e.RuleRef, &e.Decision, &e.Reason, &e.ExpiresAt, &e.Enabled, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan content audit exception: %w", err)
		}
		excs = append(excs, &e)
	}
	return excs, rows.Err()
}

// NormalizeAndValidateContentAuditException normalizes the public storage
// contract without touching the database. Handlers use it before resolving
// tenant-owned scope references; the repository repeats it for direct callers.
func NormalizeAndValidateContentAuditException(e *ContentAuditException) error {
	if e == nil {
		return invalidContentAuditException("exception is required")
	}
	e.ScopeType = strings.ToLower(strings.TrimSpace(e.ScopeType))
	e.ScopeRef = strings.TrimSpace(e.ScopeRef)
	e.RuleID = strings.TrimSpace(e.RuleID)
	e.RuleRef = strings.TrimSpace(e.RuleRef)
	e.Decision = strings.ToLower(strings.TrimSpace(e.Decision))
	e.Reason = strings.TrimSpace(e.Reason)

	if contentAuditExceptionFieldTooLong(e.ScopeType, maxContentAuditExceptionScopeTypeRunes) {
		return invalidContentAuditException("scope_type exceeds %d characters", maxContentAuditExceptionScopeTypeRunes)
	}
	if contentAuditExceptionFieldTooLong(e.ScopeRef, maxContentAuditExceptionScopeRefRunes) {
		return invalidContentAuditException("scope_ref exceeds %d characters", maxContentAuditExceptionScopeRefRunes)
	}
	if contentAuditExceptionFieldTooLong(e.RuleID, maxContentAuditExceptionRuleIDRunes) {
		return invalidContentAuditException("rule_id exceeds %d characters", maxContentAuditExceptionRuleIDRunes)
	}
	if contentAuditExceptionFieldTooLong(e.RuleRef, maxContentAuditExceptionRuleRefRunes) {
		return invalidContentAuditException("rule_ref exceeds %d characters", maxContentAuditExceptionRuleRefRunes)
	}
	if contentAuditExceptionFieldTooLong(e.Reason, maxContentAuditExceptionReasonRunes) {
		return invalidContentAuditException("reason exceeds %d characters", maxContentAuditExceptionReasonRunes)
	}

	switch e.ScopeType {
	case "tenant":
	case "project", "user":
		if e.ScopeRef == "" {
			return invalidContentAuditException("scope_ref is required for %s scope", e.ScopeType)
		}
	case "rule":
		if e.RuleRef == "" && e.RuleID == "" {
			return invalidContentAuditException("rule_ref or rule_id is required for rule scope")
		}
	case "key_v1", "actor_department_v1":
		if e.ScopeRef == "" {
			return invalidContentAuditException("scope_ref is required for %s scope", e.ScopeType)
		}
	default:
		return invalidContentAuditException("scope_type must be tenant, project, user, rule, key_v1, or actor_department_v1")
	}
	if e.IncludeChildren && e.ScopeType != "actor_department_v1" {
		return invalidContentAuditException("include_children is only valid for actor_department_v1 scope")
	}

	if e.Decision == "" {
		e.Decision = "audit"
	}
	if e.Reason == "" {
		return invalidContentAuditException("reason is required")
	}
	// nil = 永久（迁移 109）；非 nil 必须在未来
	if e.ExpiresAt != nil && !e.ExpiresAt.After(time.Now()) {
		return invalidContentAuditException("expires_at must be in the future")
	}
	if e.Decision != "allow" && e.Decision != "audit" {
		return invalidContentAuditException("decision must be allow or audit")
	}
	if e.RuleRef == "" {
		e.RuleRef = e.RuleID // 旧调用方兼容：只给了 rule_id
	}
	return nil
}

// CreateContentAuditException creates a content/data exception.
func (r *RuleRepository) CreateContentAuditException(ctx context.Context, e *ContentAuditException) error {
	if err := NormalizeAndValidateContentAuditException(e); err != nil {
		return err
	}
	// The row id is the primary key and the exception_id the engine validates in every rule pack; an empty
	// one stores a row nobody can address and makes the engine reject the whole pack.
	if strings.TrimSpace(e.ID) == "" {
		e.ID = "cex_" + uuid.NewString()
	}
	if e.RuleRef != "" {
		// rule_ref 若指向本租户的自定义规则（rules.id），同步填 rule_id（外键）并做
		// 既有确定性红线类别校验；查不到则视为内置规则引用，rule_id 保持空。
		var matchConfig []byte
		err := r.db.QueryRow(ctx, `
			SELECT r.match_config_json
			FROM rules r
			JOIN rule_sets rs ON rs.id = r.rule_set_id
			WHERE r.id = $1 AND rs.tenant_id = $2
		`, e.RuleRef, e.TenantID).Scan(&matchConfig)
		switch {
		case err == nil:
			e.RuleID = e.RuleRef
		case err == pgx.ErrNoRows:
			e.RuleID = "" // 内置规则引用：不落外键列
		default:
			return fmt.Errorf("failed to load exception rule: %w", err)
		}
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO content_audit_exceptions (id, tenant_id, scope_type, scope_ref, include_children, rule_id, rule_ref, decision, reason, expires_at, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8, $9, $10, $11, $12)
	`, e.ID, e.TenantID, e.ScopeType, e.ScopeRef, e.IncludeChildren, e.RuleID, e.RuleRef, e.Decision, e.Reason, e.ExpiresAt, e.Enabled, e.CreatedBy)
	if err != nil {
		return fmt.Errorf("create content audit exception: %w", err)
	}
	return nil
}

// DisableContentAuditException soft-deletes a content audit exception for management UI.
func (r *RuleRepository) DisableContentAuditException(ctx context.Context, tenantID, id string) (bool, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return false, fmt.Errorf("tenant_id and exception id are required")
	}
	result, err := r.db.Exec(ctx, `
		UPDATE content_audit_exceptions
		SET enabled = FALSE, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND enabled = TRUE
	`, tenantID, id)
	if err != nil {
		return false, fmt.Errorf("disable content audit exception: %w", err)
	}
	return result.RowsAffected() > 0, nil
}
