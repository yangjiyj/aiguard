package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Querier 是工具访问数据库的唯一入口：实现方保证只读事务与语句超时（见 exec.go）。
// 测试里可以用内存假实现替代。
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) ([]map[string]any, error)
}

// Tool 是一个只读诊断工具，L2 排查树与 L3 模型共用同一批工具。
type Tool interface {
	Name() string            // 如 "get_request"
	Description() string     // 给模型看的中文说明
	Schema() json.RawMessage // 参数 JSON Schema
	AdminOnly() bool         // 员工不可调用
	Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error)
}

// MaxToolOutput 是单次工具输出上限，超出时由 Registry.Call 截断。
const MaxToolOutput = 32 << 10

var (
	ErrUnknownTool = errors.New("unknown tool")
	ErrForbidden   = errors.New("tool not allowed for this scope")
)

type Registry struct{ tools map[string]Tool }

func NewRegistry(tools ...Tool) *Registry {
	r := &Registry{tools: map[string]Tool{}}
	for _, t := range tools {
		r.tools[t.Name()] = t
	}
	return r
}

// For 返回该身份可用的工具，按名字排序，供 L3 生成 tools 列表。
func (r *Registry) For(scope Scope) []Tool {
	var out []Tool
	for _, t := range r.tools {
		if t.AdminOnly() && !scope.IsAdmin {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Call 执行工具并统一做权限检查、脱敏与截断，返回可直接放进 Step 的结果。
func (r *Registry) Call(ctx context.Context, q Querier, scope Scope, name string, args json.RawMessage) Step {
	step := Step{Tool: name, Args: args}
	t, ok := r.tools[name]
	if !ok {
		step.Err = ErrUnknownTool.Error()
		return step
	}
	if t.AdminOnly() && !scope.IsAdmin {
		step.Err = ErrForbidden.Error()
		return step
	}
	out, err := t.Run(ctx, q, scope, args)
	if err != nil {
		step.Err = err.Error()
		return step
	}
	red := Redact(string(out))
	if len(red) > MaxToolOutput {
		trunc, _ := json.Marshal(map[string]any{"truncated": true, "partial": red[:MaxToolOutput]})
		step.Output = trunc
		return step
	}
	if !json.Valid([]byte(red)) {
		step.Err = fmt.Sprintf("tool %s returned invalid json", name)
		return step
	}
	step.Output = json.RawMessage(red)
	return step
}
