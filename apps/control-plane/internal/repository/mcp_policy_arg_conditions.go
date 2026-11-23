package repository

// W1 1.12：MCP 策略参数条件（JSONPath 子集）。
//
// 本文件在 control-plane repository 与 gateway-core handler 两处逐字相同（仅 package 行不同），
// 两侧测试共用同一组黄金向量，保证控制面校验/预演与网关运行时求值口径一致。
//
// 路径语法：以 $ 开头，后接若干段：.name（[A-Za-z0-9_-]+）、['任意键']、[n]（非负下标）、[*]（数组全部元素）。
// 键名区分大小写。最多 16 段。
//
// 运算符：eq ne in not_in contains prefix suffix regex gt gte lt lte exists not_exists。
// contains 对字符串做子串匹配，对数组做“含某元素”匹配；regex 为 RE2，长度 ≤ 256。
//
// 量词：路径可能解析出多个值（[*] 或数组 contains）。
//   - 放行类策略（allow）：解析出的每一个值都必须满足，且至少解析出一个值（防止诱饵值绕过）；
//   - 其余动作（audit/confirm/block）：任一值满足即命中（防止把危险值藏进数组）。
//   - not_exists 只看是否解析出值，与量词无关。
// 一条策略的多个条件之间为 AND。参数不是合法 JSON 对象时，任何条件都不成立。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// MCPArgCondition 是一条参数条件。Value 为任意 JSON（exists/not_exists 不需要）。
type MCPArgCondition struct {
	Path  string          `json:"path"`
	Op    string          `json:"op"`
	Value json.RawMessage `json:"value,omitempty"`
}

const (
	mcpArgMaxConditions = 8
	mcpArgMaxSegments   = 16
	mcpArgMaxPathLen    = 256
	mcpArgMaxRegexLen   = 256
	mcpArgMaxValueLen   = 4096
)

type mcpArgSegment struct {
	key      string
	index    int
	isIndex  bool
	wildcard bool
}

var mcpArgNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+`)

func parseMCPArgPath(path string) ([]mcpArgSegment, error) {
	if len(path) > mcpArgMaxPathLen {
		return nil, errors.New("path too long")
	}
	if !strings.HasPrefix(path, "$") {
		return nil, errors.New("path must start with $")
	}
	rest := path[1:]
	var segs []mcpArgSegment
	for rest != "" {
		if len(segs) >= mcpArgMaxSegments {
			return nil, errors.New("path has too many segments")
		}
		switch {
		case strings.HasPrefix(rest, "."):
			name := mcpArgNameRe.FindString(rest[1:])
			if name == "" {
				return nil, fmt.Errorf("invalid field name near %q", rest)
			}
			segs = append(segs, mcpArgSegment{key: name})
			rest = rest[1+len(name):]
		case strings.HasPrefix(rest, "['"):
			end := strings.Index(rest[2:], "']")
			if end < 0 {
				return nil, errors.New("unterminated quoted key")
			}
			key := rest[2 : 2+end]
			if key == "" || strings.ContainsAny(key, `'\`) {
				return nil, errors.New("invalid quoted key")
			}
			segs = append(segs, mcpArgSegment{key: key})
			rest = rest[2+end+2:]
		case strings.HasPrefix(rest, "[*]"):
			segs = append(segs, mcpArgSegment{wildcard: true})
			rest = rest[3:]
		case strings.HasPrefix(rest, "["):
			end := strings.Index(rest, "]")
			if end < 0 {
				return nil, errors.New("unterminated index")
			}
			n, err := strconv.Atoi(rest[1:end])
			if err != nil || n < 0 || rest[1] == '+' {
				return nil, fmt.Errorf("invalid index %q", rest[1:end])
			}
			segs = append(segs, mcpArgSegment{index: n, isIndex: true})
			rest = rest[end+1:]
		default:
			return nil, fmt.Errorf("unexpected %q", rest)
		}
	}
	if len(segs) == 0 {
		return nil, errors.New("path must select a field")
	}
	return segs, nil
}

func mcpArgResolve(root interface{}, segs []mcpArgSegment) []interface{} {
	current := []interface{}{root}
	for _, seg := range segs {
		var next []interface{}
		for _, node := range current {
			switch {
			case seg.wildcard:
				if arr, ok := node.([]interface{}); ok {
					next = append(next, arr...)
				}
			case seg.isIndex:
				if arr, ok := node.([]interface{}); ok && seg.index < len(arr) {
					next = append(next, arr[seg.index])
				}
			default:
				if obj, ok := node.(map[string]interface{}); ok {
					if v, exists := obj[seg.key]; exists {
						next = append(next, v)
					}
				}
			}
		}
		current = next
		if len(current) == 0 {
			return nil
		}
	}
	return current
}

func mcpArgDecode(raw []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

func mcpArgNumber(v interface{}) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func mcpArgEqual(a, b interface{}) bool {
	if fa, ok := mcpArgNumber(a); ok {
		fb, ok := mcpArgNumber(b)
		return ok && fa == fb
	}
	if _, ok := mcpArgNumber(b); ok {
		return false
	}
	return reflect.DeepEqual(a, b)
}

type mcpArgCompiled struct {
	segs  []mcpArgSegment
	op    string
	value interface{}
	re    *regexp.Regexp
}

func compileMCPArgCondition(c MCPArgCondition) (mcpArgCompiled, error) {
	segs, err := parseMCPArgPath(strings.TrimSpace(c.Path))
	if err != nil {
		return mcpArgCompiled{}, fmt.Errorf("path %q: %w", c.Path, err)
	}
	out := mcpArgCompiled{segs: segs, op: strings.TrimSpace(c.Op)}
	needsValue := out.op != "exists" && out.op != "not_exists"
	if needsValue {
		if len(bytes.TrimSpace(c.Value)) == 0 {
			return out, fmt.Errorf("op %s requires value", out.op)
		}
		if len(c.Value) > mcpArgMaxValueLen {
			return out, errors.New("value too large")
		}
		v, err := mcpArgDecode(c.Value)
		if err != nil {
			return out, fmt.Errorf("value is not valid JSON: %w", err)
		}
		out.value = v
	}
	switch out.op {
	case "eq", "ne", "contains":
	case "exists", "not_exists":
	case "in", "not_in":
		if _, ok := out.value.([]interface{}); !ok {
			return out, fmt.Errorf("op %s requires an array value", out.op)
		}
	case "prefix", "suffix":
		if _, ok := out.value.(string); !ok {
			return out, fmt.Errorf("op %s requires a string value", out.op)
		}
	case "regex":
		pattern, ok := out.value.(string)
		if !ok || pattern == "" || len(pattern) > mcpArgMaxRegexLen {
			return out, errors.New("regex requires a non-empty string of at most 256 chars")
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return out, fmt.Errorf("invalid regex: %w", err)
		}
		out.re = re
	case "gt", "gte", "lt", "lte":
		if _, ok := mcpArgNumber(out.value); !ok {
			return out, fmt.Errorf("op %s requires a number value", out.op)
		}
	default:
		return out, fmt.Errorf("unknown op %q", c.Op)
	}
	return out, nil
}

// ValidateMCPArgConditions 校验一组条件（保存策略前调用）。
func ValidateMCPArgConditions(conds []MCPArgCondition) error {
	if len(conds) > mcpArgMaxConditions {
		return fmt.Errorf("at most %d arg conditions", mcpArgMaxConditions)
	}
	for i, c := range conds {
		if _, err := compileMCPArgCondition(c); err != nil {
			return fmt.Errorf("arg_conditions[%d]: %w", i, err)
		}
	}
	return nil
}

func (c mcpArgCompiled) test(v interface{}) bool {
	switch c.op {
	case "eq":
		return mcpArgEqual(v, c.value)
	case "ne":
		return !mcpArgEqual(v, c.value)
	case "in", "not_in":
		found := false
		for _, candidate := range c.value.([]interface{}) {
			if mcpArgEqual(v, candidate) {
				found = true
				break
			}
		}
		return found == (c.op == "in")
	case "contains":
		if s, ok := v.(string); ok {
			sub, ok := c.value.(string)
			return ok && strings.Contains(s, sub)
		}
		if arr, ok := v.([]interface{}); ok {
			for _, e := range arr {
				if mcpArgEqual(e, c.value) {
					return true
				}
			}
		}
		return false
	case "prefix":
		s, ok := v.(string)
		return ok && strings.HasPrefix(s, c.value.(string))
	case "suffix":
		s, ok := v.(string)
		return ok && strings.HasSuffix(s, c.value.(string))
	case "regex":
		s, ok := v.(string)
		return ok && c.re.MatchString(s)
	case "gt", "gte", "lt", "lte":
		f, ok := mcpArgNumber(v)
		if !ok {
			return false
		}
		limit, _ := mcpArgNumber(c.value)
		switch c.op {
		case "gt":
			return f > limit
		case "gte":
			return f >= limit
		case "lt":
			return f < limit
		default:
			return f <= limit
		}
	case "exists":
		return true
	}
	return false
}

// MatchMCPArgConditions 判断参数是否满足全部条件。action 决定量词（见文件头）。
// 空条件恒为 true；参数不是合法 JSON 对象或条件非法时恒为 false。
func MatchMCPArgConditions(conds []MCPArgCondition, argumentsJSON string, action string) bool {
	if len(conds) == 0 {
		return true
	}
	root, err := mcpArgDecode([]byte(argumentsJSON))
	if err != nil {
		return false
	}
	if _, ok := root.(map[string]interface{}); !ok {
		return false
	}
	requireAll := strings.EqualFold(strings.TrimSpace(action), "allow")
	for _, raw := range conds {
		c, err := compileMCPArgCondition(raw)
		if err != nil {
			return false
		}
		values := mcpArgResolve(root, c.segs)
		if c.op == "not_exists" {
			if len(values) != 0 {
				return false
			}
			continue
		}
		if len(values) == 0 {
			return false
		}
		matched := requireAll
		for _, v := range values {
			ok := c.test(v)
			if requireAll && !ok {
				matched = false
				break
			}
			if !requireAll && ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
