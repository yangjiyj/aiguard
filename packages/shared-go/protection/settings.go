package protection

import (
	"fmt"
	"strings"
)

type Setting struct {
	Action Action         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

// Settings 是一个租户已保存的防护项（键 → 设置）。缺键取注册表默认值。
type Settings map[string]Setting

func (s Settings) ActionFor(key string) Action {
	item, ok := Lookup(key)
	if !ok {
		return ""
	}
	if setting, ok := s[key]; ok && item.Allows(setting.Action) {
		return setting.Action
	}
	return item.Default
}

func (s Settings) IntParam(key, param string) int {
	item, ok := Lookup(key)
	if !ok {
		return 0
	}
	for _, p := range item.Params {
		if p.Key != param || p.Kind != ParamInt {
			continue
		}
		def, _ := p.Default.(int)
		raw, ok := s[key].Params[param]
		if !ok {
			return def
		}
		v, ok := toInt(raw)
		if !ok || v < p.Min || (p.Max > 0 && v > p.Max) {
			return def
		}
		return v
	}
	return 0
}

func (s Settings) StringListParam(key, param string) []string {
	item, ok := Lookup(key)
	if !ok {
		return nil
	}
	for _, p := range item.Params {
		if p.Key != param || p.Kind != ParamStringList {
			continue
		}
		raw, ok := s[key].Params[param]
		if !ok {
			def, _ := p.Default.([]string)
			return append([]string(nil), def...)
		}
		return toStringList(raw)
	}
	return nil
}

// Normalize 校验一次更新：未知键、该项不允许的动作、越界参数一律报错。
func Normalize(in map[string]Setting) (map[string]Setting, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("items must not be empty")
	}
	out := make(map[string]Setting, len(in))
	for key, setting := range in {
		key = strings.TrimSpace(key)
		item, ok := Lookup(key)
		if !ok {
			return nil, fmt.Errorf("unknown protection item %q", key)
		}
		action := Action(strings.ToLower(strings.TrimSpace(string(setting.Action))))
		if !item.Allows(action) {
			return nil, fmt.Errorf("action %q not allowed for %s", action, key)
		}
		params := map[string]any{}
		for name, raw := range setting.Params {
			var spec *Param
			for i := range item.Params {
				if item.Params[i].Key == name {
					spec = &item.Params[i]
				}
			}
			if spec == nil {
				return nil, fmt.Errorf("unknown param %q for %s", name, key)
			}
			switch spec.Kind {
			case ParamInt:
				v, ok := toInt(raw)
				if !ok || v < spec.Min || (spec.Max > 0 && v > spec.Max) {
					return nil, fmt.Errorf("param %s.%s out of range", key, name)
				}
				params[name] = v
			case ParamStringList:
				list := toStringList(raw)
				if len(list) > 64 {
					return nil, fmt.Errorf("param %s.%s too long", key, name)
				}
				params[name] = list
			}
		}
		out[key] = Setting{Action: action, Params: params}
	}
	return out, nil
}

func toInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	default:
		return 0, false
	}
}

func toStringList(raw any) []string {
	var out []string
	switch v := raw.(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	cleaned := out[:0]
	for _, s := range out {
		if s = strings.TrimSpace(s); s != "" && len(s) <= 128 {
			cleaned = append(cleaned, s)
		}
	}
	return cleaned
}
