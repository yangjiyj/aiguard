package corpusscan

import (
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// jsonlTextFields 是规格 5.2 列出的已知文本字段（顶层）。messages 单独处理。
var jsonlTextFields = map[string]bool{
	"instruction": true, "input": true, "output": true, "prompt": true, "completion": true,
	"chosen": true, "rejected": true, "text": true, "system": true,
}

const maxJSONDepth = 64

// jsonlParser 是只读的 JSON 词法扫描器：校验整行是一个合法 JSON 对象，同时记下已知文本字段里
// 每个字符串字面量的字节区间。不构造 map，所以改写时键顺序和原始字节都不变。
type jsonlParser struct {
	data  []byte
	pos   int
	depth int
	units []Unit
}

func parseJSONLLine(line []byte) ([]Unit, error) {
	// Windows 工具导出的文件常以 UTF-8 BOM 开头：跳过它解析，区间再加回偏移，改写时 BOM 原样保留。
	offset := 0
	if len(line) >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF {
		offset = 3
	}
	p := &jsonlParser{data: line[offset:]}
	p.skipSpace()
	if p.pos >= len(p.data) || p.data[p.pos] != '{' {
		return nil, ErrUnparsable
	}
	if err := p.parseTopObject(); err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, ErrUnparsable
	}
	for i := range p.units {
		p.units[i].Start += offset
		p.units[i].End += offset
	}
	return p.units, nil
}

func (p *jsonlParser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonlParser) expect(c byte) error {
	p.skipSpace()
	if p.pos >= len(p.data) || p.data[p.pos] != c {
		return ErrUnparsable
	}
	p.pos++
	return nil
}

// parseTopObject 解析顶层对象，按键分派：已知文本字段、messages、其余（只校验）。
func (p *jsonlParser) parseTopObject() error {
	return p.parseObject(func(key string) func() error {
		switch {
		case key == "messages":
			return func() error { return p.parseMessages("messages") }
		case jsonlTextFields[key]:
			return func() error { return p.parseTextValue(key) }
		}
		return nil
	})
}

// parseObject 解析一个对象；pick 为某个键返回自定义的值解析函数，返回 nil 时按普通值校验。
func (p *jsonlParser) parseObject(pick func(key string) func() error) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer p.leave()
	if err := p.expect('{'); err != nil {
		return err
	}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return nil
	}
	for {
		p.skipSpace()
		key, _, _, err := p.parseString()
		if err != nil {
			return err
		}
		if err := p.expect(':'); err != nil {
			return err
		}
		p.skipSpace()
		var custom func() error
		if pick != nil {
			custom = pick(key)
		}
		if custom != nil {
			err = custom()
		} else {
			err = p.parseValue()
		}
		if err != nil {
			return err
		}
		p.skipSpace()
		if p.pos >= len(p.data) {
			return ErrUnparsable
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return nil
		default:
			return ErrUnparsable
		}
	}
}

// parseArray 解析数组，item 为每个元素调用（传入下标）；item 为 nil 时按普通值校验。
func (p *jsonlParser) parseArray(item func(index int) error) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer p.leave()
	if err := p.expect('['); err != nil {
		return err
	}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return nil
	}
	for index := 0; ; index++ {
		p.skipSpace()
		var err error
		if item != nil {
			err = item(index)
		} else {
			err = p.parseValue()
		}
		if err != nil {
			return err
		}
		p.skipSpace()
		if p.pos >= len(p.data) {
			return ErrUnparsable
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return nil
		default:
			return ErrUnparsable
		}
	}
}

func (p *jsonlParser) enter() error {
	p.depth++
	if p.depth > maxJSONDepth {
		return ErrUnparsable
	}
	return nil
}

func (p *jsonlParser) leave() { p.depth-- }

// parseTextValue 处理已知文本字段的值：字符串直接扫描；数组（偏好数据 chosen/rejected 常见的
// 消息列表）按消息处理；其他类型只校验。
func (p *jsonlParser) parseTextValue(field string) error {
	p.skipSpace()
	if p.pos >= len(p.data) {
		return ErrUnparsable
	}
	switch p.data[p.pos] {
	case '"':
		return p.recordString(field)
	case '[':
		return p.parseMessages(field)
	}
	return p.parseValue()
}

// parseMessages 处理 messages 数组：每个元素的 content 为字符串，或内容块数组里的 text。
func (p *jsonlParser) parseMessages(field string) error {
	p.skipSpace()
	if p.pos >= len(p.data) || p.data[p.pos] != '[' {
		return p.parseValue()
	}
	return p.parseArray(func(index int) error {
		prefix := field + "[" + strconv.Itoa(index) + "]"
		if p.pos >= len(p.data) || p.data[p.pos] != '{' {
			return p.parseValue()
		}
		return p.parseObject(func(key string) func() error {
			if key != "content" {
				return nil
			}
			return func() error { return p.parseContent(prefix + ".content") }
		})
	})
}

// parseContent 处理 content：字符串，或 [{"type":"text","text":"..."}] 这样的内容块数组。
func (p *jsonlParser) parseContent(field string) error {
	p.skipSpace()
	if p.pos >= len(p.data) {
		return ErrUnparsable
	}
	switch p.data[p.pos] {
	case '"':
		return p.recordString(field)
	case '[':
		return p.parseArray(func(index int) error {
			if p.pos >= len(p.data) || p.data[p.pos] != '{' {
				return p.parseValue()
			}
			blockField := field + "[" + strconv.Itoa(index) + "].text"
			return p.parseObject(func(key string) func() error {
				if key != "text" {
					return nil
				}
				return func() error {
					p.skipSpace()
					if p.pos < len(p.data) && p.data[p.pos] == '"' {
						return p.recordString(blockField)
					}
					return p.parseValue()
				}
			})
		})
	}
	return p.parseValue()
}

func (p *jsonlParser) recordString(field string) error {
	value, start, end, err := p.parseString()
	if err != nil {
		return err
	}
	if value != "" {
		p.units = append(p.units, Unit{Field: field, Start: start, End: end, Text: value, kind: kindJSONString})
	}
	return nil
}

func (p *jsonlParser) parseValue() error {
	p.skipSpace()
	if p.pos >= len(p.data) {
		return ErrUnparsable
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject(nil)
	case c == '[':
		return p.parseArray(nil)
	case c == '"':
		_, _, _, err := p.parseString()
		return err
	case c == 't':
		return p.literal("true")
	case c == 'f':
		return p.literal("false")
	case c == 'n':
		return p.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	}
	return ErrUnparsable
}

func (p *jsonlParser) literal(word string) error {
	if !strings.HasPrefix(string(p.data[p.pos:min(len(p.data), p.pos+len(word))]), word) {
		return ErrUnparsable
	}
	p.pos += len(word)
	return nil
}

func (p *jsonlParser) parseNumber() error {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	digits := func() int {
		n := 0
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if p.pos < len(p.data) && p.data[p.pos] == '0' {
		p.pos++
		if p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			return ErrUnparsable
		}
	} else if digits() == 0 {
		return ErrUnparsable
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return ErrUnparsable
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return ErrUnparsable
		}
	}
	if p.pos == start {
		return ErrUnparsable
	}
	return nil
}

// parseString 解析字符串字面量，返回解码后的值和字面量（含引号）的字节区间。
func (p *jsonlParser) parseString() (string, int, int, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != '"' {
		return "", 0, 0, ErrUnparsable
	}
	start := p.pos
	p.pos++
	var b strings.Builder
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return b.String(), start, p.pos, nil
		case c == '\\':
			if p.pos+1 >= len(p.data) {
				return "", 0, 0, ErrUnparsable
			}
			esc := p.data[p.pos+1]
			p.pos += 2
			switch esc {
			case '"', '\\', '/':
				b.WriteByte(esc)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, ok := p.readHex4()
				if !ok {
					return "", 0, 0, ErrUnparsable
				}
				if utf16.IsSurrogate(r) {
					// 必须紧跟低位代理，否则是孤立代理，Python 侧无法按码点对齐，记为不可解析。
					if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", 0, 0, ErrUnparsable
					}
					p.pos += 2
					low, ok := p.readHex4()
					if !ok {
						return "", 0, 0, ErrUnparsable
					}
					combined := utf16.DecodeRune(r, low)
					if combined == utf8.RuneError {
						return "", 0, 0, ErrUnparsable
					}
					r = combined
				}
				b.WriteRune(r)
			default:
				return "", 0, 0, ErrUnparsable
			}
		case c < 0x20:
			return "", 0, 0, ErrUnparsable
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", 0, 0, ErrUnparsable
			}
			b.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
	return "", 0, 0, ErrUnparsable
}

func (p *jsonlParser) readHex4() (rune, bool) {
	if p.pos+4 > len(p.data) {
		return 0, false
	}
	value, err := strconv.ParseUint(string(p.data[p.pos:p.pos+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	p.pos += 4
	return rune(value), true
}

// encodeJSONString 把替换后的文本编码成 JSON 字符串字面量。非 ASCII 字符原样输出（与常见语料一致），
// 只转义 JSON 要求的字符；不转义 HTML 字符，保证未命中的部分与原文写法尽量一致。
func encodeJSONString(value string) []byte {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte("0123456789abcdef"[r>>4])
				b.WriteByte("0123456789abcdef"[r&0xf])
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return []byte(b.String())
}

// parseCSVLine 按 RFC 4180 拆分一行（不支持单元格内换行：含换行的引号字段会被判为坏行）。
// 每个非空单元格是一个扫描单位，字段名为 col:<从 1 开始的列号>。
func parseCSVLine(line []byte) ([]Unit, error) {
	var units []Unit
	pos := 0
	column := 0
	for {
		column++
		start := pos
		var text string
		quoted := false
		if pos < len(line) && line[pos] == '"' {
			quoted = true
			var b strings.Builder
			pos++
			closed := false
			for pos < len(line) {
				if line[pos] == '"' {
					if pos+1 < len(line) && line[pos+1] == '"' {
						b.WriteByte('"')
						pos += 2
						continue
					}
					pos++
					closed = true
					break
				}
				b.WriteByte(line[pos])
				pos++
			}
			if !closed || (pos < len(line) && line[pos] != ',') {
				return nil, ErrUnparsable
			}
			text = b.String()
		} else {
			for pos < len(line) && line[pos] != ',' {
				if line[pos] == '"' {
					return nil, ErrUnparsable
				}
				pos++
			}
			text = string(line[start:pos])
		}
		if text != "" {
			units = append(units, Unit{Field: "col:" + strconv.Itoa(column), Start: start, End: pos, Text: text, kind: kindCSVCell, quoted: quoted})
		}
		if pos >= len(line) {
			return units, nil
		}
		pos++ // 跳过逗号
	}
}

func encodeCSVCell(value string, quoted bool) []byte {
	if !quoted && !strings.ContainsAny(value, ",\"\r\n") && !strings.HasPrefix(value, " ") && !strings.HasSuffix(value, " ") {
		return []byte(value)
	}
	return []byte(`"` + strings.ReplaceAll(value, `"`, `""`) + `"`)
}

// ValidReplacements 检查替换下标在文本范围内、按顺序且互不重叠。
func ValidReplacements(text string, replacements []Replacement) bool {
	runes := utf8.RuneCountInString(text)
	last := 0
	for _, r := range replacements {
		if r.Start < last || r.Start < 0 || r.End <= r.Start || r.End > runes {
			return false
		}
		last = r.End
	}
	return true
}
