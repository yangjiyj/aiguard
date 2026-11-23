// Package aicontentlabel 实现 AI 生成内容标识：显式标识文案与隐式水印。
//
// 隐式水印是一段零宽字符，编码请求号与 HMAC 防伪标签，网关在交付层追加到回复正文，
// 控制面据此做泄露溯源。安全引擎只按格式识别（不持有密钥），见 prompt_stego.py。
//
// 帧格式（87 个字符）：
//
//	U+2063 U+2063 | 84 个数据字符 | U+2064
//
// 数据为 21 字节：格式字节（0 = 裸 UUID，1 = "req_" 前缀）+ UUID 16 字节 + HMAC 前 4 字节，
// 每字节拆成 4 个 2 位符号，高位在前，符号 0..3 依次是 U+200B U+200C U+200D U+2060。
package aicontentlabel

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	// markRune 是 INVISIBLE SEPARATOR，两个连写作为帧起点；endRune 是 INVISIBLE PLUS，作为帧终点。
	markRune rune = 0x2063
	endRune  rune = 0x2064

	frameStart = string(markRune) + string(markRune)
	frameEnd   = string(endRune)

	formatBareUUID  byte = 0
	formatReqPrefix byte = 1

	requestIDPrefix = "req_"

	payloadBytes = 21
	tagBytes     = 4
	dataSymbols  = payloadBytes * 4
	// FrameRunes 是一个完整水印帧的字符数。
	FrameRunes = 2 + dataSymbols + 1

	keyDerivationLabel = "jjdguard-ai-content-watermark-v1"
)

// 2 位符号 0..3：ZERO WIDTH SPACE、ZERO WIDTH NON-JOINER、ZERO WIDTH JOINER、WORD JOINER。
var symbols = [4]rune{0x200B, 0x200C, 0x200D, 0x2060}

// DeriveKey 从内部共享密钥派生水印密钥。secret 为空时返回 nil，调用方应不加水印。
func DeriveKey(secret string) []byte {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(keyDerivationLabel))
	return mac.Sum(nil)
}

// Encode 返回 requestID 对应的水印帧。requestID 必须是 UUID 或 "req_"+UUID，
// key 不能为空；否则返回 false，调用方不加水印。
func Encode(requestID string, key []byte) (string, bool) {
	if len(key) == 0 {
		return "", false
	}
	format, id, ok := parseRequestID(requestID)
	if !ok {
		return "", false
	}
	payload := make([]byte, 0, payloadBytes)
	payload = append(payload, format)
	payload = append(payload, id[:]...)
	payload = append(payload, tag(key, format, id)...)

	var b strings.Builder
	b.Grow(FrameRunes * 3)
	b.WriteString(frameStart)
	for _, v := range payload {
		for shift := 6; shift >= 0; shift -= 2 {
			b.WriteRune(symbols[(v>>uint(shift))&0x3])
		}
	}
	b.WriteString(frameEnd)
	return b.String(), true
}

// Frame 是在文本里找到的一个格式完整的水印帧。
type Frame struct {
	// Start、End 是帧在原文本中的字节偏移，End 不含。
	Start, End int
	format     byte
	id         uuid.UUID
	tag        []byte
}

// Find 返回文本里所有格式完整的水印帧（按出现顺序）。只看格式，不校验 HMAC。
func Find(text string) []Frame {
	var frames []Frame
	offset := 0
	for {
		idx := strings.Index(text[offset:], frameStart)
		if idx < 0 {
			return frames
		}
		start := offset + idx
		if frame, ok := decodeAt(text, start); ok {
			frames = append(frames, frame)
			offset = frame.End
			continue
		}
		// U+2063 是 3 字节；从下一个字符继续找，覆盖 "U+2063 U+2063 U+2063 ..." 的情形。
		offset = start + utf8.RuneLen(markRune)
	}
}

// Verify 校验帧的 HMAC，通过时返回原始请求号。
func Verify(frame Frame, key []byte) (string, bool) {
	if len(key) == 0 || len(frame.tag) != tagBytes {
		return "", false
	}
	if !hmac.Equal(frame.tag, tag(key, frame.format, frame.id)) {
		return "", false
	}
	switch frame.format {
	case formatBareUUID:
		return frame.id.String(), true
	case formatReqPrefix:
		return requestIDPrefix + frame.id.String(), true
	}
	return "", false
}

// Strip 去掉文本里所有格式完整的水印帧。
func Strip(text string) string {
	frames := Find(text)
	if len(frames) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, f := range frames {
		b.WriteString(text[last:f.Start])
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String()
}

func parseRequestID(requestID string) (byte, uuid.UUID, bool) {
	requestID = strings.TrimSpace(requestID)
	format := formatBareUUID
	if strings.HasPrefix(requestID, requestIDPrefix) {
		format = formatReqPrefix
		requestID = strings.TrimPrefix(requestID, requestIDPrefix)
	}
	// 只接受规范的 36 字符小写形式，保证解码后能原样还原请求号。
	if len(requestID) != 36 {
		return 0, uuid.UUID{}, false
	}
	id, err := uuid.Parse(requestID)
	if err != nil || id.String() != requestID {
		return 0, uuid.UUID{}, false
	}
	return format, id, true
}

func tag(key []byte, format byte, id uuid.UUID) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{format})
	mac.Write(id[:])
	return mac.Sum(nil)[:tagBytes]
}

func symbolValue(r rune) (byte, bool) {
	for i, s := range symbols {
		if r == s {
			return byte(i), true
		}
	}
	return 0, false
}

func decodeAt(text string, start int) (Frame, bool) {
	pos := start + len(frameStart)
	payload := make([]byte, payloadBytes)
	for i := 0; i < dataSymbols; i++ {
		r, size := utf8.DecodeRuneInString(text[pos:])
		v, ok := symbolValue(r)
		if !ok {
			return Frame{}, false
		}
		payload[i/4] = payload[i/4]<<2 | v
		pos += size
	}
	if !strings.HasPrefix(text[pos:], frameEnd) {
		return Frame{}, false
	}
	pos += len(frameEnd)
	format := payload[0]
	if format != formatBareUUID && format != formatReqPrefix {
		return Frame{}, false
	}
	var id uuid.UUID
	copy(id[:], payload[1:17])
	return Frame{
		Start:  start,
		End:    pos,
		format: format,
		id:     id,
		tag:    append([]byte(nil), payload[17:]...),
	}, true
}
