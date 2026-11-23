package audit_chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// This admits PostgreSQL numeric's supported decimal range while bounding
	// expansion of otherwise short, untrusted scientific-notation tokens.
	maxCanonicalNumberLength  = 1 << 20
	maxCanonicalPayloadLength = 1 << 20
	maxCanonicalJSONDepth     = 10000
)

// CanonicalPayload serializes a value once using its normal JSON contract, then
// strictly decodes and canonicalizes that representation. Object keys are
// sorted recursively and numbers retain their exact decimal value. Typed
// structs, slices, maps and RawMessage therefore share the same representation.
// Nil values remain null; empty containers remain empty containers.
func CanonicalPayload(payload any) (json.RawMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal audit payload: %w", err)
	}
	if len(raw) > maxCanonicalPayloadLength {
		return nil, errors.New("audit payload exceeds canonicalization byte budget")
	}
	decoded, err := decodeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("decode audit payload: %w", err)
	}
	canonical, err := canonicalDecoded(decoded)
	if err != nil {
		return nil, fmt.Errorf("canonicalize audit payload: %w", err)
	}
	return json.RawMessage(canonical), nil
}

// DecodePayload reads an audit payload object or null without converting JSON
// numbers to float64. Duplicate object keys and trailing data are rejected at
// every nesting level, including keys that use equivalent JSON escapes.
func DecodePayload(raw []byte) (map[string]any, error) {
	decoded, err := decodeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("decode audit payload: %w", err)
	}
	if decoded == nil {
		return nil, nil
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("audit payload must be an object or null")
	}
	return object, nil
}

func decodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON contains invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("invalid trailing JSON data: %w", err)
		}
		return nil, errors.New("trailing JSON value")
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxCanonicalJSONDepth {
		return nil, errors.New("JSON nesting exceeds canonicalization limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("JSON object key must be a string")
				}
				if _, exists := object[key]; exists {
					return nil, errors.New("duplicate JSON object key")
				}
				child, err := decodeJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if closeToken, err := decoder.Token(); err != nil || closeToken != json.Delim('}') {
				if err != nil {
					return nil, err
				}
				return nil, errors.New("invalid JSON object terminator")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := decodeJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if closeToken, err := decoder.Token(); err != nil || closeToken != json.Delim(']') {
				if err != nil {
					return nil, err
				}
				return nil, errors.New("invalid JSON array terminator")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case nil, bool, string, json.Number:
		return value, nil
	default:
		return nil, fmt.Errorf("unexpected JSON token type %T", token)
	}
}

func canonicalDecoded(value any) ([]byte, error) {
	return appendCanonicalJSON(nil, value)
}

// Each append reserves the remaining payload budget before allocation. In
// particular, exponential numbers and escaped strings cannot each consume the
// full per-value bound repeatedly inside one payload.
func appendBoundedJSON(dst, value []byte) ([]byte, error) {
	if len(dst) > maxCanonicalPayloadLength || len(value) > maxCanonicalPayloadLength-len(dst) {
		return nil, errors.New("audit payload exceeds canonicalization byte budget")
	}
	return append(dst, value...), nil
}

func appendJSONString(dst []byte, value string) ([]byte, error) {
	remaining := maxCanonicalPayloadLength - len(dst)
	if remaining < 2 || len(value) > remaining-2 {
		return nil, errors.New("audit payload exceeds canonicalization byte budget")
	}
	encodedLength := 2
	for _, r := range value {
		switch r {
		case '<', '>', '&', '\u2028', '\u2029':
			encodedLength += 6
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			encodedLength += 2
		default:
			if r < 0x20 {
				encodedLength += 6
			} else {
				encodedLength += utf8.RuneLen(r)
			}
		}
		if encodedLength > remaining {
			return nil, errors.New("audit payload exceeds canonicalization byte budget")
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return appendBoundedJSON(dst, encoded)
}

func appendCanonicalJSON(dst []byte, value any) ([]byte, error) {
	if len(dst) > maxCanonicalPayloadLength {
		return nil, errors.New("audit payload exceeds canonicalization byte budget")
	}
	switch value := value.(type) {
	case nil:
		return appendBoundedJSON(dst, []byte("null"))
	case bool:
		if value {
			return appendBoundedJSON(dst, []byte("true"))
		}
		return appendBoundedJSON(dst, []byte("false"))
	case string:
		return appendJSONString(dst, value)
	case json.Number:
		number, err := normalizeJSONNumber(string(value), maxCanonicalPayloadLength-len(dst))
		if err != nil {
			return nil, err
		}
		return appendBoundedJSON(dst, []byte(number))
	case []any:
		var err error
		dst, err = appendBoundedJSON(dst, []byte("["))
		if err != nil {
			return nil, err
		}
		for i, child := range value {
			if i != 0 {
				dst, err = appendBoundedJSON(dst, []byte(","))
				if err != nil {
					return nil, err
				}
			}
			dst, err = appendCanonicalJSON(dst, child)
			if err != nil {
				return nil, err
			}
		}
		return appendBoundedJSON(dst, []byte("]"))
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var err error
		dst, err = appendBoundedJSON(dst, []byte("{"))
		if err != nil {
			return nil, err
		}
		for i, key := range keys {
			if i != 0 {
				dst, err = appendBoundedJSON(dst, []byte(","))
				if err != nil {
					return nil, err
				}
			}
			dst, err = appendJSONString(dst, key)
			if err != nil {
				return nil, err
			}
			dst, err = appendBoundedJSON(dst, []byte(":"))
			if err != nil {
				return nil, err
			}
			dst, err = appendCanonicalJSON(dst, value[key])
			if err != nil {
				return nil, err
			}
		}
		return appendBoundedJSON(dst, []byte("}"))
	default:
		return nil, fmt.Errorf("unexpected decoded JSON type %T", value)
	}
}

// normalizeJSONNumber is only called for tokens validated by the JSON decoder.
// A number is coefficient * 10^power. Reducing the coefficient without using
// floating point gives a unique exact decimal representation, including values
// outside float64's precision and exponent range.
func normalizeJSONNumber(number string, remaining int) (string, error) {
	negative := strings.HasPrefix(number, "-")
	if negative {
		number = number[1:]
	}
	exponent := int64(0)
	if index := strings.IndexAny(number, "eE"); index >= 0 {
		var err error
		exponent, err = strconv.ParseInt(number[index+1:], 10, 64)
		if err != nil {
			return "", errors.New("JSON number exponent exceeds canonicalization limit")
		}
		number = number[:index]
	}
	fractionDigits := int64(0)
	if index := strings.IndexByte(number, '.'); index >= 0 {
		fractionDigits = int64(len(number) - index - 1)
		number = number[:index] + number[index+1:]
	}
	coefficient := strings.TrimLeft(number, "0")
	if coefficient == "" {
		return "0", nil
	}
	if exponent < math.MinInt64+fractionDigits {
		return "", errors.New("JSON number exponent exceeds canonicalization limit")
	}
	power := exponent - fractionDigits
	reduced := strings.TrimRight(coefficient, "0")
	removed := int64(len(coefficient) - len(reduced))
	if power > math.MaxInt64-removed {
		return "", errors.New("JSON number exponent exceeds canonicalization limit")
	}
	power += removed
	coefficient = reduced
	digits := int64(len(coefficient))
	if power > math.MaxInt64-digits {
		return "", errors.New("JSON number exponent exceeds canonicalization limit")
	}
	point := digits + power
	signLength := int64(0)
	if negative {
		signLength = 1
	}
	var outputLength int64
	switch {
	case point <= 0:
		if point < -maxCanonicalNumberLength || digits > maxCanonicalNumberLength {
			return "", errors.New("JSON number exceeds canonicalization limit")
		}
		outputLength = signLength + 2 - point + digits
	case point >= digits:
		if point > maxCanonicalNumberLength {
			return "", errors.New("JSON number exceeds canonicalization limit")
		}
		outputLength = signLength + point
	default:
		outputLength = signLength + digits + 1
	}
	if outputLength > maxCanonicalNumberLength || outputLength > int64(remaining) {
		return "", errors.New("JSON number exceeds canonicalization limit")
	}
	var result strings.Builder
	result.Grow(int(outputLength))
	if negative {
		result.WriteByte('-')
	}
	switch {
	case point <= 0:
		result.WriteString("0.")
		result.WriteString(strings.Repeat("0", int(-point)))
		result.WriteString(coefficient)
	case point >= digits:
		result.WriteString(coefficient)
		result.WriteString(strings.Repeat("0", int(point-digits)))
	default:
		result.WriteString(coefficient[:int(point)])
		result.WriteByte('.')
		result.WriteString(coefficient[int(point):])
	}
	return result.String(), nil
}
