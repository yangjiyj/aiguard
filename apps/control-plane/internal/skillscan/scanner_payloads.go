package skillscan

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func scanPayloadText(name, hash string, payload []byte) []Finding {
	binaryPayload := !utf8.Valid(payload) || bytes.ContainsRune(payload, '\x00')
	if !binaryPayload && !isScannableText(name) && !bytes.HasPrefix(bytes.TrimPrefix(payload, []byte{0xef, 0xbb, 0xbf}), []byte("#!")) {
		return nil
	}
	views := []string{}
	if decoded := decodeUTF16Payload(payload); decoded != "" {
		views = append(views, decoded)
	}
	views = append(views, string(payload))
	var findings []Finding
	seen := map[string]bool{}
	for _, view := range views {
		var current []Finding
		if strings.EqualFold(path.Ext(name), ".ipynb") && json.Valid([]byte(view)) {
			current = append(current, scanText(name, hash, view)...)
			var notebook struct {
				Cells []struct {
					Type   string          `json:"cell_type"`
					Source json.RawMessage `json:"source"`
				} `json:"cells"`
			}
			if json.Unmarshal([]byte(view), &notebook) == nil {
				for index, cell := range notebook.Cells {
					if cell.Type != "code" {
						continue
					}
					var text string
					if json.Unmarshal(cell.Source, &text) != nil {
						var pieces []string
						if json.Unmarshal(cell.Source, &pieces) != nil {
							continue
						}
						text = strings.Join(pieces, "")
					}
					current = append(current, scanText(fmt.Sprintf("%s#cell-%d", name, index+1), hash, text)...)
				}
			}
		} else {
			current = scanText(name, hash, view)
		}
		for _, finding := range current {
			key := fmt.Sprintf("%s:%s:%d", finding.Type, finding.File, finding.Line)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func decodeUTF16Payload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(payload, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
		payload = payload[2:]
	case bytes.HasPrefix(payload, []byte{0xfe, 0xff}):
		order = binary.BigEndian
		payload = payload[2:]
	default:
		evenZero, oddZero := 0, 0
		for i, value := range payload {
			if value == 0 {
				if i%2 == 0 {
					evenZero++
				} else {
					oddZero++
				}
			}
		}
		if oddZero > len(payload)/4 && oddZero > evenZero {
			order = binary.LittleEndian
		}
		if evenZero > len(payload)/4 && evenZero > oddZero {
			order = binary.BigEndian
		}
		if order == nil {
			return ""
		}
	}
	units := make([]uint16, 0, len(payload)/2)
	for i := 0; i+1 < len(payload); i += 2 {
		units = append(units, order.Uint16(payload[i:i+2]))
	}
	return string(utf16.Decode(units))
}
