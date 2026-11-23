package provider

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const maxBedrockEventFrameBytes = 16 << 20

type bedrockEventFrame struct {
	headers map[string]string
	payload []byte
}

func readBedrockEventFrame(reader io.Reader) (bedrockEventFrame, error) {
	var prelude [12]byte
	if _, err := io.ReadFull(reader, prelude[:]); err != nil {
		return bedrockEventFrame{}, err
	}
	totalLength := binary.BigEndian.Uint32(prelude[0:4])
	headersLength := binary.BigEndian.Uint32(prelude[4:8])
	if totalLength < 16 || totalLength > maxBedrockEventFrameBytes {
		return bedrockEventFrame{}, fmt.Errorf("bedrock: invalid event-stream frame length %d", totalLength)
	}
	if headersLength > totalLength-16 {
		return bedrockEventFrame{}, fmt.Errorf("bedrock: invalid event-stream header length %d", headersLength)
	}
	if want, got := binary.BigEndian.Uint32(prelude[8:12]), crc32.ChecksumIEEE(prelude[:8]); want != got {
		return bedrockEventFrame{}, errors.New("bedrock: event-stream prelude checksum mismatch")
	}
	rest := make([]byte, int(totalLength)-12)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return bedrockEventFrame{}, fmt.Errorf("bedrock: truncated event-stream frame: %w", err)
	}
	frame := append(prelude[:], rest...)
	if want, got := binary.BigEndian.Uint32(frame[len(frame)-4:]), crc32.ChecksumIEEE(frame[:len(frame)-4]); want != got {
		return bedrockEventFrame{}, errors.New("bedrock: event-stream message checksum mismatch")
	}
	headersEnd := 12 + int(headersLength)
	headers, err := parseBedrockEventHeaders(frame[12:headersEnd])
	if err != nil {
		return bedrockEventFrame{}, err
	}
	return bedrockEventFrame{headers: headers, payload: frame[headersEnd : len(frame)-4]}, nil
}

func parseBedrockEventHeaders(raw []byte) (map[string]string, error) {
	headers := make(map[string]string)
	for offset := 0; offset < len(raw); {
		if offset+1 > len(raw) {
			return nil, errors.New("bedrock: truncated event-stream header name length")
		}
		nameLength := int(raw[offset])
		offset++
		if offset+nameLength+1 > len(raw) {
			return nil, errors.New("bedrock: truncated event-stream header")
		}
		name := string(raw[offset : offset+nameLength])
		offset += nameLength
		valueType := raw[offset]
		offset++
		var value string
		switch valueType {
		case 0:
			value = "true"
		case 1:
			value = "false"
		case 2:
			if offset+1 > len(raw) {
				return nil, errors.New("bedrock: truncated byte header")
			}
			value = fmt.Sprintf("%d", raw[offset])
			offset++
		case 3:
			if offset+2 > len(raw) {
				return nil, errors.New("bedrock: truncated short header")
			}
			value = fmt.Sprintf("%d", binary.BigEndian.Uint16(raw[offset:offset+2]))
			offset += 2
		case 4:
			if offset+4 > len(raw) {
				return nil, errors.New("bedrock: truncated int header")
			}
			value = fmt.Sprintf("%d", binary.BigEndian.Uint32(raw[offset:offset+4]))
			offset += 4
		case 5, 8:
			if offset+8 > len(raw) {
				return nil, errors.New("bedrock: truncated long/timestamp header")
			}
			value = fmt.Sprintf("%d", binary.BigEndian.Uint64(raw[offset:offset+8]))
			offset += 8
		case 6, 7:
			if offset+2 > len(raw) {
				return nil, errors.New("bedrock: truncated string header")
			}
			length := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
			offset += 2
			if offset+length > len(raw) {
				return nil, errors.New("bedrock: truncated string header value")
			}
			value = string(raw[offset : offset+length])
			offset += length
		case 9:
			if offset+16 > len(raw) {
				return nil, errors.New("bedrock: truncated UUID header")
			}
			value = string(raw[offset : offset+16])
			offset += 16
		default:
			return nil, fmt.Errorf("bedrock: unsupported event-stream header value type %d", valueType)
		}
		headers[name] = value
	}
	return headers, nil
}

func accumulateBedrockEventStream(reader io.Reader, envelope *modelrouter.RequestEnvelope, startedAt time.Time) ([]byte, error) {
	contentByIndex := make(map[int]bedrockResponseContent)
	toolInput := make(map[int]string)
	var response bedrockConverseResponse
	receivedStop := false
	recordedTTFT := false
	for {
		frame, err := readBedrockEventFrame(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if exceptionType := frame.headers[":exception-type"]; exceptionType != "" {
			message := extractErrorMessage(json.RawMessage(frame.payload))
			return nil, fmt.Errorf("bedrock: upstream stream exception %s: %s", exceptionType, message)
		}
		switch frame.headers[":event-type"] {
		case "contentBlockStart":
			var event struct {
				ContentBlockIndex int `json:"contentBlockIndex"`
				Start             struct {
					ToolUse *bedrockToolUse `json:"toolUse"`
				} `json:"start"`
			}
			if err := json.Unmarshal(frame.payload, &event); err != nil {
				return nil, err
			}
			if event.Start.ToolUse != nil {
				contentByIndex[event.ContentBlockIndex] = bedrockResponseContent{ToolUse: event.Start.ToolUse}
			}
		case "contentBlockDelta":
			var event struct {
				ContentBlockIndex int `json:"contentBlockIndex"`
				Delta             struct {
					Text    string `json:"text"`
					ToolUse *struct {
						Input string `json:"input"`
					} `json:"toolUse"`
				} `json:"delta"`
			}
			if err := json.Unmarshal(frame.payload, &event); err != nil {
				return nil, fmt.Errorf("bedrock: invalid contentBlockDelta: %w", err)
			}
			if event.Delta.ToolUse != nil {
				block := contentByIndex[event.ContentBlockIndex]
				if block.ToolUse == nil {
					return nil, errors.New("bedrock: tool input arrived before tool start")
				}
				toolInput[event.ContentBlockIndex] += event.Delta.ToolUse.Input
			}
			if event.Delta.Text != "" || event.Delta.ToolUse != nil {
				block := contentByIndex[event.ContentBlockIndex]
				block.Text += event.Delta.Text
				contentByIndex[event.ContentBlockIndex] = block
				if !recordedTTFT {
					recordUpstreamTTFT(envelope, startedAt)
					recordedTTFT = true
				}
			}
		case "messageStop":
			var event struct {
				StopReason string `json:"stopReason"`
			}
			if err := json.Unmarshal(frame.payload, &event); err != nil {
				return nil, fmt.Errorf("bedrock: invalid messageStop: %w", err)
			}
			response.StopReason = event.StopReason
			receivedStop = true
		case "metadata":
			var event struct {
				Usage bedrockUsage `json:"usage"`
			}
			if err := json.Unmarshal(frame.payload, &event); err != nil {
				return nil, fmt.Errorf("bedrock: invalid metadata event: %w", err)
			}
			response.Usage = event.Usage
		}
	}
	if !receivedStop {
		return nil, errors.New("bedrock: event stream ended before messageStop")
	}
	response.Output.Message.Role = "assistant"
	indices := make([]int, 0, len(contentByIndex))
	for index := range contentByIndex {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	for _, index := range indices {
		block := contentByIndex[index]
		if block.ToolUse != nil {
			raw := toolInput[index]
			if raw == "" {
				raw = "{}"
			}
			var object map[string]any
			if json.Unmarshal([]byte(raw), &object) != nil || object == nil {
				return nil, errors.New("bedrock: streamed tool arguments are not an object")
			}
			block.ToolUse.Input = json.RawMessage(raw)
		}
		response.Output.Message.Content = append(response.Output.Message.Content, block)
	}
	if response.Usage.TotalTokens == 0 {
		response.Usage.TotalTokens = response.Usage.InputTokens + response.Usage.OutputTokens
	}
	return json.Marshal(response)
}
