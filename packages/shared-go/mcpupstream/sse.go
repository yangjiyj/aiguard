package mcpupstream

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

// 容量常量默认值与 gateway-core 现有取值一致（maxMCPSSEEventBytes / maxMCPSSECumulativeBytes）。
const (
	DefaultMaxEventBytes  = 1 << 20
	DefaultMaxStreamBytes = 16 << 20
	DefaultMaxBodyBytes   = 4 << 20
)

var (
	errEventTooLarge  = Errorf(KindCapacity, "上游 SSE 单事件超过容量上限")
	errStreamTooLarge = Errorf(KindCapacity, "上游 SSE 累计响应超过容量上限")
)

type sseEvent struct {
	Name string // 空表示缺省的 message
	Data string
	ID   string
}

// splitSSELines 按 SSE 规范切行：\n、\r\n、\r 都是行结束符。
func splitSSELines(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			return i + 1, data[:i], nil
		case '\r':
			if i+1 < len(data) {
				if data[i+1] == '\n' {
					return i + 2, data[:i], nil
				}
				return i + 1, data[:i], nil
			}
			if atEOF {
				return i + 1, data[:i], nil
			}
			return 0, nil, nil // 需要再读一个字节判断是否 \r\n
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

type countingReader struct {
	r     io.Reader
	n     int64
	limit int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		return n, errStreamTooLarge
	}
	return n, err
}

// parseSSE 解析事件流。容忍：注释行/心跳、缺省事件名、多行 data、CRLF/CR、BOM、末尾事件缺空行。
// handle 返回 stop=true 提前结束。maxEvent 限制单事件 data 字节数，maxStream 限制累计读取字节数。
func parseSSE(r io.Reader, maxEvent int, maxStream int64, handle func(sseEvent) (bool, error)) error {
	if maxEvent <= 0 {
		maxEvent = DefaultMaxEventBytes
	}
	if maxStream <= 0 {
		maxStream = DefaultMaxStreamBytes
	}
	cr := &countingReader{r: r, limit: maxStream}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 0, 64*1024), maxEvent+4096)
	sc.Split(splitSSELines)

	var name, id string
	var data []string
	size := 0
	first := true
	dispatch := func() (bool, error) {
		defer func() { name, id, data, size = "", "", nil, 0 }()
		if len(data) == 0 {
			return false, nil
		}
		return handle(sseEvent{Name: name, Data: strings.Join(data, "\n"), ID: id})
	}
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, "\uFEFF")
			first = false
		}
		if line == "" {
			if stop, err := dispatch(); stop || err != nil {
				return err
			}
			continue
		}
		if line[0] == ':' {
			continue // 注释 / 心跳
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			name = value
		case "data":
			size += len(value) + 1
			if size > maxEvent {
				return errEventTooLarge
			}
			data = append(data, value)
		case "id":
			if !strings.ContainsRune(value, 0) {
				id = value
			}
		}
	}
	if err := sc.Err(); err != nil {
		switch {
		case errors.Is(err, bufio.ErrTooLong):
			return errEventTooLarge
		case errors.Is(err, errStreamTooLarge):
			return errStreamTooLarge
		}
		return err
	}
	if stop, err := dispatch(); stop || err != nil { // 流结束时最后一个事件可能没有收尾空行
		return err
	}
	return nil
}

// decodedBody 处理 gzip：我们请求 identity，但容忍上游强制 gzip 的响应
// （Go 只会自动解压它自己请求的 gzip，此处手动兜底）。
func decodedBody(resp *http.Response) (io.ReadCloser, error) {
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") && !resp.Uncompressed {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, Errorf(KindParse, "上游响应声明 gzip 但无法解压")
		}
		return struct {
			io.Reader
			io.Closer
		}{zr, resp.Body}, nil
	}
	return resp.Body, nil
}

// readLimited 读取至多 limit 字节；超过时返回 tooLarge=true。
func readLimited(r io.Reader, limit int64) (body []byte, tooLarge bool, err error) {
	body, err = io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return nil, true, nil
	}
	return body, false, nil
}

// peek 读取响应体前 n 字节（用于错误摘要），不报错。
func peek(resp *http.Response, n int64) []byte {
	rc, err := decodedBody(resp)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(rc, n))
	return bytes.TrimSpace(b)
}
