package handler

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// errMCPUnsupportedEncoding 表示上游回了网关无法安全处理的 Content-Encoding。
var errMCPUnsupportedEncoding = errors.New("MCP 上游返回了不支持的压缩编码，请联系厂商或在上游关闭压缩")

// errMCPDecodedTooLarge 表示解压后的数据超过容量上限（防 zip 炸弹）。
var errMCPDecodedTooLarge = errors.New("MCP 上游压缩响应解压后超过容量上限")

// mcpDecodeUpstreamResponse 在响应带 Content-Encoding 时把 Body 替换成“有界解压”读取器，并清理相关头。
//   - 仅支持 gzip（含 x-gzip）；identity / 空直接放行；br、zstd、deflate、compress 等一律明确拒绝，
//     绝不把压缩字节当成 JSON / SSE 去校验或原样透传给下游；
//   - 解压后的字节数受调用方原有的容量上限约束：这里用 mcpDecodeLimit 兜底（取非流式与 SSE 累计上限中的较大者），
//     具体分支的校验仍会按各自的上限再检查一次；
//   - 解压后 Content-Length 失效，Content-Encoding 一并删除，下游拿到的是已校验的明文。
func mcpDecodeUpstreamResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	encodings := mcpContentEncodings(resp.Header)
	if len(encodings) == 0 {
		return nil
	}
	if len(encodings) != 1 || (encodings[0] != "gzip" && encodings[0] != "x-gzip") {
		return errMCPUnsupportedEncoding
	}
	// 复审 M-3：202/204 通知应答或 Content-Length==0 的空体，上游常常仍带 Content-Encoding: gzip 头却没有任何字节；
	// gzip.NewReader 读空体会得到 EOF，被误判成「无法解压」而 502。这类响应根本没有可解压的内容，跳过解压并清掉编码头即可。
	// 长度未知的 200 响应不在此列：它声明了 gzip 却没有字节，仍按原有严格判定处理。
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusAccepted || resp.ContentLength == 0 {
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		return nil
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("MCP 上游响应声明 gzip 但无法解压: %w", errMCPUnsupportedEncoding)
	}
	resp.Body = &mcpBoundedGzipBody{zr: zr, raw: resp.Body, remaining: mcpDecodeLimit}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return nil
}

// mcpDecodeLimit 是解压后单个响应的绝对上限：不小于任何分支自己的上限（SSE 累计 16 MB 最大）。
var mcpDecodeLimit = int64(maxMCPSSECumulativeBytes) + 1

func mcpContentEncodings(h http.Header) []string {
	var out []string
	for _, raw := range h.Values("Content-Encoding") {
		for _, part := range strings.Split(raw, ",") {
			if p := strings.ToLower(strings.TrimSpace(part)); p != "" && p != "identity" {
				out = append(out, p)
			}
		}
	}
	return out
}

// mcpBoundedGzipBody 读取解压后的数据，超过上限即返回 errMCPDecodedTooLarge。
type mcpBoundedGzipBody struct {
	zr        *gzip.Reader
	raw       io.Closer
	remaining int64
}

func (b *mcpBoundedGzipBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errMCPDecodedTooLarge
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.zr.Read(p)
	b.remaining -= int64(n)
	if b.remaining <= 0 && err == nil {
		// 恰好读满上限：再探测一个字节，确认确实还有数据才算超限。
		var probe [1]byte
		if m, perr := b.zr.Read(probe[:]); m > 0 || (perr != nil && perr != io.EOF) {
			return n, errMCPDecodedTooLarge
		}
		return n, io.EOF
	}
	return n, err
}

func (b *mcpBoundedGzipBody) Close() error {
	_ = b.zr.Close()
	return b.raw.Close()
}
