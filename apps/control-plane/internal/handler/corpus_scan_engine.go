package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/corpusscan"
)

// 单个批次（最多 256 条、4 MB）的检测预算；引擎侧独立线程池的默认预算是 60 秒。
const corpusEngineScanTimeout = 90 * time.Second

// 文档上传与提取：上传沿用 scan-objects 的 100 MB 上限，提取最长 120 秒。
const corpusEngineExtractTimeout = 150 * time.Second

// corpusEngineResponseLimit 是一批结果的上限：替换后的文本不超过原文太多，留足余量。
const corpusEngineResponseLimit = 32 << 20

// corpusEngineClient 调用 security-engine 的 /internal/corpus/*（规格 5.3）。
type corpusEngineClient struct {
	base *securityEngineClient
}

func newCorpusEngineClient(baseURL, token string) *corpusEngineClient {
	return &corpusEngineClient{base: newSecurityEngineClient(baseURL, token)}
}

var errCorpusEngineUnavailable = errors.New("security engine corpus scan is unavailable")

func (c *corpusEngineClient) configured() bool {
	return c != nil && c.base != nil && c.base.baseURL != "" && c.base.internalToken != ""
}

func (c *corpusEngineClient) Scan(ctx context.Context, items []corpusscan.EngineItem) (corpusscan.EngineBatch, error) {
	var batch corpusscan.EngineBatch
	if !c.configured() {
		return batch, errCorpusEngineUnavailable
	}
	body, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		return batch, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.baseURL+"/internal/corpus/scan", bytes.NewReader(body))
	if err != nil {
		return batch, err
	}
	c.base.setRequestHeaders(req)
	resp, err := (&http.Client{Timeout: corpusEngineScanTimeout}).Do(req)
	if err != nil {
		return batch, fmt.Errorf("%w: %v", errCorpusEngineUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return batch, fmt.Errorf("%w: status %d", errCorpusEngineUnavailable, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, corpusEngineResponseLimit+1))
	if err != nil || len(data) > corpusEngineResponseLimit {
		return batch, fmt.Errorf("%w: response too large or unreadable", errCorpusEngineUnavailable)
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		return batch, fmt.Errorf("%w: invalid response", errCorpusEngineUnavailable)
	}
	return batch, nil
}

type corpusExtractResult struct {
	Text              string   `json:"text"`
	RealType          string   `json:"real_type"`
	Complete          bool     `json:"complete"`
	Truncated         bool     `json:"truncated"`
	Chars             int      `json:"chars"`
	IncompleteReasons []string `json:"incomplete_reasons"`
}

// errCorpusExtractRejected 表示文件本身不可提取（类型不符、损坏、加密），任务失败而不是重试。
var errCorpusExtractRejected = errors.New("document text extraction rejected")

// Extract 把文档字节交给引擎临时区，提取正文；引擎读完即删除对象。
func (c *corpusEngineClient) Extract(ctx context.Context, tenantID, jobID, fileName, format string, data []byte) (corpusExtractResult, error) {
	var result corpusExtractResult
	if !c.configured() {
		return result, errCorpusEngineUnavailable
	}
	objectID, err := c.base.uploadScanObject(ctx, tenantID, "corpus:"+jobID, fileName, "application/octet-stream", data)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errCorpusEngineUnavailable, err)
	}
	body, _ := json.Marshal(map[string]string{"tenant_id": tenantID, "object_id": objectID, "declared_type": format})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.baseURL+"/internal/corpus/extract", bytes.NewReader(body))
	if err != nil {
		c.base.consumeScanObject(context.Background(), tenantID, objectID)
		return result, err
	}
	c.base.setRequestHeaders(req)
	resp, err := (&http.Client{Timeout: corpusEngineExtractTimeout}).Do(req)
	if err != nil {
		c.base.consumeScanObject(context.Background(), tenantID, objectID)
		return result, fmt.Errorf("%w: %v", errCorpusEngineUnavailable, err)
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, corpusEngineResponseLimit+1))
	if err != nil || len(data) > corpusEngineResponseLimit {
		return result, fmt.Errorf("%w: response too large or unreadable", errCorpusEngineUnavailable)
	}
	switch {
	case resp.StatusCode == http.StatusUnprocessableEntity:
		return result, errCorpusExtractRejected
	case resp.StatusCode != http.StatusOK:
		if resp.StatusCode == http.StatusNotFound {
			c.base.consumeScanObject(context.Background(), tenantID, objectID)
		}
		return result, fmt.Errorf("%w: status %d", errCorpusEngineUnavailable, resp.StatusCode)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("%w: invalid response", errCorpusEngineUnavailable)
	}
	return result, nil
}
