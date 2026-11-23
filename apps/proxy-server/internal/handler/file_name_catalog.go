package handler

import (
	"container/list"
	"strings"
	"sync"
)

// fileNameCatalog 在进程内缓存「租户+厂商+file-id → 人类可读文件名」。
//
// 背景：网页大模型上传文件时，首个请求载荷里 file-id 与文件名同时出现；之后的对话轮次往往
// 只带裸 file-id。本目录把上传时见过的文件名跨请求记下来，使后续轮次的访问留存也能还原成文
// 件名，而不是把裸 file-id 当成"引用编码"展示，满足"不要出现编码与ID、要给人看"的要求。
//
// 设计取舍（与 ca_manager certCache / whitelist cache 同构）：
//   - 进程内 mutex + map，零数据库迁移；proxy-server 单容器，进程内即够用。
//   - 有界（maxFileNameCatalogEntries）+ LRU 淘汰，避免无限增长。
//   - 按 租户+厂商 隔离 key，杜绝把 A 租户的文件名串到 B 租户的留存里。
//   - 随容器重启清空（可接受）；后续可平滑升级为 DB-backed catalog。
const maxFileNameCatalogEntries = 50000

type fileNameCatalog struct {
	mu      sync.Mutex
	max     int
	entries map[string]*list.Element
	order   *list.List // 最近使用排最前；淘汰从队尾取
}

type fileNameCatalogEntry struct {
	key  string
	name string
}

func newFileNameCatalog(max int) *fileNameCatalog {
	if max <= 0 {
		max = maxFileNameCatalogEntries
	}
	return &fileNameCatalog{
		max:     max,
		entries: make(map[string]*list.Element),
		order:   list.New(),
	}
}

// defaultFileNameCatalog 是 proxy.go 接入点使用的进程级单例。
var defaultFileNameCatalog = newFileNameCatalog(maxFileNameCatalogEntries)
var defaultRetainedUploadCatalog = newRetainedUploadCatalog(maxFileNameCatalogEntries)

func fileNameCatalogKey(tenant, provider, referenceID string) string {
	return strings.Join([]string{
		strings.TrimSpace(tenant),
		strings.TrimSpace(strings.ToLower(provider)),
		strings.TrimSpace(referenceID),
	}, "\x00")
}

func (c *fileNameCatalog) put(tenant, provider, referenceID, fileName string) {
	referenceID = strings.TrimSpace(referenceID)
	fileName = strings.TrimSpace(fileName)
	if referenceID == "" || fileName == "" {
		return
	}
	key := fileNameCatalogKey(tenant, provider, referenceID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		el.Value.(*fileNameCatalogEntry).name = fileName
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&fileNameCatalogEntry{key: key, name: fileName})
	c.entries[key] = el
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*fileNameCatalogEntry).key)
	}
}

func (c *fileNameCatalog) get(tenant, provider, referenceID string) (string, bool) {
	referenceID = strings.TrimSpace(referenceID)
	if referenceID == "" {
		return "", false
	}
	key := fileNameCatalogKey(tenant, provider, referenceID)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return "", false
	}
	c.order.MoveToFront(el)
	return el.Value.(*fileNameCatalogEntry).name, true
}

// resolveAttachmentFileNames 先把本次内容里「file-id+文件名」配对登记进目录，再用目录把仅带
// 裸 file-id 的附件还原成人类可读文件名，并把留存文本里的裸 id 替换为文件名。跨请求生效：上传
// 那次登记，后续只带 id 的轮次还原。content 按值传入、返回修改后的副本（Attachments 原地改、
// Text 重新赋值）。
func resolveAttachmentFileNames(catalog *fileNameCatalog, tenant, provider string, content ExtractedContent) ExtractedContent {
	if catalog == nil || len(content.Attachments) == 0 {
		return content
	}
	// 第一遍：登记本次出现的 id+name 配对（含本次上传），让同一批里靠后的裸引用也能命中。
	for _, att := range content.Attachments {
		if att.ReferenceID != "" && att.FileName != "" {
			catalog.put(tenant, provider, att.ReferenceID, att.FileName)
		}
	}
	// 第二遍：把仅有裸 file-id、无文件名的附件还原成目录里记过的文件名，并清掉文本里的裸 id。
	for i := range content.Attachments {
		att := &content.Attachments[i]
		if att.FileName != "" || att.ReferenceID == "" {
			continue
		}
		name, ok := catalog.get(tenant, provider, att.ReferenceID)
		if !ok {
			continue
		}
		att.FileName = name
		if att.ContentType == "" || att.ContentType == "reference/file-id" {
			if inferred := inferContentType(name, nil); inferred != "" {
				att.ContentType = inferred
			}
		}
		if content.Text != "" {
			content.Text = strings.ReplaceAll(content.Text, att.ReferenceID, name)
		}
	}
	return content
}

type retainedUploadCatalog struct {
	mu      sync.Mutex
	max     int
	entries map[string]*list.Element
	order   *list.List
}

type retainedUploadCatalogEntry struct {
	key      string
	metadata retainedAttachmentMetadata
}

func newRetainedUploadCatalog(max int) *retainedUploadCatalog {
	if max <= 0 {
		max = maxFileNameCatalogEntries
	}
	return &retainedUploadCatalog{
		max:     max,
		entries: make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *retainedUploadCatalog) put(tenant, provider string, metadata retainedAttachmentMetadata) {
	if c == nil || strings.TrimSpace(metadata.ReferenceID) == "" || strings.TrimSpace(metadata.ObjectKey) == "" {
		return
	}
	key := fileNameCatalogKey(tenant, provider, metadata.ReferenceID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		el.Value.(*retainedUploadCatalogEntry).metadata = metadata
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&retainedUploadCatalogEntry{key: key, metadata: metadata})
	c.entries[key] = el
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*retainedUploadCatalogEntry).key)
	}
}

func (c *retainedUploadCatalog) get(tenant, provider, referenceID string) (retainedAttachmentMetadata, bool) {
	if c == nil || strings.TrimSpace(referenceID) == "" {
		return retainedAttachmentMetadata{}, false
	}
	key := fileNameCatalogKey(tenant, provider, referenceID)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return retainedAttachmentMetadata{}, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*retainedUploadCatalogEntry).metadata, true
}

// resolveRetainedContents 用进程级目录对一对（请求/响应）留存内容做文件名还原，供 proxy.go 的
// WriteAccessContentLog 接入点直接调用。tenant/provider 取自 MITM 入口的 tenantID 与
// providerMatch.Provider，确保按租户、按厂商隔离。
func resolveRetainedContents(tenant, provider string, reqContent, respContent ExtractedContent) (ExtractedContent, ExtractedContent) {
	return resolveAttachmentFileNames(defaultFileNameCatalog, tenant, provider, reqContent),
		resolveAttachmentFileNames(defaultFileNameCatalog, tenant, provider, respContent)
}
