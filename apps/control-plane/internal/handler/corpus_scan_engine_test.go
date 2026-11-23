package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/corpusscan"
)

func TestCorpusEngineClientSendsInternalTokenAndDecodesBatch(t *testing.T) {
	var gotToken, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, gotPath = r.Header.Get(InternalAPISecretHeader), r.URL.Path
		var body struct {
			Items []corpusscan.EngineItem `json:"items"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[{"id":"`+body.Items[0].ID+`","findings":[{"type":"phone_cn","label":"手机号","start":0,"end":11,"severity":"medium"}],"masked_text":"[手机号]","incomplete":false}],"rule_pack_version":"rp-1","engine_build":"b"}`)
	}))
	defer server.Close()
	client := newCorpusEngineClient(server.URL, "secret")
	batch, err := client.Scan(context.Background(), []corpusscan.EngineItem{{ID: "0", Text: "13812345678"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "secret" || gotPath != "/internal/corpus/scan" {
		t.Fatalf("token=%q path=%q", gotToken, gotPath)
	}
	if batch.RulePackVersion != "rp-1" || len(batch.Items) != 1 || batch.Items[0].MaskedText != "[手机号]" {
		t.Fatalf("batch = %+v", batch)
	}
}

func TestCorpusEngineClientErrorsAreUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":{"code":"corpus_scan_capacity_overflow"}}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()
	if _, err := newCorpusEngineClient(server.URL, "secret").Scan(context.Background(), []corpusscan.EngineItem{{ID: "0", Text: "x"}}); !errors.Is(err, errCorpusEngineUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := newCorpusEngineClient("", "").Scan(context.Background(), nil); !errors.Is(err, errCorpusEngineUnavailable) {
		t.Fatalf("unconfigured err = %v", err)
	}
}

func TestCorpusEngineClientExtractUploadsThenExtracts(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/scan-objects/":
			if r.URL.Query().Get("tenant_id") != "tenant-a" {
				t.Errorf("tenant = %q", r.URL.Query().Get("tenant_id"))
			}
			_, _ = io.WriteString(w, `{"object_id":"`+strings.Repeat("o", 32)+`","sha256":"x","size":3}`)
		case "/internal/corpus/extract":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["declared_type"] != "docx" || body["tenant_id"] != "tenant-a" {
				t.Errorf("extract body = %+v", body)
			}
			if r.URL.Query().Get("fail") != "" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			_, _ = io.WriteString(w, `{"text":"正文","real_type":"zip","complete":true,"truncated":false,"chars":2,"incomplete_reasons":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	result, err := newCorpusEngineClient(server.URL, "secret").Extract(context.Background(), "tenant-a", "corpus_1", "a.docx", "docx", []byte("PK\x03"))
	if err != nil || result.Text != "正文" || !result.Complete {
		t.Fatalf("result = %+v err=%v", result, err)
	}
	if strings.Join(calls, ",") != "PUT /scan-objects/,POST /internal/corpus/extract" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestCorpusEngineClientExtractRejectedIsTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/scan-objects/" {
			_, _ = io.WriteString(w, `{"object_id":"`+strings.Repeat("o", 32)+`"}`)
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"detail":{"code":"extract_failed"}}`)
	}))
	defer server.Close()
	if _, err := newCorpusEngineClient(server.URL, "secret").Extract(context.Background(), "t", "j", "a.pdf", "pdf", []byte("%PDF")); !errors.Is(err, errCorpusExtractRejected) {
		t.Fatalf("err = %v", err)
	}
}
