package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCatalogSnapshotRejectsAmbiguousOrPartialResponses(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":[],"success":false}`, `{"data":[],"code":500}`, `{"data":[],"object":"error"}`, `{"data":null}`, `{"data":[],"error":{"message":"bad"}}`, `{"data":[],"has_more":true,"last_id":"a"}`, `{"data":[],"next":"cursor"}`, `{"data":[],"next_page":"cursor"}`, `{"data":[],"total":2}`, `{"data":[{"id":""}]}`, `{"data":[{"id":"x","object":"file"}]}`, `{"data":[{"id":"x"},{"id":"x","name":"conflict"}]}`, `{"data":[]} {}`, `{"data":[{"id":"x"}],"pagination":{"next_cursor":"a"}}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			if _, err := NewOpenAIClient().FetchModels(context.Background(), server.URL, "fixture"); err == nil {
				t.Fatal("untrustworthy snapshot accepted")
			}
		})
	}
}
func TestCatalogSnapshotAcceptsExplicitCompleteEmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"object":"list","data":[],"has_more":false}`))
	}))
	defer server.Close()
	models, err := NewOpenAIClient().FetchModels(context.Background(), server.URL, "fixture")
	if err != nil || models == nil || len(models) != 0 {
		t.Fatalf("explicit empty list: models=%v err=%v", models, err)
	}
}
func TestCatalogSnapshotFailuresDoNotBecomeEmptyLists(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 502, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); w.Write([]byte(`{"data":[]}`)) }))
		_, err := NewOpenAIClient().FetchModels(context.Background(), server.URL, "fixture")
		server.Close()
		if err == nil {
			t.Fatalf("status %d accepted", status)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := NewOpenAIClient().FetchModels(ctx, server.URL, "fixture"); err == nil {
		t.Fatal("timeout accepted")
	}
}
