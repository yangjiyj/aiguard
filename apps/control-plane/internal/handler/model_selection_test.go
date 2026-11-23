package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
)

type selectionModelRepo struct {
	*MockModelRepository
	availability map[string]modelcatalog.Availability
}

func (m *selectionModelRepo) ModelAvailability(context.Context, string) (map[string]modelcatalog.Availability, error) {
	return m.availability, nil
}

func TestListModelsAvailableOnlyExcludesUnmanagedAndUnavailable(t *testing.T) {
	models := map[string]*repository.Model{}
	availability := map[string]modelcatalog.Availability{}
	for _, id := range []string{"chat", "messages", "gemini", "pending", "disabled", "unverified", "unknown"} {
		status := "active"
		if id == "pending" || id == "disabled" {
			status = id
		}
		models[id] = &repository.Model{ID: id, ProviderID: "p1", ModelName: id, Status: status}
		if id != "unknown" {
			availability[id] = modelcatalog.Availability{Callable: id == "chat" || id == "messages" || id == "gemini"}
		}
	}
	deps := &Dependencies{ModelRepo: &selectionModelRepo{MockModelRepository: &MockModelRepository{Models: models}, availability: availability}}
	user := &repository.User{ID: "admin", TenantID: "tenant-a", Role: "tenant_owner"}
	for _, tc := range []struct {
		query string
		count int
	}{{"?available_only=true", 3}, {"", 7}} {
		w := httptest.NewRecorder()
		ListModels(deps)(w, modelRoutingRequest(http.MethodGet, "/admin/v1/models"+tc.query, "", user))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var response types.ModelListResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != tc.count || len(response.Data) != tc.count {
			t.Fatalf("query=%s response=%+v", tc.query, response)
		}
		if tc.count == 3 {
			for _, model := range response.Data {
				if !model.Callable {
					t.Fatalf("non-callable selectable: %+v", model)
				}
			}
		}
	}
}
