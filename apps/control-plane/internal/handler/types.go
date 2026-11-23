package handler

import "time"

// ModelSyncPreviewRequest requests catalog candidates for an Azure provider.
type ModelSyncPreviewRequest struct {
	ProviderID string `json:"provider_id"`
}

// ModelSyncCandidate is a deployment candidate selected by an administrator.
type ModelSyncCandidate struct {
	CatalogModelID string `json:"catalog_model_id"`
	DisplayName    string `json:"display_name"`
	DeploymentName string `json:"deployment_name"`
	CurrentStatus  string `json:"current_status,omitempty"`
}

// ModelSyncPreviewResponse is the shared candidate payload: the Azure deployment
// preview and the generic catalog preview both return the same facts.
type ModelSyncPreviewResponse struct {
	ProviderID         string               `json:"provider_id"`
	Candidates         []ModelSyncCandidate `json:"candidates"`
	CatalogUnavailable bool                 `json:"catalog_unavailable"`
	CatalogTruncated   bool                 `json:"catalog_truncated"`
	CurrentActive      int                  `json:"current_active"`
}

// ModelSyncCandidateRequest asks for the upstream catalog candidates of one provider.
type ModelSyncCandidateRequest struct {
	ProviderID string `json:"provider_id"`
}

// ModelSyncCandidateListResponse lists the upstream catalog merged with the models
// already stored for the provider, so an administrator can pick which ones to sync.
// It also carries the server-side per-request selection cap so the console cannot
// drift from the handler.
type ModelSyncCandidateListResponse struct {
	ProviderID         string               `json:"provider_id"`
	Candidates         []ModelSyncCandidate `json:"candidates"`
	CatalogUnavailable bool                 `json:"catalog_unavailable"`
	CatalogTruncated   bool                 `json:"catalog_truncated"`
	CurrentActive      int                  `json:"current_active"`
	MaxSelection       int                  `json:"max_selection"`
}

type ModelSyncVerifyItem struct {
	CatalogModelID string   `json:"catalog_model_id"`
	DeploymentName string   `json:"deployment_name"`
	Protocols      []string `json:"protocols,omitempty"`
}

type ModelSyncVerifyRequest struct {
	ProviderID string                `json:"provider_id"`
	Items      []ModelSyncVerifyItem `json:"items"`
}

// ModelSyncVerificationResult carries a short-lived server proof for a verified deployment.
type ModelSyncVerificationResult struct {
	CatalogModelID string     `json:"catalog_model_id"`
	DeploymentName string     `json:"deployment_name"`
	Protocols      []string   `json:"protocols,omitempty"`
	Status         string     `json:"status"`
	ErrorKind      string     `json:"error_kind,omitempty"`
	Message        string     `json:"message,omitempty"`
	ProofToken     string     `json:"proof_token,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type ModelSyncVerifyResponse struct {
	ProviderID string                        `json:"provider_id"`
	Results    []ModelSyncVerificationResult `json:"results"`
}

type ModelSyncCommitRequest struct {
	ProviderID  string   `json:"provider_id"`
	ProofTokens []string `json:"proof_tokens"`
}

type ModelSyncCommitResponse struct {
	ProviderID  string `json:"provider_id"`
	Created     int    `json:"created"`
	Updated     int    `json:"updated"`
	Reactivated int    `json:"reactivated"`
	Deactivated int    `json:"deactivated"`
}
