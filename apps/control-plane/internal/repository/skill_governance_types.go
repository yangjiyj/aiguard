package repository

import "errors"

var ErrSkillVersionDeclarationConflict = errors.New("skill bundle declaration conflicts with existing immutable version")
var ErrSkillAdmissionConflict = errors.New("skill admission state or bundle changed")

type SkillAssetFilter struct {
	Limit, Offset                      int
	Query, SourceType, AdmissionStatus string
}
type SkillAssetSummary struct {
	UploadedAssets      int64 `json:"uploaded_assets"`
	ObservedAssets      int64 `json:"observed_assets"`
	PendingVersions     int64 `json:"pending_versions"`
	ApprovedVersions    int64 `json:"approved_versions"`
	QuarantinedVersions int64 `json:"quarantined_versions"`
	RevokedVersions     int64 `json:"revoked_versions"`
	FailedScans         int64 `json:"failed_scans"`
	Invocations         int64 `json:"invocations"`
}
type SkillAssetPage struct {
	Items             []*SkillAsset     `json:"items"`
	Total             int64             `json:"total"`
	Limit             int               `json:"limit"`
	Offset            int               `json:"offset"`
	Summary           SkillAssetSummary `json:"summary"`
	InventoryScope    string            `json:"inventory_scope"`
	EndpointInventory bool              `json:"endpoint_inventory"`
}
type SkillInvocationFilter struct {
	Limit, Offset                                                int
	AssetID, VersionID, CanonicalName, Status, EffectiveDecision string
}
type SkillInvocationPage struct {
	Items                  []*SkillInvocation `json:"items"`
	Total                  int64              `json:"total"`
	Limit                  int                `json:"limit"`
	Offset                 int                `json:"offset"`
	ObservationScope       string             `json:"observation_scope"`
	EndpointExecutionProof bool               `json:"endpoint_execution_proof"`
}
type SkillAdmissionReview struct {
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ExpectedStatus     string `json:"expected_status"`
	ExpectedBundleHash string `json:"expected_bundle_hash"`
	// OverrideReason 是强制批准扫描结论为阻断的已上传版本的原因（≤512 字，设计第 5 节）；
	// 为空时这类版本不可批准。签名无效、仅观测到的定义带原因也不可批准。
	OverrideReason string `json:"override_reason,omitempty"`
}
