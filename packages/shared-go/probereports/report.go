package probereports

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion = "aiprobe.report.v1"
	MaxBodyBytes  = 8 << 20
	MaxAssets     = 5000
	// ApprovedDestinationCatalogBasis is the only approval_basis value the
	// probe contract allows (a JSON Schema const). It names the server-side
	// catalog the destination was checked against, never a client opinion.
	ApprovedDestinationCatalogBasis = "approved_destination_catalog"
)

var (
	assetKinds     = map[string]bool{"cli_agent": true, "mcp_server": true, "desktop_app": true, "instruction_file": true, "browser_extension": true, "platform_container": true, "scheduled_agent": true, "model_service": true}
	collectorNames = map[string]bool{"homes": true, "host": true, "process": true, "netsock": true, "agents": true, "apps": true, "browser_extensions": true, "container": true, "schedule": true, "modelsvc": true}
	tokenPattern   = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
	hashPattern    = regexp.MustCompile(`^(sha256:)?[a-f0-9]{64}$`)
	// approvalRuleIDPattern mirrors contracts/model-destination-approval.v1.schema.json's
	// approval_rule_id pattern exactly: 1-64 chars, must start alphanumeric.
	approvalRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Report struct {
	SchemaVersion      string              `json:"schema_version"`
	EndpointID         string              `json:"endpoint_id"`
	ReportID           string              `json:"report_id"`
	ProbeVersion       string              `json:"probe_version"`
	ScannedAt          string              `json:"scanned_at"`
	Status             string              `json:"status"`
	Collectors         []CollectorResult   `json:"collectors"`
	Assets             []Asset             `json:"assets"`
	SocketObservations []SocketObservation `json:"socket_observations"`
}
type CollectorResult struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}
type SocketObservation struct {
	ProcessRef         string   `json:"process_ref,omitempty"`
	ObservationStatus  string   `json:"observation_status"`
	ApprovalStatus     string   `json:"approval_status"`
	GatewayMatchSource string   `json:"gateway_match_source,omitempty"`
	GatewayMatchScope  string   `json:"gateway_match_scope,omitempty"`
	PID                int32    `json:"pid,omitempty"`
	RemoteIP           string   `json:"remote_ip"`
	RemotePort         int      `json:"remote_port"`
	Protocol           string   `json:"protocol"`
	State              string   `json:"state"`
	Source             string   `json:"source"`
	Attribution        string   `json:"attribution"`
	Classification     string   `json:"classification"`
	CandidateOrigin    string   `json:"candidate_origin,omitempty"`
	GatewayOrigins     []string `json:"gateway_origins"`
}
type Asset struct {
	SourceID         string   `json:"source_id"`
	Kind             string   `json:"kind"`
	Name             string   `json:"name"`
	DisplayName      string   `json:"display_name"`
	Version          string   `json:"version,omitempty"`
	ContentHash      string   `json:"content_hash"`
	ObservedAt       string   `json:"observed_at"`
	CollectionStatus string   `json:"collection_status"`
	Running          bool     `json:"running"`
	Confidence       int      `json:"confidence"`
	EvidenceLabels   []string `json:"evidence_labels"`
	RiskFlags        []string `json:"risk_flags"`
	Evidence         Evidence `json:"evidence"`
}
type Evidence struct {
	OwnerHash               string              `json:"owner_hash,omitempty"`
	BinarySHA256            string              `json:"binary_sha256,omitempty"`
	InstallPathHash         string              `json:"install_path_hash,omitempty"`
	InstallPathLabel        string              `json:"install_path_label,omitempty"`
	Endpoint                *Destination        `json:"endpoint,omitempty"`
	Destinations            []Destination       `json:"destinations"`
	MCPServers              []MCPServer         `json:"mcp_servers"`
	Skills                  []Skill             `json:"skills"`
	Config                  AssetConfig         `json:"config"`
	ProcessPIDs             []int32             `json:"process_pids"`
	SocketAttributions      []SocketObservation `json:"socket_attributions"`
	SocketAttributionStatus string              `json:"socket_attribution_status"`
}
type Destination struct {
	Origin         string   `json:"origin"`
	Provider       string   `json:"provider"`
	Classification string   `json:"classification"`
	Source         string   `json:"source"`
	Models         []string `json:"models"`
	ApprovalStatus string   `json:"approval_status"`
	// ApprovalBasis and ApprovalRuleID carry the probe's declared approval
	// basis/rule for this destination (contracts/model-destination-approval.v1.schema.json).
	// They apply identically to every classification — an official-looking
	// endpoint gets no free pass, and a relay is not judged unapproved by
	// default. The server re-verifies these against its own catalog rather
	// than trusting the client's claim; see repository.VerifyDestinationApproval.
	ApprovalBasis  string `json:"approval_basis,omitempty"`
	ApprovalRuleID string `json:"approval_rule_id,omitempty"`
}
type MCPServer struct {
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Transport string    `json:"transport"`
	EnvKeys   []string  `json:"env_keys"`
	EnvHashes []EnvHash `json:"env_hashes"`
	RiskFlags []string  `json:"risk_flags"`
}
type EnvHash struct {
	Key  string `json:"key"`
	Hash string `json:"hash"`
}
type Skill struct {
	Name        string `json:"name"`
	SourceHash  string `json:"source_hash,omitempty"`
	SourceLabel string `json:"source_label,omitempty"`
	SHA256      string `json:"sha256"`
}
type AssetConfig struct {
	PermissionMode   string       `json:"permission_mode,omitempty"`
	HooksPresent     bool         `json:"hooks_present"`
	InstructionFiles []HashedFile `json:"instruction_files"`
	ConfigFiles      []HashedFile `json:"config_files"`
}
type HashedFile struct {
	PathHash  string `json:"path_hash,omitempty"`
	PathLabel string `json:"path_label,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// ReportID binds a report key to one authenticated endpoint and scan time. The
// ledger separately compares payloads, so changed content at the same key conflicts.
func ReportID(endpointID, scannedAt string) string {
	sum := sha256.Sum256([]byte(endpointID + "\x00" + scannedAt))
	return "pr_" + hex.EncodeToString(sum[:])
}

func Decode(data []byte) (*Report, error) {
	if len(data) == 0 || len(data) > MaxBodyBytes {
		return nil, fmt.Errorf("probe report body must be between 1 and %d bytes", MaxBodyBytes)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("probe report body must be valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid probe report: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("probe report contains trailing JSON")
		}
		return nil, fmt.Errorf("invalid trailing probe report data: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", r.SchemaVersion)
	}
	if !bounded(r.EndpointID, 255) || strings.ContainsAny(r.EndpointID, "\x1e\x1f") {
		return errors.New("invalid endpoint_id")
	}
	if r.ProbeVersion == "" || len(r.ProbeVersion) > 64 || controls(r.ProbeVersion) {
		return errors.New("invalid probe_version")
	}
	at, err := time.Parse(time.RFC3339, r.ScannedAt)
	if err != nil || at.UTC().Format(time.RFC3339) != r.ScannedAt {
		return errors.New("scanned_at must be canonical UTC RFC3339")
	}
	if at.After(time.Now().UTC().Add(5 * time.Minute)) {
		return errors.New("scanned_at cannot be future dated")
	}
	if r.ReportID != ReportID(r.EndpointID, r.ScannedAt) {
		return errors.New("report_id does not match endpoint and scan time")
	}
	if r.Status != "complete" && r.Status != "partial" {
		return errors.New("status must be complete or partial")
	}
	if len(r.Collectors) != len(collectorNames) {
		return errors.New("invalid collectors")
	}
	seenCollectors := map[string]bool{}
	incompleteCollectors := 0
	for _, c := range r.Collectors {
		if !collectorNames[c.Name] || seenCollectors[c.Name] {
			return fmt.Errorf("unknown or duplicate collector %q", c.Name)
		}
		seenCollectors[c.Name] = true
		if c.Status != "complete" && c.Status != "partial" && c.Status != "failed" {
			return fmt.Errorf("invalid collector status %q", c.Name)
		}
		if c.ErrorCode != "" && c.ErrorCode != "collector_error" {
			return fmt.Errorf("invalid collector error_code %q", c.Name)
		}
		if c.Status != "complete" {
			incompleteCollectors++
		}
		if (c.Status == "complete") != (c.ErrorCode == "") {
			return fmt.Errorf("collector error_code/status mismatch %q", c.Name)
		}
	}
	for name := range collectorNames {
		if !seenCollectors[name] {
			return fmt.Errorf("missing collector %q", name)
		}
	}
	if (r.Status == "partial") != (incompleteCollectors > 0) {
		return errors.New("report status does not match collector completeness")
	}
	if r.Assets == nil || len(r.Assets) > MaxAssets {
		return errors.New("assets must be an array within the limit")
	}
	seenIDs := map[string]bool{}
	socketRows := make(map[string]int)
	for i, a := range r.Assets {
		if err := a.Validate(at, r.EndpointID); err != nil {
			return fmt.Errorf("assets[%d]: %w", i, err)
		}
		if seenIDs[a.SourceID] {
			return fmt.Errorf("duplicate source_id %q", a.SourceID)
		}
		seenIDs[a.SourceID] = true
		for _, socket := range a.Evidence.SocketAttributions {
			key, _ := json.Marshal(socket)
			socketRows[string(key)]++
		}
	}
	if r.SocketObservations == nil || len(r.SocketObservations) > 10000 {
		return errors.New("too many socket observations")
	}
	if len(r.SocketObservations) != lenSocketRows(socketRows) {
		return errors.New("report-level sockets must exactly project asset-scoped socket evidence")
	}
	for i, socket := range r.SocketObservations {
		if err := socket.Validate(); err != nil {
			return fmt.Errorf("socket_observations[%d]: %w", i, err)
		}
		key, _ := json.Marshal(socket)
		if socketRows[string(key)] == 0 {
			return errors.New("report-level socket is not scoped to an asset process")
		}
		socketRows[string(key)]--
	}
	for _, count := range socketRows {
		if count != 0 {
			return errors.New("asset socket evidence is missing from report-level projection")
		}
	}
	return nil
}
func (a Asset) Validate(reportTime time.Time, endpointID string) error {
	if !assetKinds[a.Kind] {
		return fmt.Errorf("unsupported asset kind %q", a.Kind)
	}
	if len(a.SourceID) != 64 || !hashPattern.MatchString(a.SourceID) || strings.HasPrefix(a.SourceID, "sha256:") {
		return errors.New("source_id must be a 64-character SHA-256 digest")
	}
	if !safeLabel(a.Name, 256) || !safeLabel(a.DisplayName, 256) {
		return errors.New("name/display_name must be sanitized labels")
	}
	if len(a.Version) > 128 || controls(a.Version) {
		return errors.New("invalid version")
	}
	if !strings.HasPrefix(a.ContentHash, "sha256:") || !hashPattern.MatchString(a.ContentHash) {
		return errors.New("content_hash must use sha256:<hex>")
	}
	observed, err := time.Parse(time.RFC3339, a.ObservedAt)
	if err != nil || observed.UTC().Format(time.RFC3339) != a.ObservedAt || observed.After(reportTime.Add(5*time.Minute)) {
		return errors.New("observed_at must be canonical UTC RFC3339 and not future dated")
	}
	if a.CollectionStatus != "current" && a.CollectionStatus != "stale" {
		return errors.New("invalid collection_status")
	}
	if a.Confidence < 0 || a.Confidence > 100 {
		return errors.New("invalid confidence")
	}
	if a.EvidenceLabels == nil || a.RiskFlags == nil {
		return errors.New("evidence_labels and risk_flags must be arrays")
	}
	if err := safeTokens(a.EvidenceLabels); err != nil {
		return fmt.Errorf("evidence_labels: %w", err)
	}
	if err := safeTokens(a.RiskFlags); err != nil {
		return fmt.Errorf("risk_flags: %w", err)
	}
	return a.Evidence.Validate(endpointID, a.SourceID)
}
func (e Evidence) Validate(endpointID, sourceID string) error {
	for name, value := range map[string]string{"owner_hash": e.OwnerHash, "binary_sha256": e.BinarySHA256, "install_path_hash": e.InstallPathHash} {
		if value != "" && !hashPattern.MatchString(value) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if e.InstallPathLabel != "" && !safeLabel(e.InstallPathLabel, 128) {
		return errors.New("invalid install_path_label")
	}
	if e.Destinations == nil || e.MCPServers == nil || e.Skills == nil || e.ProcessPIDs == nil || e.SocketAttributions == nil || e.Config.InstructionFiles == nil || e.Config.ConfigFiles == nil {
		return errors.New("evidence collections must be arrays")
	}
	if e.Endpoint != nil {
		if err := e.Endpoint.Validate(); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
	}
	if e.SocketAttributionStatus != "" && e.SocketAttributionStatus != "complete" && e.SocketAttributionStatus != "partial" && e.SocketAttributionStatus != "stale" {
		return errors.New("invalid socket attribution status")
	}
	if len(e.Destinations) > 64 || len(e.MCPServers) > 128 || len(e.Skills) > 512 || len(e.ProcessPIDs) > 1024 || len(e.SocketAttributions) > 4096 {
		return errors.New("evidence collection exceeds bounds")
	}
	for i, d := range e.Destinations {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("destinations[%d]: %w", i, err)
		}
	}
	for i, m := range e.MCPServers {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("mcp_servers[%d]: %w", i, err)
		}
	}
	for i, s := range e.Skills {
		if !safeLabel(s.Name, 256) || (s.SourceLabel != "" && !safeLabel(s.SourceLabel, 128)) || (s.SourceHash != "" && !hashPattern.MatchString(s.SourceHash)) || !hashPattern.MatchString(s.SHA256) {
			return fmt.Errorf("invalid skill %d", i)
		}
	}
	if e.Config.PermissionMode != "" && !tokenPattern.MatchString(e.Config.PermissionMode) {
		return errors.New("invalid permission_mode")
	}
	if len(e.Config.InstructionFiles) > 256 || len(e.Config.ConfigFiles) > 256 {
		return errors.New("too many config file summaries")
	}
	for i, f := range e.Config.InstructionFiles {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("instruction_files[%d]: %w", i, err)
		}
	}
	for i, f := range e.Config.ConfigFiles {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("config_files[%d]: %w", i, err)
		}
	}
	pids := map[int32]bool{}
	for _, pid := range e.ProcessPIDs {
		if pid <= 0 || pids[pid] {
			return errors.New("invalid or duplicate process pid")
		}
		pids[pid] = true
	}
	for i, socket := range e.SocketAttributions {
		if err := socket.Validate(); err != nil {
			return fmt.Errorf("socket_attributions[%d]: %w", i, err)
		}
		if !pids[socket.PID] {
			return fmt.Errorf("socket_attributions[%d] owner pid is not in process_pids", i)
		}
		if want := ProcessReference(endpointID, sourceID, socket.PID); socket.ProcessRef != want {
			return fmt.Errorf("socket_attributions[%d] process_ref does not match report asset", i)
		}
	}
	return nil
}
func (d Destination) Validate() error {
	if err := origin(d.Origin); err != nil {
		return fmt.Errorf("invalid origin: %w", err)
	}
	u, _ := url.Parse(d.Origin)
	if d.Provider != "" && !strings.EqualFold(d.Provider, u.Hostname()) {
		return errors.New("provider must equal sanitized origin host")
	}
	switch d.Classification {
	case "gateway", "official", "relay", "local", "unknown":
	default:
		return errors.New("invalid destination classification")
	}
	if d.Models == nil {
		return errors.New("destination models must be an array")
	}
	if !tokenPattern.MatchString(d.Source) || len(d.Models) > 128 {
		return errors.New("invalid destination source or models")
	}
	for _, m := range d.Models {
		if m == "" || len(m) > 128 || controls(m) {
			return errors.New("invalid model label")
		}
	}
	switch d.ApprovalStatus {
	case "", "approved", "unreviewed", "not_listed", "pending":
	default:
		return errors.New("invalid approval status")
	}
	// approval_basis/approval_rule_id follow the same conditional contract as
	// contracts/model-destination-approval.v1.schema.json, for every
	// classification alike: approved requires both; not_listed requires only
	// the basis and forbids a rule id; every other status must carry neither.
	switch d.ApprovalStatus {
	case "approved":
		if d.ApprovalBasis != ApprovedDestinationCatalogBasis {
			return errors.New("approved destination requires approval_basis=approved_destination_catalog")
		}
		if !approvalRuleIDPattern.MatchString(d.ApprovalRuleID) {
			return errors.New("approved destination requires a valid approval_rule_id")
		}
	case "not_listed":
		if d.ApprovalBasis != ApprovedDestinationCatalogBasis {
			return errors.New("not_listed destination requires approval_basis=approved_destination_catalog")
		}
		if d.ApprovalRuleID != "" {
			return errors.New("not_listed destination must not carry approval_rule_id")
		}
	default:
		if d.ApprovalBasis != "" || d.ApprovalRuleID != "" {
			return errors.New("approval_basis/approval_rule_id are only allowed for approved or not_listed destinations")
		}
	}
	return nil
}
func (m MCPServer) Validate() error {
	if !safeLabel(m.Name, 256) || !tokenPattern.MatchString(m.Scope) || !tokenPattern.MatchString(m.Transport) {
		return errors.New("invalid MCP server summary")
	}
	if m.EnvKeys == nil || m.EnvHashes == nil || m.RiskFlags == nil {
		return errors.New("MCP summary collections must be arrays")
	}
	if len(m.EnvKeys) > 128 || len(m.EnvHashes) > 128 || len(m.RiskFlags) > 64 {
		return errors.New("MCP server summary exceeds bounds")
	}
	for _, key := range m.EnvKeys {
		if !tokenPattern.MatchString(key) {
			return errors.New("invalid environment key")
		}
	}
	for _, item := range m.EnvHashes {
		if !tokenPattern.MatchString(item.Key) || !hashPattern.MatchString(item.Hash) {
			return errors.New("invalid environment hash")
		}
	}
	return safeTokens(m.RiskFlags)
}
func (f HashedFile) Validate() error {
	if f.PathHash != "" && !hashPattern.MatchString(f.PathHash) {
		return errors.New("invalid path hash")
	}
	if f.PathLabel != "" && !safeLabel(f.PathLabel, 128) {
		return errors.New("invalid path label")
	}
	if f.SHA256 != "" && !hashPattern.MatchString(f.SHA256) {
		return errors.New("invalid file hash")
	}
	if f.PathHash == "" && f.SHA256 == "" {
		return errors.New("hashed file requires path_hash or sha256")
	}
	return nil
}
func ProcessReference(endpointID, sourceID string, pid int32) string {
	sum := sha256.Sum256([]byte(endpointID + "\x00" + sourceID + "\x00" + strconv.FormatInt(int64(pid), 10)))
	return hex.EncodeToString(sum[:])
}

func lenSocketRows(rows map[string]int) int {
	total := 0
	for _, count := range rows {
		total += count
	}
	return total
}

func (s SocketObservation) Validate() error {
	if len(s.ProcessRef) != 64 || !hashPattern.MatchString(s.ProcessRef) || strings.HasPrefix(s.ProcessRef, "sha256:") || s.PID <= 0 {
		return errors.New("socket requires an asset-scoped process_ref and pid")
	}
	ip := net.ParseIP(s.RemoteIP)
	if ip == nil || ip.String() != s.RemoteIP || s.RemotePort < 1 || s.RemotePort > 65535 {
		return errors.New("invalid remote socket address")
	}
	if s.Protocol != "tcp" && s.Protocol != "udp" {
		return errors.New("invalid socket protocol")
	}
	if s.ObservationStatus != "current" && s.ObservationStatus != "stale" {
		return errors.New("invalid socket observation status")
	}
	switch s.ApprovalStatus {
	case "approved", "unreviewed", "not_listed", "pending":
	default:
		return errors.New("invalid socket approval status")
	}
	if len(s.State) > 32 || controls(s.State) || s.Source != "socket" {
		return errors.New("invalid socket state/source")
	}
	if s.Attribution != "matched_process" {
		return errors.New("socket must be attributed to a matched asset process")
	}
	switch s.Classification {
	case "gateway", "official", "relay", "unknown":
	default:
		return errors.New("invalid socket classification")
	}
	if s.CandidateOrigin != "" {
		if err := origin(s.CandidateOrigin); err != nil {
			return err
		}
	}
	if s.GatewayOrigins == nil {
		return errors.New("gateway_origins must be an array")
	}
	if len(s.GatewayOrigins) > 32 {
		return errors.New("too many gateway mapping origins")
	}
	for _, o := range s.GatewayOrigins {
		if err := origin(o); err != nil {
			return err
		}
	}
	if len(s.GatewayOrigins) > 0 && (s.GatewayMatchSource != "system_resolver" && s.GatewayMatchSource != "configured_ip" || s.GatewayMatchScope != "ip_port_only") {
		return errors.New("gateway mapping origins require explicit source and ip_port_only scope")
	}
	if len(s.GatewayOrigins) == 0 && (s.GatewayMatchSource != "" || s.GatewayMatchScope != "") {
		return errors.New("gateway mapping source/scope requires mapping origins")
	}
	if s.Classification == "gateway" && len(s.GatewayOrigins) == 0 {
		return errors.New("gateway classification requires explicit mapping provenance")
	}
	if s.GatewayMatchSource == "system_resolver" && s.Classification != "unknown" {
		return errors.New("DNS-derived socket mapping must remain unknown")
	}
	return nil
}
func origin(value string) error {
	if value == "" || len(value) > 512 || controls(value) {
		return errors.New("empty or oversized origin")
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("origin must omit userinfo, path, query and fragment")
	}
	return nil
}
func safeTokens(values []string) error {
	if len(values) > 128 {
		return errors.New("too many labels")
	}
	for _, v := range values {
		if !tokenPattern.MatchString(v) {
			return fmt.Errorf("invalid label %q", v)
		}
	}
	return nil
}
func bounded(v string, max int) bool {
	return v != "" && len(v) <= max && v == strings.TrimSpace(v) && !controls(v)
}
func safeLabel(v string, max int) bool { return bounded(v, max) && !strings.ContainsAny(v, "/\\") }
func controls(v string) bool {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
