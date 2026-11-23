package probereports

import (
	"encoding/json"
	"strings"
	"testing"
)

func validReport() Report {
	names := []string{"homes", "host", "process", "netsock", "agents", "apps", "browser_extensions", "container", "schedule", "modelsvc"}
	collectors := make([]CollectorResult, 0, len(names))
	for _, name := range names {
		collectors = append(collectors, CollectorResult{Name: name, Status: "complete"})
	}
	kinds := []string{"cli_agent", "mcp_server", "desktop_app", "instruction_file", "browser_extension", "platform_container", "scheduled_agent", "model_service"}
	assets := make([]Asset, 0, len(kinds))
	for i, kind := range kinds {
		source := strings.Repeat(string("abcdef01"[i]), 64)
		assets = append(assets, Asset{SourceID: source, Kind: kind, Name: "asset-" + kind, DisplayName: "Asset " + kind, ContentHash: "sha256:" + strings.Repeat("b", 64), ObservedAt: "2025-01-02T03:04:05Z", CollectionStatus: "current", Confidence: 80, EvidenceLabels: []string{}, RiskFlags: []string{}, Evidence: Evidence{Destinations: []Destination{}, MCPServers: []MCPServer{}, Skills: []Skill{}, Config: AssetConfig{InstructionFiles: []HashedFile{}, ConfigFiles: []HashedFile{}}, ProcessPIDs: []int32{}, SocketAttributions: []SocketObservation{}}})
	}
	report := Report{SchemaVersion: SchemaVersion, EndpointID: "ep_test_1", ProbeVersion: "0.1.0", ScannedAt: "2025-01-02T03:04:05Z", Status: "complete", Collectors: collectors, Assets: assets, SocketObservations: []SocketObservation{}}
	report.ReportID = ReportID(report.EndpointID, report.ScannedAt)
	return report
}

func TestDecodeAcceptsAllT07KindsAndMappedSocketEvidence(t *testing.T) {
	report := validReport()
	socket := SocketObservation{ProcessRef: ProcessReference(report.EndpointID, report.Assets[0].SourceID, 44), PID: 44, ObservationStatus: "current", ApprovalStatus: "unreviewed", RemoteIP: "127.0.0.1", RemotePort: 11434, Protocol: "tcp", State: "ESTABLISHED", Source: "socket", Attribution: "matched_process", Classification: "gateway", CandidateOrigin: "http://127.0.0.1:11434", GatewayOrigins: []string{"https://gateway.example.test"}, GatewayMatchSource: "configured_ip", GatewayMatchScope: "ip_port_only"}
	report.Assets[0].Evidence.ProcessPIDs = []int32{44}
	report.Assets[0].Evidence.SocketAttributions = []SocketObservation{socket}
	report.Assets[0].Evidence.SocketAttributionStatus = "complete"
	report.SocketObservations = []SocketObservation{socket}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("valid v1 report rejected: %v", err)
	}
	if len(got.Assets) != 8 || got.Assets[0].Evidence.SocketAttributions[0].PID != 44 {
		t.Fatalf("typed assets/socket evidence lost: %#v", got)
	}
}

func TestDecodeRejectsUnknownRawFieldsAndUnsupportedAssetKind(t *testing.T) {
	report := validReport()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(raw), `"endpoint_id":"ep_test_1"`, `"endpoint_id":"ep_test_1","raw_host_path":"/home/alice"`, 1)
	if _, err := Decode([]byte(mutated)); err == nil {
		t.Fatal("unknown raw host field was accepted")
	}
	report = validReport()
	report.Assets[0].Kind = "other"
	if err := report.ValidateForTest(); err == nil {
		t.Fatal("unsupported asset kind was accepted")
	}
}

func TestDecodeRejectsCredentialAndUnmappedGatewayClassification(t *testing.T) {
	report := validReport()
	s := SocketObservation{ProcessRef: ProcessReference(report.EndpointID, report.Assets[0].SourceID, 44), PID: 44, ObservationStatus: "current", ApprovalStatus: "unreviewed", RemoteIP: "192.0.2.1", RemotePort: 443, Protocol: "tcp", State: "ESTABLISHED", Source: "socket", Attribution: "matched_process", Classification: "gateway", CandidateOrigin: "https://user:secret@gateway.example/path?token=secret", GatewayOrigins: []string{"https://gateway.example"}, GatewayMatchSource: "configured_ip", GatewayMatchScope: "ip_port_only"}
	if err := s.Validate(); err == nil {
		t.Fatal("credential-bearing socket origin was accepted")
	}
	s.CandidateOrigin = "https://gateway.example"
	s.GatewayOrigins = nil
	if err := s.Validate(); err == nil {
		t.Fatal("gateway observation without mapping provenance was accepted")
	}
}

func (r Report) ValidateForTest() error { return r.Validate() }

func TestDecodeRejectsUnscopedOrMismatchedSocketEvidence(t *testing.T) {
	report := validReport()
	asset := &report.Assets[0]
	asset.Evidence.ProcessPIDs = []int32{44}
	socket := SocketObservation{ProcessRef: ProcessReference(report.EndpointID, asset.SourceID, 44), PID: 44, ObservationStatus: "current", ApprovalStatus: "unreviewed", RemoteIP: "192.0.2.1", RemotePort: 443, Protocol: "tcp", State: "ESTABLISHED", Source: "socket", Attribution: "matched_process", Classification: "unknown", GatewayOrigins: []string{}}
	asset.Evidence.SocketAttributions = []SocketObservation{socket}
	report.SocketObservations = []SocketObservation{socket}
	if err := report.Validate(); err != nil {
		t.Fatalf("exact process evidence should pass: %v", err)
	}
	report.Assets[0].Evidence.SocketAttributions[0].ProcessRef = strings.Repeat("c", 64)
	report.SocketObservations[0].ProcessRef = strings.Repeat("c", 64)
	if err := report.Validate(); err == nil {
		t.Fatal("socket reference not bound to endpoint and source asset was accepted")
	}
	report = validReport()
	report.SocketObservations = []SocketObservation{{ProcessRef: ProcessReference(report.EndpointID, report.Assets[0].SourceID, 44), PID: 44, ObservationStatus: "current", ApprovalStatus: "unreviewed", RemoteIP: "192.0.2.1", RemotePort: 443, Protocol: "tcp", State: "ESTABLISHED", Source: "socket", Attribution: "matched_process", Classification: "unknown", GatewayOrigins: []string{}}}
	if err := report.Validate(); err == nil {
		t.Fatal("unowned report-level socket was accepted")
	}
}

func TestDecodeKeepsDNSMappingUnknownAndScoped(t *testing.T) {
	report := validReport()
	asset := &report.Assets[0]
	asset.Evidence.ProcessPIDs = []int32{44}
	socket := SocketObservation{ProcessRef: ProcessReference(report.EndpointID, asset.SourceID, 44), PID: 44, ObservationStatus: "current", ApprovalStatus: "unreviewed", RemoteIP: "192.0.2.1", RemotePort: 443, Protocol: "tcp", State: "ESTABLISHED", Source: "socket", Attribution: "matched_process", Classification: "unknown", GatewayOrigins: []string{"https://gateway.example.test"}, GatewayMatchSource: "system_resolver", GatewayMatchScope: "ip_port_only"}
	asset.Evidence.SocketAttributions = []SocketObservation{socket}
	report.SocketObservations = []SocketObservation{socket}
	if err := report.Validate(); err != nil {
		t.Fatalf("scoped DNS match should remain unknown: %v", err)
	}
	report.Assets[0].Evidence.SocketAttributions[0].Classification = "gateway"
	report.SocketObservations[0].Classification = "gateway"
	if err := report.Validate(); err == nil {
		t.Fatal("DNS-derived mapping was promoted to gateway identity")
	}
}

// T07: approval_basis/approval_rule_id must follow the same conditional
// contract for every destination classification (official and relay alike) —
// approved requires both fields; not_listed requires only the basis and
// forbids a rule id; every other status must carry neither field.
func TestDestinationApprovalBasisConditionalContract(t *testing.T) {
	base := func() Destination {
		return Destination{Origin: "https://relay.example.test", Provider: "relay.example.test", Classification: "relay", Source: "config_file", Models: []string{}}
	}

	approvedOfficial := base()
	approvedOfficial.Classification = "official"
	approvedOfficial.Provider = ""
	approvedOfficial.Origin = "https://api.anthropic.com"
	approvedOfficial.ApprovalStatus = "approved"
	approvedOfficial.ApprovalBasis = "approved_destination_catalog"
	approvedOfficial.ApprovalRuleID = "official-anthropic-1"
	if err := approvedOfficial.Validate(); err != nil {
		t.Fatalf("approved official destination with basis+rule_id should validate: %v", err)
	}

	approvedRelay := base()
	approvedRelay.ApprovalStatus = "approved"
	approvedRelay.ApprovalBasis = "approved_destination_catalog"
	approvedRelay.ApprovalRuleID = "relay-rule-1"
	if err := approvedRelay.Validate(); err != nil {
		t.Fatalf("approved relay destination with basis+rule_id should validate: %v", err)
	}

	approvedMissingRuleID := base()
	approvedMissingRuleID.ApprovalStatus = "approved"
	approvedMissingRuleID.ApprovalBasis = "approved_destination_catalog"
	if err := approvedMissingRuleID.Validate(); err == nil {
		t.Fatal("approved destination without approval_rule_id was accepted")
	}

	approvedMissingBasis := base()
	approvedMissingBasis.ApprovalStatus = "approved"
	approvedMissingBasis.ApprovalRuleID = "relay-rule-1"
	if err := approvedMissingBasis.Validate(); err == nil {
		t.Fatal("approved destination without approval_basis was accepted")
	}

	approvedWrongBasis := base()
	approvedWrongBasis.ApprovalStatus = "approved"
	approvedWrongBasis.ApprovalBasis = "some_other_basis"
	approvedWrongBasis.ApprovalRuleID = "relay-rule-1"
	if err := approvedWrongBasis.Validate(); err == nil {
		t.Fatal("approved destination with non-catalog approval_basis was accepted")
	}

	notListed := base()
	notListed.ApprovalStatus = "not_listed"
	notListed.ApprovalBasis = "approved_destination_catalog"
	if err := notListed.Validate(); err != nil {
		t.Fatalf("not_listed destination with only basis should validate: %v", err)
	}

	notListedWithRuleID := base()
	notListedWithRuleID.ApprovalStatus = "not_listed"
	notListedWithRuleID.ApprovalBasis = "approved_destination_catalog"
	notListedWithRuleID.ApprovalRuleID = "relay-rule-1"
	if err := notListedWithRuleID.Validate(); err == nil {
		t.Fatal("not_listed destination must not carry approval_rule_id")
	}

	notListedMissingBasis := base()
	notListedMissingBasis.ApprovalStatus = "not_listed"
	if err := notListedMissingBasis.Validate(); err == nil {
		t.Fatal("not_listed destination without approval_basis was accepted")
	}

	for _, status := range []string{"", "unreviewed", "pending"} {
		withBasis := base()
		withBasis.ApprovalStatus = status
		withBasis.ApprovalBasis = "approved_destination_catalog"
		if err := withBasis.Validate(); err == nil {
			t.Fatalf("status %q destination must not carry approval_basis", status)
		}
		withRuleID := base()
		withRuleID.ApprovalStatus = status
		withRuleID.ApprovalRuleID = "relay-rule-1"
		if err := withRuleID.Validate(); err == nil {
			t.Fatalf("status %q destination must not carry approval_rule_id", status)
		}
	}

	invalidRuleID := base()
	invalidRuleID.ApprovalStatus = "approved"
	invalidRuleID.ApprovalBasis = "approved_destination_catalog"
	invalidRuleID.ApprovalRuleID = "has a space"
	if err := invalidRuleID.Validate(); err == nil {
		t.Fatal("approval_rule_id with invalid characters was accepted")
	}

	tooLongRuleID := base()
	tooLongRuleID.ApprovalStatus = "approved"
	tooLongRuleID.ApprovalBasis = "approved_destination_catalog"
	tooLongRuleID.ApprovalRuleID = strings.Repeat("a", 65)
	if err := tooLongRuleID.Validate(); err == nil {
		t.Fatal("approval_rule_id longer than 64 characters was accepted")
	}
}

// The full report Decode/Validate path must also carry approval_basis and
// approval_rule_id through for a destination on an official-classified
// endpoint, not only relay — both must be judged the same way end to end.
func TestDecodeCarriesApprovalBasisForOfficialAndRelayDestinations(t *testing.T) {
	report := validReport()
	report.Assets[0].Evidence.Destinations = []Destination{
		{Origin: "https://api.anthropic.com", Classification: "official", Source: "env", Models: []string{"claude-sonnet-5"}, ApprovalStatus: "approved", ApprovalBasis: "approved_destination_catalog", ApprovalRuleID: "official-1"},
		{Origin: "https://relay.example.test", Provider: "relay.example.test", Classification: "relay", Source: "config_file", Models: []string{}, ApprovalStatus: "not_listed", ApprovalBasis: "approved_destination_catalog"},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("valid report with official+relay approval basis rejected: %v", err)
	}
	dests := got.Assets[0].Evidence.Destinations
	if len(dests) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(dests))
	}
	if dests[0].Classification != "official" || dests[0].ApprovalBasis != "approved_destination_catalog" || dests[0].ApprovalRuleID != "official-1" {
		t.Fatalf("official destination lost approval basis/rule_id: %#v", dests[0])
	}
	if dests[1].Classification != "relay" || dests[1].ApprovalBasis != "approved_destination_catalog" || dests[1].ApprovalRuleID != "" {
		t.Fatalf("relay destination lost approval basis or unexpectedly kept rule_id: %#v", dests[1])
	}
}
