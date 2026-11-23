package alert

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alertconfig"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// trustedDevFixtureDir holds the shared routing fixtures. The Python mirror
// (deploy/tests/test_redisposition_trusted_dev.py) reads the very same files, so
// a rule change that only lands on one side fails on the other side too.
const trustedDevFixtureDir = "../../../../deploy/tests/fixtures/trusted_dev"

type trustedDevFixtureEvent struct {
	EventType      string         `json:"event_type"`
	Severity       string         `json:"severity"`
	ActionTaken    string         `json:"action_taken"`
	PrincipalKey   string         `json:"principal_key"`
	MatchedSummary map[string]any `json:"matched_summary"`
}

type trustedDevFixtureConfig struct {
	Agents     []string `json:"agents"`
	Principals []string `json:"principals"`
}

type trustedDevFixtureExpect struct {
	Routed bool   `json:"routed"`
	Reason string `json:"reason"`
}

type trustedDevFixture struct {
	Name   string                   `json:"name"`
	Note   string                   `json:"note"`
	Config *trustedDevFixtureConfig `json:"config"`
	Event  trustedDevFixtureEvent   `json:"event"`
	Expect trustedDevFixtureExpect  `json:"expect"`
}

func (f trustedDevFixture) securityEvent() *repository.SecurityEvent {
	return &repository.SecurityEvent{
		ID:             f.Name,
		TenantID:       "tenant_fixture",
		RequestID:      "req_" + f.Name,
		EventType:      f.Event.EventType,
		Severity:       f.Event.Severity,
		ActionTaken:    f.Event.ActionTaken,
		PrincipalKey:   f.Event.PrincipalKey,
		MatchedSummary: f.Event.MatchedSummary,
	}
}

// routeConfig resolves the fixture policy: a fixture only pins the lists it
// cares about, and an absent list keeps the shipped default (a fixture that
// names a trusted principal must not silently empty the agent inventory).
func (f trustedDevFixture) routeConfig() trustedDevConfig {
	if f.Config == nil {
		return trustedDevDefaults()
	}
	agents := f.Config.Agents
	if agents == nil {
		agents = alertconfig.DefaultTrustedDevAgents
	}
	return trustedDevConfigFromLists(agents, f.Config.Principals)
}

func loadTrustedDevFixtures(t *testing.T) []trustedDevFixture {
	t.Helper()
	entries, err := os.ReadDir(trustedDevFixtureDir)
	if err != nil {
		t.Fatalf("read trusted-dev fixtures: %v", err)
	}
	fixtures := make([]trustedDevFixture, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(trustedDevFixtureDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		var fixture trustedDevFixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatalf("decode %s: %v", entry.Name(), err)
		}
		if fixture.Name == "" {
			t.Fatalf("%s: fixture must declare a name", entry.Name())
		}
		if fixture.Expect.Routed && fixture.Expect.Reason == "" {
			t.Fatalf("%s: a routed fixture must declare the expected reason", entry.Name())
		}
		if len(fixture.Event.MatchedSummary) == 0 {
			t.Fatalf("%s: fixture must carry matched_summary", entry.Name())
		}
		fixtures = append(fixtures, fixture)
	}
	if len(fixtures) < 10 {
		t.Fatalf("expected the shared routing fixtures, found only %d", len(fixtures))
	}
	return fixtures
}

// TestTrustedDevelopmentRouteFixtures drives the router with the cross-language
// fixture set. Both directions must actually be exercised: a router that always
// declines, or always routes, has to fail here rather than quietly pass.
func TestTrustedDevelopmentRouteFixtures(t *testing.T) {
	routed, declined := 0, 0
	for _, fixture := range loadTrustedDevFixtures(t) {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			route, ok := trustedDevelopmentRoute(fixture.securityEvent(), fixture.routeConfig())
			if ok != fixture.Expect.Routed {
				t.Fatalf("routed=%v, want %v — %s", ok, fixture.Expect.Routed, fixture.Note)
			}
			if !ok {
				return
			}
			if route.Route != trustedDevRouteName {
				t.Fatalf("route=%q, want %q", route.Route, trustedDevRouteName)
			}
			if route.Reason != fixture.Expect.Reason {
				t.Fatalf("reason=%q, want %q", route.Reason, fixture.Expect.Reason)
			}
		})
		if fixture.Expect.Routed {
			routed++
		} else {
			declined++
		}
	}
	if routed == 0 || declined == 0 {
		t.Fatalf("fixture set must cover both directions, routed=%d declined=%d", routed, declined)
	}
}

func TestTrustedDevelopmentRouteDefaultsToShippedAgentInventory(t *testing.T) {
	cfg := trustedDevDefaults()
	for _, agent := range []string{
		"agent_claude_code", "agent_openai_codex", "agent_workbuddy", "agent_cursor",
		"agent_opencode", "agent_codebuddy", "agent_copilot", "agent_cline",
	} {
		if !cfg.Agents[agent] {
			t.Fatalf("default agent inventory must contain %s", agent)
		}
	}
	if len(cfg.Principals) != 0 {
		t.Fatalf("no principal may be trusted by default, got %v", cfg.Principals)
	}
}

func TestTrustedDevelopmentRouteAgentOverride(t *testing.T) {
	ev := &repository.SecurityEvent{
		ID: "override", EventType: "prompt_leak_internal_rules", Severity: "high", ActionTaken: "audit",
		MatchedSummary: map[string]any{
			"agent_type": "agent_acme_cli",
			"findings": []any{
				map[string]any{"counts_as_security_finding": false, "rule_type": "agent_detect", "category": "agent_acme_cli", "severity": "low"},
				map[string]any{"counts_as_security_finding": true, "category": "prompt_leak_internal_rules", "severity": "high", "content_source": "tool_result"},
			},
		},
	}
	if _, ok := trustedDevelopmentRoute(ev, trustedDevDefaults()); ok {
		t.Fatal("an unknown agent must not route with the shipped inventory")
	}
	if route, ok := trustedDevelopmentRoute(ev, trustedDevConfigFromLists([]string{"agent_acme_cli"}, nil)); !ok {
		t.Fatal("SECEVENT_TRUSTED_DEV_AGENTS override must be able to admit a new client")
	} else if route.Reason != "tool_result_of_agent_acme_cli" {
		t.Fatalf("reason=%q, want tool_result_of_agent_acme_cli", route.Reason)
	}
}

// TestTrustedDevelopmentRouteDefersToBridgeHandledEventTypes pins the parity
// contract with computeLifecycleFields: tool_execution_risk and
// tool_attempt_blocked are dispositioned by earlier returns there, before this
// rule ever runs. The sweep must reach the same verdict, or it would downgrade a
// group the live bridge keeps raising as actionable.
func TestTrustedDevelopmentRouteDefersToBridgeHandledEventTypes(t *testing.T) {
	for _, eventType := range []string{"tool_execution_risk", "tool_attempt_blocked"} {
		eventType := eventType
		t.Run(eventType, func(t *testing.T) {
			ev := (&trustedDevFixture{
				Name: eventType, Event: trustedDevFixtureEvent{
					EventType: eventType, Severity: "high", ActionTaken: "audit", PrincipalKey: "192.168.56.1",
					MatchedSummary: map[string]any{
						"agent_type": "agent_claude_code",
						"findings": []any{
							map[string]any{"counts_as_security_finding": false, "rule_type": "agent_detect", "category": "agent_claude_code", "severity": "low"},
							map[string]any{"counts_as_security_finding": true, "category": "prompt_leak_internal_rules", "severity": "high", "content_source": "tool_result", "message_role": "tool"},
						},
					},
				},
			}).securityEvent()
			if _, ok := trustedDevelopmentRoute(ev, trustedDevDefaults()); ok {
				t.Fatalf("%s must keep the bridge's own disposition", eventType)
			}
			// The identical evidence under any other event type does route, which
			// proves the event-type exclusion is what declined it.
			ev.EventType = "security_check"
			if _, ok := trustedDevelopmentRoute(ev, trustedDevDefaults()); !ok {
				t.Fatal("the same evidence under a different event type must still route")
			}
		})
	}
}

func TestTrustedDevelopmentRouteEnvWiring(t *testing.T) {
	ev := (&trustedDevFixture{
		Name: "env", Event: trustedDevFixtureEvent{
			EventType: "phone_cn", Severity: "high", ActionTaken: "audit", PrincipalKey: "user_env",
			MatchedSummary: map[string]any{
				"agent_type": "agent_claude_code",
				"findings": []any{
					map[string]any{"counts_as_security_finding": true, "category": "phone_cn", "severity": "high", "message_role": "tool"},
				},
			},
		},
	}).securityEvent()

	t.Setenv("SECEVENT_TRUSTED_DEV_AGENTS", "agent_other")
	if _, ok := trustedDevelopmentRoute(ev, trustedDevConfigFromEnv()); ok {
		t.Fatal("replacing the agent inventory must drop agent_claude_code")
	}
	t.Setenv("SECEVENT_TRUSTED_DEV_AGENTS", "")
	if _, ok := trustedDevelopmentRoute(ev, trustedDevConfigFromEnv()); !ok {
		t.Fatal("an empty SECEVENT_TRUSTED_DEV_AGENTS must fall back to the shipped inventory")
	}
	t.Setenv("SECEVENT_TRUSTED_DEV_PRINCIPALS", "user_env, upstream:openai_account:7f3a91c0deadbeef")
	cfg := trustedDevConfigFromEnv()
	if !cfg.Principals["user_env"] || !cfg.Principals["upstream:openai_account:7f3a91c0deadbeef"] {
		t.Fatalf("SECEVENT_TRUSTED_DEV_PRINCIPALS must be split on commas and trimmed, got %v", cfg.Principals)
	}
	if cfg.Principals[" user_env"] || cfg.Principals["user_env "] {
		t.Fatalf("principal entries must be trimmed, got %v", cfg.Principals)
	}
}

// TestSecEventBridgeRoutesTrustedDevEventToObservation pins the wiring: the
// group must land as informational WITH a triage_route, the declined event must
// keep action_required and carry no route, and neither may leave the inbox.
func TestSecEventBridgeRoutesTrustedDevEventToObservation(t *testing.T) {
	byName := map[string]trustedDevFixture{}
	for _, fixture := range loadTrustedDevFixtures(t) {
		byName[fixture.Name] = fixture
	}
	positive, ok := byName["agent_claude_code_tool_result_prompt_leak"]
	if !ok {
		t.Fatal("shared fixtures must contain the claude-code tool_result case")
	}
	declined, ok := byName["user_message_illegal_system_command"]
	if !ok {
		t.Fatal("shared fixtures must contain the illegal-system-command case")
	}

	src := &fakeSecEventSource{events: []*repository.SecurityEvent{positive.securityEvent(), declined.securityEvent()}}
	pusher := &fakePusher{}
	groups := &fakeAlertGrouper{}

	cfg := trustedDevDefaults()
	bridge := gateBridge(src, pusher, &fakeNotifier{}, 0.5).WithAlertGroups(groups)
	bridge.trustedDev = &cfg

	n, err := bridge.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// Routing is a disposition change, not a visibility change: both stay alerts.
	if n != 2 {
		t.Fatalf("expected both events to stay visible, got %d alerts", n)
	}
	if len(groups.inputs) != 2 {
		t.Fatalf("expected 2 alert group upserts, got %d", len(groups.inputs))
	}
	byEvent := map[string]repository.AlertGroupUpsertInput{}
	for _, input := range groups.inputs {
		byEvent[input.RepresentativeEventID] = input
	}

	routedInput := byEvent[positive.Name]
	if routedInput.DispositionClass != "informational" {
		t.Fatalf("routed group disposition=%q, want informational", routedInput.DispositionClass)
	}
	route, isMap := routedInput.BodyJSON["triage_route"].(map[string]any)
	if !isMap {
		t.Fatalf("routed group body must carry triage_route, got %+v", routedInput.BodyJSON["triage_route"])
	}
	if route["route"] != trustedDevRouteName {
		t.Fatalf("triage_route.route=%v, want %s", route["route"], trustedDevRouteName)
	}
	if route["reason"] != "tool_result_of_agent_claude_code" {
		t.Fatalf("triage_route.reason=%v, want tool_result_of_agent_claude_code", route["reason"])
	}

	declinedInput := byEvent[declined.Name]
	if declinedInput.DispositionClass != "action_required" {
		t.Fatalf("declined group disposition=%q, want action_required", declinedInput.DispositionClass)
	}
	if _, present := declinedInput.BodyJSON["triage_route"]; present {
		t.Fatalf("declined group must not carry a triage_route, got %+v", declinedInput.BodyJSON["triage_route"])
	}
}
