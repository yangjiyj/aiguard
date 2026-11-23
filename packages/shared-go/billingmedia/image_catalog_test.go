package billingmedia

import "testing"

func TestToolReferenceRatesUseAuditedCurrencyAndModelOverrides(t *testing.T) {
	lookup := func(model, name string) ToolCapability {
		for _, v := range ToolCapabilitiesForModel(model) {
			if v.Name == name {
				return v
			}
		}
		t.Fatalf("missing tool %s", name)
		return ToolCapability{}
	}
	for _, c := range []struct {
		model, name, currency, key string
		amount                     int64
	}{
		{"gpt-4.1-mini-2025-04-14", "web_search_preview", "USD", "web_search_preview:gpt-4.1-mini*", 25_000_000},
		{"grok-4", "web_search", "USD", "web_search:grok*", 5_000_000},
		{"gemini-2.5-pro", "google_search", "USD", "google_search:gemini-2.5*", 0},
		{"gemini-2.5-pro", "google_search_grounded_prompt", "USD", "google_search_grounded_prompt:gemini-2.5*", 35_000_000},
		{"gemini-3-pro", "google_search", "USD", "google_search", 14_000_000},
		{"custom", "search_std", "CNY", "search_std", 10_000_000},
	} {
		v := lookup(c.model, c.name)
		if v.ReferencePricePerThousandMicros == nil || *v.ReferencePricePerThousandMicros != c.amount || v.ReferenceCurrency != c.currency || v.ReferenceKey != c.key || v.ReferenceURL == "" {
			t.Fatalf("reference %+v, want %+v", v, c)
		}
	}
	if v := lookup("gemini-3-pro", "google_search_grounded_prompt"); v.ReferencePricePerThousandMicros != nil {
		t.Fatalf("unseeded Google prompt price guessed: %+v", v)
	}
	if v := lookup("custom", "web_fetch"); v.ReferencePricePerThousandMicros != nil {
		t.Fatalf("unseeded fetch price guessed: %+v", v)
	}
	if v := lookup("custom", "bing_web_search"); v.Support != "native" {
		t.Fatalf("actual Bing counter not described: %+v", v)
	}
}

func TestImageTemplatesHaveNoGuessedAmounts(t *testing.T) {
	for _, c := range []struct {
		model, id  string
		recognized bool
	}{{"gpt-image-2", "gpt-image-token", true}, {"dall-e-3", "dall-e-3-legacy", true}, {"unrecognized/model", "custom-image", false}, {"gpt-image-made-up", "custom-image", false}, {"channel/gpt-image-2", "custom-image", false}} {
		id, recognized := SuggestedImageTemplate(c.model)
		if id != c.id || recognized != c.recognized {
			t.Fatalf("suggestion %q %v for %q", id, recognized, c.model)
		}
	}
}
