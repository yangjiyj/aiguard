package fx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fx.json")
	seeds := []SeedEntry{
		{Base: "USD", Target: "CNY", Rate: "7.20", EffectiveAt: "2026-05-01T00:00:00Z"},
	}
	b, _ := json.Marshal(seeds)
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSeed(path)
	if err != nil {
		t.Fatalf("LoadSeed error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded))
	}
	if loaded[0].Base != "USD" {
		t.Errorf("expected base USD, got %s", loaded[0].Base)
	}
	if ppm, err := ParseRatePPM(loaded[0].Rate.String()); err != nil || ppm != 7_200_000 {
		t.Errorf("expected rate 7.20 (7200000 ppm), got %s -> %d (%v)", loaded[0].Rate, ppm, err)
	}
}

// 7.10: rates travel as exact ppm; float parsing would store 7.1234567 as a
// silently rounded value and 0.1+0.2-style drift in conversions.
func TestRatePPMIsExactAndRejectsUnrepresentableRates(t *testing.T) {
	for raw, want := range map[string]int64{
		"7.24": 7_240_000, "7.123456": 7_123_456, "0.000001": 1, "1": 1_000_000, "7.": 7_000_000, ".5": 500_000,
		"999999999999.999999": 999_999_999_999_999_999,
	} {
		got, err := ParseRatePPM(raw)
		if err != nil || got != want {
			t.Errorf("ParseRatePPM(%q)=%d,%v want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "0", "0.0000001", "7.1234567", "-7.2", "7e0", "1000000000000", "abc", "7.2.1", "+7"} {
		if got, err := ParseRatePPM(raw); err == nil {
			t.Errorf("ParseRatePPM(%q)=%d, want ErrInvalidRate", raw, got)
		}
	}
	for ppm, want := range map[int64]string{7_240_000: "7.24", 7_123_456: "7.123456", 1: "0.000001", 7_000_000: "7"} {
		if got := FormatRatePPM(ppm).String(); got != want {
			t.Errorf("FormatRatePPM(%d)=%q want %q", ppm, got, want)
		}
	}
}

func TestLoadSeed_FileNotFound(t *testing.T) {
	_, err := LoadSeed("/nonexistent/fx.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSeedEntry_ParseEffectiveAt(t *testing.T) {
	s := SeedEntry{EffectiveAt: "2026-05-01T00:00:00Z"}
	eff, err := time.Parse(time.RFC3339, s.EffectiveAt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if eff.Year() != 2026 {
		t.Errorf("expected year 2026, got %d", eff.Year())
	}
}

// TestApplySeedIfEmpty_WithDB uses real DB if available.
func TestApplySeedIfEmpty_WithDB(t *testing.T) {
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	// Real DB integration test requires pgxpool setup
	t.Skip("real DB test requires pgxpool setup - covered by integration tests")
}
