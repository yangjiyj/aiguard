package fx

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// RateScale is the fixed-point scale of fx_rates.rate (DECIMAL(18,6)).
// Rates travel as integer parts-per-million so no float rounding can creep in.
const RateScale = 1_000_000

// maxRatePPM keeps the value inside DECIMAL(18,6): 12 integer digits.
const maxRatePPM = int64(999_999_999_999_999_999)

// ErrInvalidRate rejects rates that are not positive decimals with at most six
// fractional digits (anything finer would be silently rounded by the column).
var ErrInvalidRate = errors.New("fx rate must be a positive decimal with at most 6 fractional digits")

// Rate represents an FX exchange rate record.
type Rate struct {
	ID             int64       `json:"id"`
	BaseCurrency   string      `json:"base_currency"`
	TargetCurrency string      `json:"target_currency"`
	RatePPM        int64       `json:"rate_ppm"`
	Rate           json.Number `json:"rate"`
	EffectiveAt    time.Time   `json:"effective_at"`
	CreatedBy      string      `json:"set_by"`
	CreatedAt      time.Time   `json:"created_at"`
}

// SeedEntry is the JSON shape used by seed files.
type SeedEntry struct {
	Base        string      `json:"base"`
	Target      string      `json:"target"`
	Rate        json.Number `json:"rate"`
	EffectiveAt string      `json:"effective_at"`
}

// ParseRatePPM parses a decimal rate ("7.24", "7.123456") exactly into ppm.
func ParseRatePPM(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "eE+-") {
		return 0, ErrInvalidRate
	}
	whole, frac, _ := strings.Cut(raw, ".")
	if whole == "" {
		whole = "0"
	}
	if len(frac) > 6 || strings.Contains(frac, ".") {
		return 0, ErrInvalidRate
	}
	frac += strings.Repeat("0", 6-len(frac))
	if len(whole) > 12 {
		return 0, ErrInvalidRate
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, ErrInvalidRate
	}
	f, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, ErrInvalidRate
	}
	ppm := w*RateScale + f
	if ppm <= 0 || ppm > maxRatePPM {
		return 0, ErrInvalidRate
	}
	return ppm, nil
}

// FormatRatePPM renders ppm as the shortest exact decimal ("7240000" -> "7.24").
func FormatRatePPM(ppm int64) json.Number {
	whole, frac := ppm/RateScale, ppm%RateScale
	if frac == 0 {
		return json.Number(strconv.FormatInt(whole, 10))
	}
	digits := strings.TrimRight(strconv.FormatInt(RateScale+frac, 10)[1:], "0")
	return json.Number(strconv.FormatInt(whole, 10) + "." + digits)
}
