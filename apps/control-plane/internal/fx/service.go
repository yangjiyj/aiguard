package fx

import (
	"context"
	"encoding/json"
	"os"
	"time"
)

// Service wraps Repository with business logic.
type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// CurrentPPM returns the most recently effective exchange rate (as of now) in
// exact parts-per-million.
func (s *Service) CurrentPPM(ctx context.Context) (int64, error) {
	return s.repo.LatestEffective(ctx, time.Now())
}

// Current is a read-only adapter for the savings estimators (saving,
// saving_v2), which work on float USD estimates and are outside the billing
// chain. Billing never converts currency: prices must be in the wallet
// currency (see billing.ErrPriceCurrencyUnsupported).
func (s *Service) Current(ctx context.Context) (float64, error) {
	ppm, err := s.CurrentPPM(ctx)
	if err != nil {
		return 0, err
	}
	return float64(ppm) / RateScale, nil
}

// SetRate inserts a new exchange rate record given in exact ppm.
func (s *Service) SetRate(ctx context.Context, base, target string, ratePPM int64, eff time.Time, by string) error {
	if ratePPM <= 0 || ratePPM > maxRatePPM {
		return ErrInvalidRate
	}
	return s.repo.Insert(ctx, base, target, ratePPM, eff, by)
}

// History returns the last `limit` rates.
func (s *Service) History(ctx context.Context, limit int) ([]Rate, error) {
	return s.repo.History(ctx, limit)
}

// LoadSeed reads seed entries from a JSON file. Rates are kept as the literal
// decimal text so they can be parsed exactly.
func LoadSeed(path string) ([]SeedEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var seeds []SeedEntry
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	return seeds, decoder.Decode(&seeds)
}

// ApplySeedIfEmpty inserts seed rates only if no rates exist yet.
func ApplySeedIfEmpty(ctx context.Context, svc *Service, seeds []SeedEntry) error {
	rate, _ := svc.CurrentPPM(ctx)
	if rate > 0 {
		return nil // rates already configured
	}
	for _, s := range seeds {
		ppm, err := ParseRatePPM(s.Rate.String())
		if err != nil {
			return err
		}
		eff, _ := time.Parse(time.RFC3339, s.EffectiveAt)
		if err := svc.SetRate(ctx, s.Base, s.Target, ppm, eff, "seed"); err != nil {
			return err
		}
	}
	return nil
}
