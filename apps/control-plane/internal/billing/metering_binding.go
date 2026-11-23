package billing

import "time"

func reservationTariff(r *Reservation) TariffQuote {
	return TariffQuote{PlanID: r.TariffPlanID, PlanVersion: r.TariffPlanVersion, RuleID: r.TariffRuleID, Band: r.TariffBand, MultiplierPPM: r.TariffMultiplierPPM, Timezone: r.BillingTimezone, AdmittedAt: r.AdmittedAt}
}

func sameFrozenTariff(a, b TariffQuote) bool {
	return a.PlanID == b.PlanID && a.PlanVersion == b.PlanVersion && a.RuleID == b.RuleID && a.Band == b.Band && a.MultiplierPPM == b.MultiplierPPM && a.Timezone == b.Timezone && a.AdmittedAt.UTC().Truncate(time.Microsecond).Equal(b.AdmittedAt.UTC().Truncate(time.Microsecond))
}

func bindMeteringReservation(input *MeteringInput, w *Wallet, r *Reservation) error {
	if input.Unpriced || input.UsageUnknown || input.UserID != w.UserID || (r.UserID != "" && r.UserID != w.UserID) || input.ModelName != r.ModelName {
		return ErrIdempotencyConflict
	}
	if r.PriceID == "" {
		return ErrIdempotencyConflict
	}
	if input.QuotePriceID != "" && input.QuotePriceID != r.PriceID {
		return ErrIdempotencyConflict
	}
	if input.QuoteGroupRatioPPM != nil && *input.QuoteGroupRatioPPM != r.CustomerGroupRatioPPM {
		return ErrIdempotencyConflict
	}
	if !input.AdmittedAt.IsZero() && !input.AdmittedAt.UTC().Truncate(time.Microsecond).Equal(r.AdmittedAt.UTC().Truncate(time.Microsecond)) {
		return ErrIdempotencyConflict
	}
	tariff := reservationTariff(r)
	if input.QuoteTariff != nil && !sameFrozenTariff(*input.QuoteTariff, tariff) {
		return ErrIdempotencyConflict
	}
	input.QuotePriceID = r.PriceID
	ratio := r.CustomerGroupRatioPPM
	input.QuoteGroupRatioPPM = &ratio
	input.QuoteTariff = &tariff
	input.AdmittedAt = r.AdmittedAt
	return nil
}
