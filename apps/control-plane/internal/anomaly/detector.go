package anomaly

import "sort"

// BaselineStat holds median and MAD for a time series.
type BaselineStat struct {
	Median float64
	MAD    float64
}

// median returns the median of xs (non-destructive via copy).
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Baseline computes median and MAD from a historical series.
func Baseline(hist []float64) BaselineStat {
	m := median(hist)
	dev := make([]float64, len(hist))
	for i, x := range hist {
		d := x - m
		if d < 0 {
			d = -d
		}
		dev[i] = d
	}
	return BaselineStat{Median: m, MAD: median(dev)}
}

// HasEnoughData returns true when hist has >= 7 data points.
func HasEnoughData(hist []float64) bool { return len(hist) >= 7 }

// IsAbsoluteSpike returns true when actual exceeds median + k*1.4826*MAD.
func IsAbsoluteSpike(actual float64, b BaselineStat, k float64) bool {
	threshold := b.Median + k*1.4826*b.MAD
	return actual > threshold
}

// RatioSpike returns true when actual/prev > ratio.
func RatioSpike(actual, prev, ratio float64) bool {
	if prev <= 0 {
		return false
	}
	return actual/prev > ratio
}
