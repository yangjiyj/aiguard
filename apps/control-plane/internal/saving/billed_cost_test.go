package saving

import "testing"

func TestBilledCostUSD(t *testing.T) {
	micros := func(v int64) *int64 { return &v }
	if got, ok := billedCostUSD(micros(2_500_000), "USD", 7.2); !ok || got != 2.5 {
		t.Fatalf("USD = %v, %v", got, ok)
	}
	if got, ok := billedCostUSD(micros(7_200_000), "cny", 7.2); !ok || got != 1 {
		t.Fatalf("CNY = %v, %v", got, ok)
	}
	for name, c := range map[string]struct {
		micros   *int64
		currency string
	}{
		"missing":  {nil, "USD"},
		"zero":     {micros(0), "USD"},
		"unknown":  {micros(100), "EUR"},
		"no curr.": {micros(100), ""},
	} {
		if _, ok := billedCostUSD(c.micros, c.currency, 7.2); ok {
			t.Fatalf("%s should fall back to model pricing", name)
		}
	}
	if _, ok := billedCostUSD(micros(100), "CNY", 0); ok {
		t.Fatal("CNY without an exchange rate should fall back")
	}
}
