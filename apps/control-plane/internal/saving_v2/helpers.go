package saving_v2

import (
	"encoding/json"
	"fmt"
)

// toFloatSV2 converts an interface{} value to float64.
// (defined here as shared helper; snapshot_cron.go also defines it but that is OK since
//  this file is in the same package and Go doesn't allow duplicate top-level names)

// jsonDecodeBytes decodes JSON bytes into v.
func jsonDecodeBytes(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// pricingFromJSON extracts input/output float64 from pricing_json bytes.
func pricingFromJSON(pricingJSON []byte) (inputPrice, outputPrice float64) {
	if len(pricingJSON) == 0 {
		return 0, 0
	}
	var p map[string]any
	if err := json.Unmarshal(pricingJSON, &p); err != nil {
		return 0, 0
	}
	return toFloat64Any(p["input"]), toFloat64Any(p["output"])
}

// toFloat64Any converts interface{} to float64.
func toFloat64Any(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		var f float64
		fmt.Sscanf(n, "%f", &f)
		return f
	}
	return 0
}
