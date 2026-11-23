package audit_chain

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalPayloadExactDecimalNormalization(t *testing.T) {
	cases := []struct {
		name, want string
		inputs     []string
	}{
		{"integer_exponent", "100", []string{"1e2", "1E+02", "100.00", "0.1e3"}},
		{"fraction_zeroes", "1", []string{"1.00", "10e-1", "1000e-3"}},
		{"signed_zero", "0", []string{"-0", "-0.000e+12", "0e-4"}},
		{"small_decimal", "0.000123", []string{"1.2300e-4", "0.00012300"}},
		{"negative_exponent", "-203000", []string{"-2.0300E+05", "-203000.000"}},
		{"fraction_shift", "0.12", []string{"0.00120e2", "12e-2"}},
		{"internal_zeroes", "100.001", []string{"100.00100", "100001e-3"}},
		{"large_integer", "9007199254740993", []string{"9007199254740993", "9007199254740993.0"}},
		{"precise_decimal", "0.10000000000000001", []string{"0.10000000000000001", "10000000000000001e-17"}},
		{"outside_float_range", "1" + strings.Repeat("0", 400), []string{"1e400"}},
		{"below_float_range", "0." + strings.Repeat("0", 399) + "1", []string{"1e-400"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range tc.inputs {
				got, err := CanonicalPayload(json.Number(input))
				if err != nil {
					t.Fatalf("input %s: %v", input, err)
				}
				if string(got) != tc.want {
					t.Fatalf("input %s: got %s, want %s", input, got, tc.want)
				}
			}
		})
	}
}

func TestCanonicalPayloadGoFloatFormattingThresholds(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  string
	}{
		{1e21, "1" + strings.Repeat("0", 21)},
		{1e-7, "0.0000001"},
		{math.Copysign(0, -1), "0"},
		{0.1, "0.1"},
	} {
		got, err := CanonicalPayload(tc.value)
		if err != nil || string(got) != tc.want {
			t.Fatalf("value %v: got %s, err %v, want %s", tc.value, got, err, tc.want)
		}
	}
}

func TestCanonicalPayloadSortsTypedAndRawNestedValues(t *testing.T) {
	type nested struct {
		Z int `json:"z"`
		A int `json:"a"`
	}
	type payload struct {
		Z     []nested        `json:"z"`
		Raw   json.RawMessage `json:"raw"`
		Count int64           `json:"count"`
		A     nested          `json:"a"`
	}
	typed := payload{
		Z:     []nested{{Z: 2, A: 1}},
		Raw:   json.RawMessage(`{"z":1e2,"a":{"z":2,"a":1.00}}`),
		Count: 9007199254740993,
		A:     nested{Z: 2, A: 1},
	}
	want := `{"a":{"a":1,"z":2},"count":9007199254740993,"raw":{"a":{"a":1,"z":2},"z":100},"z":[{"a":1,"z":2}]}`
	got, err := CanonicalPayload(typed)
	if err != nil || string(got) != want {
		t.Fatalf("typed payload got %s, err %v, want %s", got, err, want)
	}
	decoded, err := DecodePayload(got)
	if err != nil {
		t.Fatal(err)
	}
	recanonical, err := CanonicalPayload(decoded)
	if err != nil || !bytes.Equal(got, recanonical) {
		t.Fatalf("typed/decoded bytes differ: %s / %s, err %v", got, recanonical, err)
	}
}

func TestCanonicalPayloadPreservesNullAndEmptyContainers(t *testing.T) {
	var nilMap map[string]int
	var nilSlice []int
	var nilPointer *int
	var nilRaw json.RawMessage
	for i, value := range []any{nil, nilMap, nilSlice, nilPointer, nilRaw, json.RawMessage("null")} {
		got, err := CanonicalPayload(value)
		if err != nil || string(got) != "null" {
			t.Fatalf("nil case %d: got %s, err %v", i, got, err)
		}
	}
	for _, tc := range []struct {
		value any
		want  string
	}{
		{map[string]int{}, "{}"},
		{[]int{}, "[]"},
		{map[string]any{"slice": nilSlice, "map": nilMap, "empty": []int{}}, `{"empty":[],"map":null,"slice":null}`},
	} {
		got, err := CanonicalPayload(tc.value)
		if err != nil || string(got) != tc.want {
			t.Fatalf("got %s, err %v, want %s", got, err, tc.want)
		}
	}
}

func TestDecodePayloadRetainsExactNumbersAtEveryLevel(t *testing.T) {
	got, err := DecodePayload([]byte(`{"integer":9007199254740993,"nested":[{"decimal":0.10000000000000001},1e400]}`))
	if err != nil {
		t.Fatal(err)
	}
	integer, ok := got["integer"].(json.Number)
	if !ok || integer.String() != "9007199254740993" {
		t.Fatalf("integer lost precision or type: %#v", got["integer"])
	}
	array := got["nested"].([]any)
	decimal := array[0].(map[string]any)["decimal"]
	if number, ok := decimal.(json.Number); !ok || number.String() != "0.10000000000000001" {
		t.Fatalf("decimal lost precision or type: %#v", decimal)
	}
	if number, ok := array[1].(json.Number); !ok || number.String() != "1e400" {
		t.Fatalf("scientific token lost precision or type: %#v", array[1])
	}
	null, err := DecodePayload([]byte(" \n null\t"))
	if err != nil || null != nil {
		t.Fatalf("null got %#v, err %v", null, err)
	}
	object, err := DecodePayload([]byte("{}"))
	if err != nil || object == nil || len(object) != 0 {
		t.Fatalf("empty object got %#v, err %v", object, err)
	}
}

func TestDecodePayloadRejectsAmbiguousOrInvalidJSON(t *testing.T) {
	for _, input := range []string{
		``, ` `, `[]`, `1`, `true`, `"object"`,
		`{"a":1,"a":2}`, `{"a":null,"a":2}`,
		`{"a":1,"\u0061":2}`, `{"nested":[{"a":1,"a":2}]}`,
		`{} {}`, `{} false`, `{} garbage`,
		`{"n":NaN}`, `{"n":Infinity}`, `{"n":01}`, `{"n":+1}`,
		`{"n":1.}`, `{"n":.1}`, `{"n":1e}`, `{"n":1,}`,
		`{"a":}`, `{"a":[1,]}`, `{"a":1`, `{"a":[1}`,
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := DecodePayload([]byte(input)); err == nil {
				t.Fatalf("accepted invalid payload %q: %#v", input, got)
			}
		})
	}
	invalidUTF8 := []byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'}
	if _, err := DecodePayload(invalidUTF8); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

type duplicateKeyJSONMarshaler struct{}

func (duplicateKeyJSONMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(`{"a":1,"\u0061":2}`), nil
}

func TestCanonicalPayloadRejectsInvalidValues(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, value := range []any{
		math.NaN(), math.Inf(1), math.Inf(-1), make(chan int), cycle,
		json.Number("01"), json.Number("NaN"),
		json.RawMessage(`{"a":1,"a":2}`),
		json.RawMessage(`{"nested":{"a":1,"a":2}}`),
		json.RawMessage(`{"n":1.}`), json.RawMessage(`{} {}`),
		duplicateKeyJSONMarshaler{},
	} {
		if got, err := CanonicalPayload(value); err == nil || got != nil {
			t.Fatalf("accepted invalid %T: %s, err %v", value, got, err)
		}
	}
}

func TestCanonicalPayloadRejectsUnboundedNumberExpansion(t *testing.T) {
	for _, input := range []string{
		"1e" + strconv.Itoa(maxCanonicalNumberLength),
		"1e-" + strconv.Itoa(maxCanonicalNumberLength),
		"1e9223372036854775807",
		"100e9223372036854775807",
		"1.1e-9223372036854775808",
		"1e999999999999999999999999999999999999",
	} {
		if got, err := CanonicalPayload(json.Number(input)); err == nil || got != nil {
			t.Fatalf("accepted unbounded number %s: length %d, err %v", input, len(got), err)
		}
	}
}

func TestCanonicalPayloadDetectsLossyLegacyFloatCandidates(t *testing.T) {
	for _, tc := range []struct {
		number string
		safe   bool
	}{
		{"0.1", true},
		{"1.00", true},
		{"1e2", true},
		{"9007199254740994", true},
		{"9007199254740993", false},
		{"0.10000000000000001", false},
		{"1e-400", false},
	} {
		raw := []byte(`{"n":` + tc.number + `}`)
		original, err := DecodePayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		var legacy map[string]any
		if err := json.Unmarshal(raw, &legacy); err != nil {
			t.Fatal(err)
		}
		originalBytes, err := CanonicalPayload(original)
		if err != nil {
			t.Fatal(err)
		}
		legacyBytes, err := CanonicalPayload(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if equal := bytes.Equal(originalBytes, legacyBytes); equal != tc.safe {
			t.Fatalf("number %s: safe=%v, want %v; original=%s legacy=%s", tc.number, equal, tc.safe, originalBytes, legacyBytes)
		}
	}
}

func FuzzCanonicalPayloadIdempotent(f *testing.F) {
	for _, seed := range []string{
		`{"z":1e2,"a":[null,-0,0.10000000000000001]}`,
		`[9007199254740993,{"z":2,"a":1}]`,
		`null`, `"escaped\ntext"`, `1e400`, `1e-400`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		canonical, err := CanonicalPayload(json.RawMessage(raw))
		if err != nil {
			return
		}
		if !json.Valid(canonical) {
			t.Fatalf("canonical output is invalid JSON: %s", canonical)
		}
		again, err := CanonicalPayload(canonical)
		if err != nil || !bytes.Equal(canonical, again) {
			t.Fatalf("canonicalization is not idempotent: %s / %s, err %v", canonical, again, err)
		}
	})
}
