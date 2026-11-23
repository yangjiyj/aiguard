package headercompat

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestResolveScalarHeader(t *testing.T) {
	tests := []struct {
		name       string
		values     [][2]string
		want       string
		wantSource Source
		wantErr    bool
	}{
		{name: "none", wantSource: SourceNone},
		{name: "new", values: [][2]string{{"X-JJDGuard-Tenant-Id", " tenant-a\t"}}, want: "tenant-a", wantSource: SourceNew},
		{name: "legacy", values: [][2]string{{"X-NewAPI-Tenant-Id", "tenant-a"}}, want: "tenant-a", wantSource: SourceLegacy},
		{name: "same cross names", values: [][2]string{{"X-JJDGuard-Tenant-Id", "tenant-a"}, {"X-NewAPI-Tenant-Id", "tenant-a"}}, want: "tenant-a", wantSource: SourceBoth},
		{name: "different cross names", values: [][2]string{{"X-JJDGuard-Tenant-Id", "canary-new"}, {"X-NewAPI-Tenant-Id", "canary-old"}}, wantErr: true},
		{name: "same repeated new", values: [][2]string{{"X-JJDGuard-Tenant-Id", "tenant-a"}, {"x-jjdguard-tenant-id", "tenant-a"}}, want: "tenant-a", wantSource: SourceNew},
		{name: "different repeated new", values: [][2]string{{"X-JJDGuard-Tenant-Id", "canary-a"}, {"x-jjdguard-tenant-id", "canary-b"}}, wantErr: true},
		{name: "empty ignored", values: [][2]string{{"X-JJDGuard-Tenant-Id", " \t"}, {"X-NewAPI-Tenant-Id", "tenant-a"}}, want: "tenant-a", wantSource: SourceLegacy},
		{name: "comma rejected", values: [][2]string{{"X-JJDGuard-Tenant-Id", "canary-a,canary-b"}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := make(http.Header)
			for _, kv := range tt.values {
				// Direct assignment preserves differently-cased keys; Header.Add canonicalizes.
				h[kv[0]] = append(h[kv[0]], kv[1])
			}
			got, source, err := Resolve(h, "X-JJDGuard-Tenant-Id", "X-NewAPI-Tenant-Id")
			if tt.wantErr {
				if got != "" || source != SourceNone || !errors.Is(err, ErrConflict) {
					t.Fatalf("Resolve() = (%q, %q, %v), want empty/none/ErrConflict", got, source, err)
				}
				for _, kv := range tt.values {
					v := strings.Trim(kv[1], " \t")
					if v != "" && strings.Contains(err.Error(), v) {
						t.Fatal("conflict error leaked header value")
					}
				}
				return
			}
			if err != nil || got != tt.want || source != tt.wantSource {
				t.Fatalf("Resolve() = (%q, %q, %v), want (%q, %q, nil)", got, source, err, tt.want, tt.wantSource)
			}
		})
	}
}

func TestResolveRejectsNilAndInvalidContractWithoutLeaking(t *testing.T) {
	if got, source, err := Resolve(nil, "X-JJDGuard-Test", "X-NewAPI-Test"); got != "" || source != SourceNone || err != nil {
		t.Fatalf("nil header = (%q, %q, %v)", got, source, err)
	}
}
