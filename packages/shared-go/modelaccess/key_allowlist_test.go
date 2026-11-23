package modelaccess

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeKeyAllowlistCannotAddUserModels(t *testing.T) {
	access := &Access{ChatAllowed: true, EffectiveModels: []string{"model-a", "model-b"}}
	for _, bad := range [][]string{{"model-c"}, {"*"}, {"model-a", "model-c"}, {""}} {
		if _, err := NormalizeKeyAllowlist(bad, access); err == nil {
			t.Fatalf("accepted unauthorized models %#v", bad)
		}
	}
	got, err := NormalizeKeyAllowlist([]string{"model-b", "model-a", "model-a"}, access)
	if err != nil || !reflect.DeepEqual(got, []string{"model-a", "model-b"}) {
		t.Fatalf("got=%v err=%v", got, err)
	}
	got, err = NormalizeKeyAllowlist(nil, access)
	if err != nil || len(got) != 0 {
		t.Fatal("empty must inherit")
	}
	access.ChatAllowed = false
	if _, err := NormalizeKeyAllowlist([]string{"model-a"}, access); !errors.Is(err, ErrKeyModelUnauthorized) {
		t.Fatal("disabled user accepted")
	}
}
