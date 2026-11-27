package catalog

import (
	"reflect"
	"testing"
)

func TestWildcards(t *testing.T) {
	got := Wildcards([]string{"identity:user:read", "identity:user:write", "identity:role:read", "dictionary:word:read", "dictionary:word:write", "bill:invoice:read", "system:status:read"})
	want := []string{
		"*",
		"bill:*", "bill:*:read", "bill:invoice:*",
		"dictionary:*", "dictionary:*:read", "dictionary:*:write", "dictionary:word:*",
		"identity:*", "identity:*:read", "identity:*:write", "identity:role:*", "identity:user:*",
		"system:*", "system:*:read", "system:status:*",
	}
	// identity:*:write exists only when something of identity ends in :write: user:write does
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if !reflect.DeepEqual(Wildcards(nil), []string{"*"}) {
		t.Error("* is always valid")
	}
}

func TestKnown(t *testing.T) {
	k := NewKnown([]string{"identity:user:read", "identity:role:write"})
	for _, ok := range []string{"identity:user:read", "*", "identity:*", "identity:*:read", "identity:user:*", "identity:*:write"} {
		if !k.Has(ok) {
			t.Errorf("%s must be known", ok)
		}
	}
	for _, bad := range []string{"identity:*:purge", "foo", "dictionary:*", "identity:user:write", "identity:user:approve"} {
		if k.Has(bad) {
			t.Errorf("%s must be unknown", bad)
		}
	}
	if got := k.Stale([]string{"*", "identity:*:read", "dictionary:*", "gone:a:b"}); !reflect.DeepEqual(got, []string{"dictionary:*", "gone:a:b"}) {
		t.Errorf("stale %v", got)
	}
}
