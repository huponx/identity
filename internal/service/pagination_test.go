package service

import (
	"reflect"
	"testing"
)

func TestPageSize(t *testing.T) {
	for in, want := range map[int32]int{0: 50, 1: 1, 200: 200, 1000: 200} {
		got, err := pageSize(in)
		if err != nil || got != want {
			t.Errorf("pageSize(%d) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := pageSize(-1); err == nil {
		t.Error("a negative page_size must be rejected")
	}
}

func TestPageToken(t *testing.T) {
	first, err := decodePageToken("", 2)
	if err != nil || !reflect.DeepEqual(first, []string{"", ""}) {
		t.Fatalf("first page = %v, %v", first, err)
	}
	got, err := decodePageToken(encodePageToken("web", "https://api"), 2)
	if err != nil || !reflect.DeepEqual(got, []string{"web", "https://api"}) {
		t.Fatalf("round trip = %v, %v", got, err)
	}
	if _, err := decodePageToken(encodePageToken("only-one"), 2); err == nil {
		t.Error("a token with the wrong number of parts must be rejected")
	}
	if _, err := decodePageToken("!!not base64!!", 1); err == nil {
		t.Error("garbage must be rejected")
	}
}
