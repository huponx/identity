package service

import (
	"context"
	"testing"

	"github.com/huponx/gocommon/grpcserver"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

func TestUIStylesAreTheThreeLooks(t *testing.T) {
	for _, v := range []string{"saas", "glass", "mono"} {
		if !uiStyles[v] {
			t.Errorf("%s is not a style", v)
		}
	}
	for _, v := range []string{"", "SaaS", "dark", "neon"} {
		if uiStyles[v] {
			t.Errorf("%q is a style", v)
		}
	}
	if !uiStyles[DefaultUIStyle] {
		t.Errorf("default %q is not a style", DefaultUIStyle)
	}
}

// An unknown style is refused before the store is reached (the store is nil here).
func TestSetUIStyleRejectsUnknown(t *testing.T) {
	s := &Service{}
	if _, err := s.SetUIStyle(context.Background(), &identityv1.SetUIStyleRequest{UiStyle: "neon"}); err == nil {
		t.Error("neon accepted")
	}
}

// Reading the look needs only a session, changing it needs the settings permission.
func TestUIStylePermissions(t *testing.T) {
	if got := Permissions["/identity.v1.IdentityService/GetUIStyle"]; got != grpcserver.Public {
		t.Errorf("GetUIStyle: %q", got)
	}
	if got := Permissions["/identity.v1.IdentityService/SetUIStyle"]; got != "identity:settings:write" {
		t.Errorf("SetUIStyle: %q", got)
	}
}

func TestUIPalettesAreTheSixColourSets(t *testing.T) {
	for _, v := range []string{"aurora", "ocean", "sunset", "mint", "rose", "graphite"} {
		if !uiPalettes[v] {
			t.Errorf("%s is not a palette", v)
		}
	}
	for _, v := range []string{"", "Aurora", "saas", "neon"} {
		if uiPalettes[v] {
			t.Errorf("%q is a palette", v)
		}
	}
	if !uiPalettes[DefaultUIPalette] {
		t.Errorf("default %q is not a palette", DefaultUIPalette)
	}
}

// A palette that does not exist, or a key that is not a style, is refused before the store is reached (the store is nil here).
func TestSetUIStyleRejectsBadPalettes(t *testing.T) {
	s := &Service{}
	for _, pal := range []map[string]string{{"glass": "neon"}, {"glass": ""}, {"dark": "ocean"}, {"aurora": "aurora"}} {
		if _, err := s.SetUIStyle(context.Background(), &identityv1.SetUIStyleRequest{UiStyle: "glass", UiPalettes: pal}); err == nil {
			t.Errorf("%v accepted", pal)
		}
	}
}

// Every look gets a palette: the stored one, else the default (also for a value that is no longer a palette).
func TestPalettesOfFillsDefaults(t *testing.T) {
	got := palettesOf(map[string]string{"glass": "ocean", "mono": "neon", "dark": "rose"})
	want := map[string]string{"saas": "aurora", "glass": "ocean", "mono": "aurora"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
}
