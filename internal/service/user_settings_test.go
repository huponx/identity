package service

import (
	"strings"
	"testing"

	"github.com/huponx/gocommon/grpcserver"
)

func TestCheckUserSettings(t *testing.T) {
	big := `{"a":"` + strings.Repeat("x", maxUserSettings) + `"}`
	cases := []struct {
		name, app, json string
		ok              bool
	}{
		{"ok", "dictionary", `{"deckName":"x"}`, true},
		{"empty object", "dictionary", `{}`, true},
		{"name with dash", "my-app_2", `{}`, true},
		{"upper case app", "Dictionary", `{}`, false},
		{"empty app", "", `{}`, false},
		{"app with a dot", "a.b", `{}`, false},
		{"too long app", strings.Repeat("a", 33), `{}`, false},
		{"array", "dictionary", `[]`, false},
		{"null", "dictionary", `null`, false},
		{"text", "dictionary", `nope`, false},
		{"too large", "dictionary", big, false},
	}
	for _, c := range cases {
		if err := checkUserSettings(c.app, c.json); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The settings methods work on the signed-in user, like the other "me" methods.
func TestUserSettingsPermissionsArePublic(t *testing.T) {
	for _, m := range []string{"GetMyUserSettings", "PutMyUserSettings"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; got != grpcserver.Public {
			t.Errorf("%s: %q", m, got)
		}
	}
}
