package appconfig

import (
	"testing"
	"time"
)

func ident(env string, apps ...string) Identity {
	var c Identity
	c.Env = env
	c.Apps = apps
	return c
}

func TestAppLinks(t *testing.T) {
	c := ident("local", "Admin=http://localhost:3002", " Bill = https://bill.example ")
	got, err := c.AppLinks()
	if err != nil || len(got) != 2 || got[0] != (AppLink{Name: "Admin", URL: "http://localhost:3002"}) || got[1] != (AppLink{Name: "Bill", URL: "https://bill.example"}) {
		t.Fatalf("%v %v", got, err)
	}
	// one entry per line (a YAML block scalar), a name with a space
	got, err = ident("local", "Admin Portal=https://admin.example|https://admin.example/logo.svg\nDict=https://dict.example\n").AppLinks()
	if err != nil || len(got) != 2 || got[0].Name != "Admin Portal" || got[0].Icon != "https://admin.example/logo.svg" || got[1].Name != "Dict" {
		t.Fatalf("lines: %v %v", got, err)
	}
	got, err = ident("local", "A=https://a.example|https://cdn.example/a.svg", "B=https://b.example|https://cdn.example/b.svg").AppLinks()
	if err != nil || got[0].Icon != "https://cdn.example/a.svg" {
		t.Fatalf("icon: %v %v", got, err)
	}
	if o := IconOrigins(got); len(o) != 1 || o[0] != "https://cdn.example" {
		t.Errorf("origins %v", o)
	}
	for _, bad := range []string{"nourl", "=https://x", "A=ftp://x", "A=javascript:alert(1)", "A=https://a.example|javascript:x"} {
		if _, err := (ident("local", bad)).AppLinks(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ident("prod", "A=https://a.example|http://insecure.example/i.svg").AppLinks(); err == nil {
		t.Error("http icon accepted outside local")
	}
	// http only for local runs
	if _, err := (ident("prod", "A=http://x")).AppLinks(); err == nil {
		t.Error("http accepted outside local")
	}
	if got, err := (Identity{}).AppLinks(); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
}

func TestValidateRegistrationRole(t *testing.T) {
	base := Identity{MFAMode: MFAOff, Issuer: "https://id.example", GRPCPort: 9090, HTTPPort: 8080, SessionIdleTTL: time.Hour, SessionAbsoluteTTL: time.Hour}
	for role, ok := range map[string]bool{"member": true, "a.b-c_1": true, "": false, "Member": false, "1x": false, "a b": false} {
		c := base
		c.RegistrationEnabled, c.RegistrationRole = true, role
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("role %q: %v", role, err)
		}
	}
	c := base
	c.RegistrationRole = "Bad Role" // not checked while registration is off
	if err := c.Validate(); err != nil {
		t.Errorf("registration off: %v", err)
	}
}
