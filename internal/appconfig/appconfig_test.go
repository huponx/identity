package appconfig

import (
	"testing"
	"time"
)

func validBase() Identity {
	return Identity{MFAMode: MFAOff, Issuer: "https://id.example", PortalURL: "https://portal.example", GRPCPort: 9090, HTTPPort: 8080, SessionIdleTTL: time.Hour, SessionAbsoluteTTL: time.Hour}
}

func TestValidatePortalURL(t *testing.T) {
	for _, tc := range []struct {
		env, url string
		ok       bool
	}{
		{"prod", "https://portal.example", true},
		{"prod", "http://portal.example", false},
		{"local", "http://localhost:3004", true},
		{"prod", "", false},
		{"local", "/portal", false},
		{"local", "not a url", false},
	} {
		c := validBase()
		c.Env, c.PortalURL = tc.env, tc.url
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("env %q url %q: %v", tc.env, tc.url, err)
		}
	}
}

func TestValidateRegistrationRole(t *testing.T) {
	base := validBase()
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

func TestValidateRateLimitFactor(t *testing.T) {
	for _, tc := range []struct {
		env    string
		factor int64
		ok     bool
	}{{"prod", 1, true}, {"prod", 0, true}, {"prod", 100, false}, {"local", 100, true}, {"local", -1, false}} {
		c := validBase()
		c.Env, c.RateLimitFactor = tc.env, tc.factor
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("env %q factor %d: %v", tc.env, tc.factor, err)
		}
	}
}

func TestValidateWebAuthn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     string
		rp      string
		origins []string
		ok      bool
	}{
		{"default is the issuer host", "prod", "", nil, true},
		{"parent domain of all origins", "prod", "example", []string{"https://id.example", "https://portal.example"}, true},
		{"rp id not a suffix of an origin", "prod", "id.example", []string{"https://id.example", "https://portal.example"}, false},
		{"suffix must be on a dot boundary", "prod", "ample", []string{"https://id.example"}, false},
		{"http origin outside local", "prod", "example", []string{"http://id.example"}, false},
		{"http origin locally", "local", "localhost", []string{"http://localhost:8080"}, true},
		{"origin with a path", "prod", "example", []string{"https://id.example/x"}, false},
		{"rp id with a port", "prod", "id.example:443", nil, false},
	} {
		c := validBase()
		c.Env, c.WebAuthnEnabled, c.WebAuthnRPID, c.WebAuthnOrigins = tc.env, true, tc.rp, tc.origins
		if tc.env == "local" {
			c.Issuer, c.PortalURL = "http://localhost:8080", "http://localhost:3004"
		}
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// off: nothing is checked
	c := validBase()
	c.WebAuthnRPID = "nope.invalid"
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
}
