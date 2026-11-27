package setup

import (
	"context"
	"strings"
	"testing"

	"github.com/huponx/identity/internal/oauth"
	"github.com/huponx/identity/internal/store"
)

type fakeStore struct {
	admins    []store.User
	clients   map[string]*store.Client
	policies  []store.ExchangePolicy
	configSet int
}

func newFake() *fakeStore { return &fakeStore{clients: map[string]*store.Client{}} }

func (f *fakeStore) CreateFirstAdmin(_ context.Context, u store.User) (*store.User, bool, error) {
	if len(f.admins) > 0 {
		return nil, false, nil
	}
	u.ID = "id-1"
	f.admins = append(f.admins, u)
	return &u, true, nil
}
func (f *fakeStore) ClientByID(_ context.Context, id string) (*store.Client, error) {
	c, ok := f.clients[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}
func (f *fakeStore) CreateClient(_ context.Context, c store.Client) (*store.Client, error) {
	f.clients[c.ClientID] = &c
	return &c, nil
}
func (f *fakeStore) SetClientConfig(_ context.Context, id string, r, l, g, s []string) error {
	c := f.clients[id]
	c.RedirectURIs, c.PostLogoutRedirectURIs, c.AllowedGrants, c.AllowedScopes = r, l, g, s
	f.configSet++
	return nil
}
func (f *fakeStore) SetClientBackchannelLogout(_ context.Context, id, uri string) error {
	f.clients[id].BackchannelLogoutURI = uri
	return nil
}
func (f *fakeStore) SetClientSecret(_ context.Context, id, h string) error {
	f.clients[id].SecretHash = h
	return nil
}
func (f *fakeStore) AssignRole(_ context.Context, _, id, role string) error {
	f.clients[id].Roles = append(f.clients[id].Roles, role)
	return nil
}
func (f *fakeStore) SetExchangePolicy(_ context.Context, p store.ExchangePolicy) error {
	f.policies = append(f.policies, p)
	return nil
}

func run(t *testing.T, f *fakeStore, cfg Config, adminPW string, env map[string]string) error {
	t.Helper()
	return Run(context.Background(), f, cfg, Env{AdminPassword: adminPW, Getenv: func(k string) string { return env[k] }},
		func(string, ...any) {})
}

const strongPW = "correct horse battery staple"

func TestAdminOnlyWhenNoAdminExists(t *testing.T) {
	f := newFake()
	cfg := Config{Admin: &Admin{Email: "first@example.com"}}
	if err := run(t, f, cfg, strongPW, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.admins) != 1 || !f.admins[0].MustChangePassword || f.admins[0].PasswordHash == "" || f.admins[0].PasswordHash == strongPW {
		t.Fatalf("admin not created as expected: %+v", f.admins)
	}
	// a second run with the same or another e-mail adds nothing
	for _, email := range []string{"first@example.com", "other@example.com"} {
		if err := run(t, f, Config{Admin: &Admin{Email: email}}, strongPW, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.admins) != 1 {
		t.Fatalf("got %d admins, want 1", len(f.admins))
	}
}

func TestAdminKeepPassword(t *testing.T) {
	f := newFake()
	if err := run(t, f, Config{Admin: &Admin{Email: "first@example.com", KeepPassword: true}}, strongPW, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.admins) != 1 || f.admins[0].MustChangePassword {
		t.Fatalf("keep_password must not force a change: %+v", f.admins)
	}
}

func TestAdminPasswordPolicy(t *testing.T) {
	for _, pw := range []string{"", "short", "first@example.com"} {
		f := newFake()
		if err := run(t, f, Config{Admin: &Admin{Email: "first@example.com"}}, pw, nil); err == nil {
			t.Errorf("password %q was accepted", pw)
		}
		if len(f.admins) != 0 {
			t.Errorf("password %q created an admin", pw)
		}
	}
}

func gatekeeper() Client {
	return Client{
		ID: "gatekeeper", Type: "confidential", Resource: "gatekeeper", SecretEnv: "GK_SECRET",
		RedirectURIs: []string{"https://api.example.com/auth/callback"}, PostLogoutURIs: []string{"https://admin.example.com/"},
		Grants: []string{"authorization_code", "refresh_token"}, Roles: []string{"gateway"},
	}
}

func TestClientCreateThenReconcile(t *testing.T) {
	f := newFake()
	env := map[string]string{"GK_SECRET": "s3cret-one"}
	cfg := Config{Clients: []Client{gatekeeper()}}
	if err := run(t, f, cfg, "", env); err != nil {
		t.Fatal(err)
	}
	c := f.clients["gatekeeper"]
	if c == nil || c.SecretHash != oauth.HashSecret("s3cret-one") || len(c.AllowedScopes) == 0 {
		t.Fatalf("client not created as expected: %+v", c)
	}

	// re-run with nothing new: no write
	if err := run(t, f, cfg, "", env); err != nil {
		t.Fatal(err)
	}
	if f.configSet != 0 {
		t.Fatal("an unchanged client was rewritten")
	}

	// a new URI, a new role and a new secret are applied; the old URI stays
	g := gatekeeper()
	g.PostLogoutURIs = []string{"https://dict.example.com/"}
	g.Roles = []string{"gateway", "extra"}
	env["GK_SECRET"] = "s3cret-two"
	if err := run(t, f, Config{Clients: []Client{g}}, "", env); err != nil {
		t.Fatal(err)
	}
	c = f.clients["gatekeeper"]
	if len(c.PostLogoutRedirectURIs) != 2 || f.configSet != 1 {
		t.Fatalf("URIs not merged: %v", c.PostLogoutRedirectURIs)
	}
	if len(c.Roles) != 2 || c.Roles[1] != "extra" {
		t.Fatalf("roles: %v", c.Roles)
	}
	if c.SecretHash != oauth.HashSecret("s3cret-two") {
		t.Fatal("secret not updated")
	}
}

func TestClientErrors(t *testing.T) {
	f := newFake()
	if err := run(t, f, Config{Clients: []Client{gatekeeper()}}, "", map[string]string{}); err == nil {
		t.Fatal("empty client secret accepted")
	}
	env := map[string]string{"GK_SECRET": "x"}
	if err := run(t, f, Config{Clients: []Client{gatekeeper()}}, "", env); err != nil {
		t.Fatal(err)
	}
	g := gatekeeper()
	g.Type, g.SecretEnv = "public", ""
	if err := run(t, f, Config{Clients: []Client{g}}, "", env); err == nil {
		t.Fatal("type change accepted")
	}
	g = gatekeeper()
	g.Resource = "other"
	if err := run(t, f, Config{Clients: []Client{g}}, "", env); err == nil {
		t.Fatal("resource change accepted")
	}
}

func TestExchangePolicies(t *testing.T) {
	f := newFake()
	cfg := Config{ExchangePolicies: []Policy{{Client: "gatekeeper", Audience: "identity", MaxDepth: 1}}}
	if err := run(t, f, cfg, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(f.policies) != 1 || f.policies[0].Audience != "identity" {
		t.Fatalf("policies: %+v", f.policies)
	}
}

func TestParse(t *testing.T) {
	good := `{"admin":{"email":"a@example.com"},"clients":[{"id":"gk","type":"confidential","resource":"gk","secret_env":"S","redirect_uris":["https://x.example.com/cb"]}],"exchange_policies":[{"client":"gk","audience":"identity"}]}`
	if _, err := Parse(good); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"empty":            ``,
		"unknown field":    `{"nope":1}`,
		"no admin email":   `{"admin":{}}`,
		"no secret env":    `{"clients":[{"id":"gk","type":"confidential","resource":"gk"}]}`,
		"bad type":         `{"clients":[{"id":"gk","type":"x","resource":"gk"}]}`,
		"bad uri":          `{"clients":[{"id":"gk","type":"public","resource":"gk","redirect_uris":["http://evil.example.com/cb"]}]}`,
		"duplicate client": `{"clients":[{"id":"gk","type":"public","resource":"gk"},{"id":"gk","type":"public","resource":"gk"}]}`,
		"policy":           `{"exchange_policies":[{"client":"gk"}]}`,
	}
	for name, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: error leaks a secret", name)
		}
	}
}

func TestBackchannelLogoutAddressIsReconciled(t *testing.T) {
	f := newFake()
	env := map[string]string{"GK_SECRET": "s3cret-one"}
	// created without an address, as before the option was configured
	if err := run(t, f, Config{Clients: []Client{gatekeeper()}}, "", env); err != nil {
		t.Fatal(err)
	}
	if got := f.clients["gatekeeper"].BackchannelLogoutURI; got != "" {
		t.Fatalf("address after create: %q", got)
	}
	// a later run with an address sets it on the existing client
	g := gatekeeper()
	g.BackchannelLogoutURI = "http://localhost:8081/auth/backchannel-logout"
	if err := run(t, f, Config{Clients: []Client{g}}, "", env); err != nil {
		t.Fatal(err)
	}
	if got := f.clients["gatekeeper"].BackchannelLogoutURI; got != g.BackchannelLogoutURI {
		t.Fatalf("address after reconcile: %q", got)
	}
	// a run without one leaves it alone
	if err := run(t, f, Config{Clients: []Client{gatekeeper()}}, "", env); err != nil {
		t.Fatal(err)
	}
	if got := f.clients["gatekeeper"].BackchannelLogoutURI; got != g.BackchannelLogoutURI {
		t.Fatalf("address after a run without one: %q", got)
	}
}
