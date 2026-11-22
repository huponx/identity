// Package setup is the initial setup of an identity installation, run once by a Job: the first admin, the
// OAuth clients (with their secrets) and the token exchange policies. Everything except the admin is
// declarative and idempotent. The admin is created only when no admin exists, so a re-run, or a run with
// another e-mail, never adds a second one. Anything that the admin web app or the gRPC API can do later does
// not belong here.
package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/huponx/identity/internal/oauth"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/store"
)

// Config is the content of SETUP_CONFIG (JSON).
type Config struct {
	// Admin is the first admin. Its password is given apart (a Secret), never in the config.
	Admin *Admin `json:"admin,omitempty"`
	// Clients are created, or brought up to date when they exist.
	Clients []Client `json:"clients,omitempty"`
	// ExchangePolicies are upserted.
	ExchangePolicies []Policy `json:"exchange_policies,omitempty"`
}

// Admin is the first administrator.
type Admin struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	// KeepPassword leaves the password as given instead of forcing a change at the first sign in. For local
	// runs and the end to end scripts only: never in a real environment.
	KeepPassword bool `json:"keep_password,omitempty"`
}

// Client is an OAuth client. A confidential client gets its secret from the environment variable SecretEnv
// (filled from a Secret), so the secret is known in advance and never printed.
type Client struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name,omitempty"`
	Type                 string   `json:"type"` // public, confidential
	Resource             string   `json:"resource"`
	SecretEnv            string   `json:"secret_env,omitempty"`
	RedirectURIs         []string `json:"redirect_uris,omitempty"`
	PostLogoutURIs       []string `json:"post_logout_uris,omitempty"`
	BackchannelLogoutURI string   `json:"backchannel_logout_uri,omitempty"`
	Grants               []string `json:"grants,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	Roles                []string `json:"roles,omitempty"`
}

// Policy is a token exchange policy.
type Policy struct {
	Client   string `json:"client"`
	Audience string `json:"audience"`
	MaxScope string `json:"max_scope,omitempty"`
	MaxDepth int    `json:"max_depth,omitempty"`
}

// Parse reads and validates the config.
func Parse(raw string) (Config, error) {
	var c Config
	if raw == "" {
		return c, errors.New("SETUP_CONFIG is empty")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("SETUP_CONFIG: %w", err)
	}
	if c.Admin != nil && store.NormalizeEmail(c.Admin.Email) == "" {
		return c, errors.New("SETUP_CONFIG: admin.email is required")
	}
	seen := map[string]bool{}
	for _, cl := range c.Clients {
		if cl.ID == "" || cl.Resource == "" || (cl.Type != "public" && cl.Type != "confidential") {
			return c, fmt.Errorf("SETUP_CONFIG: client %q needs id, resource and type public|confidential", cl.ID)
		}
		if seen[cl.ID] {
			return c, fmt.Errorf("SETUP_CONFIG: client %q is listed twice", cl.ID)
		}
		seen[cl.ID] = true
		if cl.Type == "confidential" && cl.SecretEnv == "" {
			return c, fmt.Errorf("SETUP_CONFIG: confidential client %q needs secret_env", cl.ID)
		}
		for _, u := range append(append([]string{}, cl.RedirectURIs...), cl.PostLogoutURIs...) {
			if !store.ValidURI(u) {
				return c, fmt.Errorf("SETUP_CONFIG: client %q: invalid uri %s", cl.ID, u)
			}
		}
	}
	for _, p := range c.ExchangePolicies {
		if p.Client == "" || p.Audience == "" {
			return c, errors.New("SETUP_CONFIG: an exchange policy needs client and audience")
		}
	}
	return c, nil
}

// Store is what the setup needs from the database.
type Store interface {
	CreateFirstAdmin(ctx context.Context, u store.User) (*store.User, bool, error)
	ClientByID(ctx context.Context, id string) (*store.Client, error)
	CreateClient(ctx context.Context, c store.Client) (*store.Client, error)
	SetClientConfig(ctx context.Context, id string, redirects, logouts, grants, scopes []string) error
	SetClientSecret(ctx context.Context, id, hash string) error
	AssignRole(ctx context.Context, userID, clientID, role string) error
	SetExchangePolicy(ctx context.Context, p store.ExchangePolicy) error
}

// Env supplies the secrets: the admin password and the client secrets.
type Env struct {
	AdminPassword string
	Getenv        func(string) string
}

// Run applies the config. logf receives one line per step (never a secret).
func Run(ctx context.Context, st Store, cfg Config, env Env, logf func(string, ...any)) error {
	if cfg.Admin != nil {
		if err := runAdmin(ctx, st, *cfg.Admin, env.AdminPassword, logf); err != nil {
			return err
		}
	}
	for _, cl := range cfg.Clients {
		if err := runClient(ctx, st, cl, env, logf); err != nil {
			return fmt.Errorf("client %s: %w", cl.ID, err)
		}
	}
	for _, p := range cfg.ExchangePolicies {
		if err := st.SetExchangePolicy(ctx, store.ExchangePolicy{ClientID: p.Client, Audience: p.Audience, MaxScope: p.MaxScope, MaxChainDepth: p.MaxDepth}); err != nil {
			return fmt.Errorf("exchange policy %s -> %s: %w", p.Client, p.Audience, err)
		}
		logf("exchange policy %s -> %s: set", p.Client, p.Audience)
	}
	return nil
}

func runAdmin(ctx context.Context, st Store, a Admin, pw string, logf func(string, ...any)) error {
	if pw == "" {
		return errors.New("admin: the password (SETUP_ADMIN_PASSWORD) is empty")
	}
	if err := password.Check(pw, a.Email, ""); err != nil {
		return fmt.Errorf("admin: the password is not acceptable: %w", err)
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	name := a.Name
	if name == "" {
		name = "Administrator"
	}
	u, created, err := st.CreateFirstAdmin(ctx, store.User{Email: a.Email, Name: name, PasswordHash: hash, MustChangePassword: !a.KeepPassword})
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	if !created {
		logf("admin: an admin already exists, skipped")
		return nil
	}
	if a.KeepPassword {
		logf("admin: created %s (%s); keep_password is set, the password is NOT forced to change", u.Email, u.ID)
		return nil
	}
	logf("admin: created %s (%s); the password must be changed at the first sign in", u.Email, u.ID)
	return nil
}

func runClient(ctx context.Context, st Store, want Client, env Env, logf func(string, ...any)) error {
	secret := ""
	if want.Type == "confidential" {
		if secret = env.Getenv(want.SecretEnv); secret == "" {
			return fmt.Errorf("the environment variable %s (secret of the client) is empty", want.SecretEnv)
		}
	}
	have, err := st.ClientByID(ctx, want.ID)
	if errors.Is(err, store.ErrNotFound) {
		c := store.Client{
			ClientID: want.ID, Name: firstNonEmpty(want.Name, want.ID), Type: want.Type, Resource: want.Resource,
			RedirectURIs: want.RedirectURIs, PostLogoutRedirectURIs: want.PostLogoutURIs, BackchannelLogoutURI: want.BackchannelLogoutURI,
			AllowedGrants: orDefault(want.Grants, "authorization_code", "refresh_token"),
			AllowedScopes: orDefault(want.Scopes, "openid", "profile", "email", "offline_access"),
			Roles:         want.Roles,
		}
		if secret != "" {
			c.SecretHash = oauth.HashSecret(secret)
		}
		if _, err := st.CreateClient(ctx, c); err != nil {
			return err
		}
		logf("client %s: created", want.ID)
		return nil
	}
	if err != nil {
		return err
	}
	if have.Type != want.Type {
		return fmt.Errorf("exists as %s, the config says %s (a type cannot change)", have.Type, want.Type)
	}
	if have.Resource != want.Resource {
		return fmt.Errorf("exists with resource %q, the config says %q (the audience cannot change here)", have.Resource, want.Resource)
	}
	redirects, logouts := union(have.RedirectURIs, want.RedirectURIs), union(have.PostLogoutRedirectURIs, want.PostLogoutURIs)
	grants, scopes := union(have.AllowedGrants, want.Grants), union(have.AllowedScopes, want.Scopes)
	if !same(have.RedirectURIs, redirects) || !same(have.PostLogoutRedirectURIs, logouts) || !same(have.AllowedGrants, grants) || !same(have.AllowedScopes, scopes) {
		if err := st.SetClientConfig(ctx, want.ID, redirects, logouts, grants, scopes); err != nil {
			return err
		}
		logf("client %s: URIs, grants or scopes added", want.ID)
	}
	for _, r := range want.Roles {
		if !contains(have.Roles, r) {
			if err := st.AssignRole(ctx, "", want.ID, r); err != nil {
				return fmt.Errorf("role %s: %w", r, err)
			}
			logf("client %s: role %s added", want.ID, r)
		}
	}
	if secret != "" {
		if h := oauth.HashSecret(secret); h != have.SecretHash {
			if err := st.SetClientSecret(ctx, want.ID, h); err != nil {
				return err
			}
			logf("client %s: secret updated", want.ID)
		}
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orDefault(v []string, def ...string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// union keeps the stored values first and adds the wanted ones that are missing.
func union(have, want []string) []string {
	out := append([]string{}, have...)
	for _, w := range want {
		if !contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

func same(a, b []string) bool {
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
