// Package token issues the JWTs of identity (access, ID, logout) and implements token
// exchange (RFC 8693).
package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/huponx/gocommon/authz"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/identity/internal/keys"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
)

// Error is an OAuth 2.0 error response (RFC 6749 section 5.2).
type Error struct {
	Code   string
	Desc   string
	Status int
}

func (e *Error) Error() string { return e.Code + ": " + e.Desc }

func oauthErr(code, desc string) *Error {
	status := http.StatusBadRequest
	if code == "invalid_client" {
		status = http.StatusUnauthorized
	}
	return &Error{Code: code, Desc: desc, Status: status}
}

// Config holds the lifetimes and the issuer.
type Config struct {
	Issuer      string
	AccessTTL   time.Duration
	IDTTL       time.Duration
	RefreshTTL  time.Duration
	ExchangeTTL time.Duration
}

// Service signs tokens.
type Service struct {
	cfg   Config
	keys  *keys.Set
	store *store.Store
	state *state.State
	now   func() time.Time
}

// New builds the service.
func New(cfg Config, k *keys.Set, st *store.Store, sta *state.State) *Service {
	return &Service{cfg: cfg, keys: k, store: st, state: sta, now: time.Now}
}

// SetClock overrides the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Config returns the settings.
func (s *Service) Config() Config { return s.cfg }

// AccessParams describes an access token.
type AccessParams struct {
	Subject   string
	ClientID  string
	Audience  string
	Scope     string
	Roles     []string
	Perms     []string
	AMR       []string
	ACR       string
	SessionID string
	AuthTime  time.Time
	TTL       time.Duration // 0: the configured access token lifetime
	Act       *jwtx.Actor
}

// Access signs an access token.
func (s *Service) Access(p AccessParams) (string, *jwtx.Claims, error) {
	now := s.now()
	ttl := p.TTL
	if ttl <= 0 {
		ttl = s.cfg.AccessTTL
	}
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   p.Subject,
			Audience:  jwt.ClaimStrings{p.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Scope: p.Scope, Roles: p.Roles, Perms: p.Perms, ClientID: p.ClientID, AZP: p.ClientID,
		Type: jwtx.TypeAccess, AMR: p.AMR, ACR: p.ACR, SessionID: p.SessionID, Act: p.Act,
	}
	if !p.AuthTime.IsZero() {
		c.AuthTime = p.AuthTime.Unix()
	}
	raw, err := s.keys.Signer.Sign(c)
	return raw, c, err
}

// IDParams describes an ID token.
type IDParams struct {
	Subject     string
	ClientID    string
	Nonce       string
	AccessToken string
	Name, Email string
	AMR         []string
	ACR         string
	SessionID   string
	AuthTime    time.Time
}

// ID signs an ID token for the client.
func (s *Service) ID(p IDParams) (string, error) {
	now := s.now()
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   p.Subject,
			Audience:  jwt.ClaimStrings{p.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.IDTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Type: jwtx.TypeID, AZP: p.ClientID, Nonce: p.Nonce, Name: p.Name, Email: p.Email,
		AMR: p.AMR, ACR: p.ACR, SessionID: p.SessionID,
	}
	if !p.AuthTime.IsZero() {
		c.AuthTime = p.AuthTime.Unix()
	}
	if p.AccessToken != "" {
		sum := sha256.Sum256([]byte(p.AccessToken))
		c.AtHash = base64.RawURLEncoding.EncodeToString(sum[:16])
	}
	return s.keys.Signer.Sign(c)
}

// LogoutEvent is the event URI of OpenID Connect Back-Channel Logout 1.0.
const LogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// Logout signs a back-channel logout token for a client (sid and/or sub).
func (s *Service) Logout(clientID, sub, sid string) (string, error) {
	now := s.now()
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Type: jwtx.TypeLogout, SessionID: sid,
		Events: map[string]any{LogoutEvent: map[string]any{}},
	}
	return s.keys.Signer.Sign(c)
}

// Verifier returns a verifier of tokens issued by this service for the audience.
func (s *Service) Verifier(audience string) (*jwtx.Verifier, error) {
	return jwtx.NewVerifier(jwtx.VerifierConfig{
		Issuer: s.cfg.Issuer, Audience: audience, Keys: jwtx.StaticKeySet(s.keys.Public), Now: s.now,
	})
}

// VerifyAccess verifies one of our own access tokens for the audience and refuses it when it
// was revoked (denylist) or issued before the cutoff of its user. Errors are *Error values
// with code invalid_grant; infrastructure errors are returned as is.
func (s *Service) VerifyAccess(ctx context.Context, raw, audience string) (*jwtx.Claims, error) {
	v, err := s.Verifier(audience)
	if err != nil {
		return nil, err
	}
	c, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, oauthErr("invalid_grant", "the token is not valid")
	}
	if c.Type != jwtx.TypeAccess {
		return nil, oauthErr("invalid_grant", "the token is not an access token")
	}
	return c, s.checkLive(ctx, c)
}

// firstAudience reads the first aud of a token WITHOUT trusting it; it only chooses which
// audience the verifier will then insist on, the signature is checked right after.
func firstAudience(raw string) (string, bool) {
	var c jwtx.Claims
	if err := jwtx.ParseUnverified(raw, &c); err != nil || len(c.Audience) == 0 {
		return "", false
	}
	return c.Audience[0], true
}

// VerifyAny verifies one of our own tokens whatever its audience (introspection, revocation,
// userinfo). The token must have been signed by this service and not be expired.
func (s *Service) VerifyAny(ctx context.Context, raw string) (*jwtx.Claims, error) {
	return s.verifyAny(ctx, raw, 0)
}

// VerifyIDHint verifies an ID token used as id_token_hint at logout: an expired one is fine
// (up to the refresh token lifetime), a forged one is not.
func (s *Service) VerifyIDHint(ctx context.Context, raw string) (*jwtx.Claims, error) {
	c, err := s.verifyAny(ctx, raw, s.cfg.RefreshTTL)
	if err != nil {
		return nil, err
	}
	if c.Type != jwtx.TypeID {
		return nil, oauthErr("invalid_request", "id_token_hint is not an ID token")
	}
	return c, nil
}

func (s *Service) verifyAny(ctx context.Context, raw string, leeway time.Duration) (*jwtx.Claims, error) {
	aud, ok := firstAudience(raw)
	if !ok {
		return nil, oauthErr("invalid_grant", "the token is not valid")
	}
	v, err := jwtx.NewVerifier(jwtx.VerifierConfig{
		Issuer: s.cfg.Issuer, Audience: aud, Keys: jwtx.StaticKeySet(s.keys.Public), Leeway: leeway, Now: s.now,
	})
	if err != nil {
		return nil, err
	}
	c, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, oauthErr("invalid_grant", "the token is not valid")
	}
	return c, nil
}

// checkLive applies the denylist and the user cutoff.
func (s *Service) checkLive(ctx context.Context, c *jwtx.Claims) error {
	denied, err := s.state.Denied(ctx, c.ID)
	if err != nil {
		return err
	}
	if denied {
		return oauthErr("invalid_grant", "the token was revoked")
	}
	if c.Subject != c.ClientID { // a user token
		cut, err := s.state.Cutoff(ctx, c.Subject)
		if err != nil {
			return err
		}
		if !cut.IsZero() && c.IssuedAt != nil && c.IssuedAt.Time.Before(cut) {
			return oauthErr("invalid_grant", "the token was revoked")
		}
	}
	return nil
}

// IsLive is checkLive for introspection: false when the token must be treated as inactive.
func (s *Service) IsLive(ctx context.Context, c *jwtx.Claims) (bool, error) {
	err := s.checkLive(ctx, c)
	var oe *Error
	if errors.As(err, &oe) {
		return false, nil
	}
	return err == nil, err
}

// FilterPerms keeps what is relevant for the audience: the global "*" and the permissions whose
// first segment is the audience (or a wildcard). A service never sees the permissions of
// another one.
func FilterPerms(perms []string, audience string) []string {
	var out []string
	for _, p := range perms {
		first, _, _ := strings.Cut(p, ":")
		if p == "*" || first == audience || first == "*" {
			out = append(out, p)
		}
	}
	return out
}

// NarrowScope returns the scopes that are in requested (all of subject when requested is
// empty), in subject, and in max. An empty max grants nothing.
func NarrowScope(requested, subject, max string) string {
	in := func(list []string, s string) bool {
		for _, v := range list {
			if v == s {
				return true
			}
		}
		return false
	}
	sub, mx := strings.Fields(subject), strings.Fields(max)
	req := strings.Fields(requested)
	if len(req) == 0 {
		req = sub
	}
	var out []string
	for _, s := range req {
		if in(sub, s) && in(mx, s) && !in(out, s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// ValidPerms reports whether every permission is well formed.
func ValidPerms(perms []string) bool {
	for _, p := range perms {
		if !authz.Valid(p) {
			return false
		}
	}
	return true
}

// ExchangeRequest is a token exchange request of an authenticated client.
type ExchangeRequest struct {
	Client           *store.Client
	SubjectToken     string
	SubjectTokenType string
	RequestedType    string
	Audience         []string
	Scope            string
}

// ExchangeResult is an issued exchanged token plus what the audit log needs.
type ExchangeResult struct {
	AccessToken string
	Claims      *jwtx.Claims
	Scope       string
	SubjectJTI  string
	TTL         time.Duration
}

const tokenTypeAccess = "urn:ietf:params:oauth:token-type:access_token"

// Exchange implements RFC 8693 for access tokens, with the rules of the platform:
// the caller is a confidential client with the token-exchange grant; the subject token is a
// live access token whose audience is the caller's resource; a policy must allow (client, audience); the
// scope can only narrow; the permissions are read again from the database; the new token is
// short lived and carries the caller in "act".
func (s *Service) Exchange(ctx context.Context, r ExchangeRequest) (*ExchangeResult, error) {
	if r.SubjectToken == "" {
		return nil, oauthErr("invalid_request", "subject_token is required")
	}
	if r.SubjectTokenType != "" && r.SubjectTokenType != tokenTypeAccess {
		return nil, oauthErr("invalid_request", "subject_token_type must be an access token")
	}
	if r.RequestedType != "" && r.RequestedType != tokenTypeAccess {
		return nil, oauthErr("invalid_request", "requested_token_type must be an access token")
	}
	if len(r.Audience) != 1 || r.Audience[0] == "" {
		return nil, oauthErr("invalid_request", "exactly one audience is required")
	}
	audience := r.Audience[0]

	subj, err := s.VerifyAccess(ctx, r.SubjectToken, r.Client.Resource)
	if err != nil {
		return nil, err
	}
	isService := subj.Subject == subj.ClientID

	pol, err := s.store.ExchangePolicyFor(ctx, r.Client.ClientID, audience)
	if errors.Is(err, store.ErrNotFound) {
		return nil, oauthErr("access_denied", "exchange for this audience is not allowed")
	}
	if err != nil {
		return nil, err
	}
	if subj.Act.Depth()+1 > pol.MaxChainDepth {
		return nil, oauthErr("access_denied", "delegation chain too long")
	}

	// the subject is a user, or a service (client credentials token) that the caller, a gateway,
	// forwards: the new token keeps the service as subject and carries the permissions of its roles
	var subject string
	var perms, roles []string
	if isService {
		sc, err := s.store.ClientByID(ctx, subj.Subject)
		if errors.Is(err, store.ErrNotFound) {
			return nil, oauthErr("invalid_grant", "the service is not active")
		}
		if err != nil {
			return nil, err
		}
		if perms, err = s.store.ClientPermissions(ctx, sc.ClientID); err != nil {
			return nil, err
		}
		subject, roles = sc.ClientID, sc.Roles
	} else {
		user, err := s.store.UserByID(ctx, subj.Subject)
		if errors.Is(err, store.ErrNotFound) || (err == nil && user.Disabled) {
			return nil, oauthErr("invalid_grant", "the user is not active")
		}
		if err != nil {
			return nil, err
		}
		if perms, err = s.store.UserPermissions(ctx, user.ID); err != nil {
			return nil, err
		}
		if roles, err = s.store.UserRoles(ctx, user.ID); err != nil {
			return nil, err
		}
		subject = user.ID
	}

	scope := NarrowScope(r.Scope, subj.Scope, pol.MaxScope)
	ttl := s.cfg.ExchangeTTL
	if subj.ExpiresAt != nil {
		if left := subj.ExpiresAt.Time.Sub(s.now()); left < ttl {
			ttl = left
		}
	}
	if ttl <= 0 {
		return nil, oauthErr("invalid_grant", "the token is expired")
	}
	var authTime time.Time
	if subj.AuthTime > 0 {
		authTime = time.Unix(subj.AuthTime, 0)
	}
	raw, claims, err := s.Access(AccessParams{
		Subject: subject, ClientID: r.Client.ClientID, Audience: audience, Scope: scope,
		Roles: roles, Perms: FilterPerms(perms, audience), AMR: subj.AMR, ACR: subj.ACR,
		SessionID: subj.SessionID, AuthTime: authTime, TTL: ttl,
		Act: &jwtx.Actor{Subject: r.Client.ClientID, ClientID: r.Client.ClientID, Act: subj.Act},
	})
	if err != nil {
		return nil, err
	}
	return &ExchangeResult{AccessToken: raw, Claims: claims, Scope: scope, SubjectJTI: subj.ID, TTL: ttl}, nil
}
