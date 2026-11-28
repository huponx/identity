package oauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/keys"
	"github.com/huponx/identity/internal/mfa"
	"github.com/huponx/identity/internal/notify"
	"github.com/huponx/identity/internal/passkey"
	"github.com/huponx/identity/internal/passkey/passkeytest"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// These tests run the real server on PostgreSQL and Redis: IDENTITY_TEST_POSTGRES_URL (the database of
// `make up` in db-migration) and IDENTITY_TEST_REDIS_URL, for example redis://localhost:6379/15.

const (
	pkIssuer = "https://auth.example.com"
	pkPass   = "correct horse battery staple"
)

type pkEnv struct {
	t     *testing.T
	st    *store.Store
	sta   *state.State
	acct  *account.Service
	r     *gin.Engine
	ip    string
	mode  string
	sealr *mfa.Sealer
}

func newPKEnv(t *testing.T, mfaMode string, limitFactor int64) *pkEnv {
	t.Helper()
	pg, rd := os.Getenv("IDENTITY_TEST_POSTGRES_URL"), os.Getenv("IDENTITY_TEST_REDIS_URL")
	if pg == "" || rd == "" {
		t.Skip("IDENTITY_TEST_POSTGRES_URL and IDENTITY_TEST_REDIS_URL are not set")
	}
	ctx := context.Background()
	st, err := store.New(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	opt, err := redis.ParseURL(rd)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	sta := state.NewWithClient(rdb, nil)
	sta.LimitFactor = limitFactor

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwtx.NewSigner(key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	ks := &keys.Set{Signer: signer, Public: map[string]crypto.PublicKey{"k1": signer.Public()}}
	if ks.JWKS, err = jwtx.MarshalJWKS(ks.Public); err != nil {
		t.Fatal(err)
	}
	tk := token.New(token.Config{Issuer: pkIssuer, AccessTTL: time.Minute, IDTTL: time.Minute, RefreshTTL: time.Hour, ExchangeTTL: time.Minute}, ks, st, sta)

	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	sealer, err := mfa.NewSealer([]string{"k1:" + base64.StdEncoding.EncodeToString(rawKey)})
	if err != nil {
		t.Fatal(err)
	}
	log := zap.NewNop()
	pk, err := passkey.New(passkey.Config{RPID: "example.com", RPName: "Example", Origins: []string{pkIssuer, "https://portal.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	acct := account.New(account.Config{Issuer: pkIssuer, MFAMode: mfaMode, MFAIssuerName: "Example"}, st, sta, tk, sealer, notify.None{Logger: log}, log)
	acct.Passkeys = pk
	t.Cleanup(acct.Drain)

	gin.SetMode(gin.TestMode)
	srv := New(Config{Issuer: pkIssuer, SessionIdle: time.Hour, SessionAbsolute: time.Hour, MFAMode: mfaMode, PortalURL: "https://portal.example.com",
		AccessTokenDefault: time.Minute, RefreshTokenTTL: time.Hour}, acct, st, sta, tk, ks, log)
	r := gin.New()
	if err := srv.Routes(r); err != nil {
		t.Fatal(err)
	}
	return &pkEnv{t: t, st: st, sta: sta, acct: acct, r: r, mode: mfaMode, sealr: sealer,
		ip: fmt.Sprintf("10.%d.%d.%d:4000", randByte(), randByte(), randByte())}
}

func randByte() int { b := make([]byte, 1); _, _ = rand.Read(b); return int(b[0]) }

func (e *pkEnv) newUser() *store.User {
	e.t.Helper()
	hash, err := password.Hash(pkPass)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.st.CreateUser(context.Background(), store.User{Email: "pk-" + uuid.NewString() + "@example.com", Name: "Pk", PasswordHash: hash}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = e.st.DeleteUser(context.Background(), u.ID) })
	return u
}

// browser keeps the cookies of one visitor.
type browser struct {
	e       *pkEnv
	cookies map[string]string
	csrf    string
	// ua and remote, when set, are the User-Agent and the address of this visitor (the env's address otherwise)
	ua, remote string
}

func (e *pkEnv) browser() *browser {
	b := &browser{e: e, cookies: map[string]string{}}
	var out struct{ CSRF string }
	b.call("GET", "/auth-api/csrf", nil, &out)
	b.csrf = out.CSRF
	return b
}

type reply struct {
	code int
	body []byte
	hdr  http.Header
}

func (b *browser) do(method, path string, body any) reply {
	b.e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		m, _ := json.Marshal(body)
		var obj map[string]any
		_ = json.Unmarshal(m, &obj)
		if _, ok := obj["csrf"]; !ok && method != "GET" {
			obj["csrf"] = b.csrf
		}
		m, _ = json.Marshal(obj)
		rd = bytes.NewReader(m)
	} else if method != "GET" {
		m, _ := json.Marshal(map[string]any{"csrf": b.csrf})
		rd = bytes.NewReader(m)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = b.e.ip
	if b.remote != "" {
		req.RemoteAddr = b.remote
	}
	if b.ua != "" {
		req.Header.Set("User-Agent", b.ua)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range b.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	b.e.r.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return reply{w.Code, w.Body.Bytes(), w.Header()}
}

func (b *browser) call(method, path string, body, out any) reply {
	b.e.t.Helper()
	r := b.do(method, path, body)
	if out != nil && r.code == 200 {
		if err := json.Unmarshal(r.body, out); err != nil {
			b.e.t.Fatalf("%s %s: %v: %s", method, path, err, r.body)
		}
	}
	return r
}

func (r reply) errCode() string {
	var e struct{ Code string }
	_ = json.Unmarshal(r.body, &e)
	return e.Code
}

func (b *browser) mustOK(method, path string, body, out any) {
	b.e.t.Helper()
	if r := b.call(method, path, body, out); r.code != 200 {
		b.e.t.Fatalf("%s %s: %d %s", method, path, r.code, r.body)
	}
}

func (b *browser) passwordLogin(u *store.User, returnTo string) (redirect string) {
	b.e.t.Helper()
	var out struct{ Redirect string }
	b.mustOK("POST", "/auth-api/login", map[string]any{"email": u.Email, "password": pkPass, "return_to": returnTo}, &out)
	return out.Redirect
}

// addPasskey registers an authenticator through the account endpoints (the browser is signed in).
func (b *browser) addPasskey(a *passkeytest.Authenticator, name string) string {
	b.e.t.Helper()
	var begin struct {
		C       string
		Options json.RawMessage
	}
	b.mustOK("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}, &begin)
	var added struct{ ID string }
	b.mustOK("POST", "/auth-api/account/passkeys/finish", map[string]any{"c": begin.C, "credential": json.RawMessage(a.Create(b.e.t, begin.Options)), "name": name}, &added)
	return added.ID
}

func (b *browser) passkeyLogin(a *passkeytest.Authenticator, returnTo string) reply {
	b.e.t.Helper()
	var begin struct {
		C       string
		Options json.RawMessage
	}
	b.mustOK("POST", "/auth-api/passkey/login/begin", nil, &begin)
	return b.do("POST", "/auth-api/passkey/login/finish", map[string]any{"c": begin.C, "credential": json.RawMessage(a.Get(b.e.t, begin.Options)), "return_to": returnTo})
}

// session reads the SSO session of the browser.
func (b *browser) session() *state.Session {
	b.e.t.Helper()
	s, err := b.e.sta.GetSession(context.Background(), b.cookies["sid"], time.Hour, time.Hour)
	if err != nil {
		b.e.t.Fatalf("no session: %v", err)
	}
	return s
}

func (b *browser) hasSession() bool {
	_, err := b.e.sta.GetSession(context.Background(), b.cookies["sid"], time.Hour, time.Hour)
	return b.cookies["sid"] != "" && err == nil
}

func newAuth(t *testing.T) *passkeytest.Authenticator {
	return passkeytest.New(t, pkIssuer, "example.com")
}

func TestPasskeyRegistrationNeedsThePassword(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	b := e.browser()
	b.passwordLogin(u, "")

	if r := b.do("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": "wrong wrong wrong"}); r.code != 401 || r.errCode() != "invalid_password" {
		t.Fatalf("wrong password: %d %s", r.code, r.body)
	}
	// no session: no passkeys
	anon := e.browser()
	if r := anon.do("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}); r.code != 401 {
		t.Fatalf("anonymous: %d", r.code)
	}
	if r := anon.do("GET", "/auth-api/account/passkeys", nil); r.code != 401 {
		t.Fatalf("anonymous list: %d", r.code)
	}

	a := newAuth(t)
	id := b.addPasskey(a, "  Laptop  ")
	var list struct {
		Passkeys []struct{ ID, Name string }
	}
	b.mustOK("GET", "/auth-api/account/passkeys", nil, &list)
	if len(list.Passkeys) != 1 || list.Passkeys[0].ID != id || list.Passkeys[0].Name != "Laptop" {
		t.Fatalf("list: %+v", list)
	}

	// the same authenticator twice
	var begin struct {
		C       string
		Options json.RawMessage
	}
	b.mustOK("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}, &begin)
	if r := b.do("POST", "/auth-api/account/passkeys/finish", map[string]any{"c": begin.C, "credential": json.RawMessage(a.Create(t, begin.Options)), "name": "again"}); r.code != 401 {
		t.Errorf("same credential twice: %d %s", r.code, r.body)
	}
	// a ceremony works once
	b.mustOK("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}, &begin)
	cred := json.RawMessage(newAuth(t).Create(t, begin.Options))
	b.mustOK("POST", "/auth-api/account/passkeys/finish", map[string]any{"c": begin.C, "credential": cred, "name": "second"}, nil)
	if r := b.do("POST", "/auth-api/account/passkeys/finish", map[string]any{"c": begin.C, "credential": cred, "name": "replay"}); r.code != 401 || r.errCode() != "invalid_passkey" {
		t.Errorf("replayed ceremony: %d %s", r.code, r.body)
	}
	// a bad name
	b.mustOK("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}, &begin)
	if r := b.do("POST", "/auth-api/account/passkeys/finish", map[string]any{"c": begin.C, "credential": json.RawMessage(newAuth(t).Create(t, begin.Options)), "name": strings.Repeat("x", 61)}); r.code != 400 || r.errCode() != "invalid_passkey_name" {
		t.Errorf("long name: %d %s", r.code, r.body)
	}

	// rename, then delete: the password is required
	b.mustOK("PATCH", "/auth-api/account/passkeys/"+id, map[string]any{"name": "Work laptop"}, nil)
	if r := b.do("DELETE", "/auth-api/account/passkeys/"+id, map[string]any{"password": "wrong wrong wrong"}); r.code != 401 {
		t.Errorf("delete without the password: %d", r.code)
	}
	if r := b.do("DELETE", "/auth-api/account/passkeys/not-a-uuid", map[string]any{"password": pkPass}); r.code != 404 {
		t.Errorf("delete a bad id: %d", r.code)
	}
	b.mustOK("DELETE", "/auth-api/account/passkeys/"+id, map[string]any{"password": pkPass}, nil)
	if n, _ := e.st.CountPasskeys(context.Background(), u.ID); n != 1 {
		t.Errorf("%d passkeys left, want 1", n)
	}
	// somebody else's passkey cannot be renamed or deleted
	other := e.newUser()
	ob := e.browser()
	ob.passwordLogin(other, "")
	left, _ := e.st.ListPasskeys(context.Background(), u.ID)
	if r := ob.do("DELETE", "/auth-api/account/passkeys/"+left[0].ID, map[string]any{"password": pkPass}); r.code != 404 {
		t.Errorf("delete of another user's passkey: %d", r.code)
	}
	if r := ob.do("PATCH", "/auth-api/account/passkeys/"+left[0].ID, map[string]any{"name": "mine now"}); r.code != 404 {
		t.Errorf("rename of another user's passkey: %d", r.code)
	}
}

// authorizeCode runs /oauth2/authorize for a public client and returns the code, or the Location when there is none.
func (b *browser) authorize(client *store.Client, extra url.Values) (loc string) {
	b.e.t.Helper()
	v := url.Values{"response_type": {"code"}, "client_id": {client.ClientID}, "redirect_uri": {client.RedirectURIs[0]}, "scope": {"openid"},
		"state": {"s"}, "nonce": {"n"}, "code_challenge_method": {"S256"}, "code_challenge": {pkceChallenge("v" + strings.Repeat("a", 50))}}
	for k, vs := range extra {
		v[k] = vs
	}
	req := httptest.NewRequest("GET", "/oauth2/authorize?"+v.Encode(), nil)
	req.RemoteAddr = b.e.ip
	for k, c := range b.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: c})
	}
	w := httptest.NewRecorder()
	b.e.r.ServeHTTP(w, req)
	return w.Header().Get("Location")
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e *pkEnv) client() *store.Client {
	e.t.Helper()
	c, err := e.st.CreateClient(context.Background(), store.Client{ClientID: "pk-" + uuid.NewString(), Name: "t", Type: "public",
		RedirectURIs: []string{"https://app.example.com/cb"}, AllowedGrants: []string{"authorization_code"}, AllowedScopes: []string{"openid"}, Resource: "identity"})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		ctx := context.Background()
		if _, err := e.st.SetClientDisabled(ctx, c.ClientID, true); err == nil {
			_ = e.st.DeleteClient(ctx, c.ClientID)
		}
	})
	return c
}

// exchange trades the code in loc for the tokens and returns the claims of the ID token.
func (b *browser) exchange(client *store.Client, loc string) map[string]any {
	b.e.t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get("code") == "" {
		b.e.t.Fatalf("no code in %q", loc)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ClientID}, "code": {u.Query().Get("code")},
		"redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {"v" + strings.Repeat("a", 50)}}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	b.e.r.ServeHTTP(w, req)
	if w.Code != 200 {
		b.e.t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	claims := func(jwt string) map[string]any {
		parts := strings.Split(jwt, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	out := claims(tok.IDToken)
	out["access_amr"] = claims(tok.AccessToken)["amr"]
	out["access_acr"] = claims(tok.AccessToken)["acr"]
	return out
}

func TestPasskeyLoginIsMultiFactor(t *testing.T) {
	for _, mode := range []string{"optional", "required"} {
		t.Run(mode, func(t *testing.T) {
			e := newPKEnv(t, mode, 1000)
			u := e.newUser()
			cl := e.client()
			a := newAuth(t)
			setup := e.browser()
			setup.passwordLogin(u, "")
			if mode == "required" {
				// a password only user has to enroll before anything else
				if loc := setup.authorize(cl, nil); !strings.HasPrefix(loc, "/account/mfa") {
					t.Fatalf("password session in required mode: %q", loc)
				}
				// the enrollment page knows it cannot be skipped
				var enr struct{ Enabled, Forced bool }
				setup.mustOK("GET", "/auth-api/account/mfa", nil, &enr)
				if enr.Enabled || !enr.Forced {
					t.Errorf("enrollment status in required mode: %+v", enr)
				}
			}
			setup.addPasskey(a, "k")

			b := e.browser()
			ret := "/oauth2/authorize?" + url.Values{"client_id": {cl.ClientID}}.Encode()
			r := b.passkeyLogin(a, ret)
			if r.code != 200 {
				t.Fatalf("passkey login: %d %s", r.code, r.body)
			}
			var out struct{ Redirect string }
			_ = json.Unmarshal(r.body, &out)
			if out.Redirect != ret {
				t.Errorf("redirect %q", out.Redirect)
			}
			sess := b.session()
			if sess.UserID != u.ID || !hasAMR(sess.AMR, "mfa") || !(hasAMR(sess.AMR, "hwk") || hasAMR(sess.AMR, "swk")) || hasAMR(sess.AMR, "pwd") {
				t.Errorf("amr %v", sess.AMR)
			}
			if time.Since(sess.AuthTime) > time.Minute {
				t.Errorf("auth_time %v", sess.AuthTime)
			}
			if got, _ := e.st.UserByID(context.Background(), u.ID); got.LastLoginAt == nil {
				t.Error("the sign in was not recorded")
			}
			// the passkey was used
			list, _ := e.st.ListPasskeys(context.Background(), u.ID)
			if list[0].LastUsedAt == nil || list[0].SignCount != 1 {
				t.Errorf("passkey after use: %+v", list[0])
			}

			// acr_values=mfa is satisfied without any step-up, and the tokens say so
			loc := b.authorize(cl, url.Values{"acr_values": {"mfa"}})
			claims := b.exchange(cl, loc)
			if claims["acr"] != "mfa" || fmt.Sprint(claims["amr"]) != fmt.Sprint(sess.AMR) || claims["access_acr"] != "mfa" {
				t.Errorf("claims: %v", claims)
			}
		})
	}
}

func TestPasswordLoginDoesNotAskForThePasskey(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	setup := e.browser()
	setup.passwordLogin(u, "")
	setup.addPasskey(newAuth(t), "k")

	// a password sign in stays a password sign in: no second step, a session with the password only
	b := e.browser()
	if to := b.passwordLogin(u, ""); strings.HasPrefix(to, "/login/mfa") {
		t.Fatalf("after the password: %q", to)
	}
	if s := b.session(); mfaDone(s.AMR) || !hasAMR(s.AMR, "pwd") {
		t.Errorf("amr %v", s.AMR)
	}
}

func TestPasskeyIsTheSecondFactorWhenMFAIsRequired(t *testing.T) {
	e := newPKEnv(t, "required", 1000)
	u := e.newUser()
	cl := e.client()
	a := newAuth(t)
	setup := e.browser()
	setup.passwordLogin(u, "") // no factor yet: the session is for the enrollment
	setup.addPasskey(a, "k")

	b := e.browser()
	to := b.passwordLogin(u, "")
	if !strings.HasPrefix(to, "/login/mfa?c=") {
		t.Fatalf("after the password: %q", to)
	}
	if b.hasSession() {
		t.Fatal("a session exists before the second factor")
	}
	c := strings.TrimPrefix(to, "/login/mfa?c=")
	var methods struct{ TOTP, Passkey bool }
	b.mustOK("GET", "/auth-api/login/mfa?c="+c, nil, &methods)
	if methods.TOTP || !methods.Passkey {
		t.Fatalf("methods %+v", methods)
	}
	// a TOTP code is no use to a user who has none
	if r := b.do("POST", "/auth-api/login/mfa", map[string]any{"c": c, "code": "123456"}); r.code != 401 {
		t.Errorf("code without TOTP: %d", r.code)
	}
	// that was a try; a fresh challenge for the rest
	c = strings.TrimPrefix(b.passwordLogin(u, ""), "/login/mfa?c=")
	var begin struct{ Options json.RawMessage }
	b.mustOK("POST", "/auth-api/login/mfa/passkey/begin", map[string]any{"c": c}, &begin)
	cred := json.RawMessage(a.Get(t, begin.Options))
	// another user's credential cannot finish it
	var fb struct{ Options json.RawMessage }
	b.mustOK("POST", "/auth-api/login/mfa/passkey/begin", map[string]any{"c": c}, &fb)
	if r := b.do("POST", "/auth-api/login/mfa/passkey/finish", map[string]any{"c": c, "credential": json.RawMessage(newAuth(t).Get(t, fb.Options))}); r.code != 401 || r.errCode() != "invalid_passkey" {
		t.Errorf("foreign credential: %d %s", r.code, r.body)
	}
	// the ceremony was consumed by that try: the right answer to the old options fails too (single use)
	if r := b.do("POST", "/auth-api/login/mfa/passkey/finish", map[string]any{"c": c, "credential": cred}); r.code != 401 {
		t.Errorf("answer after a consumed ceremony: %d", r.code)
	}

	c = strings.TrimPrefix(b.passwordLogin(u, ""), "/login/mfa?c=")
	b.mustOK("POST", "/auth-api/login/mfa/passkey/begin", map[string]any{"c": c}, &begin)
	b.mustOK("POST", "/auth-api/login/mfa/passkey/finish", map[string]any{"c": c, "credential": json.RawMessage(a.Get(t, begin.Options))}, nil)
	if sess := b.session(); !hasAMR(sess.AMR, "pwd") || !hasAMR(sess.AMR, "mfa") {
		t.Errorf("amr %v", sess.AMR)
	}
	if claims := b.exchange(cl, b.authorize(cl, nil)); claims["acr"] != "mfa" {
		t.Errorf("claims %v", claims)
	}
	// the challenge is gone
	if r := b.do("POST", "/auth-api/login/mfa/passkey/begin", map[string]any{"c": c}); r.code != 401 {
		t.Errorf("begin on a finished challenge: %d", r.code)
	}
}

func TestPasswordSessionStepsUpWithPasskey(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	cl := e.client()
	a := newAuth(t)
	setup := e.browser()
	setup.passwordLogin(u, "")
	setup.addPasskey(a, "k")

	// a client that asks for acr_values=mfa gets the passkey step for a password only session
	up := e.browser()
	up.passwordLogin(u, "")
	loc := up.authorize(cl, url.Values{"acr_values": {"mfa"}})
	if !strings.HasPrefix(loc, "/login/mfa?c=") {
		t.Fatalf("step-up: %q", loc)
	}
	c := strings.TrimPrefix(loc, "/login/mfa?c=")
	var begin struct{ Options json.RawMessage }
	var done struct{ Redirect string }
	up.mustOK("POST", "/auth-api/login/mfa/passkey/begin", map[string]any{"c": c}, &begin)
	up.mustOK("POST", "/auth-api/login/mfa/passkey/finish", map[string]any{"c": c, "credential": json.RawMessage(a.Get(t, begin.Options))}, &done)
	if !mfaDone(up.session().AMR) {
		t.Errorf("session after the step-up: %v", up.session().AMR)
	}
	if claims := up.exchange(cl, up.authorize(cl, url.Values{"acr_values": {"mfa"}})); claims["acr"] != "mfa" {
		t.Errorf("claims after the step-up: %v", claims)
	}
	// a password only session without acr_values is let through
	plain := e.browser()
	plain.passwordLogin(u, "")
	if claims := plain.exchange(cl, plain.authorize(cl, nil)); claims["acr"] == "mfa" {
		t.Errorf("a password session got acr=mfa: %v", claims)
	}
}

func TestPasskeyLoginRefusals(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	a := newAuth(t)
	setup := e.browser()
	setup.passwordLogin(u, "")
	setup.addPasskey(a, "k")

	// wrong origin and no user verification
	for name, mutate := range map[string]func(*passkeytest.Authenticator){
		"origin": func(x *passkeytest.Authenticator) { x.Origin = "https://evil.example.net" },
		"uv":     func(x *passkeytest.Authenticator) { x.UV = false },
	} {
		bad := *a
		mutate(&bad)
		b := e.browser()
		if r := b.passkeyLogin(&bad, ""); r.code != 401 || r.errCode() != "invalid_passkey" || b.hasSession() {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}

	// a ceremony works once
	b := e.browser()
	var begin struct {
		C       string
		Options json.RawMessage
	}
	b.mustOK("POST", "/auth-api/passkey/login/begin", nil, &begin)
	cred := json.RawMessage(a.Get(t, begin.Options))
	b.mustOK("POST", "/auth-api/passkey/login/finish", map[string]any{"c": begin.C, "credential": cred}, nil)
	b2 := e.browser()
	if r := b2.do("POST", "/auth-api/passkey/login/finish", map[string]any{"c": begin.C, "credential": cred}); r.code != 401 {
		t.Errorf("replay: %d", r.code)
	}
	// a ceremony of another purpose is not a login: the one of a registration
	var reg struct {
		C       string
		Options json.RawMessage
	}
	b.mustOK("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}, &reg)
	if r := b2.do("POST", "/auth-api/passkey/login/finish", map[string]any{"c": reg.C, "credential": json.RawMessage(a.Get(t, begin.Options))}); r.code != 401 {
		t.Errorf("registration ceremony used for a login: %d", r.code)
	}

	// the sign count must go forward: the server saw count 1; an answer with 1 again is refused
	a.Count = 0
	if r := e.browser().passkeyLogin(a, ""); r.code != 401 {
		t.Errorf("sign count regression: %d %s", r.code, r.body)
	}
	a.Count = 5
	if r := e.browser().passkeyLogin(a, ""); r.code != 200 {
		t.Errorf("sign count forward: %d %s", r.code, r.body)
	}

	// a disabled user
	if err := e.st.SetUserDisabled(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	nb := e.browser()
	if r := nb.passkeyLogin(a, ""); r.code != 401 || nb.hasSession() {
		t.Errorf("disabled user: %d %s", r.code, r.body)
	}
	_ = e.st.SetUserDisabled(context.Background(), u.ID, false)

	// a deleted user: the credential is gone with the row
	if err := e.st.DeleteUser(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	if r := e.browser().passkeyLogin(a, ""); r.code != 401 {
		t.Errorf("deleted user: %d", r.code)
	}
}

func TestPasskeyEndpointsAreRateLimited(t *testing.T) {
	e := newPKEnv(t, "optional", 1) // the real limits
	b := e.browser()
	var last int
	for i := 0; i < 70; i++ {
		last = b.do("POST", "/auth-api/passkey/login/begin", nil).code
	}
	if last != 429 {
		t.Errorf("70 begins from one address: last status %d", last)
	}
}

func TestPasskeyAndTOTPBothWork(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	ctx := context.Background()
	u := e.newUser()
	a := newAuth(t)
	setup := e.browser()
	setup.passwordLogin(u, "")
	setup.addPasskey(a, "k")

	// TOTP on, with a known secret
	secret := mfa.NewSecret()
	sealed, err := e.sealr.Seal(secret, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.ReplaceMFAFactor(ctx, u.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ConfirmMFAFactor(ctx, u.ID, mfa.Step(time.Now())-1, [][]byte{password.Digest("x")}); err != nil {
		t.Fatal(err)
	}

	b := e.browser()
	c := strings.TrimPrefix(b.passwordLogin(u, ""), "/login/mfa?c=")
	var methods struct{ TOTP, Passkey bool }
	b.mustOK("GET", "/auth-api/login/mfa?c="+c, nil, &methods)
	if !methods.TOTP || !methods.Passkey {
		t.Fatalf("methods %+v", methods)
	}
	b.mustOK("POST", "/auth-api/login/mfa", map[string]any{"c": c, "code": mfa.Code(secret, mfa.Step(time.Now()))}, nil)
	if s := b.session(); !hasAMR(s.AMR, "otp") || !hasAMR(s.AMR, "pwd") {
		t.Errorf("amr with the code: %v", s.AMR)
	}

	// and the passkey on the same account
	p := e.browser()
	c = strings.TrimPrefix(p.passwordLogin(u, ""), "/login/mfa?c=")
	var begin struct{ Options json.RawMessage }
	p.mustOK("POST", "/auth-api/login/mfa/passkey/begin", map[string]any{"c": c}, &begin)
	p.mustOK("POST", "/auth-api/login/mfa/passkey/finish", map[string]any{"c": c, "credential": json.RawMessage(a.Get(t, begin.Options))}, nil)
	if s := p.session(); !hasAMR(s.AMR, "mfa") {
		t.Errorf("amr with the passkey: %v", s.AMR)
	}

	// the administrator's reset removes the passkeys and the TOTP
	user, _ := e.st.UserByID(ctx, u.ID)
	if err := e.acct.AdminResetMFA(ctx, user); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.st.CountPasskeys(ctx, u.ID); n != 0 {
		t.Errorf("%d passkeys after the reset", n)
	}
	if r := e.browser().passkeyLogin(a, ""); r.code != 401 {
		t.Errorf("a reset passkey signed in: %d", r.code)
	}
	// without any factor the password alone gives a session again
	if to := e.browser().passwordLogin(u, ""); strings.HasPrefix(to, "/login/mfa") {
		t.Errorf("after the reset: %q", to)
	}
}

func TestPasskeysOff(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	e.acct.Passkeys = nil
	b := e.browser()
	for _, p := range []string{"/auth-api/passkey/login/begin", "/auth-api/passkey/login/finish", "/auth-api/login/mfa/passkey/begin", "/auth-api/account/passkeys/begin"} {
		if r := b.do("POST", p, nil); r.code != 404 {
			t.Errorf("%s: %d", p, r.code)
		}
	}
	if r := b.do("GET", "/auth-api/account/passkeys", nil); r.code != 404 {
		t.Errorf("list: %d", r.code)
	}
}

func TestAddingAPasskeyCompletesTheEnrollmentWhenMFAIsRequired(t *testing.T) {
	e := newPKEnv(t, "required", 1000)
	u := e.newUser()
	cl := e.client()
	b := e.browser()
	b.passwordLogin(u, "")
	// no factor yet: the application sends the user to enroll
	if loc := b.authorize(cl, nil); !strings.HasPrefix(loc, "/account/mfa") {
		t.Fatalf("before the passkey: %q", loc)
	}
	ret := "/oauth2/authorize?" + url.Values{"client_id": {cl.ClientID}}.Encode()
	var begin struct {
		C       string
		Options json.RawMessage
	}
	b.mustOK("POST", "/auth-api/account/passkeys/begin", map[string]any{"password": pkPass}, &begin)
	var added struct{ Redirect string }
	b.mustOK("POST", "/auth-api/account/passkeys/finish", map[string]any{"c": begin.C, "credential": json.RawMessage(newAuth(t).Create(t, begin.Options)), "name": "k", "return_to": ret}, &added)
	if added.Redirect != ret {
		t.Errorf("redirect %q, want %q", added.Redirect, ret)
	}
	if s := b.session(); !mfaDone(s.AMR) || !hasAMR(s.AMR, "pwd") {
		t.Errorf("amr %v", s.AMR)
	}
	// the application now issues its code: no step-up for the key that was just made
	if claims := b.exchange(cl, b.authorize(cl, nil)); claims["acr"] != "mfa" {
		t.Errorf("claims %v", claims)
	}
}

func TestAnotherPasskeyDoesNotMakeAPasswordSessionMultiFactor(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	first := e.browser()
	first.passwordLogin(u, "")
	first.addPasskey(newAuth(t), "first") // the first one is the enrollment

	// a password only session of a user who has a passkey adds another: it proves nothing new
	b := e.browser()
	b.passwordLogin(u, "")
	b.addPasskey(newAuth(t), "second")
	if s := b.session(); mfaDone(s.AMR) {
		t.Errorf("amr %v", s.AMR)
	}
}
