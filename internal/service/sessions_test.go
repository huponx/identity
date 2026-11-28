package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

const chromeMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// clientFor creates the client the refresh tokens of a test belong to (they reference it).
func clientFor(t *testing.T, s *Service) string {
	t.Helper()
	ctx := context.Background()
	id := "sess-" + uuid.NewString()
	if _, err := s.Store.CreateClient(ctx, store.Client{ClientID: id, Name: "t", Type: "public", RedirectURIs: []string{"https://app.example.com/cb"},
		AllowedGrants: []string{"authorization_code"}, AllowedScopes: []string{"openid"}, Resource: "identity"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.Store.SetClientDisabled(ctx, id, true); err == nil {
			_ = s.Store.DeleteClient(ctx, id)
		}
	})
	return id
}

// addSession signs the user in on a "device": a session in Redis and a refresh token of it.
func addSession(t *testing.T, s *Service, client, uid, ip, ua string) (pid string, refreshHash []byte) {
	t.Helper()
	ctx := context.Background()
	pid = uuid.NewString()
	if err := s.State.CreateSession(ctx, stateSession(uid, ip, ua), "cookie-"+pid, pid, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	refreshHash = []byte("refresh-" + pid)
	if err := s.Store.InsertRefreshToken(ctx, refreshHash, store.RefreshToken{UserID: uid, ClientID: client, SessionID: pid, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.State.DeleteSession(context.Background(), pid) })
	return pid, refreshHash
}

func refreshAlive(s *Service, client string, hash []byte) bool {
	_, err := s.Store.ConsumeRefreshToken(context.Background(), hash, client)
	return err == nil
}

func asSession(ctx context.Context, uid, sid string) context.Context {
	return authn.WithPrincipal(ctx, &authn.Principal{Subject: uid, ClientID: "gk", SessionID: sid})
}

func sessionIDs(list []*identityv1.Session) map[string]*identityv1.Session {
	m := map[string]*identityv1.Session{}
	for _, x := range list {
		m[x.Id] = x
	}
	return m
}

func TestMySessions(t *testing.T) {
	s, u, ctx := passkeyService(t, false)
	client := clientFor(t, s)
	a, aRefresh := addSession(t, s, client, u.ID, "10.0.0.1", chromeMac)
	b, bRefresh := addSession(t, s, client, u.ID, "10.0.0.2", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
	c, cRefresh := addSession(t, s, client, u.ID, "10.0.0.3", "")

	// another user's session, to prove it is out of reach
	other, err := s.Store.CreateUser(ctx, store.User{Email: "o-" + uuid.NewString() + "@example.com", PasswordHash: mustHash(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Store.DeleteUser(context.Background(), other.ID) })
	foreign, foreignRefresh := addSession(t, s, client, other.ID, "10.9.9.9", chromeMac)

	ctxA := asSession(ctx, u.ID, a)
	list, err := s.ListMySessions(ctxA, &identityv1.ListMySessionsRequest{})
	if err != nil || len(list.Sessions) != 3 {
		t.Fatalf("list: %+v %v", list, err)
	}
	m := sessionIDs(list.Sessions)
	if !m[a].Current || m[b].Current || m[c].Current || m[foreign] != nil {
		t.Errorf("current/foreign: %+v", m)
	}
	if x := m[a]; x.Ip != "10.0.0.1" || x.Browser != "Chrome" || x.BrowserVersion != "126" || x.Os != "macOS" || x.Device != "desktop" || x.CreatedAt == 0 {
		t.Errorf("session a: %+v", x)
	}
	if x := m[b]; x.Browser != "Safari" || x.Os != "iOS" || x.Device != "mobile" {
		t.Errorf("session b: %+v", x)
	}
	if x := m[c]; x.Browser != "" || x.Os != "" || x.Device != "unknown" {
		t.Errorf("session c (no user agent): %+v", x)
	}

	// another user's id and an unknown id are the same answer
	for _, id := range []string{foreign, uuid.NewString()} {
		if _, err := s.RevokeMySession(ctxA, &identityv1.RevokeMySessionRequest{Id: id}); reasonOf(err) != "session_not_found" {
			t.Errorf("revoke %s: %v", id, err)
		}
	}
	if !refreshAlive(s, client, foreignRefresh) {
		t.Error("the refresh token of another user was revoked")
	}

	// revoke another session: it and its refresh tokens go
	if _, err := s.RevokeMySession(ctxA, &identityv1.RevokeMySessionRequest{Id: b}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.State.SessionAlive(ctx, b); ok {
		t.Error("session b is alive")
	}
	if refreshAlive(s, client, bRefresh) {
		t.Error("refresh token of b is alive")
	}
	if !refreshAlive(s, client, aRefresh) {
		t.Error("refresh token of a was revoked")
	}

	// revoke the others keeps the current one
	res, err := s.RevokeMyOtherSessions(ctxA, &identityv1.RevokeMyOtherSessionsRequest{})
	if err != nil || res.Revoked != 1 {
		t.Fatalf("others: %+v %v", res, err)
	}
	if ok, _ := s.State.SessionAlive(ctx, c); ok || refreshAlive(s, client, cRefresh) {
		t.Error("session c survived")
	}
	if ok, _ := s.State.SessionAlive(ctx, a); !ok {
		t.Error("the current session ended")
	}
	if ok, _ := s.State.SessionAlive(ctx, foreign); !ok {
		t.Error("the session of another user ended")
	}
	if res, err = s.RevokeMyOtherSessions(ctxA, &identityv1.RevokeMyOtherSessionsRequest{}); err != nil || res.Revoked != 0 {
		t.Errorf("alone: %+v %v", res, err)
	}
	// without a sid nothing is "other"
	if _, err := s.RevokeMyOtherSessions(ctx, &identityv1.RevokeMyOtherSessionsRequest{}); reasonOf(err) != "no_current_session" {
		t.Errorf("no sid: %v", err)
	}

	// revoking the current session is a sign out
	if _, err := s.RevokeMySession(ctxA, &identityv1.RevokeMySessionRequest{Id: a}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.State.SessionAlive(ctx, a); ok {
		t.Error("the current session is alive after revoking it")
	}
}

func TestMySessionsNeedAUserToken(t *testing.T) {
	s, _, ctx := passkeyService(t, false)
	for name, c := range map[string]context.Context{
		"no principal": context.Background(),
		"service":      authn.WithPrincipal(ctx, &authn.Principal{Subject: "svc", ClientID: "svc"}),
	} {
		if _, err := s.ListMySessions(c, &identityv1.ListMySessionsRequest{}); reasonOf(err) != "user_token_required" {
			t.Errorf("%s list: %v", name, err)
		}
		if _, err := s.RevokeMySession(c, &identityv1.RevokeMySessionRequest{Id: "x"}); reasonOf(err) != "user_token_required" {
			t.Errorf("%s revoke: %v", name, err)
		}
		if _, err := s.RevokeMyOtherSessions(c, &identityv1.RevokeMyOtherSessionsRequest{}); reasonOf(err) != "user_token_required" {
			t.Errorf("%s others: %v", name, err)
		}
	}
}

func TestAdminUserSessions(t *testing.T) {
	s, u, ctx := passkeyService(t, false)
	client := clientFor(t, s)
	a, aRefresh := addSession(t, s, client, u.ID, "10.0.0.1", chromeMac)
	b, bRefresh := addSession(t, s, client, u.ID, "10.0.0.2", chromeMac)
	other, err := s.Store.CreateUser(ctx, store.User{Email: "o-" + uuid.NewString() + "@example.com", PasswordHash: mustHash(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Store.DeleteUser(context.Background(), other.ID) })
	foreign, foreignRefresh := addSession(t, s, client, other.ID, "10.9.9.9", chromeMac)

	// an administrator is not the user: the list has no current session
	admin := asSession(ctx, other.ID, foreign)
	list, err := s.ListUserSessions(admin, &identityv1.ListUserSessionsRequest{UserId: u.ID})
	if err != nil || len(list.Sessions) != 2 {
		t.Fatalf("list: %+v %v", list, err)
	}
	for _, x := range list.Sessions {
		if x.Current || x.Ip == "" {
			t.Errorf("session %+v", x)
		}
	}
	if _, err := s.ListUserSessions(admin, &identityv1.ListUserSessionsRequest{UserId: uuid.NewString()}); err == nil {
		t.Error("unknown user")
	}

	res, err := s.RevokeUserSessions(admin, &identityv1.RevokeUserSessionsRequest{UserId: u.ID})
	if err != nil || res.Revoked != 2 {
		t.Fatalf("revoke: %+v %v", res, err)
	}
	for _, pid := range []string{a, b} {
		if ok, _ := s.State.SessionAlive(ctx, pid); ok {
			t.Errorf("session %s is alive", pid)
		}
	}
	if refreshAlive(s, client, aRefresh) || refreshAlive(s, client, bRefresh) {
		t.Error("a refresh token of the user is alive")
	}
	if ok, _ := s.State.SessionAlive(ctx, foreign); !ok || !refreshAlive(s, client, foreignRefresh) {
		t.Error("the other user was touched")
	}
	if cut, _ := s.State.Cutoff(ctx, u.ID); cut.IsZero() {
		t.Error("no access token cutoff")
	}
	if list, _ = s.ListUserSessions(admin, &identityv1.ListUserSessionsRequest{UserId: u.ID}); len(list.Sessions) != 0 {
		t.Errorf("after: %+v", list.Sessions)
	}
}

func TestSessionRPCRules(t *testing.T) {
	const svc = "/identity.v1.IdentityService/"
	if r := Permissions[svc+"ListUserSessions"]; !ruleIs(r, "identity:user:read") {
		t.Errorf("ListUserSessions: %+v", r)
	}
	if r := Permissions[svc+"RevokeUserSessions"]; !ruleIs(r, "identity:user:write") {
		t.Errorf("RevokeUserSessions: %+v", r)
	}
	for _, m := range []string{"ListMySessions", "RevokeMySession", "RevokeMyOtherSessions"} {
		if r := Permissions[svc+m]; !r.Public {
			t.Errorf("%s: %+v", m, r)
		}
	}
}

func mustHash(t *testing.T) string {
	t.Helper()
	h, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func stateSession(uid, ip, ua string) state.Session {
	return state.Session{UserID: uid, IP: ip, UserAgent: ua, AMR: []string{"pwd"}}
}
