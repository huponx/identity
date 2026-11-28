package service

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/notify"
	"github.com/huponx/identity/internal/passkey"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// needs IDENTITY_TEST_POSTGRES_URL and IDENTITY_TEST_REDIS_URL, like the tests of internal/oauth
func passkeyService(t *testing.T, on bool) (*Service, *store.User, context.Context) {
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
	sta.LimitFactor = 1000
	log := zap.NewNop()
	acct := account.New(account.Config{Issuer: "https://auth.example.com", MFAMode: "optional"}, st, sta, nil, nil, notify.None{Logger: log}, log)
	if on {
		if acct.Passkeys, err = passkey.New(passkey.Config{RPID: "example.com", RPName: "Example", Origins: []string{"https://auth.example.com"}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(acct.Drain)
	hash, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, store.User{Email: "pk-" + uuid.NewString() + "@example.com", PasswordHash: hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteUser(context.Background(), u.ID) })
	ctx = authn.WithPrincipal(ctx, &authn.Principal{Subject: u.ID, ClientID: "gk"})
	return &Service{Acct: acct, Store: st, State: sta, MFAMode: "optional"}, u, ctx
}

func reasonOf(err error) string {
	var ae *apperror.Error
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ""
}

func TestMyPasskeysAndTheAdminView(t *testing.T) {
	s, u, ctx := passkeyService(t, true)
	p, err := s.Store.InsertPasskey(ctx, store.Passkey{UserID: u.ID, CredentialID: []byte("cred-" + u.ID), PublicKey: []byte("k"), Name: "Laptop", BackupEligible: true})
	if err != nil {
		t.Fatal(err)
	}

	list, err := s.ListMyPasskeys(ctx, &identityv1.ListMyPasskeysRequest{})
	if err != nil || len(list.Passkeys) != 1 || list.Passkeys[0].Id != p.ID || list.Passkeys[0].Name != "Laptop" || !list.Passkeys[0].Synced || list.Passkeys[0].LastUsedAt != 0 || list.Max != account.MaxPasskeys {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := s.RenameMyPasskey(ctx, &identityv1.RenameMyPasskeyRequest{Id: p.ID, Name: "Work laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenameMyPasskey(ctx, &identityv1.RenameMyPasskeyRequest{Id: p.ID, Name: ""}); reasonOf(err) != "invalid_passkey_name" {
		t.Errorf("empty name: %v", err)
	}
	if _, err := s.RenameMyPasskey(ctx, &identityv1.RenameMyPasskeyRequest{Id: uuid.NewString(), Name: "x"}); reasonOf(err) != "passkey_not_found" {
		t.Errorf("not mine: %v", err)
	}
	// begin and delete need the password
	if _, err := s.BeginMyPasskey(ctx, &identityv1.BeginMyPasskeyRequest{Password: "wrong wrong wrong"}); err == nil {
		t.Error("begin with a wrong password")
	}
	if _, err := s.DeleteMyPasskey(ctx, &identityv1.DeleteMyPasskeyRequest{Id: p.ID, Password: "wrong wrong wrong"}); err == nil {
		t.Error("delete with a wrong password")
	}
	begin, err := s.BeginMyPasskey(ctx, &identityv1.BeginMyPasskeyRequest{Password: "correct horse battery staple"})
	if err != nil || begin.CeremonyId == "" || begin.OptionsJson == "" {
		t.Fatalf("begin: %+v %v", begin, err)
	}

	// the administrator sees the count, and a reset removes them
	mfa, err := s.GetUserMFA(ctx, &identityv1.GetUserMFARequest{UserId: u.ID})
	if err != nil || mfa.PasskeyCount != 1 {
		t.Fatalf("GetUserMFA: %+v %v", mfa, err)
	}
	if _, err := s.ResetUserMFA(ctx, &identityv1.ResetUserMFARequest{UserId: u.ID}); err != nil {
		t.Fatal(err)
	}
	if mfa, _ = s.GetUserMFA(ctx, &identityv1.GetUserMFARequest{UserId: u.ID}); mfa.PasskeyCount != 0 {
		t.Errorf("after the reset: %d", mfa.PasskeyCount)
	}
	// turning TOTP off is not a reset: a passkey stays
	if _, err := s.Store.InsertPasskey(ctx, store.Passkey{UserID: u.ID, CredentialID: []byte("cred2-" + u.ID), PublicKey: []byte("k"), Name: "Phone"}); err != nil {
		t.Fatal(err)
	}
	user, _ := s.Store.UserByID(ctx, u.ID)
	if err := s.Acct.AdminDisableMFA(ctx, user); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Store.CountPasskeys(ctx, u.ID); n != 1 {
		t.Errorf("AdminDisableMFA removed the passkeys: %d left", n)
	}
}

func TestMyPasskeysWhenOff(t *testing.T) {
	s, _, ctx := passkeyService(t, false)
	if _, err := s.ListMyPasskeys(ctx, &identityv1.ListMyPasskeysRequest{}); reasonOf(err) != "passkeys_off" {
		t.Errorf("list: %v", err)
	}
	if _, err := s.BeginMyPasskey(ctx, &identityv1.BeginMyPasskeyRequest{Password: "x"}); reasonOf(err) != "passkeys_off" {
		t.Errorf("begin: %v", err)
	}
}

func TestMyPasskeysNeedAUserToken(t *testing.T) {
	s, _, _ := passkeyService(t, true)
	ctx := authn.WithPrincipal(context.Background(), &authn.Principal{Subject: "gk", ClientID: "gk"})
	if _, err := s.ListMyPasskeys(ctx, &identityv1.ListMyPasskeysRequest{}); reasonOf(err) != "user_token_required" {
		t.Errorf("service token: %v", err)
	}
}
