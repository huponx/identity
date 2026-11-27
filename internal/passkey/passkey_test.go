package passkey

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/huponx/identity/internal/passkey/passkeytest"
	"github.com/huponx/identity/internal/store"
)

const origin = "https://auth.example.com"

func newService(t *testing.T) *Service {
	t.Helper()
	s, err := New(Config{RPID: "example.com", RPName: "Example", Origins: []string{origin, "https://portal.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testUser() *store.User {
	return &store.User{ID: uuid.NewString(), Email: "hu@example.com", Name: "Hu"}
}

// register runs the registration ceremony with the authenticator and returns the user with the new passkey.
func register(t *testing.T, s *Service, u *store.User, a *passkeytest.Authenticator) User {
	t.Helper()
	pu := User{U: u}
	opts, sd, err := s.BeginRegistration(pu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.FinishRegistration(pu, *sd, a.Create(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	if r.AttestationType != "none" || r.SignCount != 0 {
		t.Fatalf("registered: %+v", r)
	}
	pu.Passkeys = []store.Passkey{{ID: uuid.NewString(), UserID: u.ID, CredentialID: r.CredentialID, PublicKey: r.PublicKey,
		SignCount: r.SignCount, AAGUID: r.AAGUID, Transports: r.Transports, BackupEligible: r.BackupEligible, BackupState: r.BackupState, Name: "k"}}
	return pu
}

func TestRegisterAndUsernamelessLogin(t *testing.T) {
	s := newService(t)
	u := testUser()
	a := passkeytest.New(t, origin, "example.com")
	pu := register(t, s, u, a)

	opts, sd, err := s.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	got, as, err := s.FinishLogin(func(rawID, handle []byte) (User, error) {
		if id, ok := UserID(handle); !ok || id != u.ID {
			t.Errorf("user handle %x is not the user id", handle)
		}
		return pu, nil
	}, *sd, a.Get(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	if got.U.ID != u.ID || as.SignCount != 1 {
		t.Errorf("got %+v %+v", got.U, as)
	}
	if amr := as.AMR(); amr[0] != "hwk" || amr[1] != "mfa" {
		t.Errorf("amr %v", amr)
	}
}

func TestSyncedPasskeyIsSoftwareKey(t *testing.T) {
	s := newService(t)
	u := testUser()
	a := passkeytest.New(t, origin, "example.com")
	a.BE, a.BS = true, true
	pu := register(t, s, u, a)
	opts, sd, _ := s.BeginUserLogin(pu)
	as, err := s.FinishUserLogin(pu, *sd, a.Get(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	if amr := as.AMR(); amr[0] != "swk" || amr[1] != "mfa" {
		t.Errorf("amr %v", amr)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	s := newService(t)
	u := testUser()
	for name, tc := range map[string]func(a *passkeytest.Authenticator){
		"wrong origin":         func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example.net" },
		"wrong rp id":          func(a *passkeytest.Authenticator) { a.RPID = "evil.example.net" },
		"no user verification": func(a *passkeytest.Authenticator) { a.UV = false },
	} {
		a := passkeytest.New(t, origin, "example.com")
		tc(a)
		opts, sd, err := s.BeginRegistration(User{U: u})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.FinishRegistration(User{U: u}, *sd, a.Create(t, opts)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLoginRefusals(t *testing.T) {
	s := newService(t)
	u := testUser()
	a := passkeytest.New(t, origin, "example.com")
	pu := register(t, s, u, a)
	lookup := func(_, _ []byte) (User, error) { return pu, nil }

	for name, tc := range map[string]func(a *passkeytest.Authenticator){
		"wrong origin":         func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example.net" },
		"wrong rp id":          func(a *passkeytest.Authenticator) { a.RPID = "evil.example.net" },
		"no user verification": func(a *passkeytest.Authenticator) { a.UV = false },
	} {
		opts, sd, _ := s.BeginLogin()
		bad := *a
		tc(&bad)
		if _, _, err := s.FinishLogin(lookup, *sd, bad.Get(t, opts)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// the challenge of another ceremony
	_, sd1, _ := s.BeginLogin()
	opts2, _, _ := s.BeginLogin()
	if _, _, err := s.FinishLogin(lookup, *sd1, a.Get(t, opts2)); !errors.Is(err, ErrInvalid) {
		t.Errorf("another challenge: %v", err)
	}

	// a credential nobody registered
	other := passkeytest.New(t, origin, "example.com")
	opts, sd, _ := s.BeginLogin()
	if _, _, err := s.FinishLogin(lookup, *sd, other.Get(t, opts)); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown credential: %v", err)
	}
}

func TestSignCountMustAdvance(t *testing.T) {
	s := newService(t)
	u := testUser()
	a := passkeytest.New(t, origin, "example.com")
	pu := register(t, s, u, a)
	pu.Passkeys[0].SignCount = 10 // what the server stored after earlier sign ins
	a.Count = 4                   // a clone that has been used less

	opts, sd, _ := s.BeginUserLogin(pu)
	if _, err := s.FinishUserLogin(pu, *sd, a.Get(t, opts)); !errors.Is(err, ErrCloned) {
		t.Fatalf("a sign count that goes backwards: %v", err)
	}
	// an authenticator without a counter stays at zero and is fine
	b := passkeytest.New(t, origin, "example.com")
	b.Frozen = true
	pb := register(t, s, testUser(), b)
	opts, sd, _ = s.BeginUserLogin(pb)
	if _, err := s.FinishUserLogin(pb, *sd, b.Get(t, opts)); err != nil {
		t.Errorf("zero counter: %v", err)
	}
}

func TestCredentialOfAnotherUser(t *testing.T) {
	s := newService(t)
	a := passkeytest.New(t, origin, "example.com")
	register(t, s, testUser(), a)
	b := passkeytest.New(t, origin, "example.com")
	pb := register(t, s, testUser(), b) // user B has only B's passkey

	opts, sd, _ := s.BeginUserLogin(pb)
	if _, err := s.FinishUserLogin(pb, *sd, a.Get(t, opts)); !errors.Is(err, ErrInvalid) {
		t.Errorf("A's credential for B's ceremony: %v", err)
	}
}

func TestExpiredCeremony(t *testing.T) {
	s := newService(t)
	a := passkeytest.New(t, origin, "example.com")
	pu := register(t, s, testUser(), a)
	opts, sd, _ := s.BeginUserLogin(pu)
	sd.Expires = sd.Expires.AddDate(0, 0, -1)
	if _, err := s.FinishUserLogin(pu, *sd, a.Get(t, opts)); !errors.Is(err, ErrInvalid) {
		t.Errorf("expired: %v", err)
	}
}

func TestBadConfig(t *testing.T) {
	if _, err := New(Config{RPID: "example.com", RPName: "x"}); err == nil {
		t.Error("no origin accepted")
	}
}
