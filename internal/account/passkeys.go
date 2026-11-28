package account

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/huponx/identity/internal/passkey"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"go.uber.org/zap"
)

// Passkey errors.
var (
	// ErrPasskeyOff: passkeys are turned off on this server (IDENTITY_WEBAUTHN_ENABLED=false).
	ErrPasskeyOff = errors.New("account: passkeys are turned off on this server")
	// ErrPasskeyInvalid is every refused ceremony: it never says which check failed (the log does).
	ErrPasskeyInvalid = errors.New("account: invalid passkey")
	// ErrPasskeyNotFound: the passkey does not exist or is not the user's.
	ErrPasskeyNotFound = errors.New("account: passkey not found")
	// ErrPasskeyLimit: the user has MaxPasskeys already.
	ErrPasskeyLimit = errors.New("account: too many passkeys")
	// ErrPasskeyName: the name is empty or longer than 60 characters.
	ErrPasskeyName = errors.New("account: invalid passkey name")
)

// MaxPasskeys is how many passkeys one user may register.
const MaxPasskeys = 20

// PasskeysEnabled reports that the WebAuthn endpoints work.
func (s *Service) PasskeysEnabled() bool { return s.Passkeys != nil }

func (s *Service) passkeyUser(ctx context.Context, u *store.User) (passkey.User, error) {
	list, err := s.Store.ListPasskeys(ctx, u.ID)
	return passkey.User{U: u, Passkeys: list}, err
}

// MFAMethods tells which second factors the user has: a TOTP device and/or passkeys. A passkey
// counts as one only when the server runs them.
func (s *Service) MFAMethods(ctx context.Context, u *store.User) (totp, passkeys bool, err error) {
	totp = u.MFAEnabled
	if s.Passkeys != nil {
		n, err := s.Store.CountPasskeys(ctx, u.ID)
		if err != nil {
			return false, false, err
		}
		passkeys = n > 0
	}
	return totp, passkeys, nil
}

// ---- sign in ----

func (s *Service) passkeyAllow(ctx context.Context, key string, max int64, window time.Duration) error {
	ok, err := s.State.Allow(ctx, key, max, window)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}
	return nil
}

// PasskeyLoginBegin starts the usernameless sign in: it returns the id of the ceremony and the options
// for navigator.credentials.get.
func (s *Service) PasskeyLoginBegin(ctx context.Context, ip string) (id string, options []byte, err error) {
	if s.Passkeys == nil {
		return "", nil, ErrPasskeyOff
	}
	if err := s.passkeyAllow(ctx, "passkey:ip:"+ip, 60, 5*time.Minute); err != nil {
		return "", nil, err
	}
	options, sd, err := s.Passkeys.BeginLogin()
	if err != nil {
		return "", nil, err
	}
	id, err = s.saveCeremony(ctx, state.CeremonyLogin, "", sd)
	return id, options, err
}

func (s *Service) saveCeremony(ctx context.Context, purpose, userID string, sd *passkey.Session) (string, error) {
	id := password.Random(24)
	return id, s.saveCeremonyAs(ctx, id, purpose, userID, sd)
}

func (s *Service) saveCeremonyAs(ctx context.Context, id, purpose, userID string, sd *passkey.Session) error {
	raw, err := passkey.SessionJSON(sd)
	if err != nil {
		return err
	}
	return s.State.SaveCeremony(ctx, id, state.Ceremony{Purpose: purpose, UserID: userID, Data: raw})
}

// takeCeremony consumes the ceremony (one try) and checks its purpose and owner.
func (s *Service) takeCeremony(ctx context.Context, id, purpose, userID string) (passkey.Session, error) {
	c, err := s.State.TakeCeremony(ctx, id)
	if errors.Is(err, state.ErrNotFound) {
		return passkey.Session{}, ErrPasskeyInvalid
	}
	if err != nil {
		return passkey.Session{}, err
	}
	if c.Purpose != purpose || c.UserID != userID {
		return passkey.Session{}, ErrPasskeyInvalid
	}
	return passkey.ParseSession(c.Data)
}

var errInactive = errors.New("the user is disabled or awaiting approval")

// activeUser is a user who may sign in with a passkey.
func activeUser(u *store.User) bool { return !u.Disabled && !u.PendingApproval }

// PasskeyLoginFinish verifies the answer of the usernameless sign in and returns the user and what the
// passkey proved (for the amr of the session).
func (s *Service) PasskeyLoginFinish(ctx context.Context, id string, credential []byte, ip string) (*store.User, *passkey.Assertion, error) {
	if s.Passkeys == nil {
		return nil, nil, ErrPasskeyOff
	}
	if err := s.passkeyAllow(ctx, "passkey:ip:"+ip, 60, 5*time.Minute); err != nil {
		return nil, nil, err
	}
	sd, err := s.takeCeremony(ctx, id, state.CeremonyLogin, "")
	if err != nil {
		return nil, nil, err
	}
	var owner *store.User
	user, a, err := s.Passkeys.FinishLogin(func(rawID, handle []byte) (passkey.User, error) {
		uid, ok := passkey.UserID(handle)
		if !ok {
			return passkey.User{}, ErrPasskeyInvalid
		}
		u, err := s.Store.UserByID(ctx, uid)
		if err != nil {
			return passkey.User{}, err
		}
		owner = u
		return s.passkeyUser(ctx, u)
	}, sd, credential)
	if err != nil {
		return nil, nil, s.passkeyFailed(ctx, owner, ip, err)
	}
	u := user.U
	if !activeUser(u) {
		return nil, nil, s.passkeyFailed(ctx, u, ip, errInactive)
	}
	if err := s.passkeyUsed(ctx, *user, a); err != nil {
		return nil, nil, s.passkeyFailed(ctx, u, ip, err)
	}
	_ = s.State.Reset(ctx, "passkey:user:"+u.ID)
	return u, a, nil
}

// passkeyUsed records the use of the credential: the sign count and the time. The sign count that did
// not move forward was refused by the library (passkey.ErrCloned).
func (s *Service) passkeyUsed(ctx context.Context, u passkey.User, a *passkey.Assertion) error {
	for _, p := range u.Passkeys {
		if string(p.CredentialID) == string(a.CredentialID) {
			return s.Store.TouchPasskey(ctx, p.ID, a.SignCount, a.BackupState)
		}
	}
	return ErrPasskeyInvalid
}

// passkeyFailed logs a refused ceremony, counts it against the user it names (when known), and returns what
// the caller shows: ErrRateLimited after too many failures, ErrPasskeyInvalid otherwise. A real database or
// Redis error is returned as it is.
func (s *Service) passkeyFailed(ctx context.Context, u *store.User, ip string, cause error) error {
	if !errors.Is(cause, passkey.ErrInvalid) && !errors.Is(cause, passkey.ErrCloned) && !errors.Is(cause, ErrPasskeyInvalid) &&
		!errors.Is(cause, store.ErrNotFound) && !errors.Is(cause, errInactive) {
		return cause
	}
	fields := []zap.Field{zap.String("ip", ip), zap.Error(cause)}
	if u != nil {
		fields = append(fields, zap.String("user_id", u.ID))
	}
	if errors.Is(cause, passkey.ErrCloned) {
		s.Log.Warn("passkey refused: the sign count did not move forward (a cloned authenticator?)", fields...)
	} else {
		s.Log.Info("passkey refused", fields...)
	}
	if u != nil {
		if err := s.passkeyAllow(ctx, "passkey:user:"+u.ID, 10, 10*time.Minute); err != nil {
			return err
		}
	}
	return ErrPasskeyInvalid
}

// PasskeyMFABegin starts the passkey as the second factor of the login (or step-up) challenge `challengeID`:
// the ceremony is bound to that challenge and to the user, who must have a passkey.
func (s *Service) PasskeyMFABegin(ctx context.Context, u *store.User, challengeID string) ([]byte, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeyOff
	}
	pu, err := s.passkeyUser(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(pu.Passkeys) == 0 {
		return nil, ErrPasskeyNotFound
	}
	options, sd, err := s.Passkeys.BeginUserLogin(pu)
	if err != nil {
		return nil, err
	}
	return options, s.saveCeremonyAs(ctx, challengeID, state.CeremonyMFA, u.ID, sd)
}

// PasskeyMFAFinish verifies the answer for the second factor.
func (s *Service) PasskeyMFAFinish(ctx context.Context, u *store.User, challengeID string, credential []byte, ip string) (*passkey.Assertion, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeyOff
	}
	sd, err := s.takeCeremony(ctx, challengeID, state.CeremonyMFA, u.ID)
	if err != nil {
		return nil, err
	}
	pu, err := s.passkeyUser(ctx, u)
	if err != nil {
		return nil, err
	}
	a, err := s.Passkeys.FinishUserLogin(pu, sd, credential)
	if err == nil {
		err = s.passkeyUsed(ctx, pu, a)
	}
	if err != nil {
		return nil, s.passkeyFailed(ctx, u, ip, err)
	}
	return a, nil
}

// ---- the passkeys of the signed in user ----

// ListPasskeys returns the passkeys of the user.
func (s *Service) ListPasskeys(ctx context.Context, u *store.User) ([]store.Passkey, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeyOff
	}
	return s.Store.ListPasskeys(ctx, u.ID)
}

// checkPassword is the password check that guards the changes of the passkeys (the pattern of DisableMFA and
// ChangePassword): a stolen session alone cannot add or remove a key. Failures are limited per user.
func (s *Service) checkPassword(ctx context.Context, u *store.User, pw string) error {
	if err := s.passkeyAllow(ctx, "passkey:pw:"+u.ID, 5, 15*time.Minute); err != nil {
		return err
	}
	if u.PasswordHash == "" || !password.Verify(pw, u.PasswordHash) {
		if u.PasswordHash == "" {
			password.DummyVerify(pw)
		}
		return ErrInvalidCredentials
	}
	_ = s.State.Reset(ctx, "passkey:pw:"+u.ID)
	return nil
}

// PasskeyRegisterBegin checks the password and returns the id of the ceremony and the options for
// navigator.credentials.create.
func (s *Service) PasskeyRegisterBegin(ctx context.Context, u *store.User, pw string) (id string, options []byte, err error) {
	if s.Passkeys == nil {
		return "", nil, ErrPasskeyOff
	}
	if err := s.checkPassword(ctx, u, pw); err != nil {
		return "", nil, err
	}
	pu, err := s.passkeyUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	if len(pu.Passkeys) >= MaxPasskeys {
		return "", nil, ErrPasskeyLimit
	}
	options, sd, err := s.Passkeys.BeginRegistration(pu)
	if err != nil {
		return "", nil, err
	}
	id, err = s.saveCeremony(ctx, state.CeremonyRegister, u.ID, sd)
	return id, options, err
}

// PasskeyRegisterFinish verifies the new credential and stores it under name.
func (s *Service) PasskeyRegisterFinish(ctx context.Context, u *store.User, id string, credential []byte, name string) (*store.Passkey, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeyOff
	}
	name, ok := passkey.ValidName(name)
	if !ok {
		return nil, ErrPasskeyName
	}
	sd, err := s.takeCeremony(ctx, id, state.CeremonyRegister, u.ID)
	if err != nil {
		return nil, err
	}
	pu, err := s.passkeyUser(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(pu.Passkeys) >= MaxPasskeys {
		return nil, ErrPasskeyLimit
	}
	r, err := s.Passkeys.FinishRegistration(pu, sd, credential)
	if err != nil {
		s.Log.Info("passkey registration refused", zap.String("user_id", u.ID), zap.Error(err))
		return nil, ErrPasskeyInvalid
	}
	p, err := s.Store.InsertPasskey(ctx, store.Passkey{
		UserID: u.ID, CredentialID: r.CredentialID, PublicKey: r.PublicKey, SignCount: r.SignCount, AAGUID: r.AAGUID,
		Transports: r.Transports, BackupEligible: r.BackupEligible, BackupState: r.BackupState, AttestationType: r.AttestationType, Name: name,
	})
	if errors.Is(err, store.ErrConflict) { // this authenticator is registered already (by anybody)
		return nil, ErrPasskeyInvalid
	}
	if err != nil {
		return nil, err
	}
	s.mailMFA(u, "passkey_added")
	return p, nil
}

// RenamePasskey renames a passkey of the user.
func (s *Service) RenamePasskey(ctx context.Context, u *store.User, id, name string) error {
	if s.Passkeys == nil {
		return ErrPasskeyOff
	}
	name, ok := passkey.ValidName(name)
	if !ok {
		return ErrPasskeyName
	}
	if _, err := uuid.Parse(id); err != nil {
		return ErrPasskeyNotFound
	}
	if err := s.Store.RenamePasskey(ctx, u.ID, id, name); errors.Is(err, store.ErrNotFound) {
		return ErrPasskeyNotFound
	} else {
		return err
	}
}

// DeletePasskey deletes a passkey of the user after checking the password.
func (s *Service) DeletePasskey(ctx context.Context, u *store.User, id, pw string) error {
	if s.Passkeys == nil {
		return ErrPasskeyOff
	}
	if _, err := uuid.Parse(id); err != nil {
		return ErrPasskeyNotFound
	}
	if err := s.checkPassword(ctx, u, pw); err != nil {
		return err
	}
	if err := s.Store.DeletePasskey(ctx, u.ID, id); errors.Is(err, store.ErrNotFound) {
		return ErrPasskeyNotFound
	} else if err != nil {
		return err
	}
	s.mailMFA(u, "passkey_removed")
	return nil
}
