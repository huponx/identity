// Package account holds the account operations shared by the HTTP pages and the gRPC API:
// password login, password reset, MFA, and the revocation of sessions and tokens.
package account

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/huponx/gocommon/grpcserver"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/mfa"
	"github.com/huponx/identity/internal/notify"
	"github.com/huponx/identity/internal/passkey"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"github.com/skip2/go-qrcode"
	"go.uber.org/zap"
)

// Errors the callers map to a page or a status. They never say which part of a credential was wrong.
var (
	ErrInvalidCredentials = errors.New("account: invalid credentials")
	ErrRateLimited        = errors.New("account: too many attempts")
	ErrInvalidCode        = errors.New("account: invalid code")
	ErrInvalidResetToken  = errors.New("account: invalid or expired reset token")
	ErrMFAOff             = errors.New("account: mfa is turned off on this server")
	ErrMFAEnabled         = errors.New("account: mfa is already enabled")
	ErrMFANotEnrolled     = errors.New("account: the user has not enrolled a second factor")
	ErrMFAForced          = errors.New("account: mfa is required for this user")
	// ErrAwaitingApproval is returned for a user whose registration an administrator has not approved: no link is
	// sent to them and no reset works, or approval could be bypassed.
	ErrAwaitingApproval = errors.New("account: the user is awaiting approval")
	// ErrNotAwaitingApproval is returned by ApproveRegistration and RejectRegistration for another user.
	ErrNotAwaitingApproval = errors.New("account: the user is not awaiting approval")
)

// Config is the part of the settings used here.
type Config struct {
	Issuer        string
	MFAMode       string
	MFAIssuerName string
	ResetTTL      time.Duration // default 30 minutes
	WelcomeTTL    time.Duration // validity of the set-password link of a new user, default 7 days
	AdminURL      string        // link to the admin app in the mail to the approvers; "" omits it
	// RevokeTTL is how long the per-user token cutoff is kept: longer than any access token.
	RevokeTTL time.Duration
}

// Service is the account logic.
type Service struct {
	Cfg    Config
	Store  *store.Store
	State  *state.State
	Tokens *token.Service
	Sealer *mfa.Sealer // nil when MFA is off
	// Passkeys is nil when passkeys are turned off (IDENTITY_WEBAUTHN_ENABLED=false)
	Passkeys *passkey.Service
	Notify   notify.Notifier
	Log      *zap.Logger
	HTTP     *http.Client

	wg  sync.WaitGroup
	now func() time.Time
}

// New fills the defaults.
func New(cfg Config, st *store.Store, sta *state.State, tk *token.Service, sealer *mfa.Sealer, n notify.Notifier, log *zap.Logger) *Service {
	if cfg.ResetTTL <= 0 {
		cfg.ResetTTL = 30 * time.Minute
	}
	if cfg.WelcomeTTL <= 0 {
		cfg.WelcomeTTL = 7 * 24 * time.Hour
	}
	if cfg.RevokeTTL <= 0 {
		cfg.RevokeTTL = time.Hour
	}
	if cfg.MFAMode == "" {
		cfg.MFAMode = appconfig.MFAOptional
	}
	return &Service{Cfg: cfg, Store: st, State: sta, Tokens: tk, Sealer: sealer, Notify: n, Log: log,
		HTTP: &http.Client{Timeout: 5 * time.Second}, now: time.Now}
}

// Drain waits for the background work (mails, back-channel logout) to finish (shutdown, tests).
func (s *Service) Drain() { s.wg.Wait() }

func (s *Service) background(name string, fn func(ctx context.Context) error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := fn(ctx); err != nil {
			s.Log.Warn("background task failed", zap.String("task", name), zap.Error(err))
		}
	}()
}

func mailUser(u *store.User) notify.User {
	return notify.User{ID: u.ID, Email: u.Email, Name: u.Name, Locale: u.Locale}
}

// ---- password login ----

// PasswordLogin checks the credentials. Failures are limited per client IP and per e-mail, and
// an unknown user costs as much time as a wrong password.
func (s *Service) PasswordLogin(ctx context.Context, email, pw, ip string) (*store.User, error) {
	email = store.NormalizeEmail(email)
	for _, l := range []struct {
		key string
		max int64
		win time.Duration
	}{
		{"login:ip:" + ip, 20, 5 * time.Minute},
		{"login:email:" + email, 5, 15 * time.Minute},
	} {
		ok, err := s.State.Allow(ctx, l.key, l.max, l.win)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrRateLimited
		}
	}
	u, err := s.Store.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (u.PasswordHash == "" || u.Disabled)) {
		password.DummyVerify(pw)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !password.Verify(pw, u.PasswordHash) {
		return nil, ErrInvalidCredentials
	}
	_ = s.State.Reset(ctx, "login:email:"+email)
	return u, nil
}

// ChangePassword is the change of the own password of a signed-in user: the current password is checked
// first (failures are limited per user, like a login) and the policy applies to the new one. As
// SetPassword it ends every session and token of the user.
func (s *Service) ChangePassword(ctx context.Context, u *store.User, current, newPassword string) error {
	ok, err := s.State.Allow(ctx, "chpw:user:"+u.ID, 5, 15*time.Minute)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}
	if u.PasswordHash == "" || !password.Verify(current, u.PasswordHash) {
		if u.PasswordHash == "" {
			password.DummyVerify(current)
		}
		return ErrInvalidCredentials
	}
	if err := s.SetPassword(ctx, u, newPassword, true); err != nil {
		return err
	}
	_ = s.State.Reset(ctx, "chpw:user:"+u.ID)
	return nil
}

// ---- MFA ----

// Requirement is what a login needs after the password.
type Requirement int

// Requirements.
const (
	NoMFA  Requirement = iota
	Verify             // ask for a code
	Enroll             // the user must set up a second factor first
)

// MFARequirement applies the server mode and the flags of the user. A TOTP device is always asked for after the
// password. A passkey is not: signing in with the password stays a password sign in, and the passkey is a way in of its
// own. Only when MFA is required (mode or enforced user) does it count as a second factor that can be verified, so such
// a user with a passkey and no TOTP is asked for the passkey and is not sent to enroll.
func (s *Service) MFARequirement(ctx context.Context, u *store.User) (Requirement, error) {
	if s.Cfg.MFAMode == appconfig.MFAOff {
		return NoMFA, nil
	}
	if u.MFAEnabled {
		return Verify, nil
	}
	if !s.MFAForced(u) {
		return NoMFA, nil
	}
	_, passkeys, err := s.MFAMethods(ctx, u)
	if err != nil {
		return NoMFA, err
	}
	if passkeys {
		return Verify, nil
	}
	return Enroll, nil
}

// MFAForced reports that the user cannot turn MFA off.
func (s *Service) MFAForced(u *store.User) bool {
	return s.Cfg.MFAMode == appconfig.MFARequired || u.MFAEnforced
}

// Enrollment is what the user needs to add the factor to an authenticator app.
type Enrollment struct {
	Secret string // base32
	URI    string // otpauth://
	QRData string // data:image/png;base64,...
}

// BeginEnrollment returns the pending enrollment of the user, creating it when there is none.
func (s *Service) BeginEnrollment(ctx context.Context, u *store.User) (*Enrollment, error) {
	if s.Cfg.MFAMode == appconfig.MFAOff || s.Sealer == nil {
		return nil, ErrMFAOff
	}
	if u.MFAEnabled {
		return nil, ErrMFAEnabled
	}
	// A pending enrollment is reused, so reloading the page keeps the same QR code.
	var secret []byte
	if f, sec, err := s.openFactor(ctx, u.ID); err == nil && !f.Confirmed {
		secret = sec
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if secret == nil {
		secret = mfa.NewSecret()
		sealed, err := s.Sealer.Seal(secret, u.ID)
		if err != nil {
			return nil, err
		}
		if err := s.Store.ReplaceMFAFactor(ctx, u.ID, sealed); err != nil {
			return nil, err
		}
	}
	uri := mfa.URI(s.Cfg.MFAIssuerName, u.Email, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 224)
	if err != nil {
		return nil, err
	}
	return &Enrollment{Secret: mfa.EncodeSecret(secret), URI: uri, QRData: "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}, nil
}

func (s *Service) openFactor(ctx context.Context, userID string) (*store.MFAFactor, []byte, error) {
	f, err := s.Store.MFAFactorOf(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	secret, err := s.Sealer.Open(f.Sealed, userID)
	if err != nil {
		return nil, nil, err
	}
	if s.Sealer.NeedsReseal(f.Sealed) {
		if sealed, err := s.Sealer.Seal(secret, userID); err == nil {
			_ = s.Store.UpdateMFASealed(ctx, userID, sealed)
		}
	}
	return f, secret, nil
}

// ConfirmEnrollment checks the first code and turns MFA on. It returns the recovery codes,
// shown once.
func (s *Service) ConfirmEnrollment(ctx context.Context, u *store.User, code string) ([]string, error) {
	ok, err := s.State.Allow(ctx, "mfa:confirm:"+u.ID, 10, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRateLimited
	}
	f, secret, err := s.openFactor(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	if f.Confirmed {
		return nil, ErrMFAEnabled
	}
	step, matched := mfa.Match(secret, code, s.now())
	if !matched {
		return nil, ErrInvalidCode
	}
	codes := mfa.RecoveryCodes(10)
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = password.Digest(c)
	}
	if err := s.Store.ConfirmMFAFactor(ctx, u.ID, step, hashes); err != nil {
		return nil, err
	}
	s.mailMFA(u, "enabled")
	return codes, nil
}

// VerifySecondFactor accepts a TOTP code or a recovery code. A TOTP step is accepted once.
// It reports whether a recovery code was used.
func (s *Service) VerifySecondFactor(ctx context.Context, u *store.User, code string) (recovery bool, err error) {
	if rc := mfa.NormalizeRecoveryCode(code); rc != "" { // 12 characters: never a TOTP code
		ok, err := s.Store.UseRecoveryCode(ctx, u.ID, password.Digest(rc))
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
		return false, ErrInvalidCode
	}
	return false, s.verifyTOTP(ctx, u, code)
}

// verifyTOTP accepts a code of the authenticator app; a TOTP step is accepted once.
func (s *Service) verifyTOTP(ctx context.Context, u *store.User, code string) error {
	_, secret, err := s.openFactor(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrInvalidCode
	}
	if err != nil {
		return err
	}
	step, matched := mfa.Match(secret, code, s.now())
	if !matched {
		return ErrInvalidCode
	}
	fresh, err := s.Store.AdvanceMFAStep(ctx, u.ID, step)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrInvalidCode // the code was already used
	}
	return nil
}

// RegenerateRecoveryCodes replaces the recovery codes of the user after the password and a code of the authenticator
// app. A recovery code is not accepted: it would be spent just before it is replaced. The new codes are shown once.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, u *store.User, pw, code string) ([]string, error) {
	if !u.MFAEnabled {
		return nil, ErrMFANotEnrolled
	}
	if ok, err := s.State.Allow(ctx, "mfa:regen:"+u.ID, 10, 10*time.Minute); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrRateLimited
	}
	if !password.Verify(pw, u.PasswordHash) {
		return nil, ErrInvalidCredentials
	}
	if err := s.verifyTOTP(ctx, u, code); err != nil {
		return nil, err
	}
	codes := mfa.RecoveryCodes(10)
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = password.Digest(c)
	}
	if err := s.Store.ReplaceRecoveryCodes(ctx, u.ID, hashes); err != nil {
		return nil, err
	}
	s.mailMFA(u, "recovery_regenerated")
	return codes, nil
}

// DisableMFA turns MFA off for the user after checking the password and a second factor.
func (s *Service) DisableMFA(ctx context.Context, u *store.User, pw, code string) error {
	if s.MFAForced(u) {
		return ErrMFAForced
	}
	if ok, err := s.State.Allow(ctx, "mfa:disable:"+u.ID, 10, 10*time.Minute); err != nil {
		return err
	} else if !ok {
		return ErrRateLimited
	}
	if !password.Verify(pw, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	if _, err := s.VerifySecondFactor(ctx, u, code); err != nil {
		return err
	}
	return s.AdminDisableMFA(ctx, u)
}

// AdminDisableMFA turns MFA off without asking the user (admin API), unless it is required.
func (s *Service) AdminDisableMFA(ctx context.Context, u *store.User) error {
	if s.MFAForced(u) {
		return ErrMFAForced
	}
	if err := s.Store.ResetMFA(ctx, u.ID); err != nil {
		return err
	}
	s.mailMFA(u, "disabled")
	return nil
}

// AdminResetMFA deletes the factor and the passkeys of a user who lost the device, and ends their sessions.
func (s *Service) AdminResetMFA(ctx context.Context, u *store.User) error {
	if err := s.Store.ResetMFA(ctx, u.ID); err != nil {
		return err
	}
	// a lost device may be the one that holds the passkeys
	if _, err := s.Store.DeleteUserPasskeys(ctx, u.ID); err != nil {
		return err
	}
	s.mailMFA(u, "reset")
	return s.RevokeUserAccess(ctx, u.ID)
}

// AdminEnforceMFA sets or clears the enforcement flag.
func (s *Service) AdminEnforceMFA(ctx context.Context, u *store.User, enforced bool) error {
	if err := s.Store.SetUserMFAFlags(ctx, u.ID, nil, &enforced); err != nil {
		return err
	}
	if enforced {
		s.mailMFA(u, "enforced")
	}
	return nil
}

func (s *Service) mailMFA(u *store.User, change string) {
	id := uuid.NewString()
	user := mailUser(u)
	s.background("mfa mail", func(ctx context.Context) error { return s.Notify.MFAChanged(ctx, user, change, id) })
}

// ---- registration ----

// ApprovePermission is held by the users who decide on self-registrations; they get the mail about a new request.
var ApprovePermission = declared("identity:user:approve")

// declared returns the name if permissions.proto declares it, and panics at start otherwise: the constant cannot
// drift from the declaration.
func declared(name string) string {
	for _, d := range grpcserver.DeclaredPermissions(identityv1.File_identity_v1_permissions_proto) {
		if d.Name == name {
			return name
		}
	}
	panic("account: " + name + " is not declared in identity/v1/permissions.proto")
}

// Register creates the account of a visitor (no password). Without the approval setting it sends the welcome mail
// with the link to set the password; with it the account waits for an administrator and the applicant and the
// approvers get a mail instead. It never says whether the e-mail was known: an existing account (or a rate limited address) is answered like a new one,
// and nothing is sent to it. Only the limit per client IP is reported, which tells nothing about any account.
func (s *Service) Register(ctx context.Context, u store.User, roles []string, ip string) error {
	u.Email = store.NormalizeEmail(u.Email)
	if ok, err := s.State.Allow(ctx, "register:ip:"+ip, 10, time.Hour); err != nil {
		return err
	} else if !ok {
		return ErrRateLimited
	}
	if ok, err := s.State.Allow(ctx, "register:email:"+u.Email, 3, time.Hour); err != nil {
		return err
	} else if !ok {
		s.Log.Warn("registration rate limited", zap.String("key", "register:email"))
		return nil
	}
	needsApproval, err := s.Store.RegistrationRequiresApproval(ctx)
	if err != nil {
		return err
	}
	u.PendingApproval = needsApproval
	created, err := s.Store.CreateUser(ctx, u, roles)
	if errors.Is(err, store.ErrConflict) {
		return nil
	}
	if err != nil {
		return err
	}
	if !needsApproval {
		return s.SendWelcome(ctx, created)
	}
	s.mailRegistrationRequest(created)
	return nil
}

// mailRegistrationRequest tells the applicant that the request arrived and the approvers that it waits.
func (s *Service) mailRegistrationRequest(applicant *store.User) {
	id := uuid.NewString()
	user := mailUser(applicant)
	s.background("registration received mail", func(ctx context.Context) error {
		return s.Notify.RegistrationReceived(ctx, user, id)
	})
	s.background("registration pending mail", func(ctx context.Context) error {
		approvers, err := s.Store.ListUsersWithPermission(ctx, ApprovePermission)
		if err != nil {
			return err
		}
		if len(approvers) == 0 {
			s.Log.Warn("registration awaits approval but nobody may approve it", zap.String("applicant", applicant.ID))
			return nil
		}
		admins := make([]notify.User, len(approvers))
		for i := range approvers {
			admins[i] = mailUser(&approvers[i])
		}
		return s.Notify.RegistrationPending(ctx, admins, user, s.Cfg.AdminURL, id)
	})
}

// ApproveRegistration clears the flag of a user awaiting approval and sends the welcome mail with the link to set
// the password.
func (s *Service) ApproveRegistration(ctx context.Context, u *store.User) error {
	if !u.PendingApproval {
		return ErrNotAwaitingApproval
	}
	approved, err := s.Store.ApproveUser(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotAwaitingApproval
	}
	if err != nil {
		return err
	}
	return s.SendWelcome(ctx, approved)
}

// RejectRegistration deletes a user awaiting approval (the address is free to register again) and tells them.
func (s *Service) RejectRegistration(ctx context.Context, u *store.User) error {
	if !u.PendingApproval {
		return ErrNotAwaitingApproval
	}
	if err := s.Store.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	id := uuid.NewString()
	user := mailUser(u)
	s.background("registration rejected mail", func(ctx context.Context) error {
		return s.Notify.RegistrationRejected(ctx, user, id)
	})
	return nil
}

// ---- password reset ----

// RequestReset starts a password reset. It never says whether the e-mail exists: the caller
// shows the same answer in every case. The mail is sent in the background so the time does
// not depend on the outcome.
func (s *Service) RequestReset(ctx context.Context, email, ip string) error {
	email = store.NormalizeEmail(email)
	for _, l := range []struct {
		key string
		max int64
	}{{"reset:ip:" + ip, 10}, {"reset:email:" + email, 3}} {
		ok, err := s.State.Allow(ctx, l.key, l.max, time.Hour)
		if err != nil {
			return err
		}
		if !ok {
			s.Log.Warn("password reset rate limited", zap.String("key", l.key))
			return nil
		}
	}
	u, err := s.Store.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (u.Disabled || u.PendingApproval)) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.sendReset(ctx, u, ip)
}

// SendReset sends a reset mail to a known user (admin API).
func (s *Service) SendReset(ctx context.Context, u *store.User) error {
	if u.PendingApproval {
		return ErrAwaitingApproval
	}
	return s.sendReset(ctx, u, "")
}

// ErrNotPending is returned by SendWelcome for a user who already has a password.
var ErrNotPending = errors.New("account: the user already has a password")

// SendWelcome sends the welcome mail with a link to set the first password (admin API). It is
// for a user who has no password yet; the link lives Cfg.WelcomeTTL and replaces older links.
func (s *Service) SendWelcome(ctx context.Context, u *store.User) error {
	if u.PendingApproval {
		return ErrAwaitingApproval
	}
	if u.PasswordHash != "" {
		return ErrNotPending
	}
	link, id, err := s.issueLink(ctx, u, "", setPasswordPage, s.Cfg.WelcomeTTL)
	if err != nil {
		return err
	}
	user := mailUser(u)
	ttl := s.Cfg.WelcomeTTL
	s.background("welcome mail", func(ctx context.Context) error { return s.Notify.Welcome(ctx, user, link, ttl, id) })
	return nil
}

// The pages of the two links. Both take the same single-use token; the first password and a new one differ only in
// the wording of the page.
const (
	setPasswordPage   = "/password/set"   // welcome mail
	resetPasswordPage = "/password/reset" // forgot password, admin reset
)

// issueLink creates a single-use reset token valid for ttl and returns the link to the reset page.
func (s *Service) issueLink(ctx context.Context, u *store.User, ip, page string, ttl time.Duration) (link, id string, err error) {
	tok := password.Random(32)
	id, err = s.Store.CreatePasswordReset(ctx, u.ID, password.Digest(tok), ip, s.now().Add(ttl))
	if err != nil {
		return "", "", err
	}
	return strings.TrimRight(s.Cfg.Issuer, "/") + page + "?token=" + url.QueryEscape(tok), id, nil
}

func (s *Service) sendReset(ctx context.Context, u *store.User, ip string) error {
	link, id, err := s.issueLink(ctx, u, ip, resetPasswordPage, s.Cfg.ResetTTL)
	if err != nil {
		return err
	}
	user := mailUser(u)
	ttl := s.Cfg.ResetTTL
	s.background("reset mail", func(ctx context.Context) error { return s.Notify.PasswordReset(ctx, user, link, ttl, id) })
	return nil
}

// ResetTokenUser checks a reset token without consuming it (to show the form).
func (s *Service) ResetTokenUser(ctx context.Context, tok string) (*store.User, error) {
	uid, err := s.Store.PeekPasswordReset(ctx, password.Digest(tok))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidResetToken
	}
	if err != nil {
		return nil, err
	}
	u, err := s.Store.UserByID(ctx, uid)
	if err != nil {
		return nil, err
	}
	if u.PendingApproval { // a token issued before the user was held back is no use either
		return nil, ErrInvalidResetToken
	}
	return u, nil
}

// CompleteReset sets the new password. The token is consumed only after the policy accepted
// the password, and consuming is atomic, so two requests with one token cannot both win.
func (s *Service) CompleteReset(ctx context.Context, tok, newPassword string) error {
	u, err := s.ResetTokenUser(ctx, tok)
	if err != nil {
		return err
	}
	if err := password.Check(newPassword, u.Email, u.PasswordHash); err != nil {
		return err
	}
	if _, err := s.Store.ConsumePasswordReset(ctx, password.Digest(tok)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidResetToken
		}
		return err
	}
	return s.setPassword(ctx, u, newPassword, false, mailPasswordChanged(u.PasswordHash != ""))
}

// SetPassword stores a new password and ends every session and token of the user. With
// check, the policy is applied first (admin API); the reset flow already did.
func (s *Service) SetPassword(ctx context.Context, u *store.User, newPassword string, check bool) error {
	return s.setPassword(ctx, u, newPassword, check, true)
}

// mailPasswordChanged tells whether the "password changed" notice is sent: only when an
// existing password is replaced, not when the first one is set (welcome link).
func mailPasswordChanged(hadPassword bool) bool { return hadPassword }

func (s *Service) setPassword(ctx context.Context, u *store.User, newPassword string, check, notify bool) error {
	if check {
		if err := password.Check(newPassword, u.Email, u.PasswordHash); err != nil {
			return err
		}
	}
	hash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := s.Store.SetUserPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.RevokeUserAccess(ctx, u.ID); err != nil {
		return err
	}
	if !notify {
		return nil
	}
	user := mailUser(u)
	id := uuid.NewString()
	s.background("password changed mail", func(ctx context.Context) error { return s.Notify.PasswordChanged(ctx, user, id) })
	return nil
}

// ---- revocation ----

// EndSession ends one SSO session: deletes it, revokes its refresh tokens and sends the
// back-channel logout to the clients that used it. It returns the clients.
func (s *Service) EndSession(ctx context.Context, publicID string) (*state.Session, error) {
	sess, err := s.State.DeleteSession(ctx, publicID)
	if err != nil {
		return nil, err
	}
	if err := s.Store.RevokeRefreshBySession(ctx, publicID); err != nil {
		return nil, err
	}
	if sess != nil {
		s.backchannel(*sess)
	}
	return sess, nil
}

// RevokeUserAccess ends every session and refresh token of a user and makes the access tokens
// issued so far unusable for introspection and token exchange (services that verify locally
// stop accepting them within the access token lifetime).
func (s *Service) RevokeUserAccess(ctx context.Context, userID string) error {
	sessions, err := s.State.DeleteUserSessions(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.Store.RevokeRefreshByUser(ctx, userID); err != nil {
		return err
	}
	if err := s.State.SetCutoff(ctx, userID, s.now(), s.Cfg.RevokeTTL); err != nil {
		return err
	}
	for _, sess := range sessions {
		s.backchannel(sess)
	}
	return nil
}

// backchannel sends OpenID Connect Back-Channel Logout to every client of the session. It runs
// in the background with a few retries; a failure is logged, never fatal.
func (s *Service) backchannel(sess state.Session) {
	for _, clientID := range sess.Clients {
		clientID := clientID
		s.background("backchannel logout "+clientID, func(ctx context.Context) error {
			c, err := s.Store.ClientByID(ctx, clientID)
			if err != nil || c.BackchannelLogoutURI == "" {
				return nil
			}
			lt, err := s.Tokens.Logout(clientID, sess.UserID, sess.PublicID)
			if err != nil {
				return err
			}
			var last error
			for attempt := 0; attempt < 3; attempt++ {
				if attempt > 0 {
					select {
					case <-time.After(time.Duration(attempt) * time.Second):
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if last = s.postLogout(ctx, c.BackchannelLogoutURI, lt); last == nil {
					return nil
				}
			}
			return last
		})
	}
}

func (s *Service) postLogout(ctx context.Context, endpoint, logoutToken string) error {
	form := url.Values{"logout_token": {logoutToken}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
