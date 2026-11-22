package oauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
)

// ---- logout (OpenID Connect RP-Initiated Logout 1.0) ----

// endSession ends the SSO session of the browser. With a valid id_token_hint (proof that the
// application asked for it) it logs out at once; without one a confirmation page with a POST
// form is shown, so another site cannot sign people out with an image tag.
func (s *Server) endSession(c *gin.Context) {
	ctx := c.Request.Context()
	param := func(k string) string {
		if c.Request.Method == http.MethodPost {
			return c.PostForm(k)
		}
		return c.Query(k)
	}
	hint, redirect, state := param("id_token_hint"), param("post_logout_redirect_uri"), param("state")

	var client *store.Client
	trusted := false
	if hint != "" {
		claims, err := s.tokens.VerifyIDHint(ctx, hint)
		if err != nil {
			s.errorPage(c, http.StatusBadRequest, "The logout request is not valid.")
			return
		}
		if cl, err := s.store.ClientByID(ctx, claims.Audience[0]); err == nil {
			client, trusted = cl, true
		}
	} else if id := param("client_id"); id != "" {
		client, _ = s.store.ClientByID(ctx, id)
	}
	// the redirect is honoured only for a registered address of the client
	target := ""
	if client != nil && redirect != "" && contains(client.PostLogoutRedirectURIs, redirect) {
		target = redirect
	}

	if !trusted {
		if c.Request.Method == http.MethodGet {
			s.render(c, http.StatusOK, "confirm-logout", page{Title: "Sign out", CSRF: s.csrfToken(c), Fields: map[string]string{
				"post_logout_redirect_uri": target, "state": state, "client_id": param("client_id"),
			}})
			return
		}
		if !s.csrfOK(c) {
			s.errorPage(c, http.StatusForbidden, "The form expired. Please try again.")
			return
		}
	}

	if sess, _, _ := s.sessionFrom(c); sess != nil {
		if _, err := s.acct.EndSession(ctx, sess.PublicID); err != nil {
			s.fail(c, err)
			return
		}
	}
	s.setCookie(c, "sid", "", -1)

	if target != "" {
		u, _ := url.Parse(target)
		if state != "" {
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
		}
		c.Redirect(http.StatusFound, u.String())
		return
	}
	s.render(c, http.StatusOK, "message", page{Title: "Signed out", Message: "You have been signed out.", Notice: true})
}

// ---- password reset ----

func (s *Server) forgotForm(c *gin.Context) {
	s.render(c, http.StatusOK, "forgot", page{Title: "Forgot your password?", CSRF: s.csrfToken(c)})
}

// forgotSubmit answers the same way whether or not the address is registered.
func (s *Server) forgotSubmit(c *gin.Context) {
	if !s.csrfOK(c) {
		s.render(c, http.StatusForbidden, "forgot", page{Title: "Forgot your password?", Message: "The form expired. Please try again.", CSRF: s.csrfToken(c)})
		return
	}
	if err := s.acct.RequestReset(c.Request.Context(), c.PostForm("email"), c.ClientIP()); err != nil {
		s.fail(c, err)
		return
	}
	s.render(c, http.StatusOK, "forgot", page{Title: "Check your e-mail", Notice: true,
		Message: "If the address is registered, we sent a link to reset the password. It works for 30 minutes."})
}

func (s *Server) resetForm(c *gin.Context) {
	tok := c.Query("token")
	if _, err := s.acct.ResetTokenUser(c.Request.Context(), tok); err != nil {
		if errors.Is(err, account.ErrInvalidResetToken) || errors.Is(err, store.ErrNotFound) {
			s.render(c, http.StatusBadRequest, "forgot", page{Title: "Link not valid", Message: "This link is not valid or has expired. Ask for a new one.", CSRF: s.csrfToken(c)})
			return
		}
		s.fail(c, err)
		return
	}
	s.render(c, http.StatusOK, "reset", page{Title: "Choose a new password", CSRF: s.csrfToken(c), Fields: map[string]string{"token": tok}})
}

func (s *Server) resetSubmit(c *gin.Context) {
	tok := c.PostForm("token")
	again := func(status int, msg string) {
		s.render(c, status, "reset", page{Title: "Choose a new password", Message: msg, CSRF: s.csrfToken(c), Fields: map[string]string{"token": tok}})
	}
	if !s.csrfOK(c) {
		again(http.StatusForbidden, "The form expired. Please try again.")
		return
	}
	err := s.acct.CompleteReset(c.Request.Context(), tok, c.PostForm("password"))
	switch {
	case err == nil:
		s.render(c, http.StatusOK, "message", page{Title: "Password changed", Notice: true,
			Message: "Your password was changed and you were signed out everywhere.", ReturnTo: "/login"})
	case errors.Is(err, account.ErrInvalidResetToken):
		s.render(c, http.StatusBadRequest, "forgot", page{Title: "Link not valid", Message: "This link is not valid or has expired. Ask for a new one.", CSRF: s.csrfToken(c)})
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrCommon),
		errors.Is(err, password.ErrSame), errors.Is(err, password.ErrEmail):
		again(http.StatusUnprocessableEntity, err.Error()+".")
	default:
		s.fail(c, err)
	}
}

// ---- forced password change at login ----

// passwordChangeForm asks for a new password after a correct login with a password somebody else set
// (the setup Job). The challenge is created by loginSubmit; no session exists yet.
func (s *Server) passwordChangeForm(c *gin.Context) {
	id := c.Query("c")
	if ch, err := s.state.PeekChallenge(c.Request.Context(), id); err != nil || ch.Purpose != state.PurposePassword {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	s.render(c, http.StatusOK, "password-change", page{Title: "Choose a new password", CSRF: s.csrfToken(c),
		Message: "You are signing in with a temporary password. Choose your own to continue.", Notice: true, Fields: map[string]string{"c": id}})
}

func (s *Server) passwordChangeSubmit(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.PostForm("c")
	again := func(status int, msg string) {
		s.render(c, status, "password-change", page{Title: "Choose a new password", Message: msg, CSRF: s.csrfToken(c), Fields: map[string]string{"c": id}})
	}
	if !s.csrfOK(c) {
		again(http.StatusForbidden, "The form expired. Please try again.")
		return
	}
	ch, err := s.state.Attempt(ctx, id, 10)
	if err == nil && ch.Purpose != state.PurposePassword {
		err = state.ErrNotFound
	}
	if errors.Is(err, state.ErrNotFound) {
		s.render(c, http.StatusUnauthorized, "login", page{Title: "Sign in", Message: "Too many attempts or the request expired. Please sign in again.",
			CSRF: s.csrfToken(c), ReturnTo: "/account/mfa", Fields: map[string]string{}})
		return
	}
	if err != nil {
		s.fail(c, err)
		return
	}
	user, err := s.store.UserByID(ctx, ch.UserID)
	if err != nil || user.Disabled || !user.MustChangePassword {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	pw := c.PostForm("password")
	if pw != c.PostForm("password2") {
		again(http.StatusUnprocessableEntity, "The two passwords are not the same.")
		return
	}
	switch err := s.acct.SetPassword(ctx, user, pw, true); {
	case err == nil:
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrCommon),
		errors.Is(err, password.ErrSame), errors.Is(err, password.ErrEmail):
		again(http.StatusUnprocessableEntity, err.Error()+".")
		return
	default:
		s.fail(c, err)
		return
	}
	_ = s.state.DeleteChallenge(ctx, id)
	user, err = s.store.UserByID(ctx, user.ID) // the flag is cleared; the next steps use the stored user
	if err != nil {
		s.fail(c, err)
		return
	}
	s.continueLogin(c, user, safeReturn(ch.ReturnTo))
}

// ---- account MFA page ----

// requireSession returns the signed in user or sends the browser to the login.
func (s *Server) requireSession(c *gin.Context) (*store.User, bool) {
	sess, user, _ := s.sessionFrom(c)
	if sess == nil {
		back := c.Request.URL.RequestURI()
		c.Redirect(http.StatusSeeOther, "/login?return_to="+url.QueryEscape(safeReturn(back)))
		return nil, false
	}
	return user, true
}

func (s *Server) accountMFA(c *gin.Context) {
	if s.cfg.MFAMode == appconfig.MFAOff {
		c.Status(http.StatusNotFound)
		return
	}
	user, ok := s.requireSession(c)
	if !ok {
		return
	}
	s.mfaPage(c, user, http.StatusOK, "", safeReturn(c.Query("return_to")))
}

// mfaPage shows the enrollment of a user without MFA, or the status of one with MFA.
func (s *Server) mfaPage(c *gin.Context, user *store.User, status int, msg, ret string) {
	ctx := c.Request.Context()
	if user.MFAEnabled {
		left, err := s.store.RecoveryCodesLeft(ctx, user.ID)
		if err != nil {
			s.fail(c, err)
			return
		}
		s.render(c, status, "mfa-status", page{Title: "Multi-factor authentication", Message: msg, CSRF: s.csrfToken(c), ReturnTo: ret,
			Data: map[string]any{"CodesLeft": left, "Forced": s.acct.MFAForced(user)}})
		return
	}
	enr, err := s.acct.BeginEnrollment(ctx, user)
	if err != nil {
		s.fail(c, err)
		return
	}
	s.render(c, status, "mfa-enroll", page{Title: "Turn on multi-factor authentication", Message: msg, CSRF: s.csrfToken(c), ReturnTo: ret, Data: enr})
}

func (s *Server) accountMFAConfirm(c *gin.Context) {
	if s.cfg.MFAMode == appconfig.MFAOff {
		c.Status(http.StatusNotFound)
		return
	}
	user, ok := s.requireSession(c)
	if !ok {
		return
	}
	ret := safeReturn(c.PostForm("return_to"))
	if !s.csrfOK(c) {
		s.mfaPage(c, user, http.StatusForbidden, "The form expired. Please try again.", ret)
		return
	}
	codes, err := s.acct.ConfirmEnrollment(c.Request.Context(), user, c.PostForm("code"))
	switch {
	case errors.Is(err, account.ErrInvalidCode):
		s.mfaPage(c, user, http.StatusUnauthorized, "Wrong code. Check the clock of your device and try again.", ret)
	case errors.Is(err, account.ErrRateLimited):
		s.mfaPage(c, user, http.StatusTooManyRequests, "Too many attempts. Please wait a few minutes.", ret)
	case errors.Is(err, account.ErrMFAEnabled):
		c.Redirect(http.StatusSeeOther, "/account/mfa")
	case err != nil:
		s.fail(c, err)
	default:
		// the user just proved they hold the device: this session now counts as multi-factor
		if err := s.upgradeSession(c); err != nil {
			s.fail(c, err)
			return
		}
		s.render(c, http.StatusOK, "mfa-codes", page{Title: "Recovery codes", ReturnTo: ret, Data: codes})
	}
}

func (s *Server) accountMFADisable(c *gin.Context) {
	if s.cfg.MFAMode == appconfig.MFAOff {
		c.Status(http.StatusNotFound)
		return
	}
	user, ok := s.requireSession(c)
	if !ok {
		return
	}
	if !s.csrfOK(c) {
		s.mfaPage(c, user, http.StatusForbidden, "The form expired. Please try again.", "/account/mfa")
		return
	}
	err := s.acct.DisableMFA(c.Request.Context(), user, c.PostForm("password"), c.PostForm("code"))
	switch {
	case err == nil:
		c.Redirect(http.StatusSeeOther, "/account/mfa")
	case errors.Is(err, account.ErrMFAForced):
		s.mfaPage(c, user, http.StatusForbidden, "Multi-factor authentication is required for your account.", "/account/mfa")
	case errors.Is(err, account.ErrInvalidCredentials), errors.Is(err, account.ErrInvalidCode):
		s.mfaPage(c, user, http.StatusUnauthorized, "Wrong password or code.", "/account/mfa")
	case errors.Is(err, account.ErrRateLimited):
		s.mfaPage(c, user, http.StatusTooManyRequests, "Too many attempts. Please wait a few minutes.", "/account/mfa")
	default:
		s.fail(c, err)
	}
}
