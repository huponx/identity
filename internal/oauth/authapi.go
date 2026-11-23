package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"go.uber.org/zap"
)

// The JSON API of the sign in app (apps/auth of the web repository), same origin as the pages.
//
// Every state changing call is a POST with a JSON body that carries the `csrf` token of the cookie (fetched
// with GET /auth-api/csrf) and passes the Origin check. An answer is either `{"redirect": "<path>"}` (the
// next step; the app only follows paths) or an error `{"code": "...", "message": "..."}` whose code the app
// turns into text. The logic of each step is the one the HTML forms had: rate limits, challenges, session
// fixation, safeReturn.

// apiMessages are the English texts of the error codes (the app has its own, localized ones).
var apiMessages = map[string]string{
	"bad_request":              "The request is not valid.",
	"csrf_expired":             "The form expired. Please try again.",
	"rate_limited":             "Too many attempts. Please wait a few minutes.",
	"invalid_credentials":      "Wrong e-mail or password.",
	"invalid_code":             "Wrong code. Check the clock of your device and try again.",
	"invalid_mfa_code":         "Wrong code.",
	"invalid_password_or_code": "Wrong password or code.",
	"challenge_expired":        "Too many wrong attempts or the request expired. Please sign in again.",
	"unauthenticated":          "Please sign in again.",
	"invalid_link":             "This link is not valid or has expired. Ask for a new one.",
	"mfa_forced":               "Multi-factor authentication is required for your account.",
	"mfa_enabled":              "Multi-factor authentication is already on.",
	"not_found":                "Not found.",
	"password_mismatch":        "The two passwords are not the same.",
	"password_too_short":       "The password must have at least 12 characters.",
	"password_too_long":        "The password is too long.",
	"password_common":          "The password is too common.",
	"password_same":            "The password must differ from the previous one.",
	"password_email":           "The password must not contain the e-mail address.",
	"internal":                 "Something went wrong. Please try again.",
}

func (s *Server) apiError(c *gin.Context, status int, code string) {
	c.AbortWithStatusJSON(status, gin.H{"code": code, "message": apiMessages[code]})
}

// apiFail logs an unexpected error and answers 500.
func (s *Server) apiFail(c *gin.Context, err error) {
	logging.FromCtx(c.Request.Context()).Error("request failed", zap.Error(err))
	s.apiError(c, http.StatusInternalServerError, "internal")
}

func next(c *gin.Context, to string) { c.JSON(http.StatusOK, gin.H{"redirect": to}) }

// csrfBody is embedded in the body of every POST.
type csrfBody struct {
	CSRF string `json:"csrf"`
}

func (b *csrfBody) token() string { return b.CSRF }

type tokenCarrier interface{ token() string }

// readJSON binds the body and checks the CSRF token; it answers the error itself and returns false.
func (s *Server) readJSON(c *gin.Context, v tokenCarrier) bool {
	if err := c.ShouldBindJSON(v); err != nil {
		s.apiError(c, http.StatusBadRequest, "bad_request")
		return false
	}
	if !s.csrfOK(c, v.token()) {
		s.apiError(c, http.StatusForbidden, "csrf_expired")
		return false
	}
	return true
}

// passwordCode maps the errors of the password policy to the codes of the app.
func passwordCode(err error) (string, bool) {
	switch {
	case errors.Is(err, password.ErrTooShort):
		return "password_too_short", true
	case errors.Is(err, password.ErrTooLong):
		return "password_too_long", true
	case errors.Is(err, password.ErrCommon):
		return "password_common", true
	case errors.Is(err, password.ErrSame):
		return "password_same", true
	case errors.Is(err, password.ErrEmail):
		return "password_email", true
	}
	return "", false
}

func (s *Server) authAPI(r *gin.Engine) {
	a := r.Group("/auth-api")
	a.GET("/csrf", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"csrf": s.csrfToken(c)}) })

	a.POST("/login", s.apiLogin)
	a.GET("/login/mfa", s.apiMFACheck)
	a.POST("/login/mfa", s.apiMFA)
	a.GET("/login/password", s.apiPasswordChangeCheck)
	a.POST("/login/password", s.apiPasswordChange)

	a.POST("/password/forgot", s.apiForgot)
	a.GET("/password/reset", s.apiResetCheck)
	a.POST("/password/reset", s.apiReset)

	a.GET("/account/mfa", s.apiAccountMFA)
	a.POST("/account/mfa", s.apiAccountMFAConfirm)
	a.POST("/account/mfa/disable", s.apiAccountMFADisable)

	a.POST("/logout", s.apiLogout)
	a.GET("/apps", s.apiApps)
	a.GET("/ui-style", s.apiUIStyle)
	a.GET("/preferences", s.apiPreferences)
	a.POST("/preferences", s.apiSetPreferences)
}

// apiApps lists the applications of the signed in user's landing page (and whether the link to the MFA page is shown: only for an account that must use MFA and has not set it up yet).
func (s *Server) apiApps(c *gin.Context) {
	_, user, _ := s.sessionFrom(c)
	if user == nil {
		s.apiError(c, http.StatusUnauthorized, "unauthenticated")
		return
	}
	apps := s.cfg.Apps
	if apps == nil {
		apps = []appconfig.AppLink{}
	}
	c.JSON(http.StatusOK, gin.H{"apps": apps, "name": user.Name, "email": user.Email, "theme": user.Theme, "mfa": s.cfg.MFAMode != appconfig.MFAOff && s.acct.MFAForced(user) && !user.MFAEnabled})
}

// apiUIStyle answers the look of the web apps and the palette of each look (set by an administrator for the whole
// system). No session: the sign in pages show it before anybody is signed in. A missing or unknown value is the
// default: "saas" and "aurora".
func (s *Server) apiUIStyle(c *gin.Context) {
	style, err := "saas", error(nil)
	stored := map[string]string{}
	if s.store != nil {
		ctx := c.Request.Context()
		if style, err = s.store.UIStyle(ctx, "saas"); err == nil {
			stored, err = s.store.UIPalettes(ctx)
		}
	}
	if err != nil || (style != "saas" && style != "glass" && style != "mono") {
		style = "saas"
	}
	palettes := map[string]string{}
	for _, st := range []string{"saas", "glass", "mono"} {
		palettes[st] = "aurora"
		switch p := stored[st]; p {
		case "ocean", "sunset", "mint", "rose", "graphite":
			palettes[st] = p
		}
	}
	c.JSON(http.StatusOK, gin.H{"uiStyle": style, "uiPalettes": palettes})
}

// apiPreferences answers the theme and the language of the signed in user's account, which the pages keep in step with the apps.
func (s *Server) apiPreferences(c *gin.Context) {
	_, user, _ := s.sessionFrom(c)
	if user == nil {
		s.apiError(c, http.StatusUnauthorized, "unauthenticated")
		return
	}
	c.JSON(http.StatusOK, gin.H{"theme": user.Theme, "locale": user.Locale})
}

// apiSetPreferences stores the theme and/or the language the signed in user picked on these pages.
func (s *Server) apiSetPreferences(c *gin.Context) {
	var req struct {
		csrfBody
		Theme  string `json:"theme"`
		Locale string `json:"locale"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	_, user, _ := s.sessionFrom(c)
	if user == nil {
		s.apiError(c, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if (req.Theme != "" && !themeChoices[req.Theme]) || (req.Locale != "" && !localeChoices[req.Locale]) {
		s.apiError(c, http.StatusBadRequest, "bad_request")
		return
	}
	s.keepPreferences(c, user, req.Theme, req.Locale)
	c.JSON(http.StatusOK, gin.H{"theme": user.Theme, "locale": user.Locale})
}

// ---- password login ----

func (s *Server) apiLogin(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		csrfBody
		Email    string `json:"email"`
		Password string `json:"password"`
		ReturnTo string `json:"return_to"`
		// what the user picked on this page before signing in (the pages are another origin than the apps, so
		// the account is how the choice reaches them); empty when the user did not touch it
		Theme  string `json:"theme"`
		Locale string `json:"locale"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	ret := safeReturn(req.ReturnTo)
	user, err := s.acct.PasswordLogin(ctx, req.Email, req.Password, c.ClientIP())
	switch {
	case errors.Is(err, account.ErrRateLimited):
		s.apiError(c, http.StatusTooManyRequests, "rate_limited")
		return
	case errors.Is(err, account.ErrInvalidCredentials):
		s.apiError(c, http.StatusUnauthorized, "invalid_credentials")
		return
	case err != nil:
		s.apiFail(c, err)
		return
	}

	s.keepPreferences(c, user, req.Theme, req.Locale)

	// a login always starts a new session (no session fixation)
	if _, _, old := s.sessionFrom(c); old != "" {
		if sess, err := s.state.GetSession(ctx, old, s.cfg.SessionIdle, s.cfg.SessionAbsolute); err == nil {
			_, _ = s.acct.EndSession(ctx, sess.PublicID)
		}
	}

	if user.MustChangePassword {
		// the password was set by somebody else: no session until the user chose their own
		id := password.Random(24)
		if err := s.state.SaveChallenge(ctx, id, state.Challenge{UserID: user.ID, ReturnTo: ret, Purpose: state.PurposePassword}); err != nil {
			s.apiFail(c, err)
			return
		}
		next(c, "/login/password?c="+url.QueryEscape(id))
		return
	}
	to, err := s.continueLogin(c, user, ret)
	if err != nil {
		s.apiFail(c, err)
		return
	}
	// the theme of the account: the app keeps it for the next visit of the pages (they are another origin than the apps)
	c.JSON(http.StatusOK, gin.H{"redirect": to, "theme": user.Theme, "locale": user.Locale})
}

var (
	themeChoices  = map[string]bool{"light": true, "dark": true, "system": true}
	localeChoices = map[string]bool{"en": true, "vi": true}
)

// keepPreferences stores the theme and the language the user picked on the sign in page in the account (an
// unknown value is ignored) and updates `user`, which the answer is built from. Best effort: the password was
// right, so a failed save must not fail the sign in.
func (s *Server) keepPreferences(c *gin.Context, user *store.User, theme, locale string) {
	ctx := c.Request.Context()
	if themeChoices[theme] && theme != user.Theme {
		if err := s.store.SetUserTheme(ctx, user.ID, theme); err == nil {
			user.Theme = theme
		}
	}
	if localeChoices[locale] && locale != user.Locale {
		if err := s.store.UpdateUser(ctx, user.ID, user.Name, locale); err == nil {
			user.Locale = locale
		}
	}
}

// ---- second factor at login ----

// apiMFACheck tells whether the challenge `c` of the second factor still exists.
func (s *Server) apiMFACheck(c *gin.Context) {
	if ch, err := s.state.PeekChallenge(c.Request.Context(), c.Query("c")); err != nil || ch.Purpose != "" {
		s.apiError(c, http.StatusNotFound, "challenge_expired")
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) apiMFA(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		csrfBody
		C    string `json:"c"`
		Code string `json:"code"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	ch, err := s.state.Attempt(ctx, req.C, 5)
	if err == nil && ch.Purpose != "" { // a password change challenge is not a second factor
		err = state.ErrNotFound
	}
	if errors.Is(err, state.ErrNotFound) {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	if err != nil {
		s.apiFail(c, err)
		return
	}
	user, err := s.store.UserByID(ctx, ch.UserID)
	if err != nil || user.Disabled {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	if ok, err := s.state.Allow(ctx, "mfa:user:"+user.ID, 15, 10*time.Minute); err != nil {
		s.apiFail(c, err)
		return
	} else if !ok {
		s.apiError(c, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if _, err := s.acct.VerifySecondFactor(ctx, user, req.Code); err != nil {
		if errors.Is(err, account.ErrInvalidCode) {
			s.apiError(c, http.StatusUnauthorized, "invalid_mfa_code")
			return
		}
		s.apiFail(c, err)
		return
	}
	_ = s.state.DeleteChallenge(ctx, req.C)

	if ch.SessionID == "" { // login: the session is created now, after both factors
		if err := s.startSession(c, user.ID, []string{"pwd", "otp"}); err != nil {
			s.apiFail(c, err)
			return
		}
		next(c, safeReturn(ch.ReturnTo))
		return
	}
	// step-up of the current session
	if err := s.upgradeSession(c); err != nil {
		s.apiFail(c, err)
		return
	}
	next(c, safeReturn(ch.ReturnTo))
}

// ---- forced password change at login ----

// apiPasswordChangeCheck tells whether the password change challenge `c` (created by apiLogin) still exists.
func (s *Server) apiPasswordChangeCheck(c *gin.Context) {
	if ch, err := s.state.PeekChallenge(c.Request.Context(), c.Query("c")); err != nil || ch.Purpose != state.PurposePassword {
		s.apiError(c, http.StatusNotFound, "challenge_expired")
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// apiPasswordChange asks for a new password after a correct login with a password somebody else set (the
// setup Job). The challenge is created by apiLogin; no session exists yet.
func (s *Server) apiPasswordChange(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		csrfBody
		C         string `json:"c"`
		Password  string `json:"password"`
		Password2 string `json:"password2"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	ch, err := s.state.Attempt(ctx, req.C, 10)
	if err == nil && ch.Purpose != state.PurposePassword {
		err = state.ErrNotFound
	}
	if errors.Is(err, state.ErrNotFound) {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	if err != nil {
		s.apiFail(c, err)
		return
	}
	user, err := s.store.UserByID(ctx, ch.UserID)
	if err != nil || user.Disabled || !user.MustChangePassword {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	if req.Password != req.Password2 {
		s.apiError(c, http.StatusUnprocessableEntity, "password_mismatch")
		return
	}
	if err := s.acct.SetPassword(ctx, user, req.Password, true); err != nil {
		if code, ok := passwordCode(err); ok {
			s.apiError(c, http.StatusUnprocessableEntity, code)
			return
		}
		s.apiFail(c, err)
		return
	}
	_ = s.state.DeleteChallenge(ctx, req.C)
	user, err = s.store.UserByID(ctx, user.ID) // the flag is cleared; the next steps use the stored user
	if err != nil {
		s.apiFail(c, err)
		return
	}
	to, err := s.continueLogin(c, user, safeReturn(ch.ReturnTo))
	if err != nil {
		s.apiFail(c, err)
		return
	}
	next(c, to)
}

// ---- password reset ----

// apiForgot answers the same way whether or not the address is registered.
func (s *Server) apiForgot(c *gin.Context) {
	var req struct {
		csrfBody
		Email string `json:"email"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	if err := s.acct.RequestReset(c.Request.Context(), req.Email, c.ClientIP()); err != nil {
		s.apiFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// resetErr answers the errors of a reset token: an invalid or expired one is a 400, anything else a 500.
func (s *Server) resetErr(c *gin.Context, err error) {
	if errors.Is(err, account.ErrInvalidResetToken) || errors.Is(err, store.ErrNotFound) {
		s.apiError(c, http.StatusBadRequest, "invalid_link")
		return
	}
	s.apiFail(c, err)
}

func (s *Server) apiResetCheck(c *gin.Context) {
	if _, err := s.acct.ResetTokenUser(c.Request.Context(), c.Query("token")); err != nil {
		s.resetErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) apiReset(c *gin.Context) {
	var req struct {
		csrfBody
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	if err := s.acct.CompleteReset(c.Request.Context(), req.Token, req.Password); err != nil {
		if code, ok := passwordCode(err); ok {
			s.apiError(c, http.StatusUnprocessableEntity, code)
			return
		}
		s.resetErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// ---- account MFA ----

// mfaSession returns the signed in user, or answers: 404 when MFA is off for the whole service, 401 without a
// session.
func (s *Server) mfaSession(c *gin.Context) (*store.User, bool) {
	if s.cfg.MFAMode == appconfig.MFAOff {
		s.apiError(c, http.StatusNotFound, "not_found")
		return nil, false
	}
	_, user, _ := s.sessionFrom(c)
	if user == nil {
		s.apiError(c, http.StatusUnauthorized, "unauthenticated")
		return nil, false
	}
	return user, true
}

// apiAccountMFA shows the enrollment of a user without MFA, or the status of one with MFA.
func (s *Server) apiAccountMFA(c *gin.Context) {
	user, ok := s.mfaSession(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	if user.MFAEnabled {
		left, err := s.store.RecoveryCodesLeft(ctx, user.ID)
		if err != nil {
			s.apiFail(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"enabled": true, "codesLeft": left, "forced": s.acct.MFAForced(user)})
		return
	}
	enr, err := s.acct.BeginEnrollment(ctx, user)
	if err != nil {
		s.apiFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": false, "qr": enr.QRData, "secret": enr.Secret})
}

func (s *Server) apiAccountMFAConfirm(c *gin.Context) {
	user, ok := s.mfaSession(c)
	if !ok {
		return
	}
	var req struct {
		csrfBody
		Code     string `json:"code"`
		ReturnTo string `json:"return_to"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	codes, err := s.acct.ConfirmEnrollment(c.Request.Context(), user, req.Code)
	switch {
	case errors.Is(err, account.ErrInvalidCode):
		s.apiError(c, http.StatusUnauthorized, "invalid_code")
	case errors.Is(err, account.ErrRateLimited):
		s.apiError(c, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, account.ErrMFAEnabled):
		s.apiError(c, http.StatusConflict, "mfa_enabled")
	case err != nil:
		s.apiFail(c, err)
	default:
		// the user just proved they hold the device: this session now counts as multi-factor
		if err := s.upgradeSession(c); err != nil {
			s.apiFail(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"recoveryCodes": codes, "redirect": safeReturn(req.ReturnTo)})
	}
}

func (s *Server) apiAccountMFADisable(c *gin.Context) {
	user, ok := s.mfaSession(c)
	if !ok {
		return
	}
	var req struct {
		csrfBody
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	err := s.acct.DisableMFA(c.Request.Context(), user, req.Password, req.Code)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{})
	case errors.Is(err, account.ErrMFAForced):
		s.apiError(c, http.StatusForbidden, "mfa_forced")
	case errors.Is(err, account.ErrInvalidCredentials), errors.Is(err, account.ErrInvalidCode):
		s.apiError(c, http.StatusUnauthorized, "invalid_password_or_code")
	case errors.Is(err, account.ErrRateLimited):
		s.apiError(c, http.StatusTooManyRequests, "rate_limited")
	default:
		s.apiFail(c, err)
	}
}

// ---- sign out (the confirmation page) ----

func (s *Server) apiLogout(c *gin.Context) {
	var req struct {
		csrfBody
		PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
		State                 string `json:"state"`
		ClientID              string `json:"client_id"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	var client *store.Client
	if req.ClientID != "" {
		client, _ = s.store.ClientByID(c.Request.Context(), req.ClientID)
	}
	// the address is honoured only when it is registered for the client
	target := logoutTarget(client, req.PostLogoutRedirectURI)
	if err := s.signOut(c); err != nil {
		s.apiFail(c, err)
		return
	}
	if target != "" {
		next(c, withState(target, req.State))
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}
