// Package oauth is the HTTP side of identity: OpenID Connect discovery and JWKS, authorize,
// login (password and second factor), token, revoke, introspect, userinfo, logout, password
// reset and the account MFA page.
package oauth

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/keys"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	"go.uber.org/zap"
)

// Config is the HTTP configuration.
type Config struct {
	Issuer string
	// SecureCookies sets the Secure attribute and the __Host- prefix (always, except local http).
	SecureCookies      bool
	SessionIdle        time.Duration
	SessionAbsolute    time.Duration
	MFAMode            string
	TrustedProxies     []string
	AccessTokenDefault time.Duration
	RefreshTokenTTL    time.Duration
}

// Server serves the endpoints.
type Server struct {
	cfg    Config
	acct   *account.Service
	store  *store.Store
	state  *state.State
	tokens *token.Service
	keys   *keys.Set
	log    *zap.Logger
	now    func() time.Time
}

// New builds the server.
func New(cfg Config, acct *account.Service, st *store.Store, sta *state.State, tk *token.Service, k *keys.Set, log *zap.Logger) *Server {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	return &Server{cfg: cfg, acct: acct, store: st, state: sta, tokens: tk, keys: k, log: log, now: time.Now}
}

// SetClock overrides the clock (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// Routes registers the endpoints on the router.
func (s *Server) Routes(r *gin.Engine) error {
	if err := r.SetTrustedProxies(s.cfg.TrustedProxies); err != nil {
		return err
	}
	r.Use(securityHeaders(), limitBody(64<<10))

	r.GET("/.well-known/openid-configuration", s.discovery)
	r.GET("/.well-known/jwks.json", s.jwks)

	r.GET("/oauth2/authorize", s.authorize)
	r.POST("/oauth2/token", s.tokenEndpoint)
	r.POST("/oauth2/revoke", s.revoke)
	r.POST("/oauth2/introspect", s.introspect)
	r.GET("/oauth2/logout", s.endSession)
	r.POST("/oauth2/logout", s.endSession)
	r.GET("/userinfo", s.userinfo)
	r.POST("/userinfo", s.userinfo)

	r.GET("/login", s.loginForm)
	r.POST("/login", s.loginSubmit)
	r.GET("/login/mfa", s.mfaForm)
	r.POST("/login/mfa", s.mfaSubmit)

	r.GET("/password/forgot", s.forgotForm)
	r.POST("/password/forgot", s.forgotSubmit)
	r.GET("/password/reset", s.resetForm)
	r.POST("/password/reset", s.resetSubmit)

	r.GET("/account/mfa", s.accountMFA)
	r.POST("/account/mfa", s.accountMFAConfirm)
	r.POST("/account/mfa/disable", s.accountMFADisable)
	return nil
}

// ---- cookies ----

func (s *Server) cookieName(base string) string {
	if s.cfg.SecureCookies {
		return "__Host-" + base
	}
	return base
}

func (s *Server) setCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: s.cookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		Secure: s.cfg.SecureCookies, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) cookie(c *gin.Context, name string) string {
	v, err := c.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return v
}

// ---- CSRF (double submit cookie plus Origin check) ----

const csrfField = "csrf"

// csrfToken returns the token of this browser, creating the cookie on the first visit.
func (s *Server) csrfToken(c *gin.Context) string {
	if v := s.cookie(c, "csrf"); len(v) >= 32 {
		return v
	}
	v := password.Random(32)
	s.setCookie(c, "csrf", v, 0)
	return v
}

// csrfOK checks a state changing request: the form token equals the cookie, and when the
// browser sends an Origin it is ours.
func (s *Server) csrfOK(c *gin.Context) bool {
	cookie := s.cookie(c, "csrf")
	form := c.PostForm(csrfField)
	if len(cookie) < 32 || subtle.ConstantTimeCompare([]byte(cookie), []byte(form)) != 1 {
		return false
	}
	if origin := c.GetHeader("Origin"); origin != "" && origin != "null" {
		return origin == s.origin()
	}
	return true
}

func (s *Server) origin() string {
	u, err := url.Parse(s.cfg.Issuer)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ---- middleware ----

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff") // existing standard header, not a new x- name
		// no form-action: browsers apply it to the redirects that follow a POST as well
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'")
		c.Next()
	}
}

func limitBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

// ---- rendering ----

type page struct {
	Title    string
	Message  string // error or notice
	Notice   bool   // Message is not an error
	CSRF     string
	ReturnTo string
	Fields   map[string]string
	Data     any
}

var tmpl = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><style>
body{font:16px/1.4 system-ui,sans-serif;background:#f4f5f7;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 4px #0002;width:min(24rem,92vw)}
h1{font-size:1.3rem;margin-top:0}label{display:block;margin:.8rem 0 .2rem}
input[type=text],input[type=password],input[type=email]{width:100%;padding:.55rem;box-sizing:border-box;border:1px solid #999;border-radius:4px}
button{margin-top:1rem;padding:.6rem 1rem;border:0;border-radius:4px;background:#1a56db;color:#fff;font-size:1rem;cursor:pointer}
.err{color:#b00020}.ok{color:#146c2e}code{word-break:break-all}a{color:#1a56db}ul{padding-left:1.2rem}
</style></head><body><main><h1>{{.Title}}</h1>{{if .Message}}<p class="{{if .Notice}}ok{{else}}err{{end}}" role="alert">{{.Message}}</p>{{end}}{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "login"}}{{template "head" .}}<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="return_to" value="{{.ReturnTo}}">
<label for="email">E-mail</label><input id="email" type="email" name="email" value="{{.Fields.email}}" autocomplete="username" required autofocus>
<label for="pw">Password</label><input id="pw" type="password" name="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form><p><a href="/password/forgot">Forgot your password?</a></p>{{template "foot"}}{{end}}

{{define "mfa"}}{{template "head" .}}<form method="post" action="/login/mfa">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="c" value="{{.Fields.c}}">
<label for="code">Code from your authenticator app, or a recovery code</label>
<input id="code" type="text" name="code" inputmode="text" autocomplete="one-time-code" required autofocus>
<button type="submit">Verify</button></form>{{template "foot"}}{{end}}

{{define "forgot"}}{{template "head" .}}{{if not .Notice}}<form method="post" action="/password/forgot">
<input type="hidden" name="csrf" value="{{.CSRF}}"><label for="email">E-mail</label>
<input id="email" type="email" name="email" autocomplete="username" required autofocus><button type="submit">Send the link</button></form>{{end}}
<p><a href="/login">Back to sign in</a></p>{{template "foot"}}{{end}}

{{define "reset"}}{{template "head" .}}<form method="post" action="/password/reset">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="token" value="{{.Fields.token}}">
<label for="pw">New password (at least 12 characters)</label><input id="pw" type="password" name="password" autocomplete="new-password" minlength="12" required autofocus>
<button type="submit">Set the password</button></form>{{template "foot"}}{{end}}

{{define "message"}}{{template "head" .}}{{if .ReturnTo}}<p><a href="{{.ReturnTo}}">Continue</a></p>{{end}}{{template "foot"}}{{end}}

{{define "confirm-logout"}}{{template "head" .}}<form method="post" action="/oauth2/logout">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="post_logout_redirect_uri" value="{{.Fields.post_logout_redirect_uri}}">
<input type="hidden" name="state" value="{{.Fields.state}}"><input type="hidden" name="client_id" value="{{.Fields.client_id}}">
<button type="submit">Sign out</button></form>{{template "foot"}}{{end}}

{{define "mfa-enroll"}}{{template "head" .}}<p>Scan the code with an authenticator app, then enter the 6 digit code it shows.</p>
<p><img src="{{.Data.QRData}}" alt="QR code" width="224" height="224"></p><p>Or type this key: <code>{{.Data.Secret}}</code></p>
<form method="post" action="/account/mfa"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="return_to" value="{{.ReturnTo}}">
<label for="code">Code</label><input id="code" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>
<button type="submit">Turn on</button></form>{{template "foot"}}{{end}}

{{define "mfa-codes"}}{{template "head" .}}<p>Multi-factor authentication is on. Keep these recovery codes in a safe place: each works once, and they are not shown again.</p>
<ul>{{range .Data}}<li><code>{{.}}</code></li>{{end}}</ul><p><a href="{{.ReturnTo}}">Continue</a></p>{{template "foot"}}{{end}}

{{define "mfa-status"}}{{template "head" .}}<p>Multi-factor authentication is <strong>on</strong>. Recovery codes left: {{.Data.CodesLeft}}.</p>
{{if .Data.Forced}}<p>It is required for your account and cannot be turned off.</p>{{else}}
<form method="post" action="/account/mfa/disable"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="pw">Password</label><input id="pw" type="password" name="password" autocomplete="current-password" required>
<label for="code">Code or recovery code</label><input id="code" type="text" name="code" autocomplete="one-time-code" required>
<button type="submit">Turn off</button></form>{{end}}{{template "foot"}}{{end}}
`))

func (s *Server) render(c *gin.Context, status int, name string, p page) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	if err := tmpl.ExecuteTemplate(c.Writer, name, p); err != nil {
		logging.FromCtx(c.Request.Context()).Error("render", zap.String("template", name), zap.Error(err))
	}
}

func (s *Server) errorPage(c *gin.Context, status int, msg string) {
	s.render(c, status, "message", page{Title: "Something went wrong", Message: msg})
}

// safeReturn only accepts local paths we send people to, so return_to is never an open redirect.
func safeReturn(rt string) string {
	for _, p := range []string{"/oauth2/authorize?", "/account/mfa"} {
		if strings.HasPrefix(rt, p) && !strings.ContainsAny(rt, "\\\r\n") && !strings.HasPrefix(rt, "//") {
			return rt
		}
	}
	return "/account/mfa"
}
