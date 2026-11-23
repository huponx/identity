// Package oauth is the HTTP side of identity: OpenID Connect discovery and JWKS, authorize,
// token, revoke, introspect, userinfo and logout, plus the sign in pages: a React app (built by the web
// repository, found in Config.UIDir) served for the page paths, and the JSON endpoints it calls under
// /auth-api (login, second factor, password reset, account MFA, sign out).
package oauth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
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
	SecureCookies   bool
	SessionIdle     time.Duration
	SessionAbsolute time.Duration
	MFAMode         string
	// Apps are listed on /apps (IDENTITY_APPS).
	Apps               []appconfig.AppLink
	TrustedProxies     []string
	AccessTokenDefault time.Duration
	RefreshTokenTTL    time.Duration
	// UIDir holds the built sign in app (index.html, assets/). Without it the pages answer 503.
	UIDir string
	// RequireUI makes Routes fail when UIDir has no index.html (outside local runs: a service without
	// its sign in pages must not start).
	RequireUI bool
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
	// index is index.html of the sign in app (nil when it is not installed)
	index []byte
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
	r.Use(securityHeaders(appconfig.IconOrigins(s.cfg.Apps)), limitBody(64<<10))

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

	s.authAPI(r)
	return s.pages(r)
}

// pages serves the sign in app: its index.html for every page path (the app routes itself) and its files.
func (s *Server) pages(r *gin.Engine) error {
	if s.cfg.UIDir != "" {
		if b, err := os.ReadFile(filepath.Join(s.cfg.UIDir, "index.html")); err == nil {
			s.index = b
		}
	}
	if s.index == nil {
		if s.cfg.RequireUI {
			return fmt.Errorf("the sign in pages are missing: no index.html in IDENTITY_UI_DIR %q", s.cfg.UIDir)
		}
		s.log.Warn("the sign in pages are not installed (IDENTITY_UI_DIR has no index.html): the page paths answer 503", zap.String("dir", s.cfg.UIDir))
	}
	// the bare address: the applications for a signed in user, the sign in page for the others
	r.GET("/", func(c *gin.Context) {
		if _, user, _ := s.sessionFrom(c); user != nil {
			c.Redirect(http.StatusFound, "/apps")
			return
		}
		c.Redirect(http.StatusFound, "/login")
	})
	// the page paths of the app; e-mailed links and return_to values use them
	for _, p := range []string{"/login", "/login/mfa", "/login/password", "/password/forgot", "/password/reset", "/account/mfa", "/apps", "/logout", "/error"} {
		r.GET(p, s.spa)
	}
	if s.index != nil {
		// Vite names the files after their content: cache for ever
		assets := r.Group("/assets", func(c *gin.Context) {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
			c.Next()
		})
		assets.StaticFS("/", gin.Dir(filepath.Join(s.cfg.UIDir, "assets"), false)) // no directory listing
		for _, f := range []string{"logo.svg", "theme-init.js"} {
			path := filepath.Join(s.cfg.UIDir, f)
			r.GET("/"+f, func(c *gin.Context) { c.File(path) })
		}
	}
	return nil
}

func (s *Server) spa(c *gin.Context) {
	if s.index == nil {
		c.String(http.StatusServiceUnavailable, "The sign in pages are not available.")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", s.index)
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

// csrfToken returns the token of this browser, creating the cookie on the first visit.
func (s *Server) csrfToken(c *gin.Context) string {
	if v := s.cookie(c, "csrf"); len(v) >= 32 {
		return v
	}
	v := password.Random(32)
	s.setCookie(c, "csrf", v, 0)
	return v
}

// csrfOK checks a state changing request: the token of the request body equals the cookie, and when the
// browser sends an Origin it is ours.
func (s *Server) csrfOK(c *gin.Context, token string) bool {
	cookie := s.cookie(c, "csrf")
	if len(cookie) < 32 || subtle.ConstantTimeCompare([]byte(cookie), []byte(token)) != 1 {
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

func securityHeaders(iconOrigins []string) gin.HandlerFunc {
	img := strings.Join(append([]string{"'self'", "data:"}, iconOrigins...), " ")
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff") // existing standard header, not a new x- name
		// the sign in app is script and style files of this origin (no inline code), its API is this origin, the
		// QR code of the MFA enrollment is a data: image, the icons of the applications come from their origins
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src "+img+"; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		c.Next()
	}
}

func limitBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

// ---- errors of the browser endpoints ----

// errorPage sends the browser to the error page of the sign in app. Only a fixed code travels in the URL
// (unknown_client, bad_redirect, bad_request, not_found, internal): the app has the texts, so nothing that
// came from the request is ever shown.
func (s *Server) errorPage(c *gin.Context, code string) {
	c.Redirect(http.StatusFound, "/error?e="+url.QueryEscape(code))
}

// safeReturn only accepts local paths we send people to, so return_to is never an open redirect.
func safeReturn(rt string) string {
	for _, p := range []string{"/oauth2/authorize?", "/account/mfa", "/apps"} {
		if strings.HasPrefix(rt, p) && !strings.ContainsAny(rt, "\\\r\n") && !strings.HasPrefix(rt, "//") {
			return rt
		}
	}
	return "/apps" // nobody sent the user here: the list of applications
}
