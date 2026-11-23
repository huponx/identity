package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/huponx/identity/internal/store"
)

// ---- logout (OpenID Connect RP-Initiated Logout 1.0) ----

// endSession ends the SSO session of the browser. With a valid id_token_hint (proof that the
// application asked for it) it logs out at once; without one the browser goes to the confirmation page of the
// sign in app (/logout), which asks for a POST of its own (/auth-api/logout), so another site cannot sign
// people out with an image tag.
func (s *Server) endSession(c *gin.Context) {
	ctx := c.Request.Context()
	param := func(k string) string {
		if c.Request.Method == http.MethodPost {
			return c.PostForm(k)
		}
		return c.Query(k)
	}
	hint, redirect, stateParam := param("id_token_hint"), param("post_logout_redirect_uri"), param("state")

	var client *store.Client
	trusted := false
	if hint != "" {
		claims, err := s.tokens.VerifyIDHint(ctx, hint)
		if err != nil {
			s.errorPage(c, "bad_request")
			return
		}
		if cl, err := s.store.ClientByID(ctx, claims.Audience[0]); err == nil {
			client, trusted = cl, true
		}
	} else if id := param("client_id"); id != "" {
		client, _ = s.store.ClientByID(ctx, id)
	}
	target := logoutTarget(client, redirect)

	if !trusted {
		q := url.Values{}
		for k, v := range map[string]string{"post_logout_redirect_uri": target, "state": stateParam, "client_id": param("client_id")} {
			if v != "" {
				q.Set(k, v)
			}
		}
		to := "/logout"
		if len(q) > 0 {
			to += "?" + q.Encode()
		}
		c.Redirect(http.StatusSeeOther, to)
		return
	}

	if err := s.signOut(c); err != nil {
		s.fail(c, err)
		return
	}
	if target != "" {
		c.Redirect(http.StatusFound, withState(target, stateParam))
		return
	}
	c.Redirect(http.StatusFound, "/logout?done=1")
}

// logoutTarget is the address to go back to after the logout: only a registered post logout address of the client.
func logoutTarget(client *store.Client, redirect string) string {
	if client != nil && redirect != "" && contains(client.PostLogoutRedirectURIs, redirect) {
		return redirect
	}
	return ""
}

// withState adds the state of the request to the address.
func withState(target, state string) string {
	u, err := url.Parse(target)
	if err != nil || state == "" {
		return target
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// signOut ends the SSO session of the browser (if there is one) and clears its cookie.
func (s *Server) signOut(c *gin.Context) error {
	if sess, user, _ := s.sessionFrom(c); sess != nil {
		s.setPrefsCookie(c, user)
		if _, err := s.acct.EndSession(c.Request.Context(), sess.PublicID); err != nil {
			return err
		}
	}
	s.setCookie(c, "sid", "", -1)
	return nil
}

// setPrefsCookie leaves the theme and language of the account for the sign in pages of this browser: they
// run on their own origin and cannot read what the applications saved, so after a logout the login page
// would show whatever this origin kept last. The pages take the cookie over once (see theme-init.js and
// i18n) and delete it. Not HttpOnly on purpose: the page reads it; it holds no secret.
func (s *Server) setPrefsCookie(c *gin.Context, user *store.User) {
	if user == nil {
		return
	}
	lang := strings.SplitN(user.Locale, "-", 2)[0]
	theme := user.Theme
	if (theme == "" && lang == "") || strings.ContainsAny(theme+lang, " ;,\\\"") {
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name: "mm_prefs", Value: theme + "." + lang, Path: "/", MaxAge: 600,
		Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}
