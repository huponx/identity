package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// newTestServer builds a Server without a database or Redis: enough for the pages and the steps that stop
// before the first lookup (CSRF, body checks).
func newTestServer(t *testing.T, uiDir string, require bool) (*gin.Engine, error) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := New(Config{Issuer: "https://id.example", UIDir: uiDir, RequireUI: require}, nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	return r, s.Routes(r)
}

func installUI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<!doctype html><title>app</title>", "assets/app-1.js": "console.log(1)", "logo.svg": "<svg/>"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func do(r http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestPagesServeTheApp(t *testing.T) {
	r, err := newTestServer(t, installUI(t), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/login", "/login/mfa", "/login/password", "/password/forgot", "/password/reset", "/account/mfa", "/apps", "/logout", "/error"} {
		w := do(r, "GET", p, "", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "<title>app</title>") {
			t.Errorf("%s: %d %q", p, w.Code, w.Body.String())
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: csp %q", p, csp)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: cache %q", p, w.Header().Get("Cache-Control"))
		}
	}
	if w := do(r, "GET", "/", "", nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("/: %d %q", w.Code, w.Header().Get("Location"))
	}
	w := do(r, "GET", "/assets/app-1.js", "", nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	if w := do(r, "GET", "/assets/", "", nil); w.Code == 200 {
		t.Error("the assets directory is listed")
	}
	if w := do(r, "GET", "/logo.svg", "", nil); w.Code != 200 {
		t.Errorf("logo: %d", w.Code)
	}
}

func TestPagesMissingApp(t *testing.T) {
	if _, err := newTestServer(t, t.TempDir(), true); err == nil {
		t.Error("the server started without the app although it is required")
	}
	r, err := newTestServer(t, t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if w := do(r, "GET", "/login", "", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("login without app: %d", w.Code)
	}
}

func TestAuthAPICSRF(t *testing.T) {
	r, err := newTestServer(t, installUI(t), true)
	if err != nil {
		t.Fatal(err)
	}
	w := do(r, "GET", "/auth-api/csrf", "", nil)
	var out struct{ CSRF string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.CSRF) < 32 {
		t.Fatalf("csrf: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	jsonHdr := func(origin string) map[string]string {
		return map[string]string{"Content-Type": "application/json", "Origin": origin, "Cookie": cookie.Name + "=" + cookie.Value}
	}

	code := func(w *httptest.ResponseRecorder) string {
		var e struct{ Code string }
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		return e.Code
	}
	// every POST step refuses a request without a matching token, before any lookup
	for _, p := range []string{"/auth-api/login", "/auth-api/login/mfa", "/auth-api/login/password", "/auth-api/password/forgot",
		"/auth-api/password/reset", "/auth-api/logout", "/auth-api/preferences"} {
		if w := do(r, "POST", p, `{"csrf":"wrong"}`, jsonHdr("https://id.example")); w.Code != 403 || code(w) != "csrf_expired" {
			t.Errorf("%s with a wrong token: %d %s", p, w.Code, w.Body.String())
		}
		if w := do(r, "POST", p, `{"csrf":"`+out.CSRF+`"}`, jsonHdr("https://evil.example")); w.Code != 403 {
			t.Errorf("%s from another origin: %d", p, w.Code)
		}
		if w := do(r, "POST", p, `not json`, jsonHdr("https://id.example")); w.Code != 400 || code(w) != "bad_request" {
			t.Errorf("%s with a bad body: %d %s", p, w.Code, w.Body.String())
		}
		if w := do(r, "POST", p, `{"csrf":"`+out.CSRF+`"}`, nil); w.Code != 403 {
			t.Errorf("%s without the cookie: %d", p, w.Code)
		}
	}
	// the account steps need a session first
	for _, p := range []string{"/auth-api/account/mfa", "/auth-api/account/mfa/disable", "/auth-api/preferences"} {
		if w := do(r, "POST", p, `{"csrf":"`+out.CSRF+`"}`, jsonHdr("https://id.example")); w.Code != 401 || code(w) != "unauthenticated" {
			t.Errorf("%s without a session: %d %s", p, w.Code, w.Body.String())
		}
	}
	if w := do(r, "GET", "/auth-api/apps", "", nil); w.Code != 401 {
		t.Errorf("GET apps without a session: %d", w.Code)
	}
	if w := do(r, "GET", "/auth-api/account/mfa", "", nil); w.Code != 401 {
		t.Errorf("GET account/mfa without a session: %d", w.Code)
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"":                               "/apps",
		"/oauth2/authorize?client_id=x":  "/oauth2/authorize?client_id=x",
		"/account/mfa?return_to=%2Fapps": "/account/mfa?return_to=%2Fapps",
		"/apps":                          "/apps",
		"//evil.example/apps":            "/apps",
		"https://evil.example/":          "/apps",
		"/apps\\evil":                    "/apps",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}
