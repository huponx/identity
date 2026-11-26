package oauth

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func registerServer(t *testing.T, enabled bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := New(Config{Issuer: "https://id.example", UIDir: installUI(t), RequireUI: true, RegistrationEnabled: enabled, RegistrationRole: "member"},
		nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	if err := s.Routes(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterDisabledIs404(t *testing.T) {
	r := registerServer(t, false)
	if w := do(r, "POST", "/auth-api/register", `{}`, map[string]string{"Content-Type": "application/json", "Origin": "https://id.example"}); w.Code != http.StatusNotFound {
		t.Errorf("disabled: %d %s", w.Code, w.Body.String())
	}
	var out struct{ Registration bool }
	_ = json.Unmarshal(do(r, "GET", "/auth-api/ui-style", "", nil).Body.Bytes(), &out)
	if out.Registration {
		t.Error("ui-style says registration is on")
	}
}

func TestRegisterChecksBeforeAnyLookup(t *testing.T) {
	r := registerServer(t, true)
	var tok struct{ CSRF string }
	w := do(r, "GET", "/auth-api/csrf", "", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	cookie := w.Result().Cookies()[0]
	hdr := map[string]string{"Content-Type": "application/json", "Origin": "https://id.example", "Cookie": cookie.Name + "=" + cookie.Value}

	if w := do(r, "POST", "/auth-api/register", `{"csrf":"wrong","email":"a@b.co"}`, hdr); w.Code != 403 {
		t.Errorf("wrong csrf: %d", w.Code)
	}
	for _, email := range []string{"", "no-at", "a b@c.co", "Name <a@b.co>"} {
		body, _ := json.Marshal(map[string]string{"csrf": tok.CSRF, "email": email})
		if w := do(r, "POST", "/auth-api/register", string(body), hdr); w.Code != 400 {
			t.Errorf("email %q: %d %s", email, w.Code, w.Body.String())
		}
	}
	var out struct{ Registration bool }
	_ = json.Unmarshal(do(r, "GET", "/auth-api/ui-style", "", nil).Body.Bytes(), &out)
	if !out.Registration {
		t.Error("ui-style does not say registration is on")
	}
}
