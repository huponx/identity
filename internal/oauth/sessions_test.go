package oauth

import (
	"strings"
	"testing"

	"github.com/huponx/identity/internal/useragent"
)

const (
	uaChromeMac  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	uaFirefoxWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
)

func TestEverySignInRecordsItsDevice(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	a := newAuth(t)

	chrome := e.browser()
	chrome.ua, chrome.remote = uaChromeMac, "203.0.113.7:5000"
	chrome.passwordLogin(u, "")
	chrome.addPasskey(a, "k")

	firefox := e.browser()
	firefox.ua, firefox.remote = uaFirefoxWin, "198.51.100.9:6000"
	if r := firefox.passkeyLogin(a, ""); r.code != 200 {
		t.Fatalf("passkey login: %d %s", r.code, r.body)
	}

	list, err := e.sta.ListUserSessions(t.Context(), u.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("sessions: %+v %v", list, err)
	}
	byPID := map[string]string{chrome.session().PublicID: "chrome", firefox.session().PublicID: "firefox"}
	for _, s := range list {
		switch byPID[s.PublicID] {
		case "chrome":
			if s.IP != "203.0.113.7" || s.UserAgent != uaChromeMac || s.LastSeen.IsZero() {
				t.Errorf("password session: %+v", s)
			}
			if got := useragent.Parse(s.UserAgent); got.Browser != "Chrome" || got.OS != "macOS" {
				t.Errorf("parsed: %+v", got)
			}
		case "firefox":
			if s.IP != "198.51.100.9" || s.UserAgent != uaFirefoxWin || s.LastSeen.IsZero() {
				t.Errorf("passkey session: %+v", s)
			}
			if !hasAMR(s.AMR, "mfa") {
				t.Errorf("passkey amr: %v", s.AMR)
			}
		default:
			t.Errorf("unknown session %s", s.PublicID)
		}
	}
}

func TestAHugeUserAgentIsCut(t *testing.T) {
	e := newPKEnv(t, "optional", 1000)
	u := e.newUser()
	b := e.browser()
	b.ua = "Mozilla/5.0 " + strings.Repeat("x", 5000)
	b.passwordLogin(u, "")
	if got := len(b.session().UserAgent); got == 0 || got > 512 {
		t.Errorf("user agent length %d", got)
	}
}
