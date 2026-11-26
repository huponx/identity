package service

import (
	"context"
	"errors"
	"testing"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/password"

	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/grpcserver"
	"github.com/huponx/gocommon/jwtx"
)

func TestMeID(t *testing.T) {
	cases := []struct {
		name string
		p    *authn.Principal
		want string
		ok   bool
	}{
		{"no token", nil, "", false},
		{"service token", &authn.Principal{Subject: "gk", ClientID: "gk"}, "", false},
		{"no subject", &authn.Principal{ClientID: "gk"}, "", false},
		{"user token", &authn.Principal{Subject: "u1", ClientID: "gk"}, "u1", true},
	}
	for _, c := range cases {
		ctx := context.Background()
		if c.p != nil {
			ctx = authn.WithPrincipal(ctx, c.p)
		}
		got, err := meID(ctx)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}

// The "me" methods need only a signed-in user; every other method of the user API needs a permission.
func TestMePermissionsArePublic(t *testing.T) {
	for _, m := range []string{"GetMe", "UpdateMe", "SetMyAvatar", "ChangeMyPassword", "GetMyMFA", "BeginMyMFA", "ConfirmMyMFA", "DisableMyMFA"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; got != grpcserver.Public {
			t.Errorf("%s: %q", m, got)
		}
	}
}

func TestIsCallerClient(t *testing.T) {
	s := &Service{}
	ctx := authn.WithPrincipal(context.Background(), &authn.Principal{ClientID: "web", Actor: &jwtx.Actor{Subject: "gk"}})
	if !s.isCallerClient(ctx, "web") || !s.isCallerClient(ctx, "gk") || s.isCallerClient(ctx, "other") {
		t.Fatal("the token client and the actors are the caller's clients")
	}
	if s.isCallerClient(context.Background(), "web") {
		t.Fatal("no principal, no caller client")
	}
}

// The errors of a password change reach the user with a reason the web apps translate.
func TestChangePasswordErrorReasons(t *testing.T) {
	cases := map[error]string{
		account.ErrInvalidCredentials: "wrong_current_password",
		account.ErrRateLimited:        "too_many_attempts",
		password.ErrTooShort:          "password_too_short",
		password.ErrSame:              "password_same",
		account.ErrInvalidCode:        "invalid_mfa_code",
		account.ErrMFAEnabled:         "mfa_already_enabled",
	}
	for in, want := range cases {
		var app *apperror.Error
		if !errors.As(toErr(in), &app) || app.Reason != want {
			t.Errorf("%v: got %+v, want reason %q", in, toErr(in), want)
		}
	}
}
