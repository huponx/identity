// Package notify sends the e-mails of identity through courier.
package notify

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/huponx/gocommon/notifyclient"
	"github.com/huponx/identity/internal/appconfig"
	courierv1 "github.com/huponx/protogen/go/courier/v1"
	"go.uber.org/zap"
)

// User is who gets the e-mail.
type User struct {
	ID, Email, Name, Locale string
}

// Notifier sends the account e-mails. Implementations must not block the request for long.
type Notifier interface {
	PasswordReset(ctx context.Context, u User, link string, expiresIn time.Duration, resetID string) error
	PasswordChanged(ctx context.Context, u User, eventID string) error
	// Welcome tells a new user to set the first password with link, valid for expiresIn.
	Welcome(ctx context.Context, u User, link string, expiresIn time.Duration, tokenID string) error
	// MFAChanged tells the user that MFA was turned on, off, enforced or reset; change is one of
	// "enabled", "disabled", "enforced", "reset", "recovery_regenerated".
	MFAChanged(ctx context.Context, u User, change, eventID string) error
	// RegistrationReceived tells an applicant that an administrator will review the request.
	RegistrationReceived(ctx context.Context, u User, eventID string) error
	// RegistrationRejected tells an applicant that the request was rejected.
	RegistrationRejected(ctx context.Context, u User, eventID string) error
	// RegistrationPending tells each admin about a request awaiting approval; adminURL (optional, the admin app) becomes a link to the applicant's user page.
	RegistrationPending(ctx context.Context, admins []User, applicant User, adminURL, eventID string) error
}

// Courier sends through the courier gRPC API (gocommon/notifyclient).
type Courier struct {
	client *notifyclient.Client
	// LogoURL is the picture at the top of every HTML mail (a PNG on a public address: mail clients do not draw SVG);
	// empty: the template draws a letter.
	LogoURL string
	// Brand is the name at the top of every mail (IDENTITY_MFA_ISSUER_NAME, the label of the authenticator apps).
	Brand string
}

// NewCourier wraps a courier client.
func NewCourier(c courierv1.CourierServiceClient) *Courier {
	return &Courier{client: notifyclient.New(c)}
}

func (c *Courier) base(data map[string]string) map[string]string {
	if data == nil {
		data = map[string]string{}
	}
	if c.Brand != "" {
		data["brand"] = c.Brand
	}
	if c.LogoURL != "" {
		data["logo_url"] = c.LogoURL
	}
	return data
}

func (c *Courier) notify(ctx context.Context, eventType, key string, ids []string, raw []notifyclient.Recipient, locale string, data map[string]string) error {
	_, err := c.client.Notify(ctx, notifyclient.Request{
		EventType: eventType, IdempotencyKey: key, UserIDs: ids, Recipients: raw, Locale: locale, Data: data,
	})
	return err
}

// send notifies one user by id: courier looks up the address, the name and the language in identity. A user without an id
// (never the case for a stored user) is sent to by address.
func (c *Courier) send(ctx context.Context, u User, eventType, key string, data map[string]string) error {
	if u.ID == "" {
		return c.sendRaw(ctx, u, eventType, key, data)
	}
	return c.notify(ctx, eventType, key, []string{u.ID}, nil, "", c.base(data))
}

// sendRaw sends to the address of u, for a user that identity no longer knows (a rejected applicant is deleted).
// The name travels in the data because courier cannot look it up.
func (c *Courier) sendRaw(ctx context.Context, u User, eventType, key string, data map[string]string) error {
	data = c.base(data)
	data["name"] = u.Name
	return c.notify(ctx, eventType, key, nil,
		[]notifyclient.Recipient{{Channel: courierv1.Channel_CHANNEL_EMAIL, Address: u.Email}}, u.Locale, data)
}

// PasswordReset implements Notifier.
func (c *Courier) PasswordReset(ctx context.Context, u User, link string, expiresIn time.Duration, resetID string) error {
	return c.send(ctx, u, "security.password_reset", "identity-password-reset-"+resetID, map[string]string{
		"link": link, "expires_in": fmt.Sprintf("%d", int(expiresIn.Minutes())),
	})
}

// Welcome implements Notifier. expires_in is in days.
func (c *Courier) Welcome(ctx context.Context, u User, link string, expiresIn time.Duration, tokenID string) error {
	return c.send(ctx, u, "account.welcome", "identity-welcome-"+tokenID, map[string]string{
		"link": link, "expires_in": fmt.Sprintf("%d", int(expiresIn.Hours()/24)),
	})
}

// PasswordChanged implements Notifier.
func (c *Courier) PasswordChanged(ctx context.Context, u User, eventID string) error {
	return c.send(ctx, u, "security.password_changed", "identity-password-changed-"+eventID, nil)
}

// MFAChanged implements Notifier.
func (c *Courier) MFAChanged(ctx context.Context, u User, change, eventID string) error {
	return c.send(ctx, u, "security.mfa_changed", "identity-mfa-"+change+"-"+eventID, map[string]string{"change": change})
}

// RegistrationReceived implements Notifier.
func (c *Courier) RegistrationReceived(ctx context.Context, u User, eventID string) error {
	return c.send(ctx, u, "account.registration_received", "identity-registration-received-"+eventID, nil)
}

// RegistrationRejected implements Notifier. The applicant is deleted before the mail, so it goes by address.
func (c *Courier) RegistrationRejected(ctx context.Context, u User, eventID string) error {
	return c.sendRaw(ctx, u, "account.registration_rejected", "identity-registration-rejected-"+eventID, nil)
}

// RegistrationPending implements Notifier: one event for all admins; courier resolves each admin and sends in
// the admin's language.
func (c *Courier) RegistrationPending(ctx context.Context, admins []User, applicant User, adminURL, eventID string) error {
	if len(admins) == 0 {
		return nil
	}
	data := map[string]string{"applicant_name": applicant.Name, "applicant_email": applicant.Email}
	if adminURL != "" { // straight to the user's page, where Approve and Reject are
		data["link"] = strings.TrimRight(adminURL, "/") + "/users/" + url.PathEscape(applicant.ID)
	}
	ids := make([]string, 0, len(admins))
	for _, a := range admins {
		ids = append(ids, a.ID)
	}
	return c.notify(ctx, "account.registration_pending", "identity-registration-pending-"+eventID, ids, nil, "", c.base(data))
}

// Log writes the mail to the log instead of sending it. It is for ENV=local only, because the
// password reset link is a credential.
type Log struct{ Logger *zap.Logger }

// PasswordReset implements Notifier.
func (l Log) PasswordReset(_ context.Context, u User, link string, _ time.Duration, _ string) error {
	l.Logger.Info("password reset mail (local, not sent)", zap.String("to", u.Email), zap.String("link", link))
	return nil
}

// Welcome implements Notifier.
func (l Log) Welcome(_ context.Context, u User, link string, _ time.Duration, _ string) error {
	l.Logger.Info("welcome mail (local, not sent)", zap.String("to", u.Email), zap.String("link", link))
	return nil
}

// PasswordChanged implements Notifier.
func (l Log) PasswordChanged(_ context.Context, u User, _ string) error {
	l.Logger.Info("password changed mail (local, not sent)", zap.String("to", u.Email))
	return nil
}

// MFAChanged implements Notifier.
func (l Log) MFAChanged(_ context.Context, u User, change, _ string) error {
	l.Logger.Info("mfa changed mail (local, not sent)", zap.String("to", u.Email), zap.String("change", change))
	return nil
}

// RegistrationReceived implements Notifier.
func (l Log) RegistrationReceived(_ context.Context, u User, _ string) error {
	l.Logger.Info("registration received mail (local, not sent)", zap.String("to", u.Email))
	return nil
}

// RegistrationRejected implements Notifier.
func (l Log) RegistrationRejected(_ context.Context, u User, _ string) error {
	l.Logger.Info("registration rejected mail (local, not sent)", zap.String("to", u.Email))
	return nil
}

// RegistrationPending implements Notifier.
func (l Log) RegistrationPending(_ context.Context, admins []User, applicant User, _, _ string) error {
	for _, a := range admins {
		l.Logger.Info("registration pending mail (local, not sent)", zap.String("to", a.Email), zap.String("applicant", applicant.Email))
	}
	return nil
}

// None drops every mail (courier not configured outside local).
type None struct{ Logger *zap.Logger }

// PasswordReset implements Notifier.
func (n None) PasswordReset(_ context.Context, _ User, _ string, _ time.Duration, _ string) error {
	n.Logger.Warn("courier is not configured: password reset mail dropped")
	return nil
}

// Welcome implements Notifier.
func (n None) Welcome(_ context.Context, _ User, _ string, _ time.Duration, _ string) error {
	n.Logger.Warn("courier is not configured: welcome mail dropped")
	return nil
}

// PasswordChanged implements Notifier.
func (n None) PasswordChanged(_ context.Context, _ User, _ string) error { return nil }

// MFAChanged implements Notifier.
func (n None) MFAChanged(_ context.Context, _ User, _, _ string) error { return nil }

// RegistrationReceived implements Notifier.
func (n None) RegistrationReceived(_ context.Context, _ User, _ string) error { return nil }

// RegistrationRejected implements Notifier.
func (n None) RegistrationRejected(_ context.Context, _ User, _ string) error { return nil }

// RegistrationPending implements Notifier.
func (n None) RegistrationPending(_ context.Context, _ []User, _ User, _, _ string) error {
	n.Logger.Warn("courier is not configured: registration pending mail dropped")
	return nil
}

// Build picks the notifier of the configuration: courier when COURIER_TARGET is set, the log
// for a local run without courier, nothing otherwise.
func Build(ctx context.Context, cfg appconfig.Identity, log *zap.Logger) Notifier {
	if cfg.CourierTarget == "" {
		if cfg.IsLocal() {
			return Log{Logger: log}
		}
		return None{Logger: log}
	}
	client, _, err := notifyclient.Dial(ctx, notifyclient.DialConfig{
		Target: cfg.CourierTarget, TokenFile: cfg.CourierTokenFile, Logger: log, Secure: !cfg.CourierInsecure, TLS: cfg.ClientTLS(),
	})
	if err != nil {
		log.Fatal("courier", zap.Error(err))
	}
	cc := &Courier{client: client}
	cc.Brand = cfg.MFAIssuerName
	cc.LogoURL = strings.TrimRight(cfg.Issuer, "/") + "/logo-mail.png"
	return cc
}
