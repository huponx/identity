// Package notify sends the e-mails of identity through courier.
package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/huponx/gocommon/grpcclient"
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
	// MFAChanged tells the user that MFA was turned on, off, enforced or reset; change is one of
	// "enabled", "disabled", "enforced", "reset".
	MFAChanged(ctx context.Context, u User, change, eventID string) error
}

// Courier sends through the courier gRPC API.
type Courier struct {
	client courierv1.CourierServiceClient
}

// NewCourier wraps a courier client.
func NewCourier(c courierv1.CourierServiceClient) *Courier { return &Courier{client: c} }

func (c *Courier) send(ctx context.Context, u User, template, key string, data map[string]string) error {
	data["name"] = u.Name
	_, err := c.client.SendNotification(ctx, &courierv1.SendNotificationRequest{
		IdempotencyKey: key,
		Locale:         u.Locale,
		TemplateId:     template,
		TemplateData:   data,
		Recipients:     []*courierv1.Recipient{{Channel: courierv1.Channel_CHANNEL_EMAIL, Address: u.Email}},
	})
	if err != nil {
		return fmt.Errorf("courier %s: %w", template, err)
	}
	return nil
}

// PasswordReset implements Notifier.
func (c *Courier) PasswordReset(ctx context.Context, u User, link string, expiresIn time.Duration, resetID string) error {
	return c.send(ctx, u, "identity_password_reset", "identity-password-reset-"+resetID, map[string]string{
		"link": link, "expires_in": fmt.Sprintf("%d", int(expiresIn.Minutes())),
	})
}

// PasswordChanged implements Notifier.
func (c *Courier) PasswordChanged(ctx context.Context, u User, eventID string) error {
	return c.send(ctx, u, "identity_password_changed", "identity-password-changed-"+eventID, map[string]string{})
}

// MFAChanged implements Notifier.
func (c *Courier) MFAChanged(ctx context.Context, u User, change, eventID string) error {
	return c.send(ctx, u, "identity_mfa_changed", "identity-mfa-"+change+"-"+eventID, map[string]string{"change": change})
}

// Log writes the mail to the log instead of sending it. It is for ENV=local only, because the
// password reset link is a credential.
type Log struct{ Logger *zap.Logger }

// PasswordReset implements Notifier.
func (l Log) PasswordReset(_ context.Context, u User, link string, _ time.Duration, _ string) error {
	l.Logger.Info("password reset mail (local, not sent)", zap.String("to", u.Email), zap.String("link", link))
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

// None drops every mail (courier not configured outside local).
type None struct{ Logger *zap.Logger }

// PasswordReset implements Notifier.
func (n None) PasswordReset(_ context.Context, _ User, _ string, _ time.Duration, _ string) error {
	n.Logger.Warn("courier is not configured: password reset mail dropped")
	return nil
}

// PasswordChanged implements Notifier.
func (n None) PasswordChanged(_ context.Context, _ User, _ string) error { return nil }

// MFAChanged implements Notifier.
func (n None) MFAChanged(_ context.Context, _ User, _, _ string) error { return nil }

// Build picks the notifier of the configuration: courier when COURIER_TARGET is set, the log
// for a local run without courier, nothing otherwise.
func Build(ctx context.Context, cfg appconfig.Identity, log *zap.Logger) Notifier {
	if cfg.CourierTarget == "" {
		if cfg.IsLocal() {
			return Log{Logger: log}
		}
		return None{Logger: log}
	}
	opts := []grpcclient.Option{grpcclient.WithLogger(log)}
	if cfg.CourierTokenFile != "" {
		opts = append(opts, grpcclient.WithBearerTokenFile(cfg.CourierTokenFile))
	} else if cfg.CourierToken != "" {
		opts = append(opts, grpcclient.WithBearerToken(cfg.CourierToken))
	}
	conn, err := grpcclient.Dial(ctx, cfg.CourierTarget, opts...)
	if err != nil {
		log.Fatal("courier", zap.Error(err))
	}
	return NewCourier(courierv1.NewCourierServiceClient(conn))
}
