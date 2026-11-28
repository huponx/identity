package notify

import (
	"context"
	"testing"

	courierv1 "github.com/huponx/protogen/go/courier/v1"
	"google.golang.org/grpc"
)

type recorder struct {
	courierv1.CourierServiceClient
	got []*courierv1.NotifyRequest
}

func (r *recorder) Notify(_ context.Context, in *courierv1.NotifyRequest, _ ...grpc.CallOption) (*courierv1.NotifyResponse, error) {
	r.got = append(r.got, in)
	return &courierv1.NotifyResponse{}, nil
}

func TestRegistrationPendingIsOneEventForAllAdmins(t *testing.T) {
	rec := &recorder{}
	c := NewCourier(rec)
	admins := []User{{ID: "a1", Email: "a@x.co", Locale: "vi"}, {ID: "a2", Email: "b@x.co"}}
	if err := c.RegistrationPending(context.Background(), admins, User{ID: "u-1", Name: "An", Email: "an@x.co"}, "https://admin.example.com/", "ev1"); err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("%d events", len(rec.got))
	}
	m := rec.got[0]
	if m.EventType != "account.registration_pending" || len(m.UserIds) != 2 || m.UserIds[0] != "a1" || len(m.Recipients) != 0 {
		t.Fatalf("request: %v", m)
	}
	f := m.Data.AsMap()
	if f["link"] != "https://admin.example.com/users/u-1" || f["applicant_email"] != "an@x.co" {
		t.Errorf("data: %v", f)
	}
	rec.got = nil
	_ = c.RegistrationPending(context.Background(), admins[:1], User{ID: "u-1"}, "", "ev2")
	if _, ok := rec.got[0].Data.AsMap()["link"]; ok {
		t.Error("a link without an admin URL")
	}
}

func TestUserEventsGoByUserID(t *testing.T) {
	rec := &recorder{}
	c := NewCourier(rec)
	c.Brand = "MM"
	if err := c.MFAChanged(context.Background(), User{ID: "u1", Email: "a@x.co", Name: "An", Locale: "vi"}, "enabled", "e1"); err != nil {
		t.Fatal(err)
	}
	m := rec.got[0]
	if m.EventType != "security.mfa_changed" || len(m.UserIds) != 1 || m.UserIds[0] != "u1" || len(m.Recipients) != 0 {
		t.Fatalf("request: %v", m)
	}
	f := m.Data.AsMap()
	if f["change"] != "enabled" || f["brand"] != "MM" {
		t.Errorf("data: %v", f)
	}
	if _, ok := f["name"]; ok {
		t.Error("the name comes from identity through courier, not from the caller")
	}
}

func TestRejectedApplicantGoesByAddress(t *testing.T) {
	rec := &recorder{}
	c := NewCourier(rec)
	if err := c.RegistrationRejected(context.Background(), User{ID: "gone", Email: "an@x.co", Name: "An", Locale: "vi"}, "e1"); err != nil {
		t.Fatal(err)
	}
	m := rec.got[0]
	if len(m.UserIds) != 0 || len(m.Recipients) != 1 || m.Recipients[0].Address != "an@x.co" || m.LocaleOverride != "vi" {
		t.Fatalf("request: %v", m)
	}
	if m.Data.AsMap()["name"] != "An" {
		t.Errorf("data: %v", m.Data.AsMap())
	}
}
