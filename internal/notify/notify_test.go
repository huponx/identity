package notify

import (
	"context"
	"testing"

	courierv1 "github.com/huponx/protogen/go/courier/v1"
	"google.golang.org/grpc"
)

type recorder struct {
	courierv1.CourierServiceClient
	got []*courierv1.SendNotificationRequest
}

func (r *recorder) SendNotification(_ context.Context, in *courierv1.SendNotificationRequest, _ ...grpc.CallOption) (*courierv1.SendNotificationResponse, error) {
	r.got = append(r.got, in)
	return &courierv1.SendNotificationResponse{}, nil
}

func TestRegistrationPendingLinksToTheApplicant(t *testing.T) {
	rec := &recorder{}
	c := NewCourier(rec)
	admins := []User{{ID: "a1", Email: "a@x.co", Locale: "vi"}, {ID: "a2", Email: "b@x.co"}}
	if err := c.RegistrationPending(context.Background(), admins, User{ID: "u-1", Name: "An", Email: "an@x.co"}, "https://admin.example.com/", "ev1"); err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 2 {
		t.Fatalf("%d mails", len(rec.got))
	}
	for _, m := range rec.got {
		if m.TemplateData["link"] != "https://admin.example.com/users/u-1" || m.TemplateData["applicant_email"] != "an@x.co" {
			t.Errorf("data: %v", m.TemplateData)
		}
	}
	if rec.got[0].IdempotencyKey == rec.got[1].IdempotencyKey {
		t.Error("one key for two admins")
	}
	rec.got = nil
	_ = c.RegistrationPending(context.Background(), admins[:1], User{ID: "u-1"}, "", "ev2")
	if _, ok := rec.got[0].TemplateData["link"]; ok {
		t.Error("a link without an admin URL")
	}
}
