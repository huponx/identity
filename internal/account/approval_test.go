package account

import (
	"context"
	"errors"
	"testing"

	"github.com/huponx/identity/internal/store"
)

// The checks come before any store access, so a Service without a store is enough.
func TestPendingApprovalUserGetsNoLink(t *testing.T) {
	s := &Service{}
	u := &store.User{ID: "u1", Email: "a@b.co", PendingApproval: true}
	if err := s.SendWelcome(context.Background(), u); !errors.Is(err, ErrAwaitingApproval) {
		t.Errorf("SendWelcome: %v", err)
	}
	if err := s.SendReset(context.Background(), u); !errors.Is(err, ErrAwaitingApproval) {
		t.Errorf("SendReset: %v", err)
	}
}

func TestApproveRejectNeedAPendingApprovalUser(t *testing.T) {
	s := &Service{}
	u := &store.User{ID: "u1", Email: "a@b.co"}
	if err := s.ApproveRegistration(context.Background(), u); !errors.Is(err, ErrNotAwaitingApproval) {
		t.Errorf("approve: %v", err)
	}
	if err := s.RejectRegistration(context.Background(), u); !errors.Is(err, ErrNotAwaitingApproval) {
		t.Errorf("reject: %v", err)
	}
}

// A user without MFA has no codes to replace: refused before any store access.
func TestRegenerateRecoveryCodesNeedsMFA(t *testing.T) {
	s := &Service{}
	u := &store.User{ID: "u1", Email: "a@b.co"}
	if _, err := s.RegenerateRecoveryCodes(context.Background(), u, "pw", "123456"); !errors.Is(err, ErrMFANotEnrolled) {
		t.Errorf("got %v", err)
	}
}
