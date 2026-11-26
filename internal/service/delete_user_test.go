package service

import (
	"context"
	"testing"

	"github.com/huponx/gocommon/authn"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeleteUserRefusesSelf(t *testing.T) {
	s := &Service{} // the check comes before the store
	ctx := authn.WithPrincipal(context.Background(), &authn.Principal{Subject: "11111111-1111-1111-1111-111111111111", ClientID: "admin"})
	_, err := s.DeleteUser(ctx, &identityv1.DeleteUserRequest{UserId: "11111111-1111-1111-1111-111111111111"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("self delete: %v", err)
	}
	if _, err := s.DeleteUser(ctx, &identityv1.DeleteUserRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty id: %v", err)
	}
}
