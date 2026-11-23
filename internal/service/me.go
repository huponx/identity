package service

import (
	"context"
	"strings"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// The "me" methods work on the user the token was issued for. The id never comes from the request,
// so a caller cannot reach another user through them, and a service token (no user) is refused.

// meID is the id of the signed-in user.
func meID(ctx context.Context) (string, error) {
	p := authn.FromContext(ctx)
	if p == nil || p.Subject == "" || p.IsService() {
		return "", apperror.PermissionDenied("a user token is required")
	}
	return p.Subject, nil
}

func (s *Service) GetMe(ctx context.Context, _ *identityv1.GetMeRequest) (*identityv1.GetMeResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	roles, err := s.Store.UserRoles(ctx, u.ID)
	if err != nil {
		return nil, toErr(err)
	}
	out, err := s.withAvatar(ctx, u, roles)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.GetMeResponse{User: out}, nil
}

func (s *Service) UpdateMe(ctx context.Context, req *identityv1.UpdateMeRequest) (*identityv1.UpdateMeResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		name = u.Name
	}
	if len([]rune(name)) > 200 {
		return nil, apperror.InvalidArgument("name is too long")
	}
	if l := req.GetLocale(); l != "" && !locales[l] {
		return nil, apperror.InvalidArgument("unsupported locale")
	}
	if t := req.GetTheme(); t != "" && !themes[t] {
		return nil, apperror.InvalidArgument("unsupported theme")
	}
	if err := s.Store.UpdateUser(ctx, id, name, req.GetLocale()); err != nil {
		return nil, toErr(err)
	}
	if t := req.GetTheme(); t != "" {
		if err := s.Store.SetUserTheme(ctx, id, t); err != nil {
			return nil, toErr(err)
		}
	}
	updated, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	roles, err := s.Store.UserRoles(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.UpdateMeResponse{User: toUser(updated, roles)}, nil
}

func (s *Service) SetMyAvatar(ctx context.Context, req *identityv1.SetMyAvatarRequest) (*identityv1.SetMyAvatarResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetImage()) > 0 {
		if err := checkAvatar(req.GetImage(), req.GetMimeType()); err != nil {
			return nil, err
		}
	}
	if err := s.Store.SetUserAvatar(ctx, id, req.GetImage(), req.GetMimeType()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetMyAvatarResponse{}, nil
}
