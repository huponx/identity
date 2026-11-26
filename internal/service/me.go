package service

import (
	"context"
	"strings"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// The "me" methods work on the user the token was issued for. The id never comes from the request,
// so a caller cannot reach another user through them, and a service token (no user) is refused.

// meID is the id of the signed-in user.
func meID(ctx context.Context) (string, error) {
	p := authn.FromContext(ctx)
	if p == nil || p.Subject == "" || p.IsService() {
		return "", apperror.PermissionDenied("a user token is required").WithReason("user_token_required")
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
		return nil, apperror.InvalidArgument("name is too long").WithReason("name_too_long")
	}
	if l := req.GetLocale(); l != "" && !locales[l] {
		return nil, apperror.InvalidArgument("unsupported locale").WithReason("unsupported_locale")
	}
	if t := req.GetTheme(); t != "" && !themes[t] {
		return nil, apperror.InvalidArgument("unsupported theme").WithReason("unsupported_theme")
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

func (s *Service) ChangeMyPassword(ctx context.Context, req *identityv1.ChangeMyPasswordRequest) (*identityv1.ChangeMyPasswordResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	if err := s.Acct.ChangePassword(ctx, u, req.GetCurrentPassword(), req.GetNewPassword()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.ChangeMyPasswordResponse{}, nil
}

// myUser is the signed-in user, read fresh (the MFA flags change under a session).
func (s *Service) myUser(ctx context.Context) (*store.User, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	return u, nil
}

func (s *Service) GetMyMFA(ctx context.Context, _ *identityv1.GetMyMFARequest) (*identityv1.GetMyMFAResponse, error) {
	u, err := s.myUser(ctx)
	if err != nil {
		return nil, err
	}
	if u.MFAEnabled {
		left, err := s.Store.RecoveryCodesLeft(ctx, u.ID)
		if err != nil {
			return nil, toErr(err)
		}
		return &identityv1.GetMyMFAResponse{Enabled: true, Forced: s.Acct.MFAForced(u), RecoveryCodesLeft: int32(left)}, nil
	}
	if s.MFAMode == appconfig.MFAOff {
		return nil, toErr(account.ErrMFAOff)
	}
	return &identityv1.GetMyMFAResponse{Forced: s.Acct.MFAForced(u)}, nil
}

func (s *Service) BeginMyMFA(ctx context.Context, _ *identityv1.BeginMyMFARequest) (*identityv1.BeginMyMFAResponse, error) {
	u, err := s.myUser(ctx)
	if err != nil {
		return nil, err
	}
	enr, err := s.Acct.BeginEnrollment(ctx, u)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.BeginMyMFAResponse{Qr: enr.QRData, Secret: enr.Secret}, nil
}

func (s *Service) ConfirmMyMFA(ctx context.Context, req *identityv1.ConfirmMyMFARequest) (*identityv1.ConfirmMyMFAResponse, error) {
	u, err := s.myUser(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := s.Acct.ConfirmEnrollment(ctx, u, req.GetCode())
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.ConfirmMyMFAResponse{RecoveryCodes: codes}, nil
}

func (s *Service) DisableMyMFA(ctx context.Context, req *identityv1.DisableMyMFARequest) (*identityv1.DisableMyMFAResponse, error) {
	u, err := s.myUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Acct.DisableMFA(ctx, u, req.GetPassword(), req.GetCode()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.DisableMyMFAResponse{}, nil
}
