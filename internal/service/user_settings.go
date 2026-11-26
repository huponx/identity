package service

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/huponx/gocommon/apperror"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// maxUserSettings is the size of the JSON object an application may keep for a user.
const maxUserSettings = 16 << 10

var appName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// checkUserSettings validates the application name and the JSON object (identity does not look inside).
func checkUserSettings(app, settings string) error {
	if !appName.MatchString(app) {
		return apperror.InvalidArgument("app is not a valid application name").WithReason("app_name_invalid")
	}
	if len(settings) > maxUserSettings {
		return apperror.InvalidArgument("settings are too large").WithReason("settings_too_large")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &obj); err != nil || obj == nil {
		return apperror.InvalidArgument("settings must be a JSON object").WithReason("settings_not_object")
	}
	return nil
}

func (s *Service) GetMyUserSettings(ctx context.Context, req *identityv1.GetMyUserSettingsRequest) (*identityv1.GetMyUserSettingsResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	if !appName.MatchString(req.GetApp()) {
		return nil, apperror.InvalidArgument("app is not a valid application name").WithReason("app_name_invalid")
	}
	out, err := s.Store.UserSettings(ctx, id, req.GetApp())
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.GetMyUserSettingsResponse{SettingsJson: out}, nil
}

func (s *Service) PutMyUserSettings(ctx context.Context, req *identityv1.PutMyUserSettingsRequest) (*identityv1.PutMyUserSettingsResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkUserSettings(req.GetApp(), req.GetSettingsJson()); err != nil {
		return nil, err
	}
	if err := s.Store.PutUserSettings(ctx, id, req.GetApp(), req.GetSettingsJson()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.PutMyUserSettingsResponse{}, nil
}
