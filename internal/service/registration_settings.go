package service

import (
	"context"
	"encoding/json"

	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

func (s *Service) GetRegistrationSettings(ctx context.Context, _ *identityv1.GetRegistrationSettingsRequest) (*identityv1.GetRegistrationSettingsResponse, error) {
	v, err := s.Store.RegistrationRequiresApproval(ctx)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.GetRegistrationSettingsResponse{RequiresApproval: v, RegistrationEnabled: s.RegistrationEnabled}, nil
}

func (s *Service) SetRegistrationSettings(ctx context.Context, req *identityv1.SetRegistrationSettingsRequest) (*identityv1.SetRegistrationSettingsResponse, error) {
	raw, _ := json.Marshal(req.GetRequiresApproval())
	if err := s.Store.PutSystemSettings(ctx, map[string]json.RawMessage{store.RegistrationApprovalKey: raw}); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetRegistrationSettingsResponse{RequiresApproval: req.GetRequiresApproval(), RegistrationEnabled: s.RegistrationEnabled}, nil
}
