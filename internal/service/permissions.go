package service

import (
	"context"
	"errors"
	"strings"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authz"
	"github.com/huponx/gocommon/pagination"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

const maxPermissionDescription = 500

func toPermission(p store.Permission) *identityv1.Permission {
	return &identityv1.Permission{Name: p.Name, Description: p.Description, RoleCount: p.RoleCount}
}

// permissionName is the name of the request: `name`, or `permission` (the path parameter of the gateway).
func permissionName(name, permission string) string {
	if name != "" {
		return name
	}
	return permission
}

func checkDescription(d string) error {
	if len([]rune(d)) > maxPermissionDescription {
		return apperror.InvalidArgument("description is too long").WithReason("description_too_long")
	}
	return nil
}

func (s *Service) ListPermissions(ctx context.Context, req *identityv1.ListPermissionsRequest) (*identityv1.ListPermissionsResponse, error) {
	size, err := pagination.Size(req.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := pagination.Decode(req.GetPageToken(), 1)
	if err != nil {
		return nil, err
	}
	list, err := s.Store.ListPermissions(ctx, strings.TrimSpace(req.GetQuery()), after[0], size)
	if err != nil {
		return nil, toErr(err)
	}
	total, err := s.Store.CountPermissions(ctx, strings.TrimSpace(req.GetQuery()))
	if err != nil {
		return nil, toErr(err)
	}
	out := &identityv1.ListPermissionsResponse{Total: total}
	if len(list) > size {
		list = list[:size]
		out.NextPageToken = pagination.Encode(list[size-1].Name)
	}
	for _, p := range list {
		out.Permissions = append(out.Permissions, toPermission(p))
	}
	return out, nil
}

func (s *Service) CreatePermission(ctx context.Context, req *identityv1.CreatePermissionRequest) (*identityv1.CreatePermissionResponse, error) {
	name := strings.TrimSpace(req.GetPermission().GetName())
	if !authz.Valid(name) {
		return nil, apperror.InvalidArgument("invalid permission "+name).WithReason("invalid_permission", "name", name)
	}
	d := strings.TrimSpace(req.GetPermission().GetDescription())
	if err := checkDescription(d); err != nil {
		return nil, err
	}
	if err := s.Store.CreatePermission(ctx, name, d); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.CreatePermissionResponse{Permission: &identityv1.Permission{Name: name, Description: d}}, nil
}

func (s *Service) UpdatePermission(ctx context.Context, req *identityv1.UpdatePermissionRequest) (*identityv1.UpdatePermissionResponse, error) {
	name := permissionName(req.GetName(), req.GetPermission())
	d := strings.TrimSpace(req.GetDescription())
	if err := checkDescription(d); err != nil {
		return nil, err
	}
	if err := s.Store.UpdatePermission(ctx, name, d); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.UpdatePermissionResponse{Permission: &identityv1.Permission{Name: name, Description: d}}, nil
}

func (s *Service) DeletePermission(ctx context.Context, req *identityv1.DeletePermissionRequest) (*identityv1.DeletePermissionResponse, error) {
	name := permissionName(req.GetName(), req.GetPermission())
	err := s.Store.DeletePermission(ctx, name)
	if errors.Is(err, store.ErrPermissionInUse) {
		roles, _ := s.Store.PermissionRoles(ctx, name)
		return nil, apperror.FailedPrecondition("the permission is held by the roles: "+strings.Join(roles, ", ")).WithReason("permission_held_by_roles", "roles", strings.Join(roles, ", "))
	}
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.DeletePermissionResponse{}, nil
}
