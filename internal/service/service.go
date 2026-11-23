// Package service implements the IdentityService gRPC API (administration).
package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/authz"
	"github.com/huponx/gocommon/grpcserver"
	"github.com/huponx/gocommon/pagination"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/oauth"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"google.golang.org/grpc/codes"
)

// Permissions required per method. grpcserver.WithMethodPermissions is deny by default, so a
// new RPC has no entry here until somebody decides who may call it.
var Permissions = map[string]string{
	"/identity.v1.IdentityService/Introspect":           "identity:token:read",
	"/identity.v1.IdentityService/CheckPermission":      "identity:permission:read",
	"/identity.v1.IdentityService/RevokeToken":          "identity:token:write",
	"/identity.v1.IdentityService/GetUser":              "identity:user:read",
	"/identity.v1.IdentityService/ListUsers":            "identity:user:read",
	"/identity.v1.IdentityService/CreateUser":           "identity:user:write",
	"/identity.v1.IdentityService/SetUserDisabled":      "identity:user:write",
	"/identity.v1.IdentityService/SetUserPassword":      "identity:user:write",
	"/identity.v1.IdentityService/SendPasswordReset":    "identity:user:write",
	"/identity.v1.IdentityService/UpdateUser":           "identity:user:write",
	"/identity.v1.IdentityService/SetUserAvatar":        "identity:user:write",
	"/identity.v1.IdentityService/SendWelcome":          "identity:user:write",
	"/identity.v1.IdentityService/GetUserStats":         "identity:user:read",
	"/identity.v1.IdentityService/GetMe":                grpcserver.Public,
	"/identity.v1.IdentityService/UpdateMe":             grpcserver.Public,
	"/identity.v1.IdentityService/SetMyAvatar":          grpcserver.Public,
	"/identity.v1.IdentityService/GetMyUserSettings":    grpcserver.Public,
	"/identity.v1.IdentityService/PutMyUserSettings":    grpcserver.Public,
	"/identity.v1.IdentityService/CreateRole":           "identity:role:write",
	"/identity.v1.IdentityService/SetRolePermissions":   "identity:role:write",
	"/identity.v1.IdentityService/UpdateRole":           "identity:role:write",
	"/identity.v1.IdentityService/DeleteRole":           "identity:role:write",
	"/identity.v1.IdentityService/ListRoles":            "identity:role:read",
	"/identity.v1.IdentityService/ListPermissions":      "identity:permission:read",
	"/identity.v1.IdentityService/CreatePermission":     "identity:permission:write",
	"/identity.v1.IdentityService/UpdatePermission":     "identity:permission:write",
	"/identity.v1.IdentityService/DeletePermission":     "identity:permission:write",
	"/identity.v1.IdentityService/AssignRole":           "identity:role:write",
	"/identity.v1.IdentityService/RevokeRole":           "identity:role:write",
	"/identity.v1.IdentityService/CreateClient":         "identity:client:write",
	"/identity.v1.IdentityService/UpdateClient":         "identity:client:write",
	"/identity.v1.IdentityService/SetClientDisabled":    "identity:client:write",
	"/identity.v1.IdentityService/DeleteClient":         "identity:client:write",
	"/identity.v1.IdentityService/RotateClientSecret":   "identity:client:write",
	"/identity.v1.IdentityService/ListClients":          "identity:client:read",
	"/identity.v1.IdentityService/SetExchangePolicy":    "identity:exchange:write",
	"/identity.v1.IdentityService/ListExchangePolicies": "identity:exchange:read",
	"/identity.v1.IdentityService/GetUserMFA":           "identity:mfa:read",
	"/identity.v1.IdentityService/SetUserMFA":           "identity:mfa:write",
	"/identity.v1.IdentityService/EnforceUserMFA":       "identity:mfa:write",
	"/identity.v1.IdentityService/ResetUserMFA":         "identity:mfa:write",
}

// Service is the gRPC implementation.
type Service struct {
	identityv1.UnimplementedIdentityServiceServer

	Acct    *account.Service
	Store   *store.Store
	State   *state.State
	Tokens  *token.Service
	MFAMode string
}

// New builds the service.
func New(acct *account.Service, st *store.Store, sta *state.State, tk *token.Service, mfaMode string) *Service {
	return &Service{Acct: acct, Store: st, State: sta, Tokens: tk, MFAMode: mfaMode}
}

// toErr maps domain errors to gRPC errors. Internal details are not sent to the caller.
func toErr(err error) error {
	if err == nil {
		return nil
	}
	var te *token.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apperror.NotFound("not found")
	case errors.Is(err, store.ErrConflict):
		return apperror.AlreadyExists("already exists")
	case errors.Is(err, store.ErrUnknownPermission):
		return apperror.InvalidArgument("a permission is not in the catalog; add it to the permissions first")
	case errors.Is(err, store.ErrClientNotDisabled):
		return apperror.FailedPrecondition("disable the client before deleting it")
	case errors.Is(err, store.ErrRoleInUse):
		return apperror.FailedPrecondition("a user or a client still holds this role")
	case errors.Is(err, store.ErrPermissionInUse):
		return apperror.FailedPrecondition("a role still holds this permission")
	case errors.Is(err, account.ErrNotPending):
		return apperror.FailedPrecondition("the user already has a password")
	case errors.Is(err, account.ErrMFAForced):
		return apperror.FailedPrecondition("multi-factor authentication is required for this user")
	case errors.Is(err, account.ErrMFAOff):
		return apperror.FailedPrecondition("multi-factor authentication is turned off on this server")
	case errors.Is(err, account.ErrMFANotEnrolled):
		return apperror.FailedPrecondition("the user has not enrolled a second factor")
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrCommon),
		errors.Is(err, password.ErrSame), errors.Is(err, password.ErrEmail):
		return apperror.InvalidArgument(err.Error())
	case errors.As(err, &te):
		return apperror.InvalidArgument(te.Desc)
	}
	var app *apperror.Error
	if errors.As(err, &app) {
		return err
	}
	return apperror.Wrap(codes.Internal, "internal error", err)
}

// ---- tokens ----

func (s *Service) Introspect(ctx context.Context, req *identityv1.IntrospectRequest) (*identityv1.IntrospectResponse, error) {
	claims, err := s.Tokens.VerifyAny(ctx, req.GetToken())
	if err != nil || claims.Type != "access" {
		return &identityv1.IntrospectResponse{}, nil
	}
	live, err := s.Tokens.IsLive(ctx, claims)
	if err != nil {
		return nil, toErr(err)
	}
	if !live {
		return &identityv1.IntrospectResponse{}, nil
	}
	out := &identityv1.IntrospectResponse{
		Active: true, Sub: claims.Subject, ClientId: claims.ClientID, Scope: claims.Scope,
		Aud: []string(claims.Audience), Jti: claims.ID, Exp: claims.ExpiresAt.Unix(),
	}
	for a := claims.Act; a != nil; a = a.Act {
		out.Act = append(out.Act, a.Subject)
	}
	return out, nil
}

func (s *Service) CheckPermission(ctx context.Context, req *identityv1.CheckPermissionRequest) (*identityv1.CheckPermissionResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if u.Disabled {
		return &identityv1.CheckPermissionResponse{}, nil
	}
	perms, err := s.Store.UserPermissions(ctx, u.ID)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.CheckPermissionResponse{Allowed: authz.Allowed(perms, req.GetPermission())}, nil
}

func (s *Service) RevokeToken(ctx context.Context, req *identityv1.RevokeTokenRequest) (*identityv1.RevokeTokenResponse, error) {
	if req.GetJti() == "" || req.GetTtlSeconds() <= 0 {
		return nil, apperror.InvalidArgument("jti and ttl_seconds are required")
	}
	if err := s.State.Deny(ctx, req.GetJti(), time.Duration(req.GetTtlSeconds())*time.Second); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.RevokeTokenResponse{}, nil
}

// ---- users ----

// userStatus: disabled wins; a user without a password is pending (a new user becomes active only
// after setting one through the welcome mail); everybody else is active.
func userStatus(u *store.User) identityv1.UserStatus {
	switch {
	case u.Disabled:
		return identityv1.UserStatus_USER_STATUS_DISABLED
	case u.PasswordHash == "":
		return identityv1.UserStatus_USER_STATUS_PENDING
	default:
		return identityv1.UserStatus_USER_STATUS_ACTIVE
	}
}

func toUser(u *store.User, roles []string) *identityv1.User {
	return &identityv1.User{
		Id: u.ID, Email: u.Email, Name: u.Name, Locale: u.Locale, Disabled: u.Disabled, Roles: roles,
		MfaEnabled: u.MFAEnabled, MfaEnforced: u.MFAEnforced, CreatedAt: u.CreatedAt.Unix(),
		Status: userStatus(u), HasAvatar: u.HasAvatar, LastLoginAt: unixOrZero(u.LastLoginAt), Theme: u.Theme,
	}
}

func unixOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

// withAvatar is toUser plus the picture as a data URI (single user responses only).
func (s *Service) withAvatar(ctx context.Context, u *store.User, roles []string) (*identityv1.User, error) {
	out := toUser(u, roles)
	if u.HasAvatar {
		img, mime, err := s.Store.UserAvatar(ctx, u.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if err == nil {
			out.Avatar = avatarURI(img, mime)
		}
	}
	return out, nil
}

// GetUserStats counts users by status, MFA and activity.
func (s *Service) GetUserStats(ctx context.Context, _ *identityv1.GetUserStatsRequest) (*identityv1.GetUserStatsResponse, error) {
	st, err := s.Store.UserStats(ctx)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.GetUserStatsResponse{
		Total: st.Total, Active: st.Active, Pending: st.Pending, Disabled: st.Disabled,
		MfaEnabled: st.MFAEnabled, MfaEnforced: st.MFAEnforced, WithAvatar: st.WithAvatar,
		SignedIn_30D: st.SignedIn30d, NeverSignedIn: st.NeverSignedIn, CreatedThisMonth: st.CreatedThisMonth,
	}, nil
}

func (s *Service) GetUser(ctx context.Context, req *identityv1.GetUserRequest) (*identityv1.GetUserResponse, error) {
	var u *store.User
	var err error
	switch {
	case req.GetId() != "":
		u, err = s.Store.UserByID(ctx, req.GetId())
	case req.GetUserId() != "":
		u, err = s.Store.UserByID(ctx, req.GetUserId())
	case req.GetEmail() != "":
		u, err = s.Store.UserByEmail(ctx, req.GetEmail())
	default:
		return nil, apperror.InvalidArgument("id or email is required")
	}
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
	return &identityv1.GetUserResponse{User: out}, nil
}

func statusFilter(s identityv1.UserStatus) string {
	switch s {
	case identityv1.UserStatus_USER_STATUS_PENDING:
		return "pending"
	case identityv1.UserStatus_USER_STATUS_ACTIVE:
		return "active"
	case identityv1.UserStatus_USER_STATUS_DISABLED:
		return "disabled"
	}
	return ""
}

// ListUsers pages through the users ordered by email. The page token is the last email of the
// previous page (opaque to callers).
func (s *Service) ListUsers(ctx context.Context, req *identityv1.ListUsersRequest) (*identityv1.ListUsersResponse, error) {
	size, err := pagination.Size(req.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := pagination.Decode(req.GetPageToken(), 1)
	if err != nil {
		return nil, err
	}
	users, roles, err := s.Store.ListUsers(ctx, store.UserFilter{
		EmailPrefix: req.GetQuery(), NameContains: req.GetName(), Role: req.GetRole(),
		Status: statusFilter(req.GetStatus()),
	}, after[0], size)
	if err != nil {
		return nil, toErr(err)
	}
	out := &identityv1.ListUsersResponse{}
	if len(users) > size {
		users = users[:size]
		out.NextPageToken = pagination.Encode(users[size-1].Email)
	}
	for i := range users {
		out.Users = append(out.Users, toUser(&users[i], roles[users[i].ID]))
	}
	return out, nil
}

func (s *Service) CreateUser(ctx context.Context, req *identityv1.CreateUserRequest) (*identityv1.CreateUserResponse, error) {
	email := store.NormalizeEmail(req.GetEmail())
	if !strings.Contains(email, "@") || len(email) > 254 {
		return nil, apperror.InvalidArgument("a valid email is required")
	}
	u := store.User{Email: email, Name: req.GetName(), Locale: req.GetLocale()}
	if pw := req.GetPassword(); pw != "" {
		if err := password.Check(pw, email, ""); err != nil {
			return nil, toErr(err)
		}
		h, err := password.Hash(pw)
		if err != nil {
			return nil, toErr(err)
		}
		u.PasswordHash = h
	}
	created, err := s.Store.CreateUser(ctx, u, req.GetRoles())
	if err != nil {
		return nil, toErr(err)
	}
	// A user without a password gets the welcome mail with the link to set it. The user is created
	// either way: a failed link is reported, and the admin can resend it.
	if created.PasswordHash == "" && req.GetSendWelcome() {
		if err := s.Acct.SendWelcome(ctx, created); err != nil {
			return nil, toErr(err)
		}
	}
	return &identityv1.CreateUserResponse{User: toUser(created, req.GetRoles())}, nil
}

// themes are the values of the theme of an account (the apps' own switch has the same three).
var themes = map[string]bool{"light": true, "dark": true, "system": true}

// locales are the languages of the mails and of the admin UI.
var locales = map[string]bool{"en": true, "vi": true}

func (s *Service) UpdateUser(ctx context.Context, req *identityv1.UpdateUserRequest) (*identityv1.UpdateUserResponse, error) {
	name := strings.TrimSpace(req.GetName())
	if len([]rune(name)) > 200 {
		return nil, apperror.InvalidArgument("name is too long")
	}
	if l := req.GetLocale(); l != "" && !locales[l] {
		return nil, apperror.InvalidArgument("unsupported locale")
	}
	if err := s.Store.UpdateUser(ctx, req.GetUserId(), name, req.GetLocale()); err != nil {
		return nil, toErr(err)
	}
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	roles, err := s.Store.UserRoles(ctx, u.ID)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.UpdateUserResponse{User: toUser(u, roles)}, nil
}

func (s *Service) SetUserAvatar(ctx context.Context, req *identityv1.SetUserAvatarRequest) (*identityv1.SetUserAvatarResponse, error) {
	if len(req.GetImage()) > 0 {
		if err := checkAvatar(req.GetImage(), req.GetMimeType()); err != nil {
			return nil, err
		}
	}
	if err := s.Store.SetUserAvatar(ctx, req.GetUserId(), req.GetImage(), req.GetMimeType()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetUserAvatarResponse{}, nil
}

func (s *Service) SendWelcome(ctx context.Context, req *identityv1.SendWelcomeRequest) (*identityv1.SendWelcomeResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if err := s.Acct.SendWelcome(ctx, u); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SendWelcomeResponse{}, nil
}

func (s *Service) SetUserDisabled(ctx context.Context, req *identityv1.SetUserDisabledRequest) (*identityv1.SetUserDisabledResponse, error) {
	if err := s.Store.SetUserDisabled(ctx, req.GetUserId(), req.GetDisabled()); err != nil {
		return nil, toErr(err)
	}
	if req.GetDisabled() { // a disabled user loses sessions and tokens now
		if err := s.Acct.RevokeUserAccess(ctx, req.GetUserId()); err != nil {
			return nil, toErr(err)
		}
	}
	return &identityv1.SetUserDisabledResponse{}, nil
}

func (s *Service) SetUserPassword(ctx context.Context, req *identityv1.SetUserPasswordRequest) (*identityv1.SetUserPasswordResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if err := s.Acct.SetPassword(ctx, u, req.GetPassword(), true); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetUserPasswordResponse{}, nil
}

func (s *Service) SendPasswordReset(ctx context.Context, req *identityv1.SendPasswordResetRequest) (*identityv1.SendPasswordResetResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if err := s.Acct.SendReset(ctx, u); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SendPasswordResetResponse{}, nil
}

// ---- roles ----

func validRole(r *identityv1.Role) error {
	if r == nil || r.GetName() == "" {
		return apperror.InvalidArgument("role name is required")
	}
	return validPerms(r.GetPermissions())
}

func validPerms(perms []string) error {
	for _, p := range perms {
		if !authz.Valid(p) {
			return apperror.InvalidArgument("invalid permission " + p)
		}
	}
	return nil
}

func toRole(r store.Role) *identityv1.Role {
	return &identityv1.Role{Name: r.Name, Description: r.Description, Permissions: r.Permissions, AssignedCount: r.AssignedCount}
}

func (s *Service) CreateRole(ctx context.Context, req *identityv1.CreateRoleRequest) (*identityv1.CreateRoleResponse, error) {
	if err := validRole(req.GetRole()); err != nil {
		return nil, err
	}
	r := store.Role{Name: req.GetRole().GetName(), Description: req.GetRole().GetDescription(), Permissions: req.GetRole().GetPermissions()}
	if err := s.Store.CreateRole(ctx, r); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.CreateRoleResponse{Role: toRole(r)}, nil
}

func (s *Service) SetRolePermissions(ctx context.Context, req *identityv1.SetRolePermissionsRequest) (*identityv1.SetRolePermissionsResponse, error) {
	if err := validPerms(req.GetPermissions()); err != nil {
		return nil, err
	}
	if err := s.Store.SetRolePermissions(ctx, req.GetRole(), req.GetPermissions()); err != nil {
		return nil, toErr(err)
	}
	r, err := s.Store.RoleByName(ctx, req.GetRole())
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetRolePermissionsResponse{Role: toRole(*r)}, nil
}

func (s *Service) UpdateRole(ctx context.Context, req *identityv1.UpdateRoleRequest) (*identityv1.UpdateRoleResponse, error) {
	if req.GetRole() == "" {
		return nil, apperror.InvalidArgument("role name is required")
	}
	if err := validPerms(req.GetPermissions()); err != nil {
		return nil, err
	}
	if err := s.Store.UpdateRole(ctx, req.GetRole(), req.GetDescription(), req.GetPermissions()); err != nil {
		return nil, toErr(err)
	}
	r, err := s.Store.RoleByName(ctx, req.GetRole())
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.UpdateRoleResponse{Role: toRole(*r)}, nil
}

func (s *Service) DeleteRole(ctx context.Context, req *identityv1.DeleteRoleRequest) (*identityv1.DeleteRoleResponse, error) {
	if req.GetRole() == "" {
		return nil, apperror.InvalidArgument("role name is required")
	}
	if err := s.Store.DeleteRole(ctx, req.GetRole()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.DeleteRoleResponse{}, nil
}

func (s *Service) ListRoles(ctx context.Context, req *identityv1.ListRolesRequest) (*identityv1.ListRolesResponse, error) {
	size, err := pagination.Size(req.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := pagination.Decode(req.GetPageToken(), 1)
	if err != nil {
		return nil, err
	}
	roles, err := s.Store.ListRoles(ctx, strings.TrimSpace(req.GetQuery()), after[0], size)
	if err != nil {
		return nil, toErr(err)
	}
	total, err := s.Store.CountRoles(ctx, strings.TrimSpace(req.GetQuery()))
	if err != nil {
		return nil, toErr(err)
	}
	out := &identityv1.ListRolesResponse{Total: total}
	if len(roles) > size {
		roles = roles[:size]
		out.NextPageToken = pagination.Encode(roles[size-1].Name)
	}
	for _, r := range roles {
		out.Roles = append(out.Roles, toRole(r))
	}
	return out, nil
}

func (s *Service) AssignRole(ctx context.Context, req *identityv1.AssignRoleRequest) (*identityv1.AssignRoleResponse, error) {
	if (req.GetUserId() == "") == (req.GetClientId() == "") || req.GetRole() == "" {
		return nil, apperror.InvalidArgument("role and exactly one of user_id and client_id are required")
	}
	if err := s.Store.AssignRole(ctx, req.GetUserId(), req.GetClientId(), req.GetRole()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.AssignRoleResponse{}, nil
}

func (s *Service) RevokeRole(ctx context.Context, req *identityv1.RevokeRoleRequest) (*identityv1.RevokeRoleResponse, error) {
	if (req.GetUserId() == "") == (req.GetClientId() == "") || req.GetRole() == "" {
		return nil, apperror.InvalidArgument("role and exactly one of user_id and client_id are required")
	}
	if err := s.Store.RevokeRole(ctx, req.GetUserId(), req.GetClientId(), req.GetRole()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.RevokeRoleResponse{}, nil
}

// ---- clients ----

func toClient(c store.Client) *identityv1.Client {
	t := identityv1.ClientType_CLIENT_TYPE_PUBLIC
	if c.Type == "confidential" {
		t = identityv1.ClientType_CLIENT_TYPE_CONFIDENTIAL
	}
	return &identityv1.Client{
		ClientId: c.ClientID, Name: c.Name, Type: t, RedirectUris: c.RedirectURIs, PostLogoutRedirectUris: c.PostLogoutRedirectURIs,
		BackchannelLogoutUri: c.BackchannelLogoutURI, AllowedGrants: c.AllowedGrants, AllowedScopes: c.AllowedScopes,
		Resource: c.Resource, Roles: c.Roles, Disabled: c.Disabled,
	}
}

var knownGrants = map[string]bool{"authorization_code": true, "refresh_token": true, "client_credentials": true, "urn:ietf:params:oauth:grant-type:token-exchange": true}

func (s *Service) CreateClient(ctx context.Context, req *identityv1.CreateClientRequest) (*identityv1.CreateClientResponse, error) {
	in := req.GetClient()
	if in.GetClientId() == "" || in.GetResource() == "" {
		return nil, apperror.InvalidArgument("client_id and resource are required")
	}
	c := store.Client{
		ClientID: in.GetClientId(), Name: in.GetName(), RedirectURIs: in.GetRedirectUris(), PostLogoutRedirectURIs: in.GetPostLogoutRedirectUris(),
		BackchannelLogoutURI: in.GetBackchannelLogoutUri(), AllowedGrants: in.GetAllowedGrants(), AllowedScopes: in.GetAllowedScopes(),
		Resource: in.GetResource(), Roles: in.GetRoles(),
	}
	if c.Name == "" {
		c.Name = c.ClientID
	}
	switch in.GetType() {
	case identityv1.ClientType_CLIENT_TYPE_PUBLIC:
		c.Type = "public"
	case identityv1.ClientType_CLIENT_TYPE_CONFIDENTIAL:
		c.Type = "confidential"
	default:
		return nil, apperror.InvalidArgument("type is required")
	}
	if err := normalizeClient(&c); err != nil {
		return nil, err
	}
	secret := ""
	if c.Type == "confidential" {
		secret = password.Random(32)
		c.SecretHash = oauth.HashSecret(secret)
	}
	created, err := s.Store.CreateClient(ctx, c)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.CreateClientResponse{Client: toClient(*created), ClientSecret: secret}, nil
}

// normalizeClient fills the defaults (grants, scopes) and checks grants and URIs; c.Type is already set.
func normalizeClient(c *store.Client) error {
	if len(c.AllowedGrants) == 0 {
		c.AllowedGrants = []string{"authorization_code", "refresh_token"}
	}
	if len(c.AllowedScopes) == 0 {
		c.AllowedScopes = []string{"openid", "profile", "email", "offline_access"}
	}
	for _, g := range c.AllowedGrants {
		if !knownGrants[g] {
			return apperror.InvalidArgument("unknown grant " + g)
		}
		if c.Type == "public" && g != "authorization_code" && g != "refresh_token" {
			return apperror.InvalidArgument("a public client cannot use " + g)
		}
	}
	for _, u := range append(append([]string{}, c.RedirectURIs...), c.PostLogoutRedirectURIs...) {
		if !validURI(u) {
			return apperror.InvalidArgument("invalid uri " + u)
		}
	}
	if c.BackchannelLogoutURI != "" && !validURI(c.BackchannelLogoutURI) {
		return apperror.InvalidArgument("invalid backchannel_logout_uri")
	}
	return nil
}

// UpdateClient replaces what can change; the type comes from the stored client, so the grant rules of a
// public client still hold.
func (s *Service) UpdateClient(ctx context.Context, req *identityv1.UpdateClientRequest) (*identityv1.UpdateClientResponse, error) {
	if req.GetClientId() == "" || req.GetResource() == "" {
		return nil, apperror.InvalidArgument("client_id and resource are required")
	}
	cur, err := s.Store.ClientByID(ctx, req.GetClientId())
	if err != nil {
		return nil, toErr(err)
	}
	c := store.Client{
		ClientID: cur.ClientID, Name: req.GetName(), Type: cur.Type, RedirectURIs: req.GetRedirectUris(), PostLogoutRedirectURIs: req.GetPostLogoutRedirectUris(),
		BackchannelLogoutURI: req.GetBackchannelLogoutUri(), AllowedGrants: req.GetAllowedGrants(), AllowedScopes: req.GetAllowedScopes(),
		Resource: req.GetResource(), Roles: req.GetRoles(),
	}
	if c.Name == "" {
		c.Name = c.ClientID
	}
	if err := normalizeClient(&c); err != nil {
		return nil, err
	}
	updated, err := s.Store.UpdateClient(ctx, c)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.UpdateClientResponse{Client: toClient(*updated)}, nil
}

func (s *Service) SetClientDisabled(ctx context.Context, req *identityv1.SetClientDisabledRequest) (*identityv1.SetClientDisabledResponse, error) {
	if req.GetClientId() == "" {
		return nil, apperror.InvalidArgument("client_id is required")
	}
	if req.GetDisabled() && s.isCallerClient(ctx, req.GetClientId()) {
		return nil, apperror.FailedPrecondition("this is the client of your own session")
	}
	c, err := s.Store.SetClientDisabled(ctx, req.GetClientId(), req.GetDisabled())
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetClientDisabledResponse{Client: toClient(*c)}, nil
}

func (s *Service) DeleteClient(ctx context.Context, req *identityv1.DeleteClientRequest) (*identityv1.DeleteClientResponse, error) {
	if req.GetClientId() == "" {
		return nil, apperror.InvalidArgument("client_id is required")
	}
	if s.isCallerClient(ctx, req.GetClientId()) {
		return nil, apperror.FailedPrecondition("this is the client of your own session")
	}
	if err := s.Store.DeleteClient(ctx, req.GetClientId()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.DeleteClientResponse{}, nil
}

// isCallerClient: the token of the request was issued to this client (an admin must not cut the branch they sit on).
func (s *Service) isCallerClient(ctx context.Context, clientID string) bool {
	p := authn.FromContext(ctx)
	if p == nil {
		return false
	}
	if p.ClientID == clientID {
		return true
	}
	// a token exchanged by a service (the gateway) names that service in the act chain
	for a := p.Actor; a != nil; a = a.Act {
		if a.Subject == clientID || a.ClientID == clientID {
			return true
		}
	}
	return false
}

func validURI(raw string) bool { return store.ValidURI(raw) }

func (s *Service) RotateClientSecret(ctx context.Context, req *identityv1.RotateClientSecretRequest) (*identityv1.RotateClientSecretResponse, error) {
	secret := password.Random(32)
	if err := s.Store.SetClientSecret(ctx, req.GetClientId(), oauth.HashSecret(secret)); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.RotateClientSecretResponse{ClientSecret: secret}, nil
}

// clientTypeName is the stored name of a client type; empty for unspecified.
func clientTypeName(t identityv1.ClientType) string {
	switch t {
	case identityv1.ClientType_CLIENT_TYPE_PUBLIC:
		return "public"
	case identityv1.ClientType_CLIENT_TYPE_CONFIDENTIAL:
		return "confidential"
	}
	return ""
}

func (s *Service) ListClients(ctx context.Context, req *identityv1.ListClientsRequest) (*identityv1.ListClientsResponse, error) {
	size, err := pagination.Size(req.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := pagination.Decode(req.GetPageToken(), 1)
	if err != nil {
		return nil, err
	}
	cs, err := s.Store.ListClients(ctx, strings.TrimSpace(req.GetQuery()), clientTypeName(req.GetType()), after[0], size)
	if err != nil {
		return nil, toErr(err)
	}
	out := &identityv1.ListClientsResponse{}
	if len(cs) > size {
		cs = cs[:size]
		out.NextPageToken = pagination.Encode(cs[size-1].ClientID)
	}
	for _, c := range cs {
		out.Clients = append(out.Clients, toClient(c))
	}
	return out, nil
}

// ---- exchange policies ----

func (s *Service) SetExchangePolicy(ctx context.Context, req *identityv1.SetExchangePolicyRequest) (*identityv1.SetExchangePolicyResponse, error) {
	p := req.GetPolicy()
	if p.GetClientId() == "" || p.GetAudience() == "" {
		return nil, apperror.InvalidArgument("client_id and audience are required")
	}
	if req.GetDelete() {
		if err := s.Store.DeleteExchangePolicy(ctx, p.GetClientId(), p.GetAudience()); err != nil {
			return nil, toErr(err)
		}
		return &identityv1.SetExchangePolicyResponse{}, nil
	}
	if d := p.GetMaxChainDepth(); d < 0 || d > 5 {
		return nil, apperror.InvalidArgument("max_chain_depth must be between 1 and 5")
	}
	err := s.Store.SetExchangePolicy(ctx, store.ExchangePolicy{
		ClientID: p.GetClientId(), Audience: p.GetAudience(), MaxScope: p.GetMaxScope(), MaxChainDepth: int(p.GetMaxChainDepth()),
	})
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetExchangePolicyResponse{}, nil
}

func (s *Service) ListExchangePolicies(ctx context.Context, req *identityv1.ListExchangePoliciesRequest) (*identityv1.ListExchangePoliciesResponse, error) {
	size, err := pagination.Size(req.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := pagination.Decode(req.GetPageToken(), 2)
	if err != nil {
		return nil, err
	}
	ps, err := s.Store.ListExchangePolicies(ctx, store.PolicyFilter{
		ClientID: req.GetClientId(), Query: strings.TrimSpace(req.GetQuery()), Audience: strings.TrimSpace(req.GetAudience()),
		AfterClientID: after[0], AfterAudience: after[1],
	}, size)
	if err != nil {
		return nil, toErr(err)
	}
	out := &identityv1.ListExchangePoliciesResponse{}
	if len(ps) > size {
		ps = ps[:size]
		out.NextPageToken = pagination.Encode(ps[size-1].ClientID, ps[size-1].Audience)
	}
	for _, p := range ps {
		out.Policies = append(out.Policies, &identityv1.ExchangePolicy{
			ClientId: p.ClientID, Audience: p.Audience, MaxScope: p.MaxScope, MaxChainDepth: int32(p.MaxChainDepth),
		})
	}
	return out, nil
}

// ---- MFA ----

func (s *Service) GetUserMFA(ctx context.Context, req *identityv1.GetUserMFARequest) (*identityv1.GetUserMFAResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	left, err := s.Store.RecoveryCodesLeft(ctx, u.ID)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.GetUserMFAResponse{Enabled: u.MFAEnabled, Enforced: u.MFAEnforced, Mode: s.MFAMode, RecoveryCodesLeft: int32(left)}, nil
}

// SetUserMFA turns MFA off for a user (the user's authenticator is deleted). Turning it on is
// the user's own act (enrollment needs their device); an admin makes it mandatory with
// EnforceUserMFA instead.
func (s *Service) SetUserMFA(ctx context.Context, req *identityv1.SetUserMFARequest) (*identityv1.SetUserMFAResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if s.MFAMode == appconfig.MFAOff {
		return nil, toErr(account.ErrMFAOff)
	}
	if req.GetEnabled() {
		if u.MFAEnabled {
			return &identityv1.SetUserMFAResponse{}, nil
		}
		return nil, apperror.FailedPrecondition("the user must enroll an authenticator; use EnforceUserMFA to make it mandatory")
	}
	if err := s.Acct.AdminDisableMFA(ctx, u); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetUserMFAResponse{}, nil
}

func (s *Service) EnforceUserMFA(ctx context.Context, req *identityv1.EnforceUserMFARequest) (*identityv1.EnforceUserMFAResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if s.MFAMode == appconfig.MFAOff {
		return nil, toErr(account.ErrMFAOff)
	}
	if err := s.Acct.AdminEnforceMFA(ctx, u, req.GetEnforced()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.EnforceUserMFAResponse{}, nil
}

func (s *Service) ResetUserMFA(ctx context.Context, req *identityv1.ResetUserMFARequest) (*identityv1.ResetUserMFAResponse, error) {
	u, err := s.Store.UserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if err := s.Acct.AdminResetMFA(ctx, u); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.ResetUserMFAResponse{}, nil
}
