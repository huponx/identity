package service

import (
	"context"
	"sort"
	"strings"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/pagination"
	"github.com/huponx/identity/internal/catalog"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"go.uber.org/zap"
)

// reservedServices are synced by identity itself from its own copy of their permissions.proto (a service without a
// process of its own, or identity), so no other caller may register them.
var reservedServices = map[string]bool{"identity": true, "bill": true, "system": true}

// describeWildcard is the text shown for a generated wildcard.
func describeWildcard(w string) string {
	segs := strings.Split(w, ":")
	switch {
	case w == "*":
		return "Everything, in every service"
	case len(segs) == 2:
		return "Everything in " + segs[0]
	case len(segs) == 3 && segs[1] == "*":
		return "Every " + segs[2] + " permission in " + segs[0]
	case len(segs) == 3 && segs[2] == "*":
		return "Every permission on " + segs[1] + " in " + segs[0]
	}
	return ""
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
	rows, err := s.Store.ListCatalog(ctx)
	if err != nil {
		return nil, toErr(err)
	}
	var active []string
	all := make([]*identityv1.Permission, 0, len(rows)+16)
	for _, p := range rows {
		if !p.Retired {
			active = append(active, p.Name)
		}
		all = append(all, &identityv1.Permission{Name: p.Name, Description: p.Description, RoleCount: p.RoleCount, Service: p.Service, Retired: p.Retired})
	}
	wild := catalog.Wildcards(active)
	counts, err := s.Store.RoleCountOf(ctx, wild)
	if err != nil {
		return nil, toErr(err)
	}
	for _, w := range wild {
		all = append(all, &identityv1.Permission{Name: w, Description: describeWildcard(w), RoleCount: counts[w], Wildcard: true})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })

	q := strings.ToLower(strings.TrimSpace(req.GetQuery()))
	var matched []*identityv1.Permission
	for _, p := range all {
		if q == "" || strings.Contains(strings.ToLower(p.Name), q) || strings.Contains(strings.ToLower(p.Description), q) {
			matched = append(matched, p)
		}
	}
	out := &identityv1.ListPermissionsResponse{Total: int64(len(matched))}
	i := sort.Search(len(matched), func(i int) bool { return matched[i].Name > after[0] })
	matched = matched[i:]
	if len(matched) > size {
		matched = matched[:size]
		out.NextPageToken = pagination.Encode(matched[size-1].Name)
	}
	out.Permissions = matched
	return out, nil
}

// RegisterPermissions syncs the permissions of the calling service (see Store.SyncPermissions). A caller with a
// token must be a client whose resource is the service; a caller authenticated by the cluster alone (no token) is
// trusted, like for every other method.
func (s *Service) RegisterPermissions(ctx context.Context, req *identityv1.RegisterPermissionsRequest) (*identityv1.RegisterPermissionsResponse, error) {
	svc := strings.TrimSpace(req.GetService())
	if svc == "" || strings.ContainsAny(svc, ":*") {
		return nil, apperror.InvalidArgument("service is required").WithReason("service_required")
	}
	if reservedServices[svc] {
		return nil, apperror.PermissionDenied("the permissions of " + svc + " are not registered by a service").WithReason("service_reserved")
	}
	if p := authn.FromContext(ctx); p != nil {
		id := p.ClientID
		if id == "" {
			id = p.Subject
		}
		c, err := s.Store.ClientByID(ctx, id)
		if err != nil || c.Resource != svc {
			return nil, apperror.PermissionDenied("a service registers only the permissions of its own namespace").WithReason("foreign_namespace")
		}
	}
	defs := make([]store.PermissionDef, 0, len(req.GetPermissions()))
	for _, d := range req.GetPermissions() {
		defs = append(defs, store.PermissionDef{Name: d.GetName(), Description: strings.TrimSpace(d.GetDescription()), RenamedFrom: d.GetRenamedFrom()})
	}
	res, err := s.Store.SyncPermissions(ctx, svc, defs)
	if err != nil {
		return nil, toErr(err)
	}
	logSync(s.Log, svc, res)
	return &identityv1.RegisterPermissionsResponse{
		Inserted: int32(res.Inserted), Updated: int32(res.Updated), Retired: int32(res.Retired), Deleted: int32(res.Deleted), Renamed: int32(res.Renamed),
	}, nil
}

// logSync writes one line per change of a sync.
func logSync(log *zap.Logger, svc string, res *store.SyncResult) {
	if log == nil {
		return
	}
	for _, line := range res.Log {
		log.Info("permission sync", zap.String("service", svc), zap.String("change", line))
	}
}
