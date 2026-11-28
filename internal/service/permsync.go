package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/huponx/gocommon/grpcserver"
	"github.com/huponx/identity/internal/store"
	billv1 "github.com/huponx/protogen/go/bill/v1"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	systemv1 "github.com/huponx/protogen/go/system/v1"
	"go.uber.org/zap"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// OwnPermissionFiles are the permissions.proto files identity syncs itself at start: its own, and those of the
// services that have no process to register them (bill is a web app, system is checked by the gateway).
var OwnPermissionFiles = []protoreflect.FileDescriptor{
	identityv1.File_identity_v1_permissions_proto,
	billv1.File_bill_v1_permissions_proto,
	systemv1.File_system_v1_permissions_proto,
}

// SyncOwnPermissions saves the permissions of OwnPermissionFiles into the catalog, one transaction per service,
// then applies the removal rule to the rows nobody owns. A failure is returned: identity does not start with a
// catalog it could not bring up to date.
func SyncOwnPermissions(ctx context.Context, st *store.Store, log *zap.Logger) error {
	byService := map[string][]store.PermissionDef{}
	for _, d := range grpcserver.DeclaredPermissions(OwnPermissionFiles...) {
		svc, _, _ := strings.Cut(d.Name, ":")
		byService[svc] = append(byService[svc], store.PermissionDef{Name: d.Name, Description: d.Description, RenamedFrom: d.RenamedFrom})
	}
	names := make([]string, 0, len(byService))
	for svc := range byService {
		names = append(names, svc)
	}
	sort.Strings(names)
	for _, svc := range names {
		res, err := st.SyncPermissions(ctx, svc, byService[svc])
		if err != nil {
			return fmt.Errorf("sync the permissions of %s: %w", svc, err)
		}
		logSync(log, svc, res)
	}
	res, err := st.RetireUnclaimed(ctx)
	if err != nil {
		return fmt.Errorf("retire the permissions of no service: %w", err)
	}
	logSync(log, "", res)
	return nil
}
