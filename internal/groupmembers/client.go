package groupmembers

import (
	"context"

	v1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/clients/ldap/types"
)

// Client is the LDAP surface needed to resolve query-based group membership.
// Kept as one interface because every implementation used today provides all three.
type Client interface {
	BuildLDAPQueryString(ctx context.Context, query *v1alpha1.LDAPQuery) (string, error)
	GetQueryMembers(ctx context.Context, query string, attributes []string) (types.QueryMembers, error)
	GetBulkUserLDAPData(ctx context.Context, userIDs []string) (map[string]map[string]interface{}, error)
}
