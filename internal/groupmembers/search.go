package groupmembers

import (
	"context"
	"time"

	v1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/clients/ldap/types"
	"github.com/redhat-data-and-ai/usernaut/pkg/logger"
)

const ldapSearchRetries = 3

// fetchQueryMembers runs a single LDAP search for the query (no report expansion).
func (s *Service) fetchQueryMembers(ctx context.Context, query *v1alpha1.LDAPQuery) (types.QueryMembers, error) {
	log := logger.Logger(ctx).WithField("fetching query members", query)

	log.WithField("ldap_query", query).Info("building query string from YAML")
	queryString, err := s.client.BuildLDAPQueryString(ctx, query)
	if err != nil {
		log.WithError(err).Error("failed to build ldap query from spec")
		return nil, err
	}
	log.WithField("query_string", queryString).Info("query string built successfully")

	var members types.QueryMembers
	for attempt := 1; attempt <= ldapSearchRetries; attempt++ {
		members, err = s.client.GetQueryMembers(ctx, queryString, []string{"uid", "manager"})
		if err == nil {
			break
		}
		log.WithError(err).WithField("attempt", attempt).Warn("error fetching users from LDAP using the query")
		if attempt < ldapSearchRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	if err != nil {
		log.WithError(err).Error("failed to fetch users from LDAP using the query after retries")
		return nil, err
	}

	if len(members) == 0 {
		log.Info("no users found in LDAP using the query")
		return nil, nil
	}
	log.WithField("query_members_count", len(members)).Info("query members fetched successfully")
	return members.Dedupe(), nil
}

// fetchUsersByUID loads UID + manager for the given UIDs via bulk LDAP.
// UIDs absent from the bulk response are omitted.
func (s *Service) fetchUsersByUID(ctx context.Context, uids []string) (types.QueryMembers, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	log := logger.Logger(ctx)

	bulkData, err := s.client.GetBulkUserLDAPData(ctx, uids)
	if err != nil {
		log.WithError(err).Error("failed to bulk-fetch manager details")
		return nil, err
	}

	out := make(types.QueryMembers, 0, len(bulkData))
	for _, uid := range uids {
		userData, ok := bulkData[uid]
		if !ok {
			continue
		}
		mgr, _ := userData["manager"].(string)
		out = append(out, types.QueryMember{UID: uid, Manager: mgr})
	}
	return out, nil
}
