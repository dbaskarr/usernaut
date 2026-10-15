package groupmembers

import (
	"context"
	"time"

	v1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/clients/ldap/types"
	"github.com/redhat-data-and-ai/usernaut/pkg/logger"
)

// Client is the member-source surface needed to resolve query-based group membership.
type Client interface {
	BuildLDAPQueryString(ctx context.Context, query *v1alpha1.LDAPQuery) (string, error)
	GetQueryMembers(ctx context.Context, query string, attributes []string) (types.QueryMembers, error)
	GetBulkUserLDAPData(ctx context.Context, userIDs []string) (map[string]map[string]interface{}, error)
}

// Service resolves a Group CR membership query into member UIDs
// (IR expansion, manager options, etc.).
type Service struct {
	Client Client
}

// New returns a Service that uses the given client.
func New(client Client) *Service {
	return &Service{Client: client}
}

// Members returns the final member UID list for a membership query.
// Search/expansion uses FilterOptions (with root options fallbacks for include_indirect_reports
// and include_manager). ldap_query.result_options transforms are applied afterward.
func (s *Service) Members(ctx context.Context, query *v1alpha1.LDAPQuery) ([]string, error) {
	members, err := s.fetchQueryMembers(ctx, query)
	if err != nil {
		return nil, err
	}

	managers := make(types.QueryMembers, 0, len(members))
	if queryHasIndirectReports(query) || queryHasOnlyManagers(query) {
		members, managers, err = s.expandReports(ctx, query, members, queryHasIndirectReports(query))
		if err != nil {
			return nil, err
		}
	}

	// include_manager filter UIDs are UID-only until verified via bulk LDAP.
	managersInQuery := extractManagersInfoFromQuery(query)
	if len(managersInQuery) > 0 {
		managersInQuery, err = s.fetchBulkUserLDAPData(ctx, managersInQuery.UIDs())
		if err != nil {
			return nil, err
		}
	}

	managers = append(managers, managersInQuery...)
	members = append(members, managersInQuery...)

	if queryHasOnlyManagers(query) {
		members = managers
	}

	resultOptions := queryResultOptions(query)
	switch {
	case resultOptions.IncludeOnlyManagersOfMembers:
		members = members.Managers()
	case resultOptions.IncludeManagersOfMembers:
		members = append(members, members.Managers()...)
	}

	return members.Dedupe().UIDs(), nil
}

// fetchQueryMembers runs a single LDAP search for the query (no report expansion).
func (s *Service) fetchQueryMembers(ctx context.Context, query *v1alpha1.LDAPQuery) (types.QueryMembers, error) {
	log := logger.Logger(ctx).WithField("fetching query members", query)

	log.WithField("ldap_query", query).Info("building query string from YAML")
	queryString, err := s.Client.BuildLDAPQueryString(ctx, query)
	if err != nil {
		log.WithError(err).Error("failed to build ldap query from spec")
		return nil, err
	}
	log.WithField("query_string", queryString).Info("query string built successfully")

	attrs := []string{"uid"}
	resultOptions := queryResultOptions(query)
	if resultOptions.IncludeOnlyManagersOfMembers || resultOptions.IncludeManagersOfMembers {
		attrs = append(attrs, "manager")
	}

	var members types.QueryMembers
	for attempt := 1; attempt <= 3; attempt++ {
		members, err = s.Client.GetQueryMembers(ctx, queryString, attrs)
		if err == nil {
			break
		}
		log.WithError(err).WithField("attempt", attempt).Warn("error fetching users from LDAP using the query")
		if attempt < 3 {
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

// expandReports walks baseMembers iteratively and collects people who have reports.
// When expandIndirect is true, reports are merged into the member set and enqueued.
// When false, only managers among baseMembers are returned and the member set is unchanged.
func (s *Service) expandReports(
	ctx context.Context,
	query *v1alpha1.LDAPQuery,
	baseMembers types.QueryMembers,
	expandIndirect bool,
) (members types.QueryMembers, managers types.QueryMembers, err error) {
	log := logger.Logger(ctx)
	if expandIndirect {
		log.Info("has manager filter with include_indirect_reports, fetching indirect reports")
	} else {
		log.Info("include_only_managers set without indirect reports; finding managers among members")
	}

	members = append(types.QueryMembers(nil), baseMembers...)
	visited := make(map[string]struct{}, len(baseMembers))
	queue := append(types.QueryMembers(nil), baseMembers...)

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		member := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, seen := visited[member.UID]; seen {
			log.WithField("member", member).Debug("skipping already-expanded member to avoid cycle")
			continue
		}
		visited[member.UID] = struct{}{}

		// Direct reports only — expansion stays in this loop, not in fetchQueryMembers.
		reports, err := s.fetchQueryMembers(ctx, buildDirectReportsQuery(query, member.UID, expandIndirect))
		if err != nil {
			log.WithError(err).WithField("manager", member).Error("error fetching reports")
			continue
		}
		if len(reports) == 0 {
			continue
		}

		log.WithField("manager", member).WithField("reports", reports).Info("reports found")
		managers = append(managers, member)
		if expandIndirect {
			members = append(members, reports...)
			queue = append(queue, reports...)
		}
	}

	return members.Dedupe(), managers.Dedupe(), nil
}

// fetchBulkUserLDAPData loads manager DNs for the given UIDs via GetBulkUserLDAPData.
// UIDs not returned by LDAP are omitted.
func (s *Service) fetchBulkUserLDAPData(ctx context.Context, uids []string) (types.QueryMembers, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	log := logger.Logger(ctx)

	bulkData, err := s.Client.GetBulkUserLDAPData(ctx, uids)
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

func queryResultOptions(query *v1alpha1.LDAPQuery) v1alpha1.LDAPQueryResultOptions {
	if query == nil || query.ResultOptions == nil {
		return v1alpha1.LDAPQueryResultOptions{}
	}
	return *query.ResultOptions
}

// buildDirectReportsQuery returns the LDAP query used to fetch direct reports for managerUID.
// Without IR: a plain manager-equals probe.
// With IR: rewrite manager filters in the original tree (other constraints kept); options are
// omitted so fetch stays a single-level search — the caller expands iteratively.
func buildDirectReportsQuery(
	query *v1alpha1.LDAPQuery,
	managerUID string,
	expandIndirect bool,
) *v1alpha1.LDAPQuery {
	if !expandIndirect {
		return &v1alpha1.LDAPQuery{
			Operator: "and",
			Filters: []v1alpha1.LDAPFilter{
				{Key: "manager", Criteria: "equals", Value: managerUID},
			},
		}
	}

	return &v1alpha1.LDAPQuery{
		Operator: query.Operator,
		Filters:  replaceManagerInFilters(query.Filters, managerUID, query.Options),
	}
}
