package groupmembers

import (
	"context"

	v1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/clients/ldap/types"
	"github.com/redhat-data-and-ai/usernaut/pkg/logger"
)

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
