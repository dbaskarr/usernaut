package groupmembers

import (
	"context"

	v1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/clients/ldap/types"
)

// Service resolves a Group CR membership query into member UIDs.
// It orchestrates search, optional report expansion, include_manager enrichment,
// and result_options transforms — each step lives in its own file.
type Service struct {
	client Client
}

// New returns a Service that uses the given client.
func New(client Client) *Service {
	return &Service{client: client}
}

// Members returns the final member UID list for a membership query.
func (s *Service) Members(ctx context.Context, query *v1alpha1.LDAPQuery) ([]string, error) {
	members, err := s.fetchQueryMembers(ctx, query)
	if err != nil {
		return nil, err
	}

	var managers types.QueryMembers
	if queryHasIndirectReports(query) || queryResultOptions(query).IncludeOnlyManagers {
		members, managers, err = s.expandReports(ctx, query, members, queryHasIndirectReports(query))
		if err != nil {
			return nil, err
		}
	}

	members, managers, err = s.addManagersFromQuery(ctx, query, members, managers)
	if err != nil {
		return nil, err
	}

	return applyResultOptions(members, managers, query).Dedupe().UIDs(), nil
}
