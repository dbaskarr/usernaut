package groupmembers

import (
	"context"

	v1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/clients/ldap/types"
)

// enrichWithManagerInfo pulls include_manager UIDs from the query, verifies them
// via bulk LDAP, and merges those found into the member and manager result sets.
func (s *Service) addManagersFromQuery(
	ctx context.Context,
	query *v1alpha1.LDAPQuery,
	members, managers types.QueryMembers,
) (types.QueryMembers, types.QueryMembers, error) {
	managersInQuery := extractManagersInfoFromQuery(query)
	if len(managersInQuery) == 0 {
		return members, managers, nil
	}

	resultOptions := queryResultOptions(query)

	if resultOptions.IncludeOnlyManagersOfMembers || resultOptions.IncludeManagersOfMembers {
		var err error
		managersInQuery, err = s.fetchUsersByUID(ctx, managersInQuery.UIDs())
		if err != nil {
			return nil, nil, err
		}
	}

	return append(members, managersInQuery...), append(managers, managersInQuery...), nil
}

// selectMembers applies include_only_managers and of-members result_options.
func selectMembers(members, managers types.QueryMembers, query *v1alpha1.LDAPQuery) types.QueryMembers {
	if queryHasOnlyManagers(query) {
		members = managers
	}
	return applyOfMembersOptions(members, queryResultOptions(query))
}

// applyOfMembersOptions transforms the member set using of-members result_options.
func applyOfMembersOptions(members types.QueryMembers, opts v1alpha1.LDAPQueryResultOptions) types.QueryMembers {
	if opts.IncludeManagersOfMembers {
		members = append(members, members.Managers()...)
	}

	if opts.IncludeOnlyManagersOfMembers {
		return members.Managers()
	}

	return members
}
