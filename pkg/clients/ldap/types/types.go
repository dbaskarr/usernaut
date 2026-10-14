package types

import (
	"strings"
)

// QueryMember is one LDAP search result used for group membership resolution.
type QueryMember struct {
	UID     string
	Manager string // raw manager DN (or empty)
}

type QueryMembers []QueryMember

// UIDs returns the UID of each query member.
func (q QueryMembers) UIDs() []string {
	uids := make([]string, 0, len(q))
	for _, member := range q {
		if member.UID == "" {
			continue
		}
		uids = append(uids, member.UID)
	}
	return uids
}

// Dedupe returns members with unique UIDs, preserving first occurrence.
func (q QueryMembers) Dedupe() QueryMembers {
	seen := make(map[string]struct{}, len(q))
	deduped := make(QueryMembers, 0, len(q))
	for _, member := range q {
		if member.UID == "" {
			continue
		}
		if _, ok := seen[member.UID]; ok {
			continue
		}
		seen[member.UID] = struct{}{}
		deduped = append(deduped, member)
	}
	return deduped
}

// Managers returns unique manager UIDs parsed from each member's Manager DN.
func (q QueryMembers) Managers() QueryMembers {
	managers := make(QueryMembers, 0, len(q))
	seen := make(map[string]struct{}, len(q))
	for _, member := range q {
		mgrUID := uidFromManagerDN(member.Manager)
		if mgrUID == "" {
			continue
		}
		if _, ok := seen[mgrUID]; ok {
			continue
		}
		seen[mgrUID] = struct{}{}
		managers = append(managers, QueryMember{UID: mgrUID})
	}
	return managers
}

// MembersWithoutManagerDetail returns members without manager detail.
func (q QueryMembers) MembersWithoutManagerDetail() QueryMembers {
	members := make(QueryMembers, 0, len(q))
	for _, member := range q {
		if member.Manager == "" {
			members = append(members, member)
		}
	}
	return members
}

// FillManagerDetails returns a copy of q with empty Manager fields filled from details
// (matched by UID). Existing Manager values are left unchanged.
func (q QueryMembers) FillManagerDetails(details QueryMembers) QueryMembers {
	if len(q) == 0 || len(details) == 0 {
		return q
	}
	byUID := make(map[string]string, len(details))
	for _, d := range details {
		if d.UID == "" || d.Manager == "" {
			continue
		}
		byUID[d.UID] = d.Manager
	}
	if len(byUID) == 0 {
		return q
	}
	out := make(QueryMembers, len(q))
	copy(out, q)
	for i := range out {
		if out[i].Manager != "" {
			continue
		}
		if mgr, ok := byUID[out[i].UID]; ok {
			out[i].Manager = mgr
		}
	}
	return out
}

func uidFromManagerDN(manager string) string {
	manager = strings.TrimSpace(manager)
	if manager == "" {
		return ""
	}
	lower := strings.ToLower(manager)
	idx := strings.Index(lower, "uid=")
	if idx < 0 {
		if !strings.Contains(manager, "=") {
			return manager
		}
		return ""
	}
	rest := manager[idx+4:]
	if comma := strings.Index(rest, ","); comma >= 0 {
		rest = rest[:comma]
	}
	return strings.TrimSpace(rest)
}
