// Package tenant holds what belongs to a tenant. For now: the roles of its
// members. It depends on nothing, so any other package can import it.
package tenant

// Role is what a member is allowed to do inside a tenant.
//
// The values must match the CHECK constraint on memberships.role (migration
// 00002). A test in the platform package keeps the two in sync.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// rank orders the roles. Unknown roles get 0, which is never enough.
func (r Role) rank() int {
	switch r {
	case RoleMember:
		return 1
	case RoleAdmin:
		return 2
	case RoleOwner:
		return 3
	default:
		return 0
	}
}

// ParseRole turns the text stored in the database into a Role. It is exact
// (case-sensitive) and returns false for anything that is not a known role.
func ParseRole(s string) (Role, bool) {
	r := Role(s)
	if r.rank() == 0 {
		return "", false
	}

	return r, true
}

// AtLeast reports whether r has at least the power of min: owner > admin >
// member. It fails closed: an unknown r or an unknown min is always false.
func (r Role) AtLeast(min Role) bool {
	return r.rank() > 0 && min.rank() > 0 && r.rank() >= min.rank()
}
