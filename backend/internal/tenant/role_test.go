package tenant_test

import (
	"testing"

	"github.com/pitercoding/aktenlens/backend/internal/tenant"
)

func TestParseRole(t *testing.T) {
	cases := []struct {
		input string
		want  tenant.Role
		ok    bool
	}{
		{"owner", tenant.RoleOwner, true},
		{"admin", tenant.RoleAdmin, true},
		{"member", tenant.RoleMember, true},

		// Roles are exact: these are what the database stores.
		{"", "", false},
		{"Owner", "", false},
		{"ADMIN", "", false},
		{" admin", "", false},
		{"superuser", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := tenant.ParseRole(tc.input)

			if ok != tc.ok || got != tc.want {
				t.Fatalf("ParseRole(%q) = (%q, %v), want (%q, %v)",
					tc.input, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestRoleAtLeast(t *testing.T) {
	const (
		owner  = tenant.RoleOwner
		admin  = tenant.RoleAdmin
		member = tenant.RoleMember
	)

	cases := []struct {
		name string
		role tenant.Role
		min  tenant.Role
		want bool
	}{
		{"owner can do owner things", owner, owner, true},
		{"owner can do admin things", owner, admin, true},
		{"owner can do member things", owner, member, true},

		{"admin cannot do owner things", admin, owner, false},
		{"admin can do admin things", admin, admin, true},
		{"admin can do member things", admin, member, true},

		{"member cannot do owner things", member, owner, false},
		{"member cannot do admin things", member, admin, false},
		{"member can do member things", member, member, true},

		// Fail closed: anything unknown is denied.
		{"empty role is denied", "", member, false},
		{"unknown role is denied", "superuser", member, false},
		{"unknown required level denies even the owner", owner, "superuser", false},
		{"empty required level denies even the owner", owner, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.role.AtLeast(tc.min); got != tc.want {
				t.Fatalf("%q.AtLeast(%q) = %v, want %v", tc.role, tc.min, got, tc.want)
			}
		})
	}
}
