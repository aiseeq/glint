package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const deleteGuardWhitelist = `CREATE OR REPLACE FUNCTION public.guard_user_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- test users only: @shop-test.local and the old fixtures on @test.com
    IF OLD.email NOT LIKE '%@shop-test.local'
       AND OLD.email NOT LIKE '%@test.com'
       AND OLD.email NOT LIKE '%@example.com'
       AND OLD.email NOT LIKE '%@qa-test.com'
       AND OLD.email NOT LIKE 'test-%' THEN
        RAISE EXCEPTION 'refusing to delete a real user %', OLD.email;
    END IF;
    RETURN OLD;
END;
$$;
`

// A trigger guarding real users from deletion lets test users through by
// their address: a registrable domain named as a test one (@test.com,
// @qa-test.com) or a test- local part on any domain also matches real
// people, and the guard deletes them. A later migration that redefines the
// function leaves the old body dead: only the live definition is reported,
// and a down migration restoring the old body is the rollback's business.
func TestTestEmailRegistrableDomainInSQL(t *testing.T) {
	files := map[string]string{
		"storage/migrations/000005_guard.up.sql":   deleteGuardWhitelist,
		"storage/migrations/000005_guard.down.sql": "DROP FUNCTION public.guard_user_delete();\n",
		"storage/migrations/000007_other.up.sql":   "DELETE FROM sessions WHERE email LIKE '%@app-test.com';\n",
		"cmd/app/main.go":                          "package main\n\nfunc main() {}\n",
	}
	assert.Equal(t, []string{
		"storage/migrations/000005_guard.up.sql:10",
		"storage/migrations/000005_guard.up.sql:11",
		"storage/migrations/000005_guard.up.sql:8",
		"storage/migrations/000007_other.up.sql:1",
	}, projectFileFindings(t, NewTestEmailRegistrableDomainRule(), files))

	files["storage/migrations/000009_guard_reserved_domain.up.sql"] = `CREATE OR REPLACE FUNCTION public.guard_user_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF lower(OLD.email) NOT LIKE '%@shop-test.local' THEN
        RAISE EXCEPTION 'refusing to delete a real user %', OLD.email;
    END IF;
    RETURN OLD;
END;
$$;
`
	files["storage/migrations/000009_guard_reserved_domain.down.sql"] = deleteGuardWhitelist
	assert.Equal(t, []string{"storage/migrations/000007_other.up.sql:1"},
		projectFileFindings(t, NewTestEmailRegistrableDomainRule(), files))
}
