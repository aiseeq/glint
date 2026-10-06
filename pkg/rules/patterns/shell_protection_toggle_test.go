package patterns

import "testing"

// A migration script turns the schema-protection trigger off and back on
// with the output thrown away and the failure turned into success: a failed
// DISABLE leaves migrations blocked, a failed ENABLE leaves the protection
// off, and neither says a word. A toggle whose failure stops the script, or
// is at least printed, is fine.
func TestShellProtectionToggleFailureIgnored(t *testing.T) {
	shellWanted(t, "shell-check-failure-ignored", "migrate.sh", `#!/bin/bash
set -euo pipefail
psql -d "$DB" -c "ALTER EVENT TRIGGER guard_schema DISABLE;" > /dev/null 2>&1 || true # want
cleanup() {
    psql -d "$DB" -c "ALTER EVENT TRIGGER guard_schema ENABLE;" > /dev/null 2>&1 || true # want
}
trap cleanup EXIT
trap 'psql -d "$DB" -c "ALTER TABLE orders ENABLE TRIGGER audit_orders;" >/dev/null 2>&1 || true' EXIT # want
psql -v ON_ERROR_STOP=1 -d "$DB" -c "ALTER EVENT TRIGGER guard_schema DISABLE;" > /dev/null
psql -d "$DB" -c "ALTER EVENT TRIGGER guard_schema ENABLE;" || echo "warning: guard stays off" >&2
psql -d "$DB" -c "SELECT 1" > /dev/null 2>&1 || true
`)
}
