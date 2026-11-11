package dbrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cacheInputRule interface {
	Name() string
	CacheInputs(root string) (string, error)
}

func migrationRoot(t *testing.T, ddl string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "migrations")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "001.up.sql"), []byte(ddl), 0o600))
	return root
}

// Each rule that reads the schema keys its cached findings by the migration
// bytes: two roots that differ only in a migration give different keys.
func TestSchemaRulesKeyCacheByMigrations(t *testing.T) {
	first := migrationRoot(t, "CREATE TABLE a (id int);")
	second := migrationRoot(t, "CREATE TABLE b (id int);")
	for _, rule := range []cacheInputRule{
		NewSQLUnknownColumnRule(), NewSQLInsertMissingNotNullRule(), NewSQLLimitWithoutOrderRule(),
		NewSQLConstantShadowsColumnRule(), NewSQLTestDDLDuplicatesMigrationRule(), NewSQLGroupBySingleRowRule(),
		NewSQLLinkUpdateIgnoresParentRule(), NewSQLPartialKeyReadRule(), NewExternalReferenceLookupWithoutUniqueIndexRule(),
		NewSQLDeleteReferencedWithoutKeyRule(), NewMoneySummedAcrossCurrenciesRule(), NewSQLMissingRowUncheckedRule(),
		NewSQLCharColumnPadsValueRule(), NewDeltaExportMissesUnlinkRule(),
	} {
		a, err := rule.CacheInputs(first)
		require.NoError(t, err, rule.Name())
		b, err := rule.CacheInputs(second)
		require.NoError(t, err, rule.Name())
		assert.NotEmpty(t, a, rule.Name())
		assert.NotEqual(t, a, b, rule.Name())
	}
}
