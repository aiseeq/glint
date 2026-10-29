package dbrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValueSetDriftSQL_RepeatedSet(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM withdrawals w WHERE w.status IN ('pending','approved','processing')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM withdrawals WHERE status IN ('processing','pending','approved')`\n",
		"c.go": "package data\nconst c = `SELECT count(*) FROM withdrawals WHERE status IN ('approved','pending','processing')`\n",
	}
	found := valueSetDriftFindings(t, files)
	require.Len(t, found, 1)
	assert.Equal(t, "c.go", found[0].File)
	assert.Contains(t, found[0].Message, "written by hand in 3 queries")
	assert.Contains(t, found[0].Message, "a.go:2, b.go:2")

	delete(files, "c.go")
	assert.Empty(t, valueSetDriftFindings(t, files))
}

func TestValueSetDriftSQL_Schema(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM public.jobs WHERE status IN ('a','b')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM public.jobs WHERE status IN ('a','b')`\n",
		"c.go": "package data\nconst c = `SELECT * FROM private.jobs WHERE status IN ('a','c')`\n",
		"d.go": "package data\nconst d = `SELECT * FROM private.jobs WHERE status IN ('a','c')`\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))
}

func TestValueSetDriftSQL_ListWithParam(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM jobs WHERE status IN ('a','b',$1)`\n",
		"b.go": "package data\nconst b = `SELECT * FROM jobs WHERE status IN ('a','b')`\n",
		"c.go": "package data\nconst c = `SELECT * FROM jobs WHERE status IN ('a','b')`\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))
}

func TestValueSetDriftSQL_SchemaRelnameQualifier(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM public.jobs WHERE jobs.status IN ('a','b')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM public.jobs WHERE jobs.status IN ('a','b')`\n",
		"c.go": "package data\nconst c = `SELECT * FROM public.jobs WHERE jobs.status IN ('a','b')`\n",
	}
	found := valueSetDriftFindings(t, files)
	require.Len(t, found, 1)
	assert.Equal(t, "c.go", found[0].File)
}

func TestValueSetDriftSQL_NotNested(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM transactions WHERE status IN ('a','b','c')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM transactions WHERE status IN ('a','d')`\n",
		"c.go": "package data\nconst c = `SELECT * FROM transactions WHERE status IN ('a','d')`\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))
}

func TestValueSetDriftSQL_OneValueApart(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM withdrawals w WHERE w.status IN ('processing','approved','pending')`\n",
		"c.go": "package data\nconst c = `SELECT count(*) FROM withdrawals WHERE status IN ('pending','processing')`\n",
	}
	found := valueSetDriftFindings(t, files)
	require.Len(t, found, 1)
	assert.Equal(t, "c.go", found[0].File)
	assert.Contains(t, found[0].Message, "differs by one value (approved)")
	assert.Contains(t, found[0].Message, "a.go:2, b.go:2")
}

func TestValueSetDriftSQL_UpdateGuard(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"c.go": "package data\nconst c = `UPDATE withdrawals SET status='rejected' WHERE id = $2 AND status IN ('pending','approved')`\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))
}

func TestValueSetDriftSQL_OtherColumnOrTable(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"c.go": "package data\nconst c = `SELECT * FROM withdrawals WHERE reason IN ('pending','approved','processing')`\n",
		"d.go": "package data\nconst d = `SELECT * FROM orders WHERE status IN ('pending','approved','processing')`\n",
		"e.go": "package data\nconst e = `SELECT * FROM withdrawals WHERE status NOT IN ('pending','approved','processing')`\n",
		"f.go": "package data\nconst f = `SELECT status IN ('pending','approved','processing')`\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))
}

func TestValueSetDriftSQL_TargetListCopies(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM orders WHERE status IN ('paid','overpaid')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM orders WHERE status IN ('overpaid','paid')`\n",
		"c.go": "package data\nconst c = `SELECT CASE WHEN o.status IN ('paid','overpaid') THEN 1 ELSE 0 END FROM orders o`\n",
		"d.go": "package data\nconst d = `SELECT COUNT(o.id) FILTER (WHERE o.status IN ('paid','overpaid')) FROM orders o`\n",
	}
	found := valueSetDriftFindings(t, files)
	require.Len(t, found, 2)
	assert.ElementsMatch(t, []string{"c.go", "d.go"}, []string{found[0].File, found[1].File})
}

func TestValueSetDriftSQL_UnionOfHandledCases(t *testing.T) {
	const query = `SELECT COUNT(*) FILTER (WHERE status = 'WAITING' AND updated_at < $1),
	COUNT(*) FILTER (WHERE status = 'UNKNOWN' AND updated_at < $2),
	COUNT(*) FILTER (WHERE status = 'COOLING' AND cooling_until < $3)
	FROM transactions WHERE status IN ('WAITING', 'UNKNOWN', 'COOLING')`
	files := map[string]string{
		"a.go": "package data\nconst a = `SELECT * FROM transactions WHERE status IN ('WAITING','UNKNOWN')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM transactions WHERE status IN ('UNKNOWN','WAITING')`\n",
		"c.go": "package data\nconst c = " + "`" + query + "`" + "\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))

	files["c.go"] = "package data\nconst c = `SELECT COUNT(*) FROM transactions WHERE status IN ('WAITING', 'UNKNOWN', 'COOLING')`\n"
	require.Len(t, valueSetDriftFindings(t, files), 1)
}

func TestValueSetDriftSQL_SameLiteralCountsOnce(t *testing.T) {
	const repeated = "t.kind IN ('swap','trade','bridge')"
	const query = "SELECT SUM(v) FILTER (WHERE " + repeated + "), COUNT(*) FILTER (WHERE " + repeated + "), BOOL_OR(" + repeated + "), MAX(v) FILTER (WHERE " + repeated + ") FROM transactions t"
	files := map[string]string{
		"a.go": "package data\nconst a = " + "\"" + query + "\"" + "\n",
	}
	assert.Empty(t, valueSetDriftFindings(t, files))

	files["b.go"] = "package data\nconst b = \"SELECT COUNT(*) FROM transactions t WHERE t.kind IN ('trade','swap','bridge')\"\n"
	files["c.go"] = "package data\nconst c = \"SELECT COUNT(*) FROM transactions t WHERE t.kind IN ('swap','bridge','trade')\"\n"
	found := valueSetDriftFindings(t, files)
	require.Len(t, found, 1)
	assert.Equal(t, "c.go", found[0].File)
	assert.Contains(t, found[0].Message, "written by hand in 3 queries")
	assert.Contains(t, found[0].Message, "a.go:2, b.go:2")
}

func TestValueSetDriftSQL_GoListSuggested(t *testing.T) {
	files := map[string]string{
		"a.go": "package data\nvar withdrawalStatuses = []string{\"pending\", \"approved\", \"processing\"}\nconst a = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"b.go": "package data\nconst b = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
		"c.go": "package data\nconst c = `SELECT * FROM withdrawals WHERE status IN ('pending','approved','processing')`\n",
	}
	found := valueSetDriftFindings(t, files)
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "withdrawalStatuses")
}
