package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPredicatesConjunctsNormalize(t *testing.T) {
	a := ConditionConjuncts(`u.status NOT IN ('system','deleted') AND u.kind = 'client'`)
	b := ConditionConjuncts(`STATUS not in ('deleted', 'system') and kind = 'client'`)
	require.Len(t, a, 2)
	require.Len(t, b, 2)
	require.Equal(t, a[0].Norm, b[0].Norm)
	require.Equal(t, a[1].Norm, b[1].Norm)
	or := ConditionConjuncts(`status = 'active' OR status = 'pending'`)
	require.Len(t, or, 1)
}
func TestPredicatesNestedLevels(t *testing.T) {
	got := Conjuncts(`WITH recent AS (SELECT id FROM users WHERE status = 'active') SELECT 1 FROM recent r WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = r.id AND o.state = 'open')`)
	require.GreaterOrEqual(t, len(got), 3)
	fragment := ConditionConjuncts(`EXISTS (SELECT 1 FROM orders WHERE state = 'open') AND status = 'active'`)
	require.Len(t, fragment, 2)
}
func TestPredicatesInLists(t *testing.T) {
	got := InLists(`SELECT * FROM users u WHERE u.status IN ('b','a') AND u.kind NOT IN ('x','y') AND u.state = ANY(ARRAY['one','two']) AND u.label = ANY('{"a b", c}')`)
	require.Len(t, got, 4)
	require.Equal(t, "users", got[0].Table)
	require.Equal(t, []string{"a", "b"}, got[0].Values)
	require.True(t, got[1].Negated)
	require.Equal(t, []string{"a b", "c"}, got[3].Values)
	ambiguous := InLists(`SELECT * FROM users u JOIN teams t ON true WHERE status IN ('a','b')`)
	require.Len(t, ambiguous, 1)
	require.Empty(t, ambiguous[0].Table)
}

func TestPredicatesInListsLevels(t *testing.T) {
	got := InLists(`WITH recent AS (SELECT * FROM users u WHERE u.status IN ('a','b')) SELECT * FROM orders o WHERE o.user_id IN (SELECT x.id FROM withdrawals x WHERE x.state IN ('c','d')) UNION SELECT * FROM staff s WHERE s.kind IN ('e','f')`)
	require.Len(t, got, 3)
	require.Equal(t, []string{"users", "withdrawals", "staff"}, []string{got[0].Table, got[1].Table, got[2].Table})
	update := InLists(`UPDATE withdrawals w SET state = 'x' WHERE id = $2 AND (status IN ('a','b') OR closed)`)
	require.Len(t, update, 1)
	require.Equal(t, "withdrawals", update[0].Table)
	require.True(t, update[0].GuardedByKey)
	deleted := InLists(`DELETE FROM orders WHERE status IN ('a','b')`)
	require.Len(t, deleted, 1)
	require.Equal(t, "orders", deleted[0].Table)
}
func TestPredicatesUpdateGuard(t *testing.T) {
	transition := Conjuncts(`UPDATE users SET status = 'deleted' WHERE id = $1 AND status != 'deleted'`)
	require.Len(t, transition, 2)
	require.True(t, transition[1].GuardedByKey)
	update := Conjuncts(`UPDATE users SET status = $1 WHERE id = $2 AND status IN ('a','b')`)
	require.Len(t, update, 2)
	require.True(t, update[0].GuardedByKey)
	require.True(t, InLists(`UPDATE users SET status = $1 WHERE id = $2 AND status IN ('a','b')`)[0].GuardedByKey)
	selects := Conjuncts(`SELECT 1 FROM users WHERE status IN ('a','b')`)
	require.Len(t, selects, 1)
	require.False(t, selects[0].GuardedByKey)
}
func TestPredicatesUnparsable(t *testing.T) {
	require.Empty(t, Conjuncts(`not valid sql ???`))
	require.Empty(t, ConditionConjuncts(`status IN (`))
	require.Empty(t, InLists(`SELECT FROM`))
}

func TestPredicatesNormalizeExists(t *testing.T) {
	first := ConditionConjuncts(`EXISTS (SELECT 1 FROM transactions t WHERE t.user_id = u.id AND t.type = 'deposit' AND t.status = 'completed')`)
	second := ConditionConjuncts(`EXISTS (SELECT 1 FROM transactions tx WHERE tx.status = 'completed' AND tx.type = 'deposit' AND tx.user_id = u.id)`)
	changed := ConditionConjuncts(`EXISTS (SELECT 1 FROM transactions tx WHERE tx.status = 'pending' AND tx.type = 'deposit' AND tx.user_id = u.id)`)
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	require.Len(t, changed, 1)
	require.Equal(t, first[0].Norm, second[0].Norm)
	require.NotEqual(t, first[0].Norm, changed[0].Norm)
}
