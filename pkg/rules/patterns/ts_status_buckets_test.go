package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Records counted into a total and spread over buckets by status with no
// final else: a status no branch names counts in the total and in no bucket,
// and the cards stop adding up to it.
func TestStatusBucketsWithoutRest(t *testing.T) {
	rule := statusBucketsWithoutRestRule()
	source := `export function stats(totals: Total[]) {
  const result = { total: bucket(), pending: bucket(), done: bucket(), failed: bucket() }
  for (const t of totals) {
    result.total.count += t.count
    if (t.status === 'pending') {
      result.pending.count += t.count
    } else if (t.status === 'completed') {
      result.done.count += t.count
    } else if (FAILED.has(t.status)) {
      result.failed.count += t.count
    }
  }
  return result
}

export function withRest(totals: Total[]) {
  const result = { total: bucket(), pending: bucket(), done: bucket(), other: bucket() }
  for (const t of totals) {
    result.total.count += t.count
    if (t.status === 'pending') {
      result.pending.count += t.count
    } else if (t.status === 'completed') {
      result.done.count += t.count
    } else {
      result.other.count += t.count
    }
  }
  return result
}

export function noTotal(items: Item[]) {
  let pending = 0, done = 0, failed = 0
  for (const t of items) {
    if (t.status === 'pending') {
      pending += 1
    } else if (t.status === 'completed') {
      done += 1
    } else if (t.status === 'failed') {
      failed += 1
    }
  }
  return { pending, done, failed }
}
`
	assert.Equal(t, []string{"src/Stats.tsx:5"}, linesOf(t, rule, "src/Stats.tsx", source))
}
