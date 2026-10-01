package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func linesOf(t *testing.T, rule rules.Rule, path, source string) []string {
	t.Helper()
	return foundLines(rule.AnalyzeFile(rulestest.TextFile(t, path, source)))
}

// A Next.js build that skips the type check ships a page that destructures a
// method its context type lacks: the first click fails in production. Lint
// skipped in the build is left out: projects run it as a separate step.
func TestNextConfigIgnoresBuildErrors(t *testing.T) {
	config := `module.exports = {
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: { ignoreDuringBuilds: true },
  images: { unoptimized: true },
}
`
	rule := NewNextConfigIgnoresBuildErrorsRule()
	assert.Equal(t, []string{"web/next.config.js:3"}, linesOf(t, rule, "web/next.config.js", config))
	assert.Empty(t, linesOf(t, rule, "web/other.config.js", config))
}

// A missing setting answered with a warning and a substitute: the page works
// on a value nobody configured.
func TestFrontendWarnedFallback(t *testing.T) {
	rule := NewFrontendWarnedFallbackRule()
	assert.Equal(t, []string{"src/hooks/useAddress.ts:10", "src/hooks/useAddress.ts:4"}, linesOf(t, rule, "src/hooks/useAddress.ts", `export async function load(api: Api) {
  const currency = await api.defaultCurrency()
  if (!currency?.code) {
    logger.warn('Default currency not configured, using USDC fallback')
    return api.address('USDC')
  }
  try {
    return await api.fees()
  } catch (err) {
    logger.warn('Failed to load fees, using defaults', { err })
    return DEFAULT_FEES
  }
}
export function strict(value?: string) {
  if (!value) {
    console.warn('value not configured')
    throw new Error('value is required')
  }
  console.warn('slow response, retrying')
  return value
}
`))
	assert.Equal(t, []string{"app/next.config.js:3"}, linesOf(t, rule, "app/next.config.js", "const usdc = config.usdc[net] || ''\n"+
		"if (!usdc) {\n"+
		"  console.warn(`USDC address не настроен для сети ${net}`)\n"+
		"}\n"))
}

// allSettled turns rejections into data; keeping only the fulfilled ones
// drops the failures without a trace.
func TestAllSettledRejectionsIgnored(t *testing.T) {
	assert.Equal(t, []string{"src/feed.ts:2"}, linesOf(t, NewAllSettledRejectionsIgnoredRule(), "src/feed.ts", `export async function loadAll(types: string[]) {
  const settled = await Promise.allSettled(types.map(load))
  const all: Item[] = []
  for (const r of settled) {
    if (r.status === 'fulfilled') all.push(...r.value)
  }
  return all
}
export async function loadReported(types: string[]) {
  const settled = await Promise.allSettled(types.map(load))
  for (const r of settled) {
    if (r.status === 'rejected') report(r.reason)
  }
}
export function passThrough(types: string[]) {
  return Promise.allSettled(types.map(load))
}
`))
}

// A hand-written .js next to the .ts module wins the resolution of an import
// without an extension and serves stale exports.
func TestJSFileShadowsTSModule(t *testing.T) {
	rule := NewJSFileShadowsTSModuleRule()
	files := []*core.FileContext{
		rulestest.TextFile(t, "e2e/utils/helpers.js", "module.exports = { wait }\n"),
		rulestest.TextFile(t, "e2e/utils/helpers.ts", "export function wait() {}\n"),
		rulestest.TextFile(t, "src/single.js", "export const a = 1\n"),
		rulestest.TextFile(t, "src/widget.tsx", "export const W = () => null\n"),
		rulestest.TextFile(t, "src/widget.js", "export const W = () => null\n"),
		rulestest.TextFile(t, "node_modules/p/index.js", "module.exports = {}\n"),
		rulestest.TextFile(t, "node_modules/p/index.ts", "export {}\n"),
	}
	rule.UseProjectFiles(files)
	var violations []*core.Violation
	for _, f := range files {
		violations = append(violations, rule.AnalyzeFile(f)...)
	}
	assert.Equal(t, []string{"e2e/utils/helpers.js:1", "src/widget.js:1"}, foundLines(violations))
}

// toISOString is the UTC date: a range built from local calendar days
// ("yesterday") lands on the day before for every zone east of UTC.
func TestISODateAsLocalDate(t *testing.T) {
	assert.Equal(t, []string{"src/range.ts:4"}, linesOf(t, NewISODateAsLocalDateRule(), "src/range.ts", `export function defaultRange() {
  const yesterday = new Date()
  yesterday.setDate(yesterday.getDate() - 1)
  const fmt = (d: Date) => d.toISOString().split('T')[0]
  return { to: fmt(yesterday) }
}
export function stamp(at: Date) {
  return at.toISOString().slice(0, 10)
}
`))
}

// The date of the terms is a fact about the document; the time of the page
// view is not.
func TestDocumentDateFromNow(t *testing.T) {
	assert.Equal(t, []string{"src/app/terms/page.tsx:3"}, linesOf(t, NewDocumentDateFromNowRule(), "src/app/terms/page.tsx", `export default function Terms() {
  return (
    <p>Последнее обновление: {new Date().toLocaleDateString('ru-RU')}</p>
  )
}
export function Clock() {
  return <span>{new Date().toLocaleTimeString()}</span>
}
`))
}

// An async IIFE yields a Promise: stored as a value, it reaches the state as
// "[object Promise]" instead of the balance.
func TestAsyncIIFEResultUnawaited(t *testing.T) {
	assert.Equal(t, []string{"src/hooks/useBalance.ts:2"}, linesOf(t, NewAsyncIIFEResultUnawaitedRule(), "src/hooks/useBalance.ts", `export async function refresh(ref: Ref, set: Setter) {
  const fallback = (async () => {
    return ref.current?.value ?? '0'
  })()
  set({ eth: fallback })
  const awaited = await (async () => ref.current)()
  const later = (async () => ref.current)()
  set({ eth: await later, other: awaited })
}
`))
}

// A credential with a literal fallback works on every machine where the
// variable is missing — with the password from the source.
func TestEnvSecretLiteralFallback(t *testing.T) {
	assert.Equal(t, []string{"shared/config/test-config.ts:3", "shared/config/test-config.ts:4"}, linesOf(t, NewEnvSecretLiteralFallbackRule(), "shared/config/test-config.ts", `export const db = {
  host: process.env['TEST_DB_HOST'] || 'localhost',
  password: process.env['TEST_DB_PASSWORD'] || 'devpass',
  dsn: process.env.TEST_DB_DSN || "postgresql://dev:devpass@localhost:5432/app",
  token: process.env.API_TOKEN ?? '',
}
`))
}

// A missing network or fee answered with a made-up value: the admin sees a
// polygon payout with no fee where the record has neither.
func TestDefaultInventsDomainValue(t *testing.T) {
	assert.Equal(t, []string{"src/app/withdrawals/page.tsx:15", "src/app/withdrawals/page.tsx:3", "src/app/withdrawals/page.tsx:4"}, linesOf(t, NewDefaultInventsDomainValueRule(), "src/app/withdrawals/page.tsx", `export function toRow(w: Withdrawal) {
  return {
    network: w.network ?? 'polygon',
    serviceFee: w.serviceFee?.toString() ?? '0',
    clientNumber: w.clientNumber ?? '',
    status: w.status ?? 'unknown',
    shown: w.network || '—',
    label: w.network || 'network not set',
    symbol: row.symbol || '-',
    pending: byStatus('pending')?.amount ?? '0',
    hasDeposit: (m.balance ?? 0) > 0,
  }
}
export class Client {
  async depositAddress(currency: string = 'USDC') {
    return this.get(currency)
  }
  async page(sort: string = 'desc') { return this.get(sort) }
}
`))
}

// A balance field missing from the response read as '0' through ||: the
// dashboard shows a zero balance instead of an error.
func TestDefaultInventsDomainValueOrZero(t *testing.T) {
	assert.Equal(t, []string{"src/lib/dashboard.ts:2", "src/lib/dashboard.ts:3", "src/lib/dashboard.ts:5", "src/lib/dashboard.ts:6"}, linesOf(t, NewDefaultInventsDomainValueRule(), "src/lib/dashboard.ts", `export function stats(balance: Balance, inv: Investment, page: Page) {
  const totalBalance = parseFloat(balance.total || '0')
  const locked = Number(userBalance.locked || 0)
  const count = page.total || 0
  const invested = parseFloat(inv.amount || '0')
  const current = parseFloat(inv.currentValue || inv.amount || '0')
  const hasFee = Number(inv.fee || 0) > 0
  const items = page.feeCount || 0
  return { totalBalance, locked, count, invested, current, hasFee, items }
}
`))
}

// A parser that answers anything it cannot read with 0, used on amounts: a
// broken payload shows as a zero-amount operation.
func TestMissingAmountCoercedToZero(t *testing.T) {
	assert.Equal(t, []string{"src/lib/history.ts:1"}, linesOf(t, NewMissingAmountCoercedToZeroRule(), "src/lib/history.ts", `function parseSafe(value: unknown): number {
  return typeof value === 'number' ? value : 0
}
function parseCount(value: unknown): number {
  return typeof value === 'number' ? value : 0
}
export function row(txn: Txn) {
  return { amount: parseSafe(txn.amount), n: parseCount(txn.items) }
}
`))
}

// A display formatter puts thousands separators into a CSV cell: the
// spreadsheet reads "10 000.00" as text.
func TestCSVCellDisplayFormatter(t *testing.T) {
	rule := NewCSVCellDisplayFormatterRule()
	assert.Equal(t, []string{"src/ops/op-csv.ts:2"}, linesOf(t, rule, "src/ops/op-csv.ts", `export function csvAmount(op: Op): string {
  return formatters.formatAmount(op.amount)
}
export function plain(op: Op): string {
  return formatters.formatAmountPlain(op.amount)
}
`))
	assert.Equal(t, []string{"src/ops/Reports.tsx:3"}, linesOf(t, rule, "src/ops/Reports.tsx", `export function Reports({ months }: Props) {
  const downloadAll = () => {
    const rows = months.map(m => [m.start, formatters.formatAmount(m.yield)])
    downloadCsv('all.csv', buildCsv(header, rows))
  }
  return <td>{formatters.formatAmount(total)}</td>
}
`))
}

// An API that reports the creation time as the time of the last change tells
// the client nothing changed since.
func TestUpdatedAtFromCreatedAt(t *testing.T) {
	ctx := rulestest.GoFile(t, "store/convert.go", `package store

import "time"

type Inv struct{ CreatedAt, UpdatedAt time.Time }
type Resp struct{ CreatedAt, UpdatedAt time.Time }

func updatedAt(i *Inv) time.Time {
	return i.CreatedAt
}

func toResp(i *Inv) Resp {
	return Resp{
		CreatedAt: i.CreatedAt,
		UpdatedAt: updatedAt(i),
	}
}

func direct(i *Inv) Resp {
	return Resp{CreatedAt: i.CreatedAt, UpdatedAt: i.CreatedAt}
}

func right(i *Inv) Resp {
	return Resp{CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt}
}
`)
	assert.Equal(t, []string{"store/convert.go:15", "store/convert.go:20"}, foundLines(NewUpdatedAtFromCreatedAtRule().AnalyzeFile(ctx)))
}
