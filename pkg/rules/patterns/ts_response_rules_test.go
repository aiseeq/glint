package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A malformed response answered with an empty list or a zero total shows
// "nothing there" for data that failed to arrive.
func TestTSResponseFieldDefaultsToEmpty(t *testing.T) {
	assert.Equal(t, []string{"frontend/api.ts:11", "frontend/api.ts:5", "frontend/api.ts:6"},
		deployFindings(t, "ts-response-field-defaults-to-empty", map[string]string{
			"frontend/api.ts": `class Api {
  async getPositions(id: string): Promise<{ positions: Position[]; total: number }> {
    const result = await this.makeRequest(` + "`/api/positions?id=${id}`" + `, 'GET') as Record<string, unknown>
    return {
      positions: Array.isArray(result.positions) ? result.positions as Position[] : [],
      total: typeof result.total === 'number' ? result.total : 0,
    }
  }
  async getHistory(id: string) {
    const result = await this.makeRequest('/api/history', 'GET') as Record<string, unknown>
    return { history: Array.isArray(result.history) ? result.history : [] }
  }
}
`,
		}))
	// A checked response, a local value, an optional string, a test.
	assert.Empty(t, deployFindings(t, "ts-response-field-defaults-to-empty", map[string]string{
		"frontend/api.ts": `class Api {
  async getPositions(id: string) {
    const result = await this.makeRequest('/api/positions', 'GET') as Record<string, unknown>
    if (!Array.isArray(result.positions) || typeof result.total !== 'number') {
      throw new Error('malformed positions response')
    }
    return { positions: result.positions as Position[], total: result.total }
  }
}
const tags = Array.isArray(value) ? value : []
const label = typeof user.email === 'string' ? user.email : ''
`,
		"frontend/e2e/api.spec.ts": `const rows = Array.isArray(body.rows) ? body.rows : []
`,
	}))
}

// Number(x).toFixed(2) is a non-empty string even for NaN: the fallback
// after it never shows.
func TestTSCoercedNumberFallbackDead(t *testing.T) {
	assert.Equal(t, []string{"src/page.tsx:2", "src/page.tsx:3", "src/page.tsx:4"},
		deployFindings(t, "ts-coerced-number-fallback-dead", map[string]string{
			"src/page.tsx": `export const Card = ({ summary }: Props) => <div>
  {Number(summary.avgMoic).toFixed(2) || '-'}x
  {parseFloat(summary.tvpi).toLocaleString() ?? '-'}
  {Number(summary.dpi) ?? 0}
</div>
`,
		}))
	assert.Empty(t, deployFindings(t, "ts-coerced-number-fallback-dead", map[string]string{
		"src/page.tsx": `export const Card = ({ summary }: Props) => <div>
  {summary.avgMoic?.toFixed(2) || '-'}x
  {Number(summary.count) || 0}
  {Number.isFinite(Number(summary.dpi)) ? Number(summary.dpi).toFixed(2) : '-'}
</div>
`,
	}))
}

// PUT replaces the record with its body: a Partial body empties every field
// the caller left out.
func TestTSPartialBodySentWithPut(t *testing.T) {
	assert.Equal(t, []string{"frontend/api.ts:11", "frontend/api.ts:2"},
		deployFindings(t, "ts-partial-body-sent-with-put", map[string]string{
			"frontend/api.ts": `class Api {
  async updateFirm(id: string, data: Partial<Firm>): Promise<Firm> {
    return await this.makeRequest(` + "`/api/firms/${id}`" + `, 'PUT', data) as Firm
  }
  async updateRule(id: string, data: Partial<Rule>): Promise<Rule> {
    return await this.makeRequest(` + "`/api/rules/${id}`" + `, 'PATCH', data) as Rule
  }
  async replaceFirm(id: string, data: Firm): Promise<Firm> {
    return await this.makeRequest(` + "`/api/firms/${id}`" + `, 'PUT', data) as Firm
  }
  async saveSchedule(id: string, patch: Partial<Schedule>) {
    const res = await fetch(` + "`/api/schedules/${id}`" + `, { method: 'PUT', body: JSON.stringify(patch) })
    return res.json()
  }
}
`,
		}))
}

// parseFloat of a form field answers NaN for text, and JSON sends NaN as
// null: the server clears the field instead of rejecting the input.
func TestTSFormNumberUncheckedInPayload(t *testing.T) {
	assert.Equal(t, []string{"src/admin.tsx:12", "src/admin.tsx:5", "src/admin.tsx:6"},
		deployFindings(t, "ts-form-number-unchecked-in-payload", map[string]string{
			"src/admin.tsx": `const create = async () => {
  await api.createPortfolio({
    firmId,
    name: portName,
    targetSize: portTargetSize ? parseFloat(portTargetSize) : undefined,
    maxChainPct: Number(portMaxChain),
  })
}
const save = async () => {
  const payload: Partial<Portfolio> = { ...editData }
  if (editData.maxPct) {
    payload.maxPct = parseFloat(editData.maxPct)
  }
  await api.updatePortfolio(id, payload)
}
`,
		}))
	// The function checks the parsed number, the value has a fallback, or the
	// object is not sent anywhere.
	assert.Empty(t, deployFindings(t, "ts-form-number-unchecked-in-payload", map[string]string{
		"src/admin.tsx": `const create = async () => {
  const size = parseFloat(portTargetSize)
  if (!Number.isFinite(size)) { setError('size'); return }
  await api.createPortfolio({ firmId, targetSize: parseFloat(portTargetSize) })
}
const chart = points.map(point => ({ value: Number(point.value) || 0 }))
const view = { total: Number(total) }
const segments = () => {
  s.push({ label: 'DeFi', value: Number(defi.totalValue) })
}
const label = async () => {
  await translate('share', { pct: Number(data.sharePct).toFixed(1) })
}
`,
	}))
}

// A filter read from the link goes to the API as it was typed, while its
// sibling is checked against the allowed values: an old link with SUCCESS
// empties the list.
func TestTSURLFilterEnumUnvalidated(t *testing.T) {
	assert.Equal(t, []string{"src/page.tsx:10", "src/page.tsx:11", "src/page.tsx:17"},
		deployFindings(t, "ts-url-filter-enum-unvalidated", map[string]string{
			"src/page.tsx": `const LINK_FILTER_VALUES = new Set(['', 'yes', 'no'])
const parseLinkFilter = (raw: string | null | undefined): string =>
  (typeof raw === 'string' && LINK_FILTER_VALUES.has(raw) ? raw : '')

const parseStored = (raw: string) => {
  const parsed = JSON.parse(raw) as Record<string, unknown>
  return {
    chain: typeof parsed.chain === 'string' ? parsed.chain : '',
    wallet: typeof parsed.wallet === 'string' ? parsed.wallet : '',
    direction: typeof parsed.direction === 'string' ? parsed.direction : '',
    status: typeof parsed.status === 'string' ? parsed.status : '',
    linked: parseLinkFilter(parsed.linked),
  }
}
const fromParams = (params: URLSearchParams) => ({
  chain: params.get('chain') ?? '',
  status: params.get('status') ?? '',
  linked: parseLinkFilter(params.get('linked')),
})
`,
		}))
	// No sibling is validated: the file does not know the allowed values.
	assert.Empty(t, deployFindings(t, "ts-url-filter-enum-unvalidated", map[string]string{
		"src/page.tsx": `const fromParams = (params: URLSearchParams) => ({
  chain: params.get('chain') ?? '',
  status: params.get('status') ?? '',
})
`,
	}))
}

const decimalStringGoModels = `package models

import "github.com/shopspring/decimal"

type SafeDecimal struct{ decimal.Decimal }

type NAVSnapshot struct {
	UnitPrice SafeDecimal ` + "`json:\"unitPrice\"`" + `
	DPI       *SafeDecimal ` + "`json:\"dpi,omitempty\"`" + `
	Units     int64 ` + "`json:\"units\"`" + `
	Ratio     float64 ` + "`json:\"ratio\"`" + `
}
`

// A Go decimal marshals as a JSON string: a TS field typed number holds a
// string, and toFixed on it throws.
func TestTSNumberFieldForDecimalJSON(t *testing.T) {
	assert.Equal(t, []string{"frontend/api.ts:2", "frontend/api.ts:3"},
		deployFindings(t, "ts-number-field-for-decimal-json", map[string]string{
			"backend/models/nav.go": decimalStringGoModels,
			"frontend/api.ts": `export interface NAVSnapshot {
  unitPrice: number
  dpi?: number | null
  units: number
  ratio: number
}
export interface Other {
  unitPrice: number
}
`,
		}))
	// The TS field takes the string, or the project marshals decimals as
	// numbers.
	assert.Empty(t, deployFindings(t, "ts-number-field-for-decimal-json", map[string]string{
		"backend/models/nav.go": decimalStringGoModels,
		"frontend/api.ts": `export interface NAVSnapshot {
  unitPrice: string
  dpi?: number | string
}
`,
	}))
	assert.Empty(t, deployFindings(t, "ts-number-field-for-decimal-json", map[string]string{
		"backend/models/nav.go": decimalStringGoModels,
		"backend/main.go": `package main

import "github.com/shopspring/decimal"

func init() { decimal.MarshalJSONWithoutQuotes = true }
`,
		"frontend/api.ts": `export interface NAVSnapshot {
  unitPrice: number
}
`,
	}))
}

// The formula guard quotes a cell that starts with '-': a negative amount
// becomes text and the spreadsheet stops summing it.
func TestCSVFormulaGuardManglesNegativeNumber(t *testing.T) {
	assert.Equal(t, []string{"lib/csv-utils.ts:4"}, deployFindings(t, "csv-formula-guard-mangles-negative-number", map[string]string{
		"lib/csv-utils.ts": `export function escapeCsvCell(value: string): string {
  if (!value) return ''
  const first = Array.from(value)[0]
  const safeValue = ['=', '+', '-', '@', '\t', '\r'].includes(first)
    ? ` + "`'${value}`" + `
    : value
  return safeValue.includes(',') ? ` + "`\"${safeValue.replace(/\"/g, '\"\"')}\"`" + ` : safeValue
}
`,
	}))
	assert.Empty(t, deployFindings(t, "csv-formula-guard-mangles-negative-number", map[string]string{
		"lib/csv-utils.ts": `const DECIMAL_STRING = /^-?\d+(\.\d+)?$/
export function escapeCsvCell(value: string): string {
  const first = Array.from(value)[0]
  const isFormulaLike = ['=', '+', '-', '@'].includes(first) && !DECIMAL_STRING.test(value)
  return isFormulaLike ? ` + "`'${value}`" + ` : value
}
`,
		"lib/other-csv.ts": `export function escapeCell(value: string): string {
  return /^[=@]/.test(value) ? ` + "`'${value}`" + ` : value
}
`,
	}))
}
