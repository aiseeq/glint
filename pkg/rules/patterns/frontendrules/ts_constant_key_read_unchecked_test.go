package frontendrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestTSConstantKeyReadUnchecked(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `type Provider = { name: string; fee: number }
const LOCAL: Record<string, Provider> = { ACME: { name: 'Acme', fee: 1 } }
export function direct(m: Record<string, Provider>) {
  return m['K'].name
}
export function called(m: Record<string, Provider>) {
  return m["K"].getName()
}
export function alias(m: { [key: string]: Provider }) {
  const v = m['K']
  return v.name
}
export function jsonRead() {
  const m = JSON.parse('{}') as Record<string, Provider>
  return m['K'].name
}
export function optional(m: Record<string, Provider>) { return m['K']?.name }
export function conditional(m: Record<string, Provider>) { return m['K'] ? m['K'].name : '' }
export function andGuard(m: Record<string, Provider>) { return m['K'] && m['K'].name }
export function typeofGuard(m: Record<string, unknown>) {
  if (typeof m['K'] === 'string' && m['K'].trim()) return m['K']
  return ''
}
export function guardedIn(m: Record<string, Provider>) {
  if (!('K' in m)) throw new Error()
  return m['K'].name
}
export function guardedUndefined(m: Record<string, Provider>) {
  if (m['K'] === undefined) throw new Error()
  return m['K'].name
}
export function guardedNotUndefined(m: Record<string, Provider>) {
  if (m['K'] !== undefined) return m['K'].name
  return ''
}
export function guardedFalsy(m: Record<string, Provider>) {
  if (!m['K']) return ''
  return m['K'].name
}
export function guardedOwn(m: Record<string, Provider>) {
  if (!m.hasOwnProperty('K')) return ''
  return m['K'].name
}
export function guardedAlias(m: Record<string, Provider>) {
  const v = m['K']
  if (!v) return ''
  return v.name
}
export function guardedAliasUndefined(m: Record<string, Provider>) {
  const v = m['K']
  if (v === undefined) return ''
  return v.name
}
export function guardedAliasNull(m: Record<string, Provider>) {
  const v = m['K']
  if (v == null) return ''
  return v.name
}
export function localObject() { return LOCAL['ACME'].name }
export function numeric(list: Provider[][]) { return list[0][1].name }
type Report = { legs: { code: string }[] }
type Leg = Report['legs'][number]
export function typeUse(leg: Leg) { return leg.code }
`
	assert.Equal(t, []string{
		"src/constant.ts:10", "src/constant.ts:15", "src/constant.ts:4", "src/constant.ts:7",
	}, patterntest.LinesOf(t, rule, "src/constant.ts", source))
}

func TestTSConstantKeyReadUncheckedTemplateScript(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `<h1>{{.Title}}</h1><script>
var ctx = {{.Ctx}};
function receiverBankName() {
  return ctx.banks['THA'].name
}
function optionalBankName() {
  return ctx.banks['THA'] ? ctx.banks['THA'].name : null
}
</script>`
	// The engine hands the scripts of a template to file rules as one
	// virtual JavaScript file with the template's path and lines.
	virtual := core.ExtractTemplateJavaScript(rulestest.TextFile(t, "templates/page.html", source))
	if !assert.Len(t, virtual, 1) {
		return
	}
	assert.Equal(t, []string{"templates/page.html:4"}, rulestest.ViolationPlaces(rule.AnalyzeFile(virtual[0])))
}

func TestTSConstantKeyReadUncheckedSecondPass(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `type Prov = { name: string; x: number }
interface Dict { [k: string]: Prov }
type Banks = Record<string, Prov>
export function interfaceIndex(d: Dict) { return d['THA'].name }
export function aliasIndex(b: Banks) { return b['THA'].name }
export function savedPath(raw: string) {
  const cfg = JSON.parse(raw)
  const bank = cfg.banks['THA']
  return bank.name
}
export function noExit(m: Record<string, Prov>) {
  if (m['K'] === undefined) console.warn('missing')
  return m['K'].x
}
export function otherDict(m: Record<string, Prov>, mm: Record<string, Prov>) {
  if (!('K' in mm)) return 0
  return m['K'].x
}
export function otherBranch(m: Record<string, Prov>) {
  if ('K' in m) { console.log('present') } else { return m['K'].x }
  return 0
}
export function truthyBlock(m: Record<string, Prov>) {
  if (m['K']) { return m['K'].x }
  return 0
}
export function truthyInline(m: Record<string, Prov>) {
  if (m['K']) return m['K'].x
  return 0
}
export function savedTruthy(m: Record<string, Prov>) {
  const v = m['K']
  if (v) { return v.x }
  return 0
}
export function savedAnd(m: Record<string, Prov>) {
  const v = m['K']
  return v && v.x
}
export function savedTernary(m: Record<string, Prov>) {
  const v = m['K']
  return v ? v.x : 0
}
export function savedOr(m: Record<string, Prov>) {
  const v = m['K'] || { name: '', x: 0 }
  return v.x
}
export function literalKeys(m: Record<'THA' | 'VNM', Prov>) { return m['THA'].name }
export function written(m: Record<string, Prov>) {
  m['K'] = { name: 'k', x: 1 }
  return m['K'].x
}
export function own(m: Record<string, Prov>) {
  if (!Object.hasOwn(m, 'K')) return 0
  return m['K'].x
}
export function keys(m: Record<string, Prov>) {
  if (!Object.keys(m).includes('K')) return 0
  return m['K'].x
}
export function fieldNotAlias(m: Record<string, Prov>, o: { v: Prov }) {
  const v = m['K']
  return o.v.x + (v ? v.x : 0)
}
export function scopedName(m: Record<string, Prov>) { return m['K'].x }
export function scopedName(m: Prov) { return m.name.length }
export function unrelatedTyped(m: Record<string, Prov>) { return m['K'].x }
export function scopedPlain(m: Prov) { return m['name'].length }
export function plainObject(m: Prov) { return m['name'].length }
`
	got := patterntest.LinesOf(t, rule, "src/second.ts", source)
	assert.Equal(t, []string{"src/second.ts:13", "src/second.ts:17", "src/second.ts:20", "src/second.ts:4", "src/second.ts:5", "src/second.ts:65", "src/second.ts:67", "src/second.ts:8"}, got)
}

func TestTSConstantKeyReadUncheckedSecondPassTemplate(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `<script>
var ctx = {{.Ctx}};
var banks = {{.Banks}};
function saved() {
  var bank = ctx.banks['IDN'];
  return bank.code;
}
function plainVariable() { return banks['MYS'].name; }
function guarded() { if (ctx.banks['THA']) { return ctx.banks['THA'].name; } }
</script>`
	virtual := core.ExtractTemplateJavaScript(rulestest.TextFile(t, "templates/second.html", source))
	if !assert.Len(t, virtual, 1) {
		return
	}
	assert.Equal(t, []string{"templates/second.html:5", "templates/second.html:8"}, rulestest.ViolationPlaces(rule.AnalyzeFile(virtual[0])))
}
