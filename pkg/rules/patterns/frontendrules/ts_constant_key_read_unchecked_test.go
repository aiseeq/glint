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

func TestTSConstantKeyReadUncheckedThirdPass(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `type Item = { x: number }
export function bracedReturn(m: Record<string, Item>) {
  if (!('K' in m)) { return 0; }
  return m['K'].x
}
export function bracedThrow(m: Record<string, Item>) {
  if (m['K'] === undefined) {
    console.warn('no K')
    throw new Error('no K')
  }
  return m['K'].x
}
export function bracedFalsy(m: Record<string, Item>) {
  if (!m['K']) { return 0 }
  return m['K'].x
}
export function bracedOwn(m: Record<string, Item>) {
  if (!Object.hasOwn(m, 'K')) { return 0 }
  return m['K'].x
}
export function sameConditionIn(m: Record<string, Item>) {
  if ('K' in m && m['K'].x > 0) return true
  return false
}
export function sameConditionDefined(m: Record<string, Item>) {
  if (m['K'] !== undefined && m['K'].x > 0) return true
  return false
}
export function orExit(m: Record<string, Item>, off: boolean) {
  if (off || !('K' in m)) return 0
  return m['K'].x
}
export function defaultedKey(m: Record<string, Item>) {
  m['K'] = m['K'] || { x: 0 }
  return m['K'].x
}
export function nullishAssigned(m: Record<string, Item>) {
  m['K'] ??= { x: 0 }
  return m['K'].x
}
export function typeofUndefined(m: Record<string, Item>) {
  if (typeof m['K'] === 'undefined') return 0
  return m['K'].x
}
interface Cfg { banks: Record<string, Item> }
export function savedTypedPath(cfg: Cfg) {
  const b = cfg.banks['KBANK']
  return b.x
}
export function directTypedPath(cfg: Cfg) {
  return cfg.banks['KBANK'].x
}
export function inlineTypedPath(cfg: { banks: Record<string, Item> }) {
  return cfg.banks['KBANK'].x
}
class Registry {
  banks: Record<string, Item> = {}
  name() { return this.banks['KBANK'].x }
}
export function destructured(m: Record<string, Item>) {
  const { x } = m['K']
  return x
}
`
	assert.Equal(t, []string{
		"src/third.ts:47", "src/third.ts:51", "src/third.ts:54", "src/third.ts:58", "src/third.ts:61",
	}, patterntest.LinesOf(t, rule, "src/third.ts", source))
	negative := `type Item = { x: number }
export function bracedReturn(m: Record<string, Item>) {
  if (!('K' in m)) { return 0; }
  return m['K'].x
}
export function bracedThrow(m: Record<string, Item>) {
  if (m['K'] === undefined) {
    console.warn('no K')
    throw new Error('no K')
  }
  return m['K'].x
}
export function bracedFalsy(m: Record<string, Item>) {
  if (!m['K']) {
    return 0
  }
  return m['K'].x
}
export function bracedOwn(m: Record<string, Item>) {
  if (!Object.hasOwn(m, 'K')) { return 0 }
  return m['K'].x
}
export function sameConditionIn(m: Record<string, Item>) {
  if ('K' in m && m['K'].x > 0) return true
  return false
}
export function sameConditionDefined(m: Record<string, Item>) {
  if (m['K'] !== undefined && m['K'].x > 0) return true
  return false
}
export function orExit(m: Record<string, Item>, off: boolean) {
  if (off || !('K' in m)) return 0
  return m['K'].x
}
export function defaultedKey(m: Record<string, Item>) {
  m['K'] = m['K'] || { x: 0 }
  return m['K'].x
}
export function nullishAssigned(m: Record<string, Item>) {
  m['K'] ??= { x: 0 }
  return m['K'].x
}
export function typeofUndefined(m: Record<string, Item>) {
  if (typeof m['K'] === 'undefined') return 0
  return m['K'].x
}
`
	assert.Empty(t, patterntest.LinesOf(t, rule, "src/third-neg.ts", negative))
}

func TestTSConstantKeyReadUncheckedDestructuringGuards(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `type Item = { x: number }
export function guardedDestructure(m: Record<string, Item>): number {
  if ('K' in m) {
    const { x } = m['K']
    return x
  }
  return 0
}
export function exitDestructure(m: Record<string, Item>): number {
  if (!('K' in m)) return 0
  const { x } = m['K']
  return x
}
export function orFallbackDestructure(m: Record<string, Item>): number {
  const { x } = m['K'] || { x: 0 }
  return x
}
export function nullishFallbackDestructure(m: Record<string, Item>): number {
  const { x } = m['K'] ?? { x: 0 }
  return x
}
export function emptyNullishFallbackDestructure(m: Record<string, Item>): number {
  const { x } = m['K'] ?? {}
  return x ?? 0
}
export function fallthroughAfterPartialExit(m: Record<string, Item>, a: boolean): number {
  if (!m['K']) {
    if (a) return 1
    log()
  }
  return m['K'].x // POS
}
function log(): void {}
`
	assert.Equal(t, []string{"src/destructure.ts:31"}, patterntest.LinesOf(t, rule, "src/destructure.ts", source))
}

// Template scripts often declare helpers first and run their setup after
// them: a top-level read past the first function is still read, and must
// not take the run down.
func TestTSConstantKeyReadUncheckedTemplateTopLevelAfterFunction(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `<script>
var banks = {{.Banks}};
function g() { return 1; }
render(banks['ACME']);
show(banks['ACME'].name);
if ('BETA' in banks) { show(banks['BETA'].name) }
</script>`
	virtual := core.ExtractTemplateJavaScript(rulestest.TextFile(t, "templates/after.html", source))
	if !assert.Len(t, virtual, 1) {
		return
	}
	assert.Equal(t, []string{"templates/after.html:5"}, rulestest.ViolationPlaces(rule.AnalyzeFile(virtual[0])))
}

func TestTSConstantKeyReadUncheckedFourthPass(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `type Item = { name: string }
type Dict = { [key: string]: Item }
interface Props { items: Readonly<Record<string, Item>> }
const moduleDict: Dict = getDict()
export function missing(m: Dict) {
  return m['K']!.name // POS
}

export function nested(m: Dict) {
  return (m['K'] as Item).name // POS
}
export function nestedKey(m: Dict) {
  return m['K']['EU'].name // POS
}
export function templateKey(m: Dict) {
	return m['K'].name // POS
}
export function optionalBase(m: Dict | undefined) {
  return m?.['K'].name // POS
}
export function moduleRead() {
  return moduleDict['K'].name // POS
}
export function callback(m: Dict) {
  return ['K'].map(() => m['K'].name) // POS
}
export function savedDestructure(m: Dict) {
  const p = m['K']
  const { name } = p // POS
  return name
}
export function protectedDouble(m: Dict) {
  if (m["K"] && enabled) return m['K'].name
  return ''
}
export function protectedInAnd(m: Dict) {
  if ('K' in m && enabled) return m['K'].name
  return ''
}
export function protectedTernary(m: Dict) {
  return 'K' in m ? m['K'].name : ''
}
export function protectedContinue(m: Dict) {
  while (!('K' in m)) continue
  return m['K'].name
}
export function protectedElse(m: Dict) {
  if (!('K' in m)) { log() } else { return m['K'].name }
  return ''
}
export function protectedAlias(m: Dict) {
  const p = m['K']
  if (p !== undefined && enabled) return p.name
  return ''
}
export function unprotectedAfterCheck(m: Dict) {
  if ('K' in m) log()
  return m['K'].name // POS
}
function enabled() { return true }
function log() {}
`
	assert.Equal(t, []string{
		"src/fourth.ts:10", "src/fourth.ts:13", "src/fourth.ts:16", "src/fourth.ts:19",
		"src/fourth.ts:22", "src/fourth.ts:25", "src/fourth.ts:28", "src/fourth.ts:58", "src/fourth.ts:6",
	}, patterntest.LinesOf(t, rule, "src/fourth.ts", source))
}

func TestTSConstantKeyReadUncheckedTemplateOuterGuardCallback(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `<script>
var banks = {{.Banks}};
function guarded(xs) {
  if (!('K' in banks)) return [];
  return xs.map(function (x) { return banks['K'].fee * x; });
}

function unguarded(xs) {
  return xs.map(function (x) { return banks['K'].fee * x; });
}
</script>`
	virtual := core.ExtractTemplateJavaScript(rulestest.TextFile(t, "templates/callback.html", source))
	if !assert.Len(t, virtual, 1) {
		return
	}
	assert.Equal(t, []string{"templates/callback.html:9"}, rulestest.ViolationPlaces(rule.AnalyzeFile(virtual[0])))
}

func TestTSConstantKeyReadUncheckedFourthPassExpressionGuards(t *testing.T) {
	rule, ok := rules.Get("ts-constant-key-read-unchecked")
	if !assert.True(t, ok, "rule is registered") {
		return
	}
	source := `interface Item { name: string }
declare function load(): Record<string, Item>
export function inferred() {
  const values = load()
  return values['K'].name // POS
}
export const arrow = (m: Record<string, Item>) => ('K' in m ? m['K'].name : '')
export function keys(m: Record<string, Item>) {
  return Object.keys(m).includes('K') && m['K'].name
}
export function own(m: Record<string, Item>) {
  return Object.prototype.hasOwnProperty.call(m, 'K') && m['K'].name
}
export function jsx(m: Record<string, Item>) {
  return <div>{'K' in m ? <b>{m['K'].name}</b> : null}</div>
}
`
	assert.Equal(t, []string{"src/fourth-expressions.ts:5"}, patterntest.LinesOf(t, rule, "src/fourth-expressions.ts", source))
}
