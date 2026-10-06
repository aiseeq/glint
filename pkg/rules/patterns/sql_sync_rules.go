package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLChildRowsIncludeVoidedParentRule())
	rules.Register(NewDeltaExportMissesUnlinkRule())
	rules.Register(NewSyncNewerWinsOnStampedTableRule())
	rules.Register(NewMirrorImportNeverRemovesRule())
	rules.Register(NewPendingPageSkipsStayAtHeadRule())
}

// SQLChildRowsIncludeVoidedParentRule detects a total of child rows (a sum,
// an average) that never looks at their parent, when the project leaves some
// parents out by a void status elsewhere:
//
//	SELECT account, SUM(amount) FROM postings GROUP BY account
//	-- elsewhere: ... JOIN journals j ON j.id = p.journal_id WHERE j.status <> 'reversed'
//
// The postings of a reversed journal still count here: a reversal does not
// take its amounts out of the totals. A read of given parents' children
// (journal_id = $1, IN, ANY) is left out - the caller chose them; so is a
// list, a count or an existence check, which answers another question; so is
// a soft-deleted parent (its children's history stays valid); so is a
// nullable reference, which does not make a row a part of its parent.
//
// The same miss within one query is reported too: a SUM that takes rows of
// every status beside aggregates that filter theirs by status.
type SQLChildRowsIncludeVoidedParentRule struct {
	*rules.BaseRule
	// voided are the void status values the project leaves out, by table.
	voided map[string][]string
}

// NewSQLChildRowsIncludeVoidedParentRule creates the rule
func NewSQLChildRowsIncludeVoidedParentRule() *SQLChildRowsIncludeVoidedParentRule {
	return &SQLChildRowsIncludeVoidedParentRule{BaseRule: rules.NewBaseRule(
		"sql-child-rows-include-voided-parent",
		"patterns",
		"Detects a total of child rows (SUM, AVG) that never joins their parent while the project leaves parents with a void status (reversed, cancelled) out elsewhere — the children of a voided parent still count; also a SUM without the status FILTER its neighbouring aggregates have",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the project's other
// queries and the migrations.
func (r *SQLChildRowsIncludeVoidedParentRule) ReadsOtherFiles() bool { return true }

// UseProjectFiles collects the void status filters of the project's queries.
func (r *SQLChildRowsIncludeVoidedParentRule) UseProjectFiles(files []*core.FileContext) {
	r.voided = make(map[string][]string)
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		schema, ok := fileSchema(ctx, r.BaseRule)
		if !ok || schema == nil {
			continue
		}
		for _, literal := range sqlFragments(ctx.GoAST) {
			for _, exclusion := range schema.StatusExclusions(literal.text) {
				for _, value := range exclusion.Values {
					if !slices.Contains(r.voided[exclusion.Table], value) {
						r.voided[exclusion.Table] = append(r.voided[exclusion.Table], value)
					}
				}
			}
		}
	}
}

// ResetState drops the filters of the previous root.
func (r *SQLChildRowsIncludeVoidedParentRule) ResetState() { r.voided = nil }

// AnalyzeFile reports the reads of child rows that skip their voided parents.
func (r *SQLChildRowsIncludeVoidedParentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	reported := make(map[int]bool)
	literals := sqlLiterals(ctx.GoAST)
	for _, literal := range literals {
		// A query finished by a built condition (+ where) parses without it.
		text := literal.text
		if literal.bare != "" {
			text = literal.bare
		}
		for _, offset := range sqlschema.UnfilteredSums(text) {
			line := literal.lineAt(ctx, offset)
			if reported[line] || ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[line] = true
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"This SUM takes rows of every status while the other aggregates of the query filter theirs by status: refused and cancelled rows still count in the total",
				"Give the SUM the FILTER (WHERE status ...) its neighbours have, or sum the column both ways when a total of every status is meant"))
		}
	}
	if len(r.voided) == 0 {
		return violations
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return violations
	}
	voided := make(map[string]bool, len(r.voided))
	for table := range r.voided {
		voided[table] = true
	}
	for _, literal := range literals {
		for _, read := range schema.ChildReadsWithoutParent(literal.text, voided) {
			line := literal.lineAt(ctx, read.Offset)
			if reported[line] || ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[line] = true
			values := strings.Join(r.voided[read.Parent], "', '")
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				fmt.Sprintf("Rows of %s are read without their %s row, while the project leaves %s with status '%s' out elsewhere — the children of a voided parent still count here", read.Child, read.Parent, read.Parent, values),
				fmt.Sprintf("Join %s on %s and leave its voided rows out as the other queries do", read.Parent, read.Column)))
		}
	}
	return violations
}

// DeltaExportMissesUnlinkRule detects a statement that takes a child row away
// from its parent without touching the parent's change time, in a file that
// transfers the parents by that time:
//
//	SELECT * FROM batches WHERE updated_at >= $1            -- the delta transfer
//	DELETE FROM batch_members WHERE batch_id = $1 AND ...   -- the batch changed, its updated_at did not
//
// The removed row leaves no trace the transfer could see: the next delta
// carries the batch without the change, and the copy keeps the link. A
// function that also updates the parent (a CTE, a second statement) is left
// out.
type DeltaExportMissesUnlinkRule struct {
	*rules.BaseRule
}

// NewDeltaExportMissesUnlinkRule creates the rule
func NewDeltaExportMissesUnlinkRule() *DeltaExportMissesUnlinkRule {
	return &DeltaExportMissesUnlinkRule{BaseRule: rules.NewBaseRule(
		"delta-export-misses-unlink",
		"patterns",
		"Detects a child row taken away from a parent that a delta transfer reads by updated_at, without touching the parent's updated_at — the transfer never carries the removal",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations.
func (r *DeltaExportMissesUnlinkRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the unlinks of the delta-transferred parents.
func (r *DeltaExportMissesUnlinkRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	exported := make(map[string]bool)
	texts := builtQueries(ctx.GoAST)
	for _, literal := range sqlFragments(ctx.GoAST) {
		texts = append(texts, literal.text)
	}
	for _, text := range texts {
		for _, table := range sqlschema.DeltaExports(text) {
			exported[table] = true
		}
	}
	if len(exported) == 0 {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		literals := sqlLiterals(fn.Body)
		touched := make(map[string]bool)
		for _, literal := range literals {
			for _, table := range sqlschema.UpdatedTables(literal.text) {
				touched[table] = true
			}
		}
		for _, literal := range literals {
			for _, unlink := range schema.ParentUnlinks(literal.text) {
				if !exported[unlink.Parent] || touched[unlink.Parent] {
					continue
				}
				line := literal.lineAt(ctx, unlink.Offset)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
					fmt.Sprintf("A row of %s is taken away from its %s row without touching %s.updated_at, and this file transfers %s by updated_at — the delta transfer never carries the removal", unlink.Child, unlink.Parent, unlink.Parent, unlink.Parent),
					fmt.Sprintf("Touch the parent in the same statement or transaction (UPDATE %s SET updated_at = NOW() WHERE id = $n)", unlink.Parent)))
			}
		}
	}
	return violations
}

// builtQueries returns the texts of the queries the functions under root
// build in a local by steps (query := "SELECT ..."; query += " WHERE ..."),
// every appended piece taken whatever branch it stands in.
func builtQueries(root ast.Node) []string {
	var texts []string
	ast.Inspect(root, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		built := make(map[string]string)
		appended := make(map[string]bool)
		var order []string
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			assign, ok := m.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			id, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			pieces := sqlTexts(assign.Rhs[0], func(string) bool { return true })
			if len(pieces) != 1 || pieces[0].expr != assign.Rhs[0] {
				return true
			}
			if _, seen := built[id.Name]; !seen {
				order = append(order, id.Name)
			}
			if assign.Tok == token.ADD_ASSIGN {
				built[id.Name] += pieces[0].text
				appended[id.Name] = true
			} else {
				built[id.Name] = pieces[0].text
			}
			return true
		})
		for _, name := range order {
			if appended[name] {
				texts = append(texts, built[name])
			}
		}
		return false
	})
	return texts
}

// changeTimeField is a struct field holding a row's last change time.
var changeTimeField = regexp.MustCompile(`^(?:Updated|Modified|Changed)At$`)

// contentComparison is a call that compares two rows by content.
var contentComparison = regexp.MustCompile(`(?i)same|equal|identical|unchanged|differ|diff`)

// SyncNewerWinsOnStampedTableRule detects an import that keeps the newer of
// two rows by their change time and writes it into a table whose trigger
// stamps every UPDATE with the time of the write:
//
//	case incoming.UpdatedAt.After(existing.UpdatedAt):
//		repo.Update(incoming) // BEFORE UPDATE trigger: NEW.updated_at = NOW()
//
// The written row comes out newer than its source, so the source then looks
// older than its copy: each transfer copies every row back the other way.
// An import that first compares the rows' content (Same, Equal) and writes
// only a changed one is left out.
func NewSyncNewerWinsOnStampedTableRule() *SyncNewerWinsOnStampedTableRule {
	return &SyncNewerWinsOnStampedTableRule{BaseRule: rules.NewBaseRule(
		"sync-newer-wins-on-stamped-table",
		"patterns",
		"Detects an import that writes the row with the newer updated_at into a table whose trigger stamps every UPDATE with NOW() — the copy turns newer than its source, and rows travel back and forth on every transfer",
		core.SeverityMedium,
	)}
}

// SyncNewerWinsOnStampedTableRule is the rule NewSyncNewerWinsOnStampedTableRule creates.
type SyncNewerWinsOnStampedTableRule struct {
	*rules.BaseRule
}

// AnalyzeFile is a no-op: the write is followed into its callee.
func (r *SyncNewerWinsOnStampedTableRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *SyncNewerWinsOnStampedTableRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the newer-wins writes into stamped tables.
func (r *SyncNewerWinsOnStampedTableRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(r.BaseRule))
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil, nil // the schema rules report the migration; nothing to check against
	}
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if !schema.AnyStampedOnUpdate() {
		return nil, nil
	}
	inner := &typedFuncRule{
		BaseRule:   r.BaseRule,
		suggestion: "Compare the rows' content first and write only a changed one; decide by the source's change time kept in a column of its own, not by the stamped updated_at",
		check: func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			return newerWinsWrites(scope, schema, fn)
		},
	}
	return inner.AnalyzeGoProject(ctx)
}

// newerWinsWrites returns the change-time comparisons of fn that decide a
// write into a stamped table, with no content comparison before them in the
// same switch or if chain.
func newerWinsWrites(scope funcScope, schema *sqlschema.Schema, fn *ast.FuncDecl) []funcFinding {
	var findings []funcFinding
	report := func(cond ast.Expr, body []ast.Stmt) {
		if !comparesChangeTimes(cond) {
			return
		}
		for _, stmt := range body {
			if writesStampedRow(scope, schema, stmt, 2, true) {
				findings = append(findings, funcFinding{node: cond, message: "The newer row by updated_at is written into a table whose trigger stamps every UPDATE with NOW() — the copy turns newer than its source, and the row travels back and forth on every transfer"})
				return
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SwitchStmt:
			if node.Tag != nil {
				return true
			}
			compared := false
			for _, clause := range node.Body.List {
				cc, ok := clause.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, cond := range cc.List {
					if !compared {
						report(cond, cc.Body)
					}
					compared = compared || comparesContent(cond)
				}
			}
		case *ast.IfStmt:
			if !comparesContent(node.Cond) {
				report(node.Cond, node.Body.List)
			}
			// An else-if chain after a content comparison is decided by it.
			if comparesContent(node.Cond) {
				return false
			}
		}
		return true
	})
	return findings
}

// comparesChangeTimes reports a.UpdatedAt.After(b.UpdatedAt) or Before.
func comparesChangeTimes(cond ast.Expr) bool {
	call, ok := ast.Unparen(cond).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	method, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (method.Sel.Name != "After" && method.Sel.Name != "Before") {
		return false
	}
	left, ok := ast.Unparen(method.X).(*ast.SelectorExpr)
	right, okRight := ast.Unparen(call.Args[0]).(*ast.SelectorExpr)
	return ok && okRight && changeTimeField.MatchString(left.Sel.Name) && left.Sel.Name == right.Sel.Name
}

// comparesContent reports a condition that calls a content comparison
// (incoming.Same(existing), reflect.DeepEqual).
func comparesContent(cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			case *ast.Ident:
				name = fun.Name
			}
			found = found || contentComparison.MatchString(name)
		}
		return !found
	})
	return found
}

// writesStampedRow reports a node that calls a write which updates a stamped
// table, followed through the writes of the callees without SQL of their own
// up to depth calls deep (a service method over a repository one). A write
// whose body is not loaded counts when the node is the import's own code and
// the schema stamps any table; one met deeper is the SQL layer's own driver.
func writesStampedRow(scope funcScope, schema *sqlschema.Schema, node ast.Node, depth int, unloadedCounts bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !helpers.IsWriteName(sel.Sel.Name) {
			return true
		}
		decl, ok := scope.callee(call)
		if !ok {
			found = unloadedCounts
			return !found
		}
		literals := sqlLiterals(decl.decl.Body)
		for _, literal := range literals {
			for _, table := range sqlschema.UpdatedTables(literal.text) {
				if t := schema.Table(table); t != nil && t.StampedOnUpdate() != "" {
					found = true
				}
			}
		}
		if !found && len(literals) == 0 && depth > 0 {
			inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
			found = writesStampedRow(inner, schema, decl.decl.Body, depth-1, false)
		}
		return !found
	})
	return found
}

// importFunction names a function that brings records from a source of
// truth into this store.
var importFunction = regexp.MustCompile(`^(?:[Ii]mport|[Mm]irror|[Rr]eplicate|[Rr]estore)(?:[A-Z_]|$)`)

// linkCall names a call that attaches children to a record.
var linkCall = regexp.MustCompile(`^(?:Link|Attach|Assign)(?:[A-Z]|$)`)

// unlinkCall names a call that takes children away from a record.
var unlinkCall = regexp.MustCompile(`^(?:Unlink|Detach|Unassign|Remove|Delete|Prune|Clear|Replace|Reset)(?:[A-Z]|$)|Except$`)

// MirrorImportNeverRemovesRule detects an import from a source of truth that
// links each incoming record's children and never takes away a link the
// source no longer has:
//
//	func (s *Service) ImportBatches(records []Record) error {
//		for _, r := range records {
//			s.repo.LinkItems(r.ID, r.Items) // an item unlinked at the source stays linked here
//		}
//	}
//
// The copy keeps every link it ever received and drifts from its source.
type MirrorImportNeverRemovesRule struct {
	*rules.BaseRule
}

// NewMirrorImportNeverRemovesRule creates the rule
func NewMirrorImportNeverRemovesRule() *MirrorImportNeverRemovesRule {
	return &MirrorImportNeverRemovesRule{BaseRule: rules.NewBaseRule(
		"mirror-import-never-removes",
		"patterns",
		"Detects an import that links each incoming record's children and never unlinks the ones the source no longer has — the copy keeps stale links and drifts from its source",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the link calls of the imports that never unlink.
func (r *MirrorImportNeverRemovesRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !importFunction.MatchString(fn.Name.Name) {
			continue
		}
		link := firstLinkInRecordLoop(fn)
		if link == nil || callsNamed(fn.Body, unlinkCall) {
			continue
		}
		line := ctx.LineFor(link)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "The import links each incoming record's children and never unlinks the ones the source no longer has — a link removed at the source stays here")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Make the record's link set equal the source's: unlink the children absent from the incoming set (UnlinkExcept), or report why it cannot be compared")
		violations = append(violations, v)
	}
	return violations
}

// firstLinkInRecordLoop returns the first link call inside a range over a
// parameter of fn - the incoming records.
func firstLinkInRecordLoop(fn *ast.FuncDecl) *ast.CallExpr {
	params := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			params[name.Name] = true
		}
	}
	var link *ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok || link != nil {
			return link == nil
		}
		if id, ok := ast.Unparen(loop.X).(*ast.Ident); !ok || !params[id.Name] {
			return true
		}
		ast.Inspect(loop.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok || link != nil {
				return link == nil
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && linkCall.MatchString(sel.Sel.Name) {
				link = call
			}
			return link == nil
		})
		return link == nil
	})
	return link
}

// callsNamed reports a call under node whose name matches.
func callsNamed(node ast.Node, name *regexp.Regexp) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				found = found || name.MatchString(fun.Sel.Name)
			case *ast.Ident:
				found = found || name.MatchString(fun.Name)
			}
		}
		return !found
	})
	return found
}

// pendingQueueRead names a read of the items still waiting for work:
// GetUnsorted, ListUnmatchedByOwner, FetchPending, ListPaidWithoutDetails.
var pendingQueueRead = regexp.MustCompile(`^(?:Get|List|Fetch|Find|Load|Select|Query)\w*(?:(?:Un[a-z]+ed|Pending|Queued)(?:[A-Z]\w*)?|Without[A-Z]\w*)$`)

// pagePosition names an argument that moves a read past the items already
// seen.
var pagePosition = regexp.MustCompile(`(?i)offset|cursor|after|page|since|last|from`)

// skipCounter names a counter of the items a pass leaves as they are.
var skipCounter = regexp.MustCompile(`(?i)skip|ignor|unmatched|unlinked|leftover`)

// PendingPageSkipsStayAtHeadRule detects a pass over the first page of a
// pending queue that skips some of the items:
//
//	items, _ := repo.GetUnmatchedByOwner(owner, 1000)
//	for _, item := range items {
//		if !link(item) { skipped++ } // still unmatched: first in the next page too
//	}
//
// A skipped item stays pending, and the next pass reads the same page: once
// a page's worth of items is skipped, the rest of the queue is never reached.
// A read that moves past the seen items (offset, cursor, after) is left out.
//
// A pass that stops at an item whose call fails (break or return on its
// error, the item not marked) is the same trap: the item stays at the head,
// and every pass stops on it before reaching the items after it.
//
// The read itself shows the same trap when a pending-queue function takes the
// stale rows by their change time (WHERE updated_at < $1 ORDER BY updated_at
// LIMIT $2) and marks nothing: a pass that finds no change does not touch
// updated_at, so the same rows head every page.
type PendingPageSkipsStayAtHeadRule struct {
	*rules.BaseRule
}

// NewPendingPageSkipsStayAtHeadRule creates the rule
func NewPendingPageSkipsStayAtHeadRule() *PendingPageSkipsStayAtHeadRule {
	return &PendingPageSkipsStayAtHeadRule{BaseRule: rules.NewBaseRule(
		"pending-page-skips-stay-at-head",
		"patterns",
		"Detects a pass over the first page of a pending queue that skips items and never moves past them — skipped items stay at the head, and the rest of the queue is never reached",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the pending-queue reads whose passes skip items.
func (r *PendingPageSkipsStayAtHeadRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
			funcs[fn.Name.Name] = fn
		}
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for _, read := range skippedPendingReads(fn.Body, funcs) {
			line := ctx.LineFor(read.call)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			message := "The pass reads the first page of a pending queue and counts skipped items, which stay pending — the next pass reads the same page, and the rest of the queue is never reached"
			suggestion := "Move past the skipped items (an offset or a cursor), give them a terminal state, or report that the page was full of them"
			if read.stops {
				message = "The pass reads the first page of a pending queue and stops at an item whose call fails without marking it — the item stays first in the queue, every pass stops on it, and the items after it are never reached"
				suggestion = "Collect the item's failure (errors.Join) and go on with the next item, or mark the failed item (attempts, a terminal state) so the next pass moves past it"
			}
			v := r.CreateViolation(ctx.RelPath, line, message)
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion(suggestion)
			violations = append(violations, v)
		}
		violations = append(violations, r.stalePageReads(ctx, fn)...)
	}
	return violations
}

// staleOrder is the first key of an ORDER BY that is a change time.
var staleOrder = regexp.MustCompile(`(?i)\bORDER\s+BY\s+(?:\w+\.)?(\w*(?:updated|modified|changed)_at)\b(?:\s+ASC)?\s*(?:,|\bLIMIT\b|\)|$)`)

// sqlLimit and sqlWrite mark a page read and a statement that writes.
var (
	sqlLimit = regexp.MustCompile(`(?i)\bLIMIT\b`)
	sqlWrite = regexp.MustCompile(`(?i)\b(?:INSERT|UPDATE|DELETE)\b`)
)

// upperBound is a column compared below a parameter: updated_at < $1.
var upperBound = regexp.MustCompile(`(?i)\b(\w+)\s*<=?\s*\$\d+`)

// boundBefore reports a condition of text that keeps the column below a
// parameter: the read takes the stale rows only.
func boundBefore(text, column string) bool {
	for _, m := range upperBound.FindAllStringSubmatch(text, -1) {
		if strings.EqualFold(m[1], column) {
			return true
		}
	}
	return false
}

// stalePageReads reports the reads of a pending-queue function (by name,
// with no page position among its parameters) that take the first page of
// stale rows by their change time - WHERE updated_at < $1 ORDER BY updated_at
// LIMIT $2 - and mark nothing: a poll that finds no change leaves updated_at
// as it is, so the same rows head every page and the rest of the queue is
// never reached.
func (r *PendingPageSkipsStayAtHeadRule) stalePageReads(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	if !pendingQueueRead.MatchString(fn.Name.Name) {
		return nil
	}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if pagePosition.MatchString(name.Name) {
				return nil
			}
		}
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(fn.Body) {
		text := literal.text
		m := staleOrder.FindStringSubmatchIndex(text)
		if m == nil || !sqlLimit.MatchString(text[m[0]:]) || sqlWrite.MatchString(text) {
			continue
		}
		column := text[m[2]:m[3]]
		if !boundBefore(text[:m[0]], column) {
			continue
		}
		line := literal.lineAt(ctx, m[0])
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "The pending queue is read by its oldest "+column+" with a LIMIT and nothing marks the rows taken — a pass that finds no change leaves "+column+" as it is, so the same rows head every page and the rest of the queue is never reached")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Order by a poll mark the read itself writes (polled_at NULLS FIRST, set in the same statement), or move past the rows taken with a cursor")
		violations = append(violations, v)
	}
	return violations
}

// pendingRead is a read of a pending queue whose pass leaves items at the
// head: skipped ones, or the failed one it stops at.
type pendingRead struct {
	call  *ast.CallExpr
	stops bool
}

// skippedPendingReads returns the reads of a pending queue in body, by a
// limit and with no page position, whose items a range loop counts as
// skipped or stops at on a failure - in body, or in a function of the file
// the items are handed to.
func skippedPendingReads(body *ast.BlockStmt, funcs map[string]*ast.FuncDecl) []pendingRead {
	reads := make(map[string]*ast.CallExpr)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !pendingQueueRead.MatchString(sel.Sel.Name) || movesPastSeen(call) {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			reads[id.Name] = call
		}
		return true
	})
	var found []pendingRead
	seen := make(map[*ast.CallExpr]bool)
	report := func(items string, stops bool) {
		if read := reads[items]; read != nil && !seen[read] {
			seen[read] = true
			found = append(found, pendingRead{call: read, stops: stops})
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.RangeStmt:
			id, ok := ast.Unparen(node.X).(*ast.Ident)
			switch {
			case !ok:
			case countsSkipped(node.Body):
				report(id.Name, false)
			case stopsAtFailedItem(node):
				report(id.Name, true)
			}
		case *ast.CallExpr:
			callee, ok := node.Fun.(*ast.Ident)
			if !ok || funcs[callee.Name] == nil {
				return true
			}
			for i, arg := range node.Args {
				if id, ok := ast.Unparen(arg).(*ast.Ident); ok && reads[id.Name] != nil && skipsParam(funcs[callee.Name], i) {
					report(id.Name, false)
				}
			}
		}
		return true
	})
	sort.Slice(found, func(i, j int) bool { return found[i].call.Pos() < found[j].call.Pos() })
	return found
}

// stopsAtFailedItem reports a loop that leaves on the failure of a call
// handed its item - `if err != nil { ...; break }` or a return - and does not
// mark the item on the way out: no call but a logger or an error constructor
// takes it.
func stopsAtFailedItem(loop *ast.RangeStmt) bool {
	item := make(map[string]bool)
	for _, v := range []ast.Expr{loop.Key, loop.Value} {
		if id, ok := v.(*ast.Ident); ok && id.Name != "_" {
			item[id.Name] = true
		}
	}
	if len(item) == 0 {
		return false
	}
	// itemErrs are the error variables set by a call handed the item.
	itemErrs := make(map[string]bool)
	noteItemErrs := func(assign *ast.AssignStmt) {
		if len(assign.Rhs) == 1 && callTakesNames(assign.Rhs[0], item) {
			for _, lhs := range assign.Lhs {
				if name, ok := errLikeName(lhs); ok {
					itemErrs[name] = true
				}
			}
		}
	}
	stops := false
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.RangeStmt, *ast.ForStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			return false
		case *ast.AssignStmt:
			noteItemErrs(node)
		case *ast.IfStmt:
			if init, ok := node.Init.(*ast.AssignStmt); ok {
				noteItemErrs(init)
			}
			name, isCheck := errNotNilName(node.Cond)
			if !isCheck || !itemErrs[name] || len(node.Body.List) == 0 || marksItem(node.Body, item) {
				return true
			}
			switch last := node.Body.List[len(node.Body.List)-1].(type) {
			case *ast.ReturnStmt:
				stops = true
			case *ast.BranchStmt:
				stops = stops || (last.Tok == token.BREAK && last.Label == nil)
			}
		}
		return !stops
	})
	return stops
}

// callTakesNames reports a call expression handed one of names in its
// arguments.
func callTakesNames(expr ast.Expr, names map[string]bool) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	for _, arg := range call.Args {
		if mentionsNames(arg, names) {
			return true
		}
	}
	return false
}

// mentionsNames reports an expression reading an identifier of names.
func mentionsNames(expr ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// marksItem reports a block that hands the item to a call other than a
// logger or an error constructor (fmt.Errorf, errors.Join): it records the
// failure on the item.
func marksItem(body *ast.BlockStmt, item map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if helpers.IsLoggerCall(call) {
			return false
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && (pkg.Name == "fmt" || pkg.Name == "errors") {
				return true
			}
		}
		found = callTakesNames(call, item)
		return !found
	})
	return found
}

// skipsParam reports a function that ranges over its parameter at index and
// counts skipped items.
func skipsParam(fn *ast.FuncDecl, index int) bool {
	var name string
	at := 0
	for _, field := range fn.Type.Params.List {
		for _, id := range field.Names {
			if at == index {
				name = id.Name
			}
			at++
		}
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if loop, ok := n.(*ast.RangeStmt); ok {
			if id, ok := ast.Unparen(loop.X).(*ast.Ident); ok && name != "" && id.Name == name && countsSkipped(loop.Body) {
				found = true
			}
		}
		return !found
	})
	return found
}

// movesPastSeen reports a read handed a page position by an argument's name.
func movesPastSeen(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		mentions := false
		ast.Inspect(arg, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && pagePosition.MatchString(id.Name) {
				mentions = true
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && pagePosition.MatchString(sel.Sel.Name) {
				mentions = true
			}
			return !mentions
		})
		if mentions {
			return true
		}
	}
	return false
}

// countsSkipped reports a loop body that increments a skip counter: skipped++,
// tally.skipped++.
func countsSkipped(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if inc, ok := n.(*ast.IncDecStmt); ok && inc.Tok == token.INC {
			switch x := inc.X.(type) {
			case *ast.Ident:
				found = skipCounter.MatchString(x.Name)
			case *ast.SelectorExpr:
				found = skipCounter.MatchString(x.Sel.Name)
			}
		}
		return !found
	})
	return found
}
