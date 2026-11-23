package dbrules

import (
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// RootFilesAndCacheInputs declares the complete inputs of the query index.
func (*SQLChildRowsIncludeVoidedParentRule) RootFilesAndCacheInputs() {}

// CacheInputs identifies the migration bytes used by the rule and its index.
func (r *SQLChildRowsIncludeVoidedParentRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLUnknownColumnRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLInsertMissingNotNullRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLLimitWithoutOrderRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLConstantShadowsColumnRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLTestDDLDuplicatesMigrationRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLGroupBySingleRowRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLLinkUpdateIgnoresParentRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLPartialKeyReadRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *ExternalReferenceLookupWithoutUniqueIndexRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLDeleteReferencedWithoutKeyRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *MoneySummedAcrossCurrenciesRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLMissingRowUncheckedRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLCharColumnPadsValueRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *DeltaExportMissesUnlinkRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLCheckConstraintInputUnvalidatedRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLConstraintViolationUnmappedRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLDateStringParsedAsDateRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLModelFieldSkippedRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLScanArgCountRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLScanNullableRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLSessionTimeZoneRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SQLXColumnWithoutFieldRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *StringLiteralExceedsColumnWidthRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *SyncNewerWinsOnStampedTableRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// CacheInputs identifies the migration bytes used by the rule.
func (r *TruncatedRandomIDAsUniqueNumberRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}
