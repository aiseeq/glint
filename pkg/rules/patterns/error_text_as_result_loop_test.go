package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A loop folds each failure's text into the result's Errors list and the
// function returns the result with a nil error: the caller that checks err
// takes the run as clean.
func TestErrorTextAsResult_LoopFoldsErrorsIntoResult(t *testing.T) {
	const source = `package imports

func (s *Service) importAll(ctx context.Context, ids []string) (*Result, error) {
	agg := &Result{Errors: []string{}}
	for _, id := range ids {
		res, err := s.importOne(ctx, id)
		if err != nil {
			agg.Errors = append(agg.Errors, fmt.Sprintf("item %s: %s", id, err.Error()))
			continue
		}
		agg.Created += res.Created
	}
	return agg, nil
}

func (s *Service) importJoined(ctx context.Context, ids []string) (*Result, error) {
	agg := &Result{}
	var failed []error
	for _, id := range ids {
		res, err := s.importOne(ctx, id)
		if err != nil {
			agg.Errors = append(agg.Errors, err.Error())
			failed = append(failed, err)
			continue
		}
		agg.Created += res.Created
	}
	return agg, errors.Join(failed...)
}
`
	violations := NewErrorTextAsResultRule().AnalyzeFile(rulestest.GoFile(t, "imports/all.go", source))
	assert.Equal(t, []int{8}, violationLines(violations))
}

// The error kept for the return next to its text, and a list of skip
// reasons, are not a failure folded into data.
func TestErrorTextAsResult_LoopKeepsErrorOrSkipReasons(t *testing.T) {
	const source = `package imports

func (s *Service) importAll(ctx context.Context, ids []string) (*Result, error) {
	agg := &Result{}
	var failed []error
	for _, id := range ids {
		res, err := s.importOne(ctx, id)
		if err != nil {
			agg.Errors = append(agg.Errors, err.Error())
			failed = append(failed, err)
			continue
		}
		agg.Created += res.Created
	}
	if len(failed) > 0 {
		return agg, errors.Join(failed...)
	}
	return agg, nil
}

func (s *Service) importEntries(ctx context.Context, entries []Entry) (*Result, error) {
	result := &Result{}
	for _, entry := range entries {
		date, err := parseDate(entry.Date)
		if err != nil {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: %v", entry.Name, err))
			continue
		}
		result.Dates = append(result.Dates, date)
	}
	return result, nil
}
`
	assert.Empty(t, violationLines(NewErrorTextAsResultRule().AnalyzeFile(rulestest.GoFile(t, "imports/all.go", source))))
}
