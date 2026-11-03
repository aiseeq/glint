package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func TestSyncNewerWinsOnStampedTableReportsOnlyOnGoFiles(t *testing.T) {
	rule := NewSyncNewerWinsOnStampedTableRule()
	declared, ok := any(rule).(rules.FindingFileRule)
	if !ok {
		t.Fatal("rule does not declare its finding file kinds")
	}
	if !declared.ReportsOn(core.NewFileContext("store.go", ".", nil, nil)) {
		t.Fatal("ReportsOn(store.go)=false, want true")
	}
	if declared.ReportsOn(core.NewFileContext("mapping.conf", ".", nil, nil)) {
		t.Fatal("ReportsOn(mapping.conf)=true, want false")
	}
}
