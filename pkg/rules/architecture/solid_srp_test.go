package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSolidSRPRule_Metadata(t *testing.T) {
	rule := NewSolidSRPRule()

	assert.Equal(t, "solid-srp", rule.Name())
	assert.Equal(t, "architecture", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestSolidSRPRule_TooManyResponsibilities(t *testing.T) {
	rule := NewSolidSRPRule()

	// User spans database, http, file, network, scheduling, transaction and
	// export areas - well above the default limit of 3 business areas
	goCode := `package app

type User struct{}

func (u *User) SaveUser() error         { return nil }
func (u *User) HandleRequest() error    { return nil }
func (u *User) OpenFile() error         { return nil }
func (u *User) ConnectPeer() error      { return nil }
func (u *User) SchedulePeriodic() error { return nil }
func (u *User) CommitWork() error       { return nil }
func (u *User) ExportCSV() error        { return nil }
`
	ctx := createTestContext(t, "backend/app/user.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "User has")
	assert.Contains(t, violations[0].Message, "business responsibility areas")
}

func TestSolidSRPRule_FewResponsibilitiesOK(t *testing.T) {
	rule := NewSolidSRPRule()

	goCode := `package app

type Account struct{}

func (a *Account) SaveAccount() error { return nil }
func (a *Account) LoadAccount() error { return nil }
`
	ctx := createTestContext(t, "backend/app/account.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestSolidSRPRule_TestFilesExcluded(t *testing.T) {
	rule := NewSolidSRPRule()

	goCode := `package app

type User struct{}

func (u *User) SaveUser() error         { return nil }
func (u *User) HandleRequest() error    { return nil }
func (u *User) OpenFile() error         { return nil }
func (u *User) ConnectPeer() error      { return nil }
func (u *User) SchedulePeriodic() error { return nil }
func (u *User) CommitWork() error       { return nil }
func (u *User) ExportCSV() error        { return nil }
`
	ctx := createTestContext(t, "backend/app/user_test.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestSolidSRPConfigureReset(t *testing.T) {
	rule := NewSolidSRPRule()

	require.NoError(t, rule.Configure(map[string]any{
		"max_responsibilities": 1,
		"infrastructure_areas": []any{"custom"},
	}))
	assert.Equal(t, 1, rule.maxResponsibilities)
	assert.True(t, rule.infrastructureAreas["custom"])
	assert.False(t, rule.infrastructureAreas["logging"])

	// Re-configuring without the keys must reset to defaults,
	// not keep the values from a previously analyzed config
	require.NoError(t, rule.Configure(map[string]any{}))
	assert.Equal(t, defaultMaxResponsibilities, rule.maxResponsibilities)
	assert.True(t, rule.infrastructureAreas["logging"])
	assert.False(t, rule.infrastructureAreas["custom"])
}
