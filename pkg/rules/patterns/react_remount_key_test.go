package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestReactRemountKeyRule(t *testing.T) {
	rule := NewReactRemountKeyRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			// Repro: projectB settings/page.tsx before aa0bf07 — the wallet
			// address is both the key and the edited input value.
			name: "key from edited field",
			code: `{walletDrafts.map((wallet, index) => (
  <div key={` + "`${wallet.walletAddress}-${index}`" + `} className="grid">
    <div>
      <label className="block">Wallet Address</label>
      <input value={wallet.walletAddress} onChange={e => updateWalletDraft(index, 'walletAddress', e.target.value)} placeholder="0x..."
        className="w-full" />
    </div>
  </div>
))}`,
			wantCount: 1,
		},
		{
			// Post-fix shape: index key, same controlled input.
			name: "index key is silent",
			code: `{walletDrafts.map((wallet, index) => (
  <div key={index} className="grid">
    <input value={wallet.walletAddress} onChange={e => updateWalletDraft(index, 'walletAddress', e.target.value)} />
  </div>
))}`,
			wantCount: 0,
		},
		{
			name: "key field differs from edited field",
			code: `{items.map(item => (
  <div key={item.id}>
    <input value={item.name} onChange={e => rename(item.id, e.target.value)} />
  </div>
))}`,
			wantCount: 0,
		},
		{
			name: "read-only input on key field is silent",
			code: `{items.map(item => (
  <div key={item.address}>
    <input value={item.address} readOnly />
  </div>
))}`,
			wantCount: 0,
		},
		{
			name: "plain key expression with controlled input",
			code: `{rows.map(row => (
  <section key={row.label}>
    <input value={row.label} onChange={e => setLabel(e.target.value)} />
  </section>
))}`,
			wantCount: 1,
		},
		{
			name: "input tag spans multiple lines",
			code: `{rows.map(row => (
  <section key={row.label}>
    <input
      value={row.label}
      onChange={e => setLabel(e.target.value)}
    />
  </section>
))}`,
			wantCount: 1,
		},
		{
			name: "onChange of a sibling tag does not count",
			code: `{rows.map(row => (
  <section key={row.label}>
    <input value={row.label} readOnly />
    <input value={row.note} onChange={e => setNote(e.target.value)} />
  </section>
))}`,
			wantCount: 0,
		},
		{
			name: "suppression comment is honored",
			code: `{rows.map(row => (
  // nolint:react-remount-key — remount намеренный: сброс внутреннего стейта редактора
  <section key={row.label}>
    <input value={row.label} onChange={e => setLabel(e.target.value)} />
  </section>
))}`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/app/settings/page.tsx", "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.wantCount, "Code: %s", tt.code)
		})
	}
}

func TestReactRemountKeyRuleSkipsNonFrontendFiles(t *testing.T) {
	rule := NewReactRemountKeyRule()
	code := `<div key={item.name}><input value={item.name} onChange={f} /></div>`

	goCtx := core.NewFileContext("/src/file.go", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(goCtx))

	testCtx := core.NewFileContext("/src/app/page.test.tsx", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(testCtx))
}
