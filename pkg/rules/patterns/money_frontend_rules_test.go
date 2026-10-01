package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

type lineRuleCase struct {
	name     string
	filename string
	code     string
	want     []int // reported lines
}

func runLineRuleCases(t *testing.T, rule interface {
	AnalyzeFile(*core.FileContext) []*core.Violation
}, cases []lineRuleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := core.NewFileContext(tc.filename, ".", []byte(tc.code), nil)
			assertLines(t, rule.AnalyzeFile(ctx), tc.want)
		})
	}
}

func assertLines(t *testing.T, violations []*core.Violation, want []int) {
	t.Helper()
	var got []int
	for _, v := range violations {
		got = append(got, v.Line)
	}
	if len(got) != len(want) {
		t.Fatalf("got lines %v, want %v (%v)", got, want, violationMessages(violations))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got lines %v, want %v (%v)", got, want, violationMessages(violations))
		}
	}
}

func violationMessages(violations []*core.Violation) []string {
	var out []string
	for _, v := range violations {
		out = append(out, v.Message)
	}
	return out
}

func TestHardcodedABISelectorRule(t *testing.T) {
	runLineRuleCases(t, NewHardcodedABISelectorRule(), []lineRuleCase{
		{"selector that does not match its signature", "web/static/pool.js",
			"const stakeSignature = '0x07836a45'; // stake(uint256) - from ABI\n", []int{1}},
		{"selector matching its signature", "web/static/pool.js",
			"const stakeSignature = '0xa694fc3a'; // stake(uint256)\n", nil},
		{"signature on the line above", "web/src/pool.ts",
			"// unstake(uint256)\nconst unstakeSelector = '0xbcf68c9a'\n", []int{2}},
		{"signature as the key of a map", "web/src/pool.ts",
			"const selectors = {\n  'stake(uint256)': '0x07836a45',\n}\n", []int{2}},
		{"selector of another party's contract kept as observed data", "web/src/classify.ts",
			"const claimRewardsSelector = '0x12345678'\n", nil},
		{"uint without its size", "web/src/pool.ts",
			"const stakeSelector = '0xa694fc3a' // stake(uint)\n", nil},
		{"error code compared, not a selector", "web/src/pool.ts",
			"if (error.message.includes('0xfb8f41b2')) { retry() }\n", nil},
		{"value of another kind", "web/src/theme.ts",
			"const overlayColor = '0xff00ff00'\nconst txHash = '0x12345678'\n", nil},
		{"commented-out code", "web/src/pool.ts",
			"// const stakeSelector = '0x07836a45' // stake(uint256)\n", nil},
		{"test file", "web/src/pool.test.ts",
			"const stakeSelector = '0x07836a45' // stake(uint256)\n", nil},
		{"Go constant that does not match", "chain/pool.go",
			"package chain\n\nconst claimSelector = \"0xdeadbeef\" // claim(uint256)\n", []int{3}},
		{"Go selector matching its signature", "chain/token.go",
			"package chain\n\nfunc f() {\n\ttransferSig := \"0xa9059cbb\" // transfer(address,uint256)\n\t_ = transferSig\n}\n", nil},
	})
}

func TestFloatToTokenUnitsRule(t *testing.T) {
	runLineRuleCases(t, NewFloatToTokenUnitsRule(), []lineRuleCase{
		{"floor of amount times a million", "web/static/pool.js",
			"const amountWei = Math.floor(amount * 1000000); // 6 decimals\n", []int{1}},
		{"floor of amount times a power of ten", "web/static/pool.js",
			"const amountWei = Math.floor(amount * Math.pow(10, 6))\n", []int{1}},
		{"exponent operator with the token decimals", "web/src/send.ts",
			"const units = BigInt(Math.round(amount * 10 ** decimals))\n", []int{1}},
		{"wei through a float", "web/src/send.ts",
			"const wei = Math.floor(depositAmount * 1e18)\n", []int{1}},
		{"cents grid belongs to financial-fp-rounding", "web/src/send.ts",
			"const v = Math.floor(balance * 100) / 100\n", nil},
		{"truncation to a precision, divided back", "web/src/send.ts",
			"const v = Math.floor(amount * 1e6) / 1e6\n", nil},
		{"round to micro units is exact at this scale", "web/src/send.ts",
			"const units = Math.round(amount * 1e6)\n", nil},
		{"not money", "web/src/clock.ts",
			"const micros = Math.floor(elapsed * 1000000)\nconst n = Math.floor(count * 1e6)\n", nil},
		{"parsed from the string", "web/src/send.ts",
			"const units = parseUnits(amount.toString(), 6)\n", nil},
		{"test file", "web/src/send.test.ts",
			"const amountWei = Math.floor(amount * 1000000)\n", nil},
	})
}

func TestMoneyMaxRoundedHalfUpRule(t *testing.T) {
	runLineRuleCases(t, NewMoneyMaxRoundedHalfUpRule(), []lineRuleCase{
		{"maximum rounded half up into the amount state", "web/src/Withdraw.tsx",
			"<button onClick={() => maxWithdraw !== null && setWithdrawalAmount(maxWithdraw.toFixed(2))}>Max</button>\n", []int{1}},
		{"maximum rounded down first", "web/src/Withdraw.tsx",
			"<button onClick={() => maxWithdraw !== null && setWithdrawalAmount(floorToCent(maxWithdraw).toFixed(2))}>Max</button>\n", nil},
		{"input value from a maximum", "web/static/pool.js",
			"const maxAmount = Math.max(0, usdcBalance - 1);\ninput.value = maxAmount.toFixed(2);\n", []int{2}},
		{"input value from a maximum floored on the line before", "web/static/pool.js",
			"const maxAmount = Math.floor(usdcBalance * 100) / 100;\ninput.value = maxAmount.toFixed(2);\n", nil},
		{"available balance into a form field", "web/src/Send.tsx",
			"setValue('amount', availableBalance.toFixed(2))\nsetAmount(balance.toFixed(6))\n", []int{1, 2}},
		{"maximum shown, not entered", "web/src/Withdraw.tsx",
			"<span>{maxWithdraw.toFixed(2)}</span>\n", nil},
		{"maximum of something other than money", "web/src/Table.tsx",
			"setPageSize(maxRows.toFixed(0))\nsetSlippage(maxSlippage.toFixed(2))\n", nil},
		{"test file", "web/src/Withdraw.test.tsx",
			"setWithdrawalAmount(maxWithdraw.toFixed(2))\n", nil},
	})
}

func TestMoneyFormatBypassesFormatterRule(t *testing.T) {
	formatter := core.NewFileContext("web/shared/lib/format.ts", ".", []byte(
		"export const formatters = {\n"+
			"  formatAmount: (amount: number, decimals = 2): string => amount.toFixed(decimals),\n"+
			"}\n"), nil)
	component := core.NewFileContext("web/app/src/components/History.tsx", ".", []byte(
		"const rows = items.map(t => [\n"+ // 1
			"  t.amount.toFixed(2),\n"+ // 2
			"  `${sign}${Math.abs(op.amount).toFixed(2)}`,\n"+ // 3
			"])\n"+ // 4
			"return <td>{transaction.amount.toLocaleString()} USDC</td>\n"+ // 5
			"const shown = count.toLocaleString()\n"+ // 6
			"const precise = amount.toLocaleString('en-US', { minimumFractionDigits: 2 })\n"+ // 7
			"console.log(`sent ${amount.toFixed(2)}`)\n"+ // 8
			"const usd = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })\n"+ // 9
			"const pct = new Intl.NumberFormat('en-US', { style: 'percent' })\n"+ // 10
			"const width = `${Math.min(100, (balance / goal) * 100).toFixed(1)}%`\n"), nil) // 11
	script := core.NewFileContext("tools/scripts/report.js", ".", []byte("console.info(total.toFixed(2))\nconst s = fee.toFixed(2)\n"), nil)
	test := core.NewFileContext("web/app/src/components/History.test.tsx", ".", []byte("expect(t.amount.toFixed(2)).toBe('1.00')\n"), nil)

	rule := NewMoneyFormatBypassesFormatterRule()
	rule.UseProjectFiles([]*core.FileContext{formatter, component, script, test})
	assertLines(t, rule.AnalyzeFile(component), []int{2, 3, 5, 9})
	assertLines(t, rule.AnalyzeFile(formatter), nil)
	assertLines(t, rule.AnalyzeFile(script), nil)
	assertLines(t, rule.AnalyzeFile(test), nil)

	rule.ResetState()
	rule.UseProjectFiles([]*core.FileContext{component})
	assertLines(t, rule.AnalyzeFile(component), nil)

	// A screen's own helper is not the project's formatter.
	screen := core.NewFileContext("web/app/src/components/Wallets.tsx", ".", []byte(
		"const formatBalance = (balance: string) => Number(balance).toFixed(2)\n"), nil)
	rule.ResetState()
	rule.UseProjectFiles([]*core.FileContext{screen, component})
	assertLines(t, rule.AnalyzeFile(component), nil)
	assertLines(t, rule.AnalyzeFile(screen), nil)
}
