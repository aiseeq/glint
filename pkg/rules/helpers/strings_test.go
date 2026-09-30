package helpers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskJSCommentsAndStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "line comment after code",
			in:   []string{"click() // no waitForTimeout( here"},
			want: []string{"click()                           "},
		},
		{
			name: "jsdoc block spans lines",
			in: []string{
				"/**",
				" * Never write process.env['X']",
				" */",
				"export const a = 1",
			},
			want: []string{
				"   ",
				"                               ",
				"   ",
				"export const a = 1",
			},
		},
		{
			name: "quotes keep delimiters, lose contents",
			in:   []string{`log('bad brace {', "x // y", e)`},
			want: []string{`log('           ', "      ", e)`},
		},
		{
			name: "escaped quote does not end the string",
			in:   []string{`a('it\'s {')`},
			want: []string{`a('       ')`},
		},
		{
			name: "template text masked, holes kept",
			in:   []string{"key={`${wallet.address}-${index}`}"},
			want: []string{"key={`${wallet.address} ${index}`}"},
		},
		{
			name: "template spans lines with nested braces in a hole",
			in: []string{
				"const s = `a {",
				"${fn({ x: '}' })} b }`",
				"if (x) {",
			},
			want: []string{
				"const s = `   ",
				"${fn({ x: ' ' })}    `",
				"if (x) {",
			},
		},
		{
			name: "regex literal after an operator",
			in:   []string{`const re = /['{]/g; x = a / b / c`},
			want: []string{`const re = /    /g; x = a / b / c`},
		},
		{
			name: "jsx closing tag is not a regex",
			in:   []string{`<li key={x.id}>{x.label}</li>`},
			want: []string{`<li key={x.id}>{x.label}</li>`},
		},
		{
			name: "unterminated string ends with its line",
			in:   []string{`<p>Don't {name}</p>`, `if (a) {`},
			want: []string{`<p>Don'` + strings.Repeat(" ", 12), `if (a) {`},
		},
		{
			name: "url inside a string is not a comment",
			in:   []string{`fetch("http://x/y") // call`},
			want: []string{`fetch("          ")` + strings.Repeat(" ", 8)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskJSCommentsAndStrings(tt.in)
			require.Equal(t, tt.want, got)
			for i := range got {
				require.Len(t, got[i], len(tt.in[i]), "line %d must keep its length", i)
			}
		})
	}
}

func TestMaskJSCommentsKeepsLiterals(t *testing.T) {
	in := []string{
		"/**",
		" * Object.keys(resp.data) throws",
		" */",
		"await page.waitForLoadState('networkidle') // not 'load'",
		"const u = `${base}/api` /* tail */ + x",
	}
	got := MaskJSComments(in)
	require.Equal(t, strings.Repeat(" ", len(in[1])), got[1])
	require.Equal(t, "await page.waitForLoadState('networkidle')"+strings.Repeat(" ", 14), got[3])
	require.Equal(t, "const u = `${base}/api`            + x", got[4])
}
