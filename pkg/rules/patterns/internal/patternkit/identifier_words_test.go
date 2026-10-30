package patternkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentifierWords(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{name: "camelCase", want: []string{"camel", "case"}},
		{name: "SNAKE_CASE", want: []string{"snake", "case"}},
		{name: "HTTPServer", want: []string{"http", "server"}},
		{name: "userID2FA", want: []string{"user", "id", "2", "fa"}},
		{name: "MAX_GOAL_AMOUNT", want: []string{"max", "goal", "amount"}},
		{name: "apyBps", want: []string{"apy", "bps"}},
		{name: "limit$2", want: []string{"limit", "2"}},
		{name: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IdentifierWords(tt.name))
		})
	}
}
