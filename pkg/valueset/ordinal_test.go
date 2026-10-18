package valueset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOrdinal(t *testing.T) {
	tests := []struct {
		name    string
		members []string
		want    bool
	}{
		{name: "numbered from one", members: []string{"H1", "H2", "H3"}, want: true},
		{name: "unordered consecutive numbers", members: []string{"step3", "step1", "step2", "step4"}, want: true},
		{name: "number gap", members: []string{"step1", "step3", "step4"}},
		{name: "different prefixes", members: []string{"H1", "H2", "v3"}},
		{name: "non-canonical number", members: []string{"H01", "H2", "H3"}},
		{name: "too few members", members: []string{"H1", "H2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Ordinal(Set{Members: tt.members}))
		})
	}
}
