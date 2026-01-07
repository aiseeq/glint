package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.Label())
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
		hasError bool
	}{
		{"low", SeverityLow, false},
		{"LOW", SeverityLow, false},
		{"Low", SeverityLow, false},
		{"medium", SeverityMedium, false},
		{"MEDIUM", SeverityMedium, false},
		{"high", SeverityHigh, false},
		{"HIGH", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"CRITICAL", SeverityCritical, false},
		{"invalid", SeverityLow, true},
		{"", SeverityLow, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseSeverity(tt.input)
			if tt.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	assert.True(t, SeverityLow < SeverityMedium)
	assert.True(t, SeverityMedium < SeverityHigh)
	assert.True(t, SeverityHigh < SeverityCritical)
}
