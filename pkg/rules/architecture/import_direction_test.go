package architecture

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportDirectionRule_Metadata(t *testing.T) {
	rule := NewImportDirectionRule()

	assert.Equal(t, "import-direction", rule.Name())
	assert.Equal(t, "architecture", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestImportDirectionRule_ServiceImportsHandler(t *testing.T) {
	rule := NewImportDirectionRule()

	goCode := `package services

import (
	"myapp/handlers"
	"myapp/models"
)

func GetUser() {
	handlers.DoSomething()
}
`
	ctx := createTestContext(t, "backend/services/user_service.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for Service importing Handler")
	assert.Contains(t, violations[0].Message, "Service imports from Handler")
}

func TestImportDirectionRule_RepoImportsService(t *testing.T) {
	rule := NewImportDirectionRule()

	goCode := `package repository

import (
	"myapp/services"
)

func SaveUser() {
	services.Validate()
}
`
	ctx := createTestContext(t, "backend/repository/user_repository.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for Repository importing Service")
	assert.Contains(t, violations[0].Message, "Repository imports from Service")
}

func TestImportDirectionRule_RepoImportsHandler(t *testing.T) {
	rule := NewImportDirectionRule()

	goCode := `package repository

import (
	"myapp/handlers"
)

func SaveUser() {
	handlers.GetContext()
}
`
	ctx := createTestContext(t, "backend/repo/user_repo.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for Repository importing Handler")
	assert.Contains(t, violations[0].Message, "Repository imports from Handler")
}

func TestImportDirectionRule_CorrectDirection(t *testing.T) {
	rule := NewImportDirectionRule()

	tests := []struct {
		name string
		path string
		code string
	}{
		{
			name: "handler imports service",
			path: "backend/handlers/user_handler.go",
			code: `package handlers

import "myapp/services"

func Handle() {
	services.GetUser()
}
`,
		},
		{
			name: "service imports repository",
			path: "backend/services/user_service.go",
			code: `package services

import "myapp/repository"

func GetUser() {
	repository.Find()
}
`,
		},
		{
			name: "handler imports repository (skip level allowed)",
			path: "backend/handlers/user_handler.go",
			code: `package handlers

import "myapp/repository"

func Handle() {
	repository.Find()
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTestContext(t, tt.path, tt.code)
			violations := rule.AnalyzeFile(ctx)
			assert.Empty(t, violations, "Expected no violation for correct import direction")
		})
	}
}

func TestImportDirectionRule_ExternalImportsIgnored(t *testing.T) {
	rule := NewImportDirectionRule()

	goCode := `package services

import (
	"fmt"
	"net/http"
	"github.com/lib/pq"
)

func GetUser() {
	fmt.Println("test")
}
`
	ctx := createTestContext(t, "backend/services/user_service.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "External imports should not trigger violations")
}

func TestImportDirectionRule_UnknownLayerIgnored(t *testing.T) {
	rule := NewImportDirectionRule()

	goCode := `package models

import (
	"myapp/handlers"
	"myapp/services"
)

type User struct{}
`
	ctx := createTestContext(t, "backend/models/user.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Unknown layers should not trigger violations")
}

func TestImportDirectionRule_TestFilesExcluded(t *testing.T) {
	rule := NewImportDirectionRule()

	goCode := `package services

import "myapp/handlers"

func TestGetUser() {
	handlers.DoSomething()
}
`
	ctx := createTestContext(t, "backend/services/user_service_test.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestImportDirectionRule_RoutingImportsHandler(t *testing.T) {
	rule := NewImportDirectionRule()

	// Routing is handler-layer, importing from services is correct
	goCode := `package routing

import "myapp/services"

func Setup() {
	services.GetUser()
}
`
	ctx := createTestContext(t, "backend/shared/routing/admin_router.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Routing (handler layer) importing services is correct")
}
