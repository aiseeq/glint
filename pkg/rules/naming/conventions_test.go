package naming

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestNamingConventionsRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "good type name",
			code: `package user

type Manager struct {}`,
			wantViolations: 0,
		},
		{
			name: "stuttering type name",
			code: `package user

type UserManager struct {}`,
			wantViolations: 1,
		},
		{
			name: "ALL_CAPS type name",
			code: `package main

type HTTP_CLIENT struct {}`,
			wantViolations: 2, // ALL_CAPS + underscore
		},
		{
			name: "underscore in exported type",
			code: `package main

type User_Data struct {}`,
			wantViolations: 1,
		},
		{
			name: "good function name",
			code: `package user

func GetByID() {}`,
			wantViolations: 0,
		},
		{
			name: "stuttering function name",
			code: `package user

func UserGetByID() {}`,
			wantViolations: 1,
		},
		{
			name: "underscore in exported function",
			code: `package main

func Get_User() {}`,
			wantViolations: 1,
		},
		{
			name: "method with underscore - ok (interface implementation)",
			code: `package main

type Handler struct {}

func (h *Handler) Handle_Request() {}`,
			wantViolations: 0, // Methods are allowed to have underscores (interface impl)
		},
		{
			name: "main and init skipped",
			code: `package main

func main() {}
func init() {}`,
			wantViolations: 0,
		},
		{
			name: "underscore in exported const - ok if ALL_CAPS",
			code: `package main

const MAX_SIZE = 100`,
			wantViolations: 0,
		},
		{
			name: "underscore in exported var - mixed case",
			code: `package main

var User_Name = "test"`,
			wantViolations: 1,
		},
		{
			name: "blank identifier - ok",
			code: `package main

var _ = struct{}{}`,
			wantViolations: 0,
		},
		{
			name: "private names with underscore - ok",
			code: `package main

type user_data struct {}
func get_user() {}
var user_name = "test"`,
			wantViolations: 0,
		},
		{
			name: "short ALL_CAPS like ID - ok",
			code: `package main

type ID int`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewNamingConventionsRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/test.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}
