package patternkit

import (
	"go/ast"
	"reflect"
	"strings"
	"unicode"
)

func JsonFieldName(field *ast.Field, allowDefault bool) (string, bool) {
	if field.Tag == nil {
		if !allowDefault || len(field.Names) == 0 || !field.Names[0].IsExported() {
			return "", false
		}
		return field.Names[0].Name, true
	}
	tag := strings.Trim(field.Tag.Value, "`")
	jsonTag, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return "", false
	}
	return strings.Split(jsonTag, ",")[0], true
}

func IdentifierTokens(name string) []string {
	runes := []rune(name)
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, strings.ToLower(string(current)))
			current = nil
		}
	}
	for index, char := range runes {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			flush()
			continue
		}
		if len(current) > 0 && unicode.IsUpper(char) {
			previous := runes[index-1]
			nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower {
				flush()
			}
		}
		current = append(current, char)
	}
	flush()
	return tokens
}
