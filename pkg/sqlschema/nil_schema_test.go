package sqlschema

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A project without migrations has a nil schema, and every rule asks it about
// its SQL anyway: no method may fail on it.
func TestNilSchemaAnswersEveryMethod(t *testing.T) {
	statements := []string{
		`SELECT id FROM users WHERE seen_on < CURRENT_DATE ORDER BY id LIMIT 1`,
		`WITH c AS (SELECT id FROM users) SELECT u.id FROM c JOIN users u USING (id) FOR UPDATE`,
		`INSERT INTO users (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING RETURNING id`,
		`UPDATE users SET name = $2, updated_at = now() WHERE id = $1`,
		`DELETE FROM users WHERE id = $1`,
		`SELECT sum(amount) FROM payments WHERE created_at::date = $1`,
	}
	var schema *Schema
	value := reflect.ValueOf(schema)
	var failed []string
	for i := 0; i < value.NumMethod(); i++ {
		method := value.Type().Method(i)
		for _, sql := range statements {
			args := make([]reflect.Value, method.Type.NumIn()-1)
			for a := range args {
				in := method.Type.In(a + 1)
				args[a] = reflect.Zero(in)
				if in.Kind() == reflect.String {
					args[a] = reflect.ValueOf(sql).Convert(in)
				}
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						failed = append(failed, fmt.Sprintf("%s: %v", method.Name, r))
					}
				}()
				value.Method(i).Call(args)
			}()
		}
	}
	assert.Empty(t, failed)
}
