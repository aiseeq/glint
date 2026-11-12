package sqlschema

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// rangeOrder wraps a message so that Range visits its set fields in a chosen
// order. protobuf-go swaps two neighbouring fields of its Range order by a hash
// of the executable, so the test cannot rely on Range itself to come out of
// declaration order in a given build.
type rangeOrder struct {
	protoreflect.Message
	reverse bool
}

func (m rangeOrder) Range(visit func(protoreflect.FieldDescriptor, protoreflect.Value) bool) {
	type entry struct {
		field protoreflect.FieldDescriptor
		value protoreflect.Value
	}
	var entries []entry
	m.Message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		entries = append(entries, entry{field, value})
		return true
	})
	slices.SortFunc(entries, func(a, b entry) int { return a.field.Index() - b.field.Index() })
	if m.reverse {
		slices.Reverse(entries)
	}
	for _, e := range entries {
		if !visit(e.field, e.value) {
			return
		}
	}
}

func TestEachChildFollowsDeclarationOrder(t *testing.T) {
	tree, ok := parse(`WITH x AS (SELECT a, b FROM things WHERE a > 1)
SELECT x.a, count(x.b) FROM x WHERE x.a > 2 GROUP BY x.a
HAVING count(x.b) > 1 ORDER BY x.a LIMIT 3 OFFSET 1`)
	require.True(t, ok)
	type child struct {
		field   protoreflect.FieldDescriptor
		message proto.Message
	}
	multiField := 0
	var check func(protoreflect.Message)
	check = func(message protoreflect.Message) {
		var want []child
		present := 0
		fields := message.Descriptor().Fields()
		for i := range fields.Len() {
			field := fields.Get(i)
			if field.Message() == nil || field.IsMap() || !message.Has(field) {
				continue
			}
			present++
			value := message.Get(field)
			if field.IsList() {
				list := value.List()
				for j := range list.Len() {
					want = append(want, child{field, list.Get(j).Message().Interface()})
				}
			} else {
				want = append(want, child{field, value.Message().Interface()})
			}
		}
		if present > 1 {
			multiField++
		}
		for _, wrapped := range []protoreflect.Message{message, rangeOrder{message, false}, rangeOrder{message, true}} {
			var got []child
			eachChild(wrapped, func(field protoreflect.FieldDescriptor, value protoreflect.Message) {
				got = append(got, child{field, value.Interface()})
			})
			require.Equal(t, want, got, "%s", message.Descriptor().FullName())
		}
		for _, c := range want {
			check(c.message.ProtoReflect())
		}
	}
	check(tree.ProtoReflect())
	// Reversal shows a broken sort only on nodes with several set fields.
	require.Positive(t, multiField)
}
