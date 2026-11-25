package httprules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// noteSource declares the type of the cases: built with Line set, stored with
// json.Marshal, Line read by the builder's caller.
const noteSource = `package sample

import "encoding/json"

type Note struct {
	Text  string            ` + "`json:\"text\"`" + `
	Word  Word              ` + "`json:\"word\"`" + `
	Marks [2]int            ` + "`json:\"marks\"`" + `
	Tags  []string          ` + "`json:\"tags\"`" + `
	Extra map[string]string ` + "`json:\"extra\"`" + `
	Line  int               ` + "`json:\"-\"`" + `
}

type Word struct{ Value string }

func (w Word) String() string { return w.Value }
func (w *Word) Trim()         { w.Value = w.Value[:1] }

func (n Note) At() string { return n.Text }

func Build(text string, line int) Note { return Note{Text: text, Line: line} }

func Send(n Note) ([]byte, error) { return json.Marshal(n) }

func Key(n Note) int { return n.Line }
`

// lostFields runs the rule on noteSource and a file using it, and returns the
// names of the fields it reports.
func lostFields(t *testing.T, use string) []string {
	t.Helper()
	lost := []string{}
	for _, violation := range rulestest.RunRuleOnFiles(t, NewJSONIgnoredFieldLostInRoundTripRule(), map[string]string{
		"note.go": noteSource, "use.go": "package sample\n\n" + use,
	}) {
		name, _, _ := strings.Cut(violation.Message, " ")
		lost = append(lost, name)
	}
	slices.Sort(lost)
	return lost
}

// body is a function that decodes a Note into v and goes on with rest.
func body(imports, rest string) string {
	return "import (\n\t\"encoding/json\"\n\t" + strings.ReplaceAll(imports, " ", "\n\t") + "\n)\n\n" +
		"func Load(raw []byte) (text string, err error) {\n\tvar v Note\n" +
		"\tif err := json.Unmarshal(raw, &v); err != nil {\n\t\treturn \"\", err\n\t}\n\t" + rest + "\n\treturn text, nil\n}\n"
}

// A value decoded into a local variable of which the function reads only
// fields JSON carries loses nothing: no one can read the ignored field of it.
func TestJSONIgnoredFieldOfPartlyReadDecode(t *testing.T) {
	for name, use := range map[string]string{
		"not decoded": `func Built() int { return Key(Build("a", 3)) }`,
		"decoded in another type's ignored field": `import "encoding/json"

type Page struct {
	Title string ` + "`json:\"title\"`" + `
	Note  Note   ` + "`json:\"-\"`" + `
}

func Load(raw []byte) (string, error) {
	var page Page
	err := json.Unmarshal(raw, &page)
	return page.Title + page.Note.Text, err
}`,
		"decoded in an unexported field": `import "encoding/json"

type Page struct {
	Title string
	note  Note
}

func Load(raw []byte) (page Page, text string, err error) {
	err = json.Unmarshal(raw, &page)
	return page, page.note.Text, err
}`,
		"filled in after a whole decode": `import "encoding/json"

func Load(raw []byte, line int) (v Note, err error) {
	err = json.Unmarshal(raw, &v)
	v.Line = line
	return v, err
}`,
		"one field read":             body("", `text = v.Text`),
		"nothing read":               body("", `text = "read"`),
		"in parentheses":             body("", `text = (v).Text + ((v.Text))`),
		"field passed":               body(`"fmt"`, `text = fmt.Sprint(v.Text, v.Tags)`),
		"field compared":             body("", `if v.Text == "" { text = "none" }`),
		"field negated":              body("", `if -v.Marks[0] > 1 { text = v.Text }`),
		"field in a literal":         body("", `text = Word{Value: v.Text}.String()`),
		"field in a closure's place": body("", `text = func(s string) string { return s }(v.Text)`),
		"field sliced":               body("", `text = v.Text[1:] + v.Tags[1:][0]`),
		"field indexed":              body("", `text = v.Tags[v.Marks[0]] + v.Extra["a"]`),
		"field ranged over":          body("", `for _, tag := range v.Tags { text += tag }`),
		"field of a field":           body("", `text = v.Word.Value`),
		"value method of a field":    body("", `text = v.Word.String()`),
		"decoded twice":              body("", `err = json.Unmarshal(raw, &v); text = v.Text`),
		"decoded from itself":        body("", `err = json.Unmarshal([]byte(v.Text), &v); text = v.Text`),
		"decoded in parentheses":     body("", `err = json.Unmarshal(raw, (&v)); err = json.Unmarshal(raw, &(v)); text = v.Text`),
		"field as an index":          body("", `seen := map[string]bool{}; seen[v.Text] = true; seen[v.Tags[0]] = true`),
		"field as a bound":           body("", `var marks [2]int; text = string(rune(len(marks[v.Marks[0]:v.Marks[1]])))`),
		"decoder": `import (
	"encoding/json"
	"io"
)

func Load(r io.Reader) (string, error) {
	var v Note
	err := json.NewDecoder(r).Decode(&v)
	return v.Text, err
}`,
		"alias": `import "encoding/json"

type Memo = Note

func Load(raw []byte) (string, error) {
	var v Memo
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"all in one closure": `import "encoding/json"

func Load(raw []byte) func() (string, error) {
	return func() (string, error) {
		var v Note
		err := json.Unmarshal(raw, &v)
		return v.Text, err
	}
}`,
		"generic type": `import "encoding/json"

type Box[T any] struct {
	Value  T   ` + "`json:\"value\"`" + `
	Hidden int ` + "`json:\"-\"`" + `
}

func Store(hidden int) ([]byte, error) {
	b := Box[string]{Hidden: hidden}
	if b.Hidden < 0 {
		return nil, nil
	}
	return json.Marshal(b)
}

func Load(raw []byte) (string, error) {
	var b Box[string]
	err := json.Unmarshal(raw, &b)
	return b.Value, err
}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, lostFields(t, use))
		})
	}
}

// Any other use of the variable, or a variable that does not hold just what
// was decoded, keeps the decode a reading of the whole type.
func TestJSONIgnoredFieldOfWhollyReadDecode(t *testing.T) {
	for name, use := range map[string]string{
		"ignored field read":         body(`"fmt"`, `text = fmt.Sprint(v.Line)`),
		"passed":                     body(`"strconv"`, `text = strconv.Itoa(Key(v))`),
		"address passed":             body("", `fill := func(n *Note) {}; fill(&v)`),
		"address kept":               body("", `p := &v; text = p.Text`),
		"printed":                    body(`"fmt"`, `text = fmt.Sprintf("%v", v)`),
		"reflected":                  body(`"reflect"`, `text = reflect.ValueOf(v).Field(0).String()`),
		"method called":              body("", `text = v.At()`),
		"method value":               body("", `at := v.At; text = at()`),
		"assigned":                   body("", `w := v; text = w.Text`),
		"assigned to":                body("", `v = Build("a", 3); text = v.Text`),
		"redeclared":                 body("", `v, n := Build("a", 3), 1; text = v.Text[n:]`),
		"compared":                   body("", `p := &Note{}; if &v == p { text = v.Text }`),
		"in a literal":               body("", `text = []Note{v}[0].Text`),
		"in a keyed literal":         body("", `text = map[string]Note{"a": v}["a"].Text`),
		"sent":                       body("", `c := make(chan Note, 1); c <- v`),
		"passed to what is decoded":  body("", `err = json.Unmarshal([]byte(v.At()), &v); text = v.Text`),
		"ignored field is decoded":   body("", `err = json.Unmarshal([]byte{byte(v.Line)}, &v); text = v.Text`),
		"copied for what is decoded": body("", `err = json.Unmarshal([]byte{byte(Key(v))}, &v); text = v.Text`),
		"decoded as XML too":         body(`"encoding/xml"`, `err = xml.Unmarshal(raw, &v); text = v.Text`),
		"in a closure":               body("", `text = func() string { return v.Text }()`),
		"field set":                  body("", `v.Text = "a"; text = v.Text`),
		"field in parentheses set":   body("", `(v.Text) = "a"; text = v.Text`),
		"element in parentheses set": body("", `(v.Marks)[0] = 1; text = v.Text`),
		"marshalled":                 body("", `_, err = json.Marshal(&v); text = v.Text`),
		"field of a field set":       body("", `v.Word.Value = "a"; text = v.Text`),
		"element of a field set":     body("", `v.Marks[0] = 1; text = v.Text`),
		"entry of a field set":       body("", `v.Extra["a"] = "b"; text = v.Text`),
		"field set with an operator": body("", `v.Text += "a"; text = v.Text`),
		"field counted up":           body("", `v.Marks[0]++; text = v.Text`),
		"field set in a range":       body("", `for _, v.Text = range v.Tags { text += v.Text }`),
		"field set by a range key":   body("", `for v.Marks[0] = range v.Tags { text = v.Text }`),
		"address of a field":         body("", `p := &v.Text; text = *p`),
		"address of a field's field": body("", `p := &v.Word.Value; text = *p`),
		"address in parentheses":     body("", `p := &(v.Text); text = *p`),
		"pointer method of a field":  body("", `v.Word.Trim(); text = v.Text`),
		"array field sliced":         body("", `text = v.Tags[v.Marks[:][0]]`),
		"returned": `import "encoding/json"

func Load(raw []byte) (Note, error) {
	var v Note
	err := json.Unmarshal(raw, &v)
	return v, err
}`,
		"returned without a name": `import "encoding/json"

func Load(raw []byte) (v Note, err error) {
	err = json.Unmarshal(raw, &v)
	return
}`,
		"pointer to an empty literal": `import "encoding/json"

func Load(raw []byte) (string, error) {
	v := &Note{}
	err := json.Unmarshal(raw, v)
	return v.Text, err
}`,
		"new": `import "encoding/json"

func Load(raw []byte) (string, error) {
	v := new(Note)
	err := json.Unmarshal(raw, v)
	return v.Text, err
}`,
		"nil pointer": `import "encoding/json"

func Load(raw []byte) (string, error) {
	var v *Note
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"empty literal": `import "encoding/json"

func Load(raw []byte) (string, error) {
	v := Note{}
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"pointer from elsewhere": `import "encoding/json"

var last = &Note{}

func Load(raw []byte) (string, error) {
	v := last
	err := json.Unmarshal(raw, v)
	return v.Text, err
}`,
		"pointer received": `import "encoding/json"

func Load(raw []byte, notes chan *Note) (string, error) {
	v := <-notes
	err := json.Unmarshal(raw, v)
	return v.Text, err
}`,
		"parameter": `import "encoding/json"

func Load(raw []byte, v *Note) (string, error) {
	err := json.Unmarshal(raw, v)
	return v.Text, err
}`,
		"package variable": `import "encoding/json"

var v Note

func Load(raw []byte) (string, error) {
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"declared with a value": `import "encoding/json"

func Load(raw []byte) (string, error) {
	var v = Build("a", 3)
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"filled literal": `import "encoding/json"

func Load(raw []byte) (string, error) {
	v := Note{Text: "a"}
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"decoded in a closure": `import "encoding/json"

func Load(raw []byte) (string, error) {
	var v Note
	decode := func() error { return json.Unmarshal(raw, &v) }
	err := decode()
	return v.Text, err
}`,
		"another decode of the type": body("", `text = v.Text`) + `
func All(raw []byte) (string, error) {
	var notes []Note
	err := json.Unmarshal(raw, &notes)
	return notes[0].Text, err
}`,
		"another decode of the type before": `import "encoding/json"

func All(raw []byte) (string, error) {
	var notes []Note
	err := json.Unmarshal(raw, &notes)
	return notes[0].Text, err
}

func Load(raw []byte) (string, error) {
	var v Note
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"decoder of elements": `import (
	"encoding/json"
	"io"
)

func Load(r io.Reader) (notes [2]Note, err error) {
	err = json.NewDecoder(r).Decode(&notes)
	return notes, err
}`,
		"type decoding itself": `import "encoding/json"

func (n *Note) UnmarshalJSON(raw []byte) error {
	type plain Note
	if err := json.Unmarshal(raw, (*plain)(n)); err != nil {
		return err
	}
	if n.Line == 0 {
		n.Text = "lost"
	}
	return nil
}

func Load(raw []byte) (string, error) {
	var v Note
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"type reading itself as text": `import "encoding/json"

func (n *Note) UnmarshalText(raw []byte) error {
	if n.Line == 0 {
		n.Text = string(raw)
	}
	return nil
}

func Load(raw []byte) (string, error) {
	var v Note
	err := json.Unmarshal(raw, &v)
	return v.Text, err
}`,
		"nested type not read": `import "encoding/json"

type Page struct {
	Title string ` + "`json:\"title\"`" + `
	Note  Note   ` + "`json:\"note\"`" + `
}

func Load(raw []byte) (string, error) {
	var page Page
	err := json.Unmarshal(raw, &page)
	return page.Title, err
}`,
		"nested type read": `import "encoding/json"

type Page struct {
	Title string ` + "`json:\"title\"`" + `
	Note  Note   ` + "`json:\"note\"`" + `
}

func Load(raw []byte) (string, error) {
	var page Page
	err := json.Unmarshal(raw, &page)
	return page.Note.Text, err
}`,
		"promoted from a type with the field": `import "encoding/json"

type Page struct {
	Note
	Title string ` + "`json:\"title\"`" + `
}

func Load(raw []byte) (string, error) {
	var page Page
	err := json.Unmarshal(raw, &page)
	return page.Text, err
}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, []string{"Line"}, lostFields(t, use))
		})
	}
}

// A field read that takes a part which may itself hold the type, or a part
// JSON does not decode, keeps the decode a reading of the outer type too.
func TestJSONIgnoredFieldOfDecodeReadInPart(t *testing.T) {
	outer := func(fields, read string) string {
		return `import "encoding/json"

type Outer struct {
	` + fields + `
	Hidden int ` + "`json:\"-\"`" + `
}

type Inner struct {
	Name   string
	Secret int ` + "`json:\"-\"`" + `
}

type holder struct{ inner Inner }

func Store(hidden int) ([]byte, error) {
	o := Outer{Hidden: hidden}
	if o.Hidden < 0 {
		return nil, nil
	}
	return json.Marshal(o)
}

func use(...any) {}

func Load(raw []byte) error {
	var o Outer
	err := json.Unmarshal(raw, &o)
	use(` + read + `)
	return err
}`
	}
	for name, use := range map[string]string{
		"struct":                           outer("In Inner", "o.In.Name"),
		"pointer":                          outer("In *Inner", "o.In"),
		"slice":                            outer("In []Inner", "o.In"),
		"array":                            outer("In [2]Inner", "o.In"),
		"map":                              outer("In map[string]Inner", "o.In"),
		"anonymous struct":                 outer("In struct{ Deep []Inner }", "o.In"),
		"unexported in a struct":           outer("In holder", "o.In"),
		"alias":                            outer("In alias", "o.In") + "\ntype alias = Inner\n",
		"itself":                           outer("Next *Outer", "o.Next"),
		"unexported field":                 outer("name string", "o.name"),
		"promoted past json":               outer("Part `json:\"-\"`", "o.Name") + "\ntype Part struct{ Name string }\n",
		"raw field is decoded":             outer("Raw []byte `json:\"-\"`", "json.Unmarshal(o.Raw, &o)"),
		"promoted":                         outer("Part", "o.Name") + "\ntype Part struct{ Name string }\n",
		"pointer method":                   outer("In *part", "o.In.trim()") + "\ntype part struct{ name string }\n\nfunc (p *part) trim() string { return p.name[:1] }\n",
		"method value":                     outer("In part", "o.In.trim") + "\ntype part struct{ name string }\n\nfunc (p *part) trim() string { return p.name[:1] }\n",
		"method of an aliased pointer":     outer("In part", "o.In.trim()") + "\ntype part struct{ name string }\n\ntype partPtr = *part\n\nfunc (p partPtr) trim() string { return p.name[:1] }\n",
		"field sliced to a field's bounds": outer("Marks [2]int", "o.Marks[o.Marks[0]:]"),
		"embedded with the field":          outer("Inner", "o.Inner.Name"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, []string{"Hidden"}, lostFields(t, use))
		})
	}
	for name, use := range map[string]string{
		"not read":       outer("In []Inner\n\tName string", "o.Name"),
		"loop of types":  outer("Loop *loop", "o.Loop") + "\ntype loop struct{ Next *loop; Name string }\n",
		"generic loop":   outer("Tree tree[int]", "o.Tree.Kids") + "\ntype tree[T any] struct{ Kids []tree[T]; Leaf *T }\n",
		"interface":      outer("In any", "o.In"),
		"embedded plain": outer("Part", "o.Part") + "\ntype Part struct{ Name string }\n",
	} {
		t.Run("plain "+name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, lostFields(t, use))
		})
	}

	t.Run("not resolved", func(t *testing.T) {
		t.Parallel()
		assert.False(t, (&jsonRoundTrip{}).isPlainJSONField(nil))
	})

	t.Run("type parameter", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"Hidden"}, lostFields(t, `import "encoding/json"

type Box[T any] struct {
	Value  T
	Hidden int `+"`json:\"-\"`"+`
}

func Store(hidden int) ([]byte, error) {
	b := Box[string]{Hidden: hidden}
	if b.Hidden < 0 {
		return nil, nil
	}
	return json.Marshal(b)
}

func Load[T any](raw []byte) (T, error) {
	var b Box[T]
	err := json.Unmarshal(raw, &b)
	return b.Value, err
}`))
	})
}

// A value that does not load back fails at the decode, whatever is read after.
func TestJSONTextCodecOneSidedOfPartlyReadDecode(t *testing.T) {
	assert.Equal(t, []string{"state.go:9"}, rulestest.ProjectRulePlaces(t, NewJSONTextCodecOneSidedRule(), map[string]string{"state.go": `package sample

import "encoding/json"

type Level int

type State struct {
	Name  string
	Level Level
}

func (l *Level) UnmarshalText(raw []byte) error { *l = Level(len(raw)); return nil }

func Store(s State) ([]byte, error) { return json.Marshal(s) }

func Load(raw []byte) (string, error) {
	var s State
	err := json.Unmarshal(raw, &s)
	return s.Name, err
}
`}))
}

// lostInOrders runs the rule on the functions of a package, each in a file of
// its own, in every order of the files, and returns what it reports, which
// must not depend on the order.
func lostInOrders(t *testing.T, decls string, funcs []string) []string {
	t.Helper()
	var all [][]string
	var permute func(order []int)
	permute = func(order []int) {
		for i := range funcs {
			if !slices.Contains(order, i) {
				permute(append(order[:len(order):len(order)], i))
			}
		}
		if len(order) < len(funcs) {
			return
		}
		apart := map[string]string{"types/types.go": "package types\n\nimport \"encoding/json\"\n\n" + decls}
		one := "package sample\n\nimport \"encoding/json\"\n\n" + decls
		together := map[string]string{"decls.go": one}
		var single strings.Builder
		single.WriteString(one)
		for place, i := range order {
			name := string(rune('a' + place))
			imports := "\n\nimport \"encoding/json\"\n\n"
			together["f"+name+".go"] = "package sample" + imports + funcs[i]
			single.WriteString("\n" + funcs[i])
			apart[name+"/"+name+".go"] = "package " + name + "\n\nimport (\n\t\"encoding/json\"\n\n\t. \"example.com/rulestest/types\"\n)\n\n" + funcs[i]
		}
		for _, files := range []map[string]string{together, {"one.go": single.String()}, apart} {
			lost := []string{}
			for _, violation := range rulestest.RunRuleOnFiles(t, NewJSONIgnoredFieldLostInRoundTripRule(), files) {
				name, _, _ := strings.Cut(violation.Message, " ")
				lost = append(lost, name)
			}
			slices.Sort(lost)
			all = append(all, lost)
		}
	}
	permute(nil)
	for _, lost := range all {
		assert.Equal(t, all[0], lost, "the order of the decodes changed the answer")
	}
	return all[0]
}

// What the decodes read does not depend on their order, nor on a partial
// decode of a type that another decode reads as a part.
func TestJSONIgnoredFieldDecodeOrder(t *testing.T) {
	const dirs = `type Dir struct {
	Name  string
	Files []File
	Cache int ` + "`json:\"-\"`" + `
}

type File struct {
	Title  string
	Parent *Dir
}

func Store(dir Dir) ([]byte, error) {
	dir.Cache = 3
	return json.Marshal(dir)
}

func Cached(dir Dir) bool { return dir.Cache > 0 }
`
	const (
		partDir = `func Name(raw []byte) (string, error) {
	var d Dir
	err := json.Unmarshal(raw, &d)
	return d.Name, err
}
`
		partFile = `func Title(raw []byte) (string, error) {
	var f File
	err := json.Unmarshal(raw, &f)
	return f.Title, err
}
`
		wholeFile = `func Parent(raw []byte) (*Dir, error) {
	var f File
	err := json.Unmarshal(raw, &f)
	return f.Parent, err
}
`
		wholeIndex = `func Index(raw []byte) (files map[string][]File, err error) {
	err = json.Unmarshal(raw, &files)
	return files, err
}
`
		wholeFiles = `func All(raw []byte) (files []File, err error) {
	err = json.Unmarshal(raw, &files)
	return files, err
}
`
	)
	trees := strings.NewReplacer("Dir)", "Dir[int])", "Dir struct", "Dir[T any] struct", "File struct", "File[T any] struct", "[]File", "[]File[T]", "*Dir", "*Dir[T]").Replace(dirs)
	// The instance in the field of File is made in the package of the types.
	instances := strings.NewReplacer("Dir)", "Dir[int])", "Dir struct", "Dir[T any] struct", "*Dir", "*Dir[int]").Replace(dirs)
	generic := strings.NewReplacer("d Dir", "d Dir[int]", "f File", "f File[int]", "*Dir", "*Dir[int]")
	// The chain is cut past its depth, but Near reaches its end from the top.
	const chain = `type Top struct {
	%s
}

type Deep struct{ Two Two }
type Two struct{ Three Three }
type Three struct{ Far Far }
type Far struct{ End End }

type End struct {
	Name string
	Cut  int ` + "`json:\"-\"`" + `
}

func Store(end End) ([]byte, error) {
	end.Cut = 3
	return json.Marshal(end)
}

func Cut(end End) bool { return end.Cut > 0 }
`
	const wholeTop = `func Load(raw []byte) (top Top, err error) {
	err = json.Unmarshal(raw, &top)
	return top, err
}
`
	const wholeDeep = `func LoadDeep(raw []byte) (deep map[string][]Deep, err error) {
	err = json.Unmarshal(raw, &deep)
	return deep, err
}
`
	const wholeElements = `func LoadElements(raw []byte) (deep []Deep, err error) {
	err = json.Unmarshal(raw, &deep)
	return deep, err
}
`
	const wholeOne = `func LoadOne(raw []byte) (deep Deep, err error) {
	err = json.Unmarshal(raw, &deep)
	return deep, err
}
`
	const partTop = `func LoadName(raw []byte) (string, error) {
	var top Top
	err := json.Unmarshal(raw, &top)
	return top.Name, err
}
`
	const wholeEnd = `func LoadEnd(raw []byte) (end End, err error) {
	err = json.Unmarshal(raw, &end)
	return end, err
}
`
	storedTop := strings.NewReplacer("func Store(end End)", "func Store(top Top, end *End)", "Marshal(end)", "Marshal(top)").Replace(chain)
	const wholeFar = `func LoadFar(raw []byte) (far Far, err error) {
	err = json.Unmarshal(raw, &far)
	return far, err
}
`
	for _, tc := range []struct {
		name, decls string
		funcs, want []string
	}{
		{"partial", dirs, []string{partDir}, []string{}},
		{"partial, then a part of a whole one", dirs, []string{partDir, wholeFile}, []string{"Cache"}},
		{"partial among the elements of a whole one", dirs, []string{partDir, wholeFiles}, []string{"Cache"}},
		{"partial, then as deep in a whole one", dirs, []string{partDir, wholeIndex}, []string{"Cache"}},
		{"partial of both", dirs, []string{partDir, partFile}, []string{"Cache"}},
		{"three", dirs, []string{partDir, partFile, wholeFiles}, []string{"Cache"}},
		{"generic partial", trees, []string{generic.Replace(partDir)}, []string{}},
		{"instances of two packages", instances, []string{generic.Replace(partDir)}, []string{}},
		{"generic part of a whole one", trees, []string{generic.Replace(partDir), generic.Replace(wholeFile)}, []string{"Cache"}},
		{"deep first", fmt.Sprintf(chain, "Deep Deep\n\tNear Far"), []string{wholeTop}, []string{"Cut"}},
		{"near first", fmt.Sprintf(chain, "Near Far\n\tDeep Deep"), []string{wholeTop}, []string{"Cut"}},
		{"too deep", fmt.Sprintf(chain, "Deep Deep"), []string{wholeTop}, []string{}},
		{"too deep, and from near", fmt.Sprintf(chain, "Deep Deep"), []string{wholeTop, wholeDeep, wholeFar}, []string{"Cut"}},
		{"as deep as it goes", fmt.Sprintf(chain, "Deep Deep"), []string{wholeOne}, []string{"Cut"}},
		{"elements too deep", fmt.Sprintf(chain, "Deep Deep"), []string{wholeElements}, []string{}},
		{"partial too deep", fmt.Sprintf(chain, "Name string\n\tDeep Deep"), []string{partTop}, []string{}},
		{"partial deep enough", fmt.Sprintf(chain, "Name string\n\tTwo Two"), []string{partTop}, []string{"Cut"}},
		{"stored", fmt.Sprintf(storedTop, "Two Two"), []string{wholeEnd}, []string{"Cut"}},
		{"stored too deep", fmt.Sprintf(storedTop, "Deep Deep"), []string{wholeEnd}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, lostInOrders(t, tc.decls, tc.funcs))
		})
	}
}

// A call that does not compile may have fewer arguments than its function.
func TestJSONCallWithoutArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []ast.Expr
	}{
		{"Marshal", nil},
		{"Unmarshal", nil},
		{"Unmarshal", []ast.Expr{ast.NewIdent("raw")}},
		{"Decode", nil},
	} {
		fun := ast.NewIdent(tc.name)
		signature := types.NewSignatureType(nil, nil, nil, nil, nil, false)
		info := &types.Info{Uses: map[*ast.Ident]types.Object{
			fun: types.NewFunc(token.NoPos, types.NewPackage("encoding/json", "json"), tc.name, signature),
		}}
		encoded, decoded := jsonCall(info, &ast.CallExpr{Fun: fun, Args: tc.args})
		assert.Nil(t, encoded, tc.name)
		assert.Nil(t, decoded, tc.name)
	}
}

// The remembered answers about types that refer to each other are the ones a
// search from each type alone gives.
func TestJSONIgnoringRemembersCycles(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for range 3000 {
		const count = 6
		var all [count]*types.Named
		for i := range all {
			all[i] = types.NewNamed(types.NewTypeName(token.NoPos, nil, fmt.Sprint("T", i), nil), nil, nil)
		}
		var edges [count][]int
		var ignored [count]bool
		for i, named := range all {
			var fields []*types.Var
			var tags []string
			for range random.IntN(3) {
				to := random.IntN(count)
				edges[i] = append(edges[i], to)
				fields = append(fields, types.NewField(token.NoPos, nil, fmt.Sprint("F", len(fields)), types.NewPointer(all[to]), false))
				tags = append(tags, "")
			}
			if ignored[i] = random.IntN(5) == 0; ignored[i] {
				fields = append(fields, types.NewField(token.NoPos, nil, "Hidden", types.Typ[types.Int], false))
				tags = append(tags, `json:"-"`)
			}
			named.SetUnderlying(types.NewStruct(fields, tags))
		}
		var reaches func(from int, seen *[count]bool) bool
		reaches = func(from int, seen *[count]bool) bool {
			seen[from] = true
			return ignored[from] || slices.ContainsFunc(edges[from], func(to int) bool { return !seen[to] && reaches(to, seen) })
		}
		ignoring := jsonIgnoring{known: map[types.Type]bool{}, at: map[types.Type]int{}}
		for _, i := range random.Perm(count) {
			held, _ := ignoring.holds(all[i])
			assert.Equal(t, reaches(i, &[count]bool{}), held, "edges %v, ignored %v, type %d", edges, ignored, i)
			assert.Empty(t, ignoring.stack)
			assert.Empty(t, ignoring.at)
		}
	}
}
