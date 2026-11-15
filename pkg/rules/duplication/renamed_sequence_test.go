package duplication

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// renamedSequenceSupport declares what the prologues call.
const renamedSequenceSupport = `package plan

type meta struct {
	header bool
	out    string
	parts  []string
}

type layout struct{ rendered []byte }

type catalog struct{ metas map[string]meta }

func (c *catalog) find(target string) (string, meta, error) { return target, c.metas[target], nil }

func strip(b []byte, path string) []byte { return b[len(path):] }

func readLayout(dir string, m meta) (layout, error) { return layout{rendered: []byte(dir + m.out)}, nil }

func readPurpose(dir string, m meta) (layout, error) { return layout{rendered: []byte(m.out + dir)}, nil }

func purposeOn(dir string) (bool, error) { return dir != "", nil }

func plan(dir string, m meta, built, actual []byte, purpose *layout) error { return nil }

func owners(parts []string, built []byte) ([]string, error) { return parts, nil }

var errStop error
`

// renamedSequenceRefused prepares the plan input and asks one question of it:
// its body is mostly the prologue, the function to call.
const renamedSequenceRefused = `package plan

func refusedForRefresh(dir string, m meta, built, actual []byte, c *catalog) (bool, error) {
	path, found, err := c.find(m.out)
	if err != nil {
		return false, err
	}
	if found.header {
		built = strip(built, path)
		actual = strip(actual, path)
	}
	l, err := readLayout(dir, found)
	if err != nil {
		return false, err
	}
	var purpose *layout
	if enabled, err := purposeOn(dir); err != nil {
		return false, err
	} else if enabled {
		l, err = readPurpose(dir, found)
		if err != nil {
			return false, err
		}
		purpose = &l
		built = l.rendered
	}
	return plan(dir, found, built, actual, purpose) != nil, nil
}
`

// renamedSequenceHint opens with the same prologue under other names; only
// the zero values returned beside the error differ.
const renamedSequenceHint = `package plan

import "strings"

func forceHint(dir string, m meta, built, actual []byte, c *catalog) (string, string, error) {
	selected := m.out
	at, mf, err := c.find(selected)
	if err != nil {
		return "", "", err
	}
	if mf.header {
		built = strip(built, at)
		actual = strip(actual, at)
	}
	lay, err := readLayout(dir, mf)
	if err != nil {
		return "", "", err
	}
	var p *layout
	if on, err := purposeOn(dir); err != nil {
		return "", "", err
	} else if on {
		lay, err = readPurpose(dir, mf)
		if err != nil {
			return "", "", err
		}
		p = &lay
		built = lay.rendered
	}
	if err := plan(dir, mf, built, actual, p); err != nil {
		return "", "", err
	}
	others, err := owners(m.parts, built)
	if err != nil {
		return "", "", err
	}
	return strings.Join(others, ", "), selected, nil
}
`

func renamedSequenceFiles(hint string) map[string]string {
	return map[string]string{
		"plan/support.go": renamedSequenceSupport,
		"plan/refresh.go": renamedSequenceRefused,
		"plan/hint.go":    hint,
	}
}

// Two functions of a package that open with one prologue of seven steps,
// differing in the names and in the zero values returned beside the error:
// the copy is reported against the function that is mostly the prologue.
func TestRenamedDuplicateSequencePrologue(t *testing.T) {
	violations, err := NewRenamedDuplicateBlockRule().AnalyzeGoProject(rulestest.Project(t, renamedSequenceFiles(renamedSequenceHint)))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "plan/hint.go", violations[0].File)
	assert.Equal(t, 7, violations[0].Line)
	assert.Equal(t, "plan/refresh.go", violations[0].Context["original_file"])
	assert.Equal(t, 4, violations[0].Context["original_line"])
	assert.Contains(t, violations[0].Message, "(in refusedForRefresh)")
}

// A copy of the prologue in the middle of a function is a copy too.
func TestRenamedDuplicateSequenceMiddle(t *testing.T) {
	hint := strings.Replace(renamedSequenceHint, "\tselected := m.out\n",
		"\tselected := m.out\n\tif selected == \"\" {\n\t\treturn \"\", \"\", nil\n\t}\n\tdir = strings.TrimSpace(dir)\n", 1)
	assert.Equal(t, []string{"plan/hint.go:11 -> plan/refresh.go:4"}, renamedBlockFindings(t, renamedSequenceFiles(hint)))
}

// A value returned beside the error that is not a zero value is a different
// answer, not a renamed one: "true, err" against "false, err" keeps them apart.
func TestRenamedDuplicateSequenceReturnedValueDiffers(t *testing.T) {
	for _, value := range []struct{ result, value, last string }{
		{"bool", "true", "true"},
		{"int", "1", "2"},
		{"string", `"x"`, `"y"`},
		{"meta", "meta{out: dir}", "found"},
	} {
		refused := strings.ReplaceAll(renamedSequenceRefused, "(bool, error)", "("+value.result+", error)")
		refused = strings.ReplaceAll(refused, "return false, err", "return "+value.value+", err")
		refused = strings.Replace(refused, "return plan(dir, found, built, actual, purpose) != nil, nil",
			"return "+value.last+", plan(dir, found, built, actual, purpose)", 1)
		files := renamedSequenceFiles(renamedSequenceHint)
		files["plan/refresh.go"] = refused
		assert.Empty(t, renamedBlockFindings(t, files), value.value)
	}
}

// Zero values of every kind returned beside the error are one answer.
func TestRenamedDuplicateSequenceZeroValues(t *testing.T) {
	refused := strings.ReplaceAll(renamedSequenceRefused, "(bool, error)", "(meta, int, float64, complex128, *layout, error)")
	refused = strings.ReplaceAll(refused, "return false, err", "return meta{}, 0, 0.0, 0i, nil, err")
	refused = strings.Replace(refused, "return plan(dir, found, built, actual, purpose) != nil, nil",
		"return found, 1, 1, 1, purpose, nil", 1)
	files := renamedSequenceFiles(renamedSequenceHint)
	files["plan/refresh.go"] = refused
	assert.Equal(t, []string{"plan/hint.go:7 -> plan/refresh.go:4"}, renamedBlockFindings(t, files))
}

// A function returning the error alone is the same prologue as one returning
// zero values beside it.
func TestRenamedDuplicateSequenceErrorAlone(t *testing.T) {
	refused := strings.ReplaceAll(renamedSequenceRefused, "(bool, error)", "error")
	refused = strings.ReplaceAll(refused, "return false, err", "return err")
	refused = strings.Replace(refused, "return plan(dir, found, built, actual, purpose) != nil, nil",
		"return plan(dir, found, built, actual, purpose)", 1)
	files := renamedSequenceFiles(renamedSequenceHint)
	files["plan/refresh.go"] = refused
	assert.Equal(t, []string{"plan/hint.go:7 -> plan/refresh.go:4"}, renamedBlockFindings(t, files))
}

// boundaryFiles builds two functions of the package opening with the same
// six statements and ending apart.
func boundaryFiles(prologue string) map[string]string {
	return map[string]string{
		"plan/support.go": renamedSequenceSupport,
		"plan/a.go": "package plan\n\nimport \"fmt\"\n\nfunc first(dir string, m meta, c *catalog, built []byte) (bool, error) {\n" +
			strings.ReplaceAll(prologue, "ZERO", "false") + "\treturn len(built) > 0, nil\n}\n\nvar _ = fmt.Errorf\n",
		"plan/b.go": "package plan\n\nimport \"fmt\"\n\nfunc second(dir string, m meta, c *catalog, built []byte) (string, error) {\n" +
			strings.ReplaceAll(prologue, "ZERO", `""`) + "\treturn string(built), nil\n}\n\nvar _ = fmt.Errorf\n",
	}
}

// boundaryPrologue is six statements on fifteen lines, four of them steps
// beside two bare error guards.
const boundaryPrologue = `	_, found, err := c.find(m.out)
	if err != nil {
		return ZERO, err
	}
	l, err := readLayout(dir, found)
	if err != nil {
		return ZERO, err
	}
	if err := plan(dir, found, built, nil, &l); err != nil {
		return ZERO, fmt.Errorf(
			"plan %s: %w",
			dir, err)
	}
	built = append(built,
		l.rendered...)
`

// Six statements on fifteen lines with four steps among them are a run,
// reported against the smaller function.
func TestRenamedDuplicateSequenceAtThreshold(t *testing.T) {
	assert.Equal(t, []string{"plan/a.go:6 -> plan/b.go:6"}, renamedBlockFindings(t, boundaryFiles(boundaryPrologue)))
}

// One line fewer is below the run.
func TestRenamedDuplicateSequenceLineShort(t *testing.T) {
	short := strings.Replace(boundaryPrologue, "append(built,\n\t\tl.rendered...)", "append(built, l.rendered...)", 1)
	require.NotEqual(t, boundaryPrologue, short)
	assert.Empty(t, renamedBlockFindings(t, boundaryFiles(short)))
}

// Three calls, each with a bare guard however long its return, are three
// steps: below the run.
func TestRenamedDuplicateSequenceGuardsAreNoSteps(t *testing.T) {
	assert.Empty(t, renamedBlockFindings(t, boundaryFiles(guardedChain())))
}

// A branch that does more than return on an error is a step: each turns the
// three steps of the guarded chain into four, a run.
func TestRenamedDuplicateSequenceBranchesAreSteps(t *testing.T) {
	guard := "\tif err != nil {\n\t\treturn ZERO, fmt.Errorf(\n\t\t\t\"step: %w\",\n\t\t\terr)\n\t}\n"
	for name, branch := range map[string]string{
		"else":        "\tif err != nil {\n\t\treturn ZERO, err\n\t} else {\n\t\tbuilt = nil\n\t}\n",
		"two in body": "\tif err != nil {\n\t\tbuilt = nil\n\t\treturn ZERO, err\n\t}\n",
		"no return":   "\tif err != nil {\n\t\tpanic(fmt.Errorf(\n\t\t\t\"step: %w\",\n\t\t\terr))\n\t}\n",
		"on no error": "\tif err == nil {\n\t\treturn ZERO, fmt.Errorf(\n\t\t\t\"step: %w\",\n\t\t\terr)\n\t}\n",
		"other value": "\tif err != errStop {\n\t\treturn ZERO, fmt.Errorf(\n\t\t\t\"step: %w\",\n\t\t\terr)\n\t}\n",
	} {
		chain := strings.Replace(guardedChain(), guard, branch, 1)
		require.NotEqual(t, guardedChain(), chain, name)
		assert.Len(t, renamedBlockFindings(t, boundaryFiles(chain)), 1, name)
	}
}

// guardedChain is three calls, each with a bare guard, on eighteen lines.
func guardedChain() string {
	guarded := strings.Replace(boundaryPrologue, "\tif err := plan(dir, found, built, nil, &l); err != nil {",
		"\terr = plan(dir, found, built, nil, &l)\n\tif err != nil {", 1)
	guarded = strings.Replace(guarded, "\tbuilt = append(built,\n\t\tl.rendered...)\n", "", 1)
	return strings.ReplaceAll(guarded, "\t\treturn ZERO, err\n", "\t\treturn ZERO, fmt.Errorf(\n\t\t\t\"step: %w\",\n\t\t\terr)\n")
}

// secondPrologue is another run of six statements on fifteen lines.
const secondPrologue = `	_, mf, err := c.find(dir)
	if err != nil {
		return ZERO, err
	}
	lay, err := readPurpose(dir, mf)
	if err != nil {
		return ZERO, err
	}
	if err := plan(dir, mf, nil, built, &lay); err != nil {
		return ZERO, fmt.Errorf(
			"purpose %s: %w",
			dir, err)
	}
	built = append(lay.rendered,
		built...)
`

// Two runs of one pair of functions with other statements between them are
// two copies, whether they keep their order or not.
func TestRenamedDuplicateSequenceTwoRuns(t *testing.T) {
	files := boundaryFiles(boundaryPrologue + "\tdir += \"/a\"\n" + secondPrologue)
	files["plan/b.go"] = boundaryFiles(boundaryPrologue + "\tdir += \"/b\"\n" + secondPrologue)["plan/b.go"]
	assert.Equal(t, []string{"plan/a.go:6 -> plan/b.go:6", "plan/a.go:22 -> plan/b.go:22"}, renamedBlockFindings(t, files), "in order")

	files["plan/b.go"] = boundaryFiles(secondPrologue + "\tdir += \"/b\"\n" + boundaryPrologue)["plan/b.go"]
	assert.Equal(t, []string{"plan/a.go:6 -> plan/b.go:22", "plan/a.go:22 -> plan/b.go:6"}, renamedBlockFindings(t, files), "swapped")
}

// A short chain of error checks every function writes - three calls, each
// with its guard - is not a prologue worth a function.
func TestRenamedDuplicateSequenceShortChain(t *testing.T) {
	files := map[string]string{
		"plan/support.go": renamedSequenceSupport,
		"plan/a.go": `package plan

func first(dir string, m meta, c *catalog) (bool, error) {
	_, found, err := c.find(m.out)
	if err != nil {
		return false, err
	}
	l, err := readLayout(dir, found)
	if err != nil {
		return false, err
	}
	on, err := purposeOn(dir)
	if err != nil {
		return false, err
	}
	return on && len(l.rendered) > 0, nil
}
`,
		"plan/b.go": `package plan

func second(dir string, m meta, c *catalog) (string, error) {
	_, mf, err := c.find(m.out)
	if err != nil {
		return "", err
	}
	lay, err := readLayout(dir, mf)
	if err != nil {
		return "", err
	}
	on, err := purposeOn(dir)
	if err != nil {
		return "", err
	}
	if on {
		return string(lay.rendered), nil
	}
	return mf.out, nil
}
`,
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// The same steps in another order, or with another call in place of one, are
// another computation.
func TestRenamedDuplicateSequenceOtherSteps(t *testing.T) {
	swap := "\tlay, err := readLayout(dir, mf)\n\tif err != nil {\n\t\treturn \"\", \"\", err\n\t}\n"
	header := "\tif mf.header {\n\t\tbuilt = strip(built, at)\n\t\tactual = strip(actual, at)\n\t}\n"
	reordered := strings.Replace(renamedSequenceHint, header+swap, swap+header, 1)
	require.NotEqual(t, renamedSequenceHint, reordered)
	assert.Empty(t, renamedBlockFindings(t, renamedSequenceFiles(reordered)), "steps in another order")

	otherCall := strings.Replace(renamedSequenceHint, "lay, err = readPurpose(dir, mf)", "lay, err = readLayout(dir, mf)", 1)
	require.NotEqual(t, renamedSequenceHint, otherCall)
	assert.Empty(t, renamedBlockFindings(t, renamedSequenceFiles(otherCall)), "another call")
}

// One prologue in two packages is left to each package: the rule compares
// runs of statements within a package.
func TestRenamedDuplicateSequenceOtherPackage(t *testing.T) {
	files := renamedSequenceFiles(renamedSequenceHint)
	files["hint/support.go"] = `package hint` + renamedSequenceSupport[len("package plan"):]
	files["hint/hint.go"] = `package hint` + renamedSequenceHint[len("package plan"):]
	delete(files, "plan/hint.go")
	assert.Empty(t, renamedBlockFindings(t, files))
}

// The prologue repeated inside one function is the textual rules' concern.
func TestRenamedDuplicateSequenceSameFunction(t *testing.T) {
	body := renamedSequenceRefused[strings.Index(renamedSequenceRefused, "\tpath, found"):strings.Index(renamedSequenceRefused, "\treturn plan(")]
	renamed := strings.NewReplacer("path", "at", "found", "mf", "l, err", "lay, err", "&l", "&lay", "l.rendered", "lay.rendered",
		"purpose ", "p ", "purpose =", "p =", "enabled", "on").Replace(body)
	twice := strings.Replace(renamedSequenceRefused, "\treturn plan(", renamed+"\t_ = p\n\treturn plan(", 1)
	files := map[string]string{
		"plan/support.go": renamedSequenceSupport,
		"plan/refresh.go": twice,
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}
