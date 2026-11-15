package duplication

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fieldNames are the fields a record and its two parties carry.
var fieldNames = []string{"First", "Last", "Country", "Address", "City", "Zip", "Phone", "Email",
	"Nation", "IDType", "IDNumber", "Issuer", "Job", "Funds", "Gender", "Region"}

// fieldsRecord declares a record with one field per name and side, and the
// requests the sides come from.
func fieldsRecord() string {
	var b strings.Builder
	b.WriteString("package fill\n\ntype Party struct {\n")
	for _, name := range fieldNames {
		fmt.Fprintf(&b, "\t%s string\n", name)
	}
	b.WriteString("}\n\ntype Record struct {\n")
	for _, name := range fieldNames {
		fmt.Fprintf(&b, "\tPayer%s, Payee%s string\n", name, name)
	}
	b.WriteString("}\n")
	return b.String()
}

// fieldsCopy writes a function setting the side's fields of the record from
// a party, one assignment per field.
func fieldsCopy(name, side, party string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package fill\n\nfunc %s(rec *Record, %s Party) {\n", name, party)
	for _, field := range fieldNames {
		fmt.Fprintf(&b, "\trec.%s%s = %s.%s\n", side, field, party, field)
	}
	b.WriteString("}\n")
	return b.String()
}

// Two functions moving other fields - the payer's into one side, the payee's
// into the other - share only their shape: each assignment touches other
// fields, and the uniform chain matched at every shift.
func TestRenamedDuplicateSequenceOtherFields(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/payer.go":  fieldsCopy("fillPayer", "Payer", "payer"),
		"fill/payee.go":  fieldsCopy("fillPayee", "Payee", "payee"),
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// The same fields moved again in another function, under another name of the
// party, are a copy: one finding for the run, not one per line.
func TestRenamedDuplicateSequenceSameFields(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/payer.go":  fieldsCopy("fillPayer", "Payer", "payer"),
		"fill/again.go":  fieldsCopy("fillPayerAgain", "Payer", "from"),
	}
	assert.Equal(t, []string{"fill/payer.go:4 -> fill/again.go:4"}, renamedBlockFindings(t, files))
}

// maskCopy writes a function copying the fields a mask names, each under its
// own bit constant.
func maskCopy(name, prefix string, fields []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package fill\n\nfunc %s(d, s *Party, m Mask) {\n", name)
	for _, field := range fields {
		fmt.Fprintf(&b, "\tif m&%s%s != 0 {\n\t\td.%s = s.%s\n\t}\n", prefix, field, field, field)
	}
	b.WriteString("}\n")
	return b.String()
}

// maskBits declares one bit per field and prefix.
func maskBits() string {
	var b strings.Builder
	b.WriteString("package fill\n\ntype Mask uint64\n\nconst (\n")
	for i, field := range fieldNames {
		fmt.Fprintf(&b, "\tP%s Mask = 1 << %d\n\tU%s Mask = 1 << %d\n", field, 2*i, field, 2*i+1)
	}
	b.WriteString(")\n")
	return b.String()
}

// Two functions copying other fields under other bits of the mask are two
// lists, not a copy of one.
func TestRenamedDuplicateSequenceOtherMaskFields(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/mask.go":   maskBits(),
		"fill/head.go":   maskCopy("copyHead", "P", fieldNames[:8]),
		"fill/tail.go":   maskCopy("copyTail", "U", fieldNames[8:]),
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// The bit constant names what is copied: the same fields under other bits are
// another list.
func TestRenamedDuplicateSequenceOtherMaskBits(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/mask.go":   maskBits(),
		"fill/head.go":   maskCopy("copyHead", "P", fieldNames[:8]),
		"fill/tail.go":   maskCopy("copyTail", "U", fieldNames[:8]),
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// The same fields under the same bits in another function are a copy, one
// finding for the run.
func TestRenamedDuplicateSequenceSameMaskFields(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/mask.go":   maskBits(),
		"fill/head.go":   maskCopy("copyHead", "P", fieldNames[:8]),
		"fill/tail.go":   maskCopy("copyTail", "P", fieldNames[:8]),
	}
	assert.Equal(t, []string{"fill/tail.go:4 -> fill/head.go:4"}, renamedBlockFindings(t, files))
}

// A chain of equal statements in two functions matches at every shift: the
// shifts overlap and make one run, one finding, also when one chain is longer.
func TestRenamedDuplicateSequenceUniformChain(t *testing.T) {
	chain := func(name string, length int) string {
		return "package fill\n\nfunc " + name + "(rec *Record, p Party) {\n" +
			strings.Repeat("\trec.PayerFirst += p.First\n", length) + "}\n"
	}
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/a.go":      chain("first", 16),
		"fill/b.go":      chain("second", 20),
	}
	assert.Equal(t, []string{"fill/a.go:4 -> fill/b.go:4"}, renamedBlockFindings(t, files))
}

// assignments are the statements setting fields from..to-1 of both sides,
// the payer's first.
func assignments(from, to int) string {
	var b strings.Builder
	for i := from; i < to; i++ {
		side, field := "Payer", fieldNames[i%len(fieldNames)]
		if i >= len(fieldNames) {
			side = "Payee"
		}
		fmt.Fprintf(&b, "\trec.%s%s = p.%s\n", side, field, field)
	}
	return b.String()
}

// assignFunc writes a function of the statements.
func assignFunc(name, body string) string {
	return "package fill\n\nfunc " + name + "(rec *Record, p Party) {\n" + body + "}\n"
}

// One run copied twice into a function, apart, is two copies.
func TestRenamedDuplicateSequenceCopiedTwice(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/a.go":      assignFunc("once", assignments(0, 16)),
		"fill/b.go":      assignFunc("twice", assignments(0, 16)+"\trec.PayeeFirst = \"\"\n"+assignments(0, 16)),
	}
	assert.Equal(t, []string{"fill/b.go:4 -> fill/a.go:4", "fill/b.go:21 -> fill/a.go:4"}, renamedBlockFindings(t, files))

	files["fill/a.go"], files["fill/b.go"] = files["fill/b.go"], files["fill/a.go"]
	assert.Equal(t, []string{"fill/a.go:4 -> fill/b.go:4", "fill/a.go:21 -> fill/b.go:4"}, renamedBlockFindings(t, files), "the twice copied first")
}

// A run whose parts repeat two other functions, overlapping, is one copy.
func TestRenamedDuplicateSequenceOverlappingOriginals(t *testing.T) {
	files := map[string]string{
		"fill/record.go": fieldsRecord(),
		"fill/a.go":      assignFunc("head", assignments(0, 16)),
		"fill/b.go":      assignFunc("tail", assignments(6, 22)),
		"fill/c.go":      assignFunc("whole", assignments(0, 22)),
	}
	assert.Equal(t, []string{"fill/c.go:4 -> fill/a.go:4"}, renamedBlockFindings(t, files))
}
