package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A `*` width or precision takes an argument of its own, and %[n]v names the
// argument it prints: the verb that prints the cause is found either way.
func TestErrorRebuiltFromText_StarWidthAndExplicitArgumentIndex(t *testing.T) {
	const source = `package p

import (
	"fmt"
	"os"
)

func A(p string, w int) error {
	_, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read %*s: %v", w, p, err)
	}
	return nil
}

func B(p string) error {
	_, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read %[2]s: %[1]v", err, p)
	}
	return nil
}

func C(p string) error {
	_, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read %s: %v", p, err)
	}
	return nil
}

func D(p string, w int) error {
	_, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read %.*s: %w", w, p, err)
	}
	return nil
}

func E(p string) error {
	_, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read %[2]s: %[1]w", err, p)
	}
	return nil
}
`
	violations := runRuleOnFiles(t, NewErrorRebuiltFromTextRule(), map[string]string{"p/p.go": source})
	assert.Equal(t, []int{11, 19, 27}, violationLines(violations))
}

func TestFormatVerbs_ArgumentPositions(t *testing.T) {
	assert.Equal(t, []byte{0, 's', 'v'}, formatVerbs("%*s: %v"))
	assert.Equal(t, []byte{0, 's', 'w'}, formatVerbs("%.*s: %w"))
	assert.Equal(t, []byte{'v', 's'}, formatVerbs("%[2]s: %[1]v"))
	assert.Equal(t, []byte{'d', 'd'}, formatVerbs("%d %d %[1]d %d"))
	assert.Equal(t, []byte{'s'}, formatVerbs("100%% %s"))
	assert.Equal(t, []byte{'s'}, formatVerbs("%[x]v %s"), "a bad index takes no argument")
}
