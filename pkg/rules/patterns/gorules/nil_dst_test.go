package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nilDstSource calls append-style APIs - they take a destination slice and
// return it extended - with nil on every iteration, so every call allocates
// a fresh buffer the API was built to reuse. A result that outlives the
// iteration (kept in a field, appended as an element, returned) needs its
// own buffer, and a call outside a loop runs once, as does a call in a loop
// that every path after it leaves.
const nilDstSource = `package codec

import (
	"io"
	"strconv"
)

type Decoder struct{}

// DecodeAll decodes input, appending to dst.
func (d *Decoder) DecodeAll(input, dst []byte) ([]byte, error) { return append(dst, input...), nil }

type Reader struct {
	dec  *Decoder
	last []byte
}

func (r *Reader) Read(index [][]byte, w io.Writer) ([][]byte, error) {
	var kept [][]byte
	for _, e := range index {
		raw, err := r.dec.DecodeAll(e, nil) // want nil-dst-in-loop
		if err != nil {
			return nil, err
		}
		_, _ = w.Write(raw)
		_, _ = w.Write(strconv.AppendInt(nil, int64(len(raw)), 10)) // want nil-dst-in-loop

		own, _ := r.dec.DecodeAll(e, nil)
		kept = append(kept, own)
		last, _ := r.dec.DecodeAll(e, nil)
		r.last = last
	}
	var buf []byte
	for _, e := range index {
		var err error
		buf, err = r.dec.DecodeAll(e, buf[:0])
		if err != nil {
			return nil, err
		}
	}
	once, _ := r.dec.DecodeAll(index[0], nil)
	_ = once
	return kept, nil
}

//glint:hot
func Format(n int, w io.Writer) {
	_, _ = w.Write(strconv.AppendInt(nil, int64(n), 10)) // want nil-dst-in-loop
}

// result hands out back to the caller: nothing is appended to it.
func result(runErr error, out []byte) (bool, []byte) { return runErr == nil, out }

// appendLen appends to out through a call that appends to its destination.
func appendLen(out []byte, n int) []byte { return strconv.AppendInt(out[:0], int64(n), 10) }

func Retry(run func() error, w io.Writer) {
	for i := 0; ; i++ {
		_, _ = w.Write(appendLen(nil, i)) // want nil-dst-in-loop
		if ok, _ := result(run(), nil); ok {
			return
		}
	}
}

func busy(path string) bool { return path == "" }

// Claim writes the slot it takes once: every path after the call leaves the
// loop, so the call runs at most once per call of Claim.
func Claim(paths []string, w io.Writer) error {
	for i := range paths {
		if busy(paths[i]) {
			continue
		}
		if _, err := w.Write(strconv.AppendInt(nil, int64(i), 10)); err != nil {
			return err
		}
		return nil
	}
	for i := range paths {
		if busy(paths[i]) {
			_, _ = w.Write(strconv.AppendInt(nil, int64(i), 10))
			break
		}
	}
	return nil
}

func Scan(paths []string, w io.Writer) {
	for i := range paths {
		_, _ = w.Write(strconv.AppendInt(nil, int64(i), 10)) // want nil-dst-in-loop
		if busy(paths[i]) {
			continue
		}
		return
	}
	for i := range paths {
		for range paths {
			_, _ = w.Write(strconv.AppendInt(nil, int64(i), 10)) // want nil-dst-in-loop
			break
		}
	}
	for i := range paths {
		switch {
		case busy(paths[i]):
			_, _ = w.Write(strconv.AppendInt(nil, int64(i), 10)) // want nil-dst-in-loop
			break
		}
	}
	for i := range paths {
		run := func() {
			_, _ = w.Write(strconv.AppendInt(nil, int64(i), 10)) // want nil-dst-in-loop
			return
		}
		run()
	}
}
`

func TestNilDstInLoop(t *testing.T) {
	files := map[string]string{"codec/codec.go": nilDstSource}
	violations, err := NewNilDstInLoopRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "nil-dst-in-loop"), patterntest.FoundLines(violations))
}
