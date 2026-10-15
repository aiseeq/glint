package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// nilDstSource calls append-style APIs - they take a destination slice and
// return it extended - with nil on every iteration, so every call allocates
// a fresh buffer the API was built to reuse. A result that outlives the
// iteration (kept in a field, appended as an element, returned) needs its
// own buffer, and a call outside a loop runs once.
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
`

func TestNilDstInLoop(t *testing.T) {
	files := map[string]string{"codec/codec.go": nilDstSource}
	violations, err := NewNilDstInLoopRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "nil-dst-in-loop"), foundLines(violations))
}
