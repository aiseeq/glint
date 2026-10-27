package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A struct whose address goes to unsafe.Pointer mirrors a layout something
// outside Go reads — the kernel behind an ioctl. Its fields, and those of the
// structs and arrays nested in it, are read by that memory, so a field filled
// for the kernel and never read back is not dead.
func TestUnusedFieldIgnoresStructHandedOutAsUnsafePointer(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"extent.go": `package extent

import "unsafe"

type head struct {
	start  uint64
	length uint64
	mapped uint32
}

type item struct{ logical, flags uint64 }

type request struct {
	head  head
	items [4]item
}

func ioctl(arg uintptr) {}

func Mapped(r *request) uint32 {
	r.head = head{start: 1, length: ^uint64(0)}
	ioctl(uintptr(unsafe.Pointer(r)))
	return r.head.mapped
}

func Single() {
	var h head
	h.length = 8
	ioctl(uintptr(unsafe.Pointer(&h)))
}
`,
	})

	assert.Empty(t, violations)
}

// encoding/binary reads and fills the fields of the value by its layout.
func TestUnusedFieldIgnoresStructPassedToBinaryCodec(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"frame.go": `package frame

import (
	"encoding/binary"
	"io"
)

type header struct {
	magic   uint32
	version uint16
	pad     uint16
}

type trailer struct{ sum uint32 }

func Write(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, &header{magic: 7, version: 1})
}

func Read(r io.Reader) (uint32, error) {
	var t [1]trailer
	err := binary.Read(r, binary.LittleEndian, t[:])
	return t[0].sum, err
}
`,
	})

	assert.Empty(t, violations)
}

// Handing a pointer to an ordinary function is not a raw memory read: a field
// only written is still dead there.
func TestUnusedFieldReportsWriteOnlyFieldOfStructPassedByPointer(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"job.go": `package job

type job struct {
	id    int
	tries int
}

func run(j *job) int { return j.id }

func Start() int {
	j := &job{id: 1, tries: 3}
	return run(j)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "job.tries")
}
