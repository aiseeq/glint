// Package cachekey carries the result cache key of a glint build: the hash of
// the driver (code every cached finding depends on), the hash of each rule's
// own code by the call that registered it, and the functions behind each.
// The build appends it to the binary after linking (a manifest of hundreds of
// kilobytes does not fit a -ldflags -X argument); glint reads it back from
// its own executable.
package cachekey

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// trailerMagic ends a binary that carries a manifest; the 8 bytes before it
// are the manifest's length.
const trailerMagic = "\x00glint-cache-key-1\x00"

// Manifest is the cache key of one build.
type Manifest struct {
	// Driver hashes the code every cached finding depends on.
	Driver string `json:"driver"`
	// All hashes the whole module: the key of a rule no site describes.
	All string `json:"all"`
	// Funcs lists every function key once; scopes refer to it by index.
	Funcs       []string `json:"funcs"`
	DriverFuncs []int    `json:"driver_funcs"`
	Sites       []Site   `json:"sites"`
	// Binary is the Go build ID of the binary the manifest was appended to:
	// a manifest on any other binary is not its key.
	Binary string `json:"binary"`
}

// Site is one call of rules.Register: File is "<import path>/<file name>",
// From and To the lines the call spans.
type Site struct {
	File  string `json:"file"`
	From  int    `json:"from"`
	To    int    `json:"to"`
	Hash  string `json:"hash"`
	Funcs []int  `json:"funcs"`
}

// SiteAt returns the site whose call spans line of file.
func (m *Manifest) SiteAt(file string, line int) *Site {
	for i := range m.Sites {
		s := &m.Sites[i]
		if s.File == file && s.From <= line && line <= s.To {
			return s
		}
	}
	return nil
}

// Names returns the function keys of indexes, sorted.
func (m *Manifest) Names(indexes []int) []string {
	names := make([]string, 0, len(indexes))
	for _, i := range indexes {
		if i >= 0 && i < len(m.Funcs) {
			names = append(names, m.Funcs[i])
		}
	}
	sort.Strings(names)
	return names
}

// Index returns the position of each key in a sorted table, adding it.
type Index struct {
	keys map[string]int
	list []string
}

// Add returns the index of key.
func (x *Index) Add(key string) int {
	if x.keys == nil {
		x.keys = make(map[string]int)
	}
	if i, ok := x.keys[key]; ok {
		return i
	}
	x.keys[key] = len(x.list)
	x.list = append(x.list, key)
	return len(x.list) - 1
}

// Keys returns the table.
func (x *Index) Keys() []string { return x.list }

// Encode returns the trailer of m: compressed JSON, its length and the magic.
func Encode(m *Manifest) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(m); err != nil {
		return nil, fmt.Errorf("encode cache key: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("compress cache key: %w", err)
	}
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], uint64(buf.Len()))
	buf.Write(size[:])
	buf.WriteString(trailerMagic)
	return buf.Bytes(), nil
}

// Append writes the trailer of m at the end of the file at path.
func Append(path string, m *Manifest) (err error) {
	id, err := BuildID(path)
	if err != nil {
		return err
	}
	bound := *m
	bound.Binary = id
	trailer, err := Encode(&bound)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()
	if _, err := f.Write(trailer); err != nil {
		return fmt.Errorf("append cache key to %s: %w", path, err)
	}
	return nil
}

// ErrNone is returned for a binary built without a cache key.
var ErrNone = errors.New("no cache key in the binary")

// Read returns the manifest at the end of the file at path.
func Read(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	tail := int64(len(trailerMagic) + 8)
	if info.Size() < tail {
		return nil, ErrNone
	}
	end := make([]byte, tail)
	if _, err := f.ReadAt(end, info.Size()-tail); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if string(end[8:]) != trailerMagic {
		return nil, ErrNone
	}
	size := int64(binary.LittleEndian.Uint64(end[:8]))
	if size <= 0 || size > info.Size()-tail {
		return nil, fmt.Errorf("cache key of %s: bad length %d", path, size)
	}
	zr, err := gzip.NewReader(io.NewSectionReader(f, info.Size()-tail-size, size))
	if err != nil {
		return nil, fmt.Errorf("cache key of %s: %w", path, err)
	}
	defer func() { _ = zr.Close() }()
	var m Manifest
	if err := json.NewDecoder(zr).Decode(&m); err != nil {
		return nil, fmt.Errorf("cache key of %s: %w", path, err)
	}
	if m.Driver == "" || m.All == "" {
		return nil, fmt.Errorf("cache key of %s: no driver hash", path)
	}
	id, err := BuildID(path)
	if err != nil {
		return nil, fmt.Errorf("%w: build ID of %s: %w", ErrNone, path, err)
	}
	if id != m.Binary {
		return nil, fmt.Errorf("%w: the cache key of %s was appended to build %q, not to this one (%q)", ErrNone, path, m.Binary, id)
	}
	return &m, nil
}

// BuildID returns the Go build ID of the executable at path: from the ELF
// note the linker writes, or from the marker other formats carry near the
// start of the file.
func BuildID(path string) (string, error) {
	if f, err := elf.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		if section := f.Section(".note.go.buildid"); section != nil {
			data, err := section.Data()
			if err != nil {
				return "", fmt.Errorf("read the build ID of %s: %w", path, err)
			}
			// namesz, descsz, type, "Go\x00\x00", then the ID.
			if len(data) >= 16 {
				descsz := int(f.ByteOrder.Uint32(data[4:8]))
				if f.ByteOrder.Uint32(data[8:12]) == 4 && string(data[12:16]) == "Go\x00\x00" && 16+descsz <= len(data) {
					return string(data[16 : 16+descsz]), nil
				}
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 64<<10)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	head = head[:n]
	const start, end = "\xff Go build ID: \"", "\"\n \xff"
	if _, rest, ok := bytes.Cut(head, []byte(start)); ok {
		if id, _, ok := bytes.Cut(rest, []byte(end)); ok {
			return string(id), nil
		}
	}
	return "", fmt.Errorf("%s carries no Go build ID", path)
}
