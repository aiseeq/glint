//go:build !linux

package frontendrules

import "os"

// statChangeTimeNS reports no change time; cache hits then compare the
// directory's entries.
func statChangeTimeNS(os.FileInfo) int64 { return 0 }
