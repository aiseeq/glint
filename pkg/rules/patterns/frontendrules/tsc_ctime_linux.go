package frontendrules

import (
	"os"
	"syscall"
)

// statChangeTimeNS returns the directory's change time: renaming an entry
// moves it even when the directory's mtime is put back.
func statChangeTimeNS(info os.FileInfo) int64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Ctim.Nano()
}
