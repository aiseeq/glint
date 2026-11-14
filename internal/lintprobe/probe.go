package lintprobe

import "os"

// Touch opens path and drops the close error.
func Touch(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}
