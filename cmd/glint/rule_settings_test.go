package main

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func captureRuleOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	file, err := os.CreateTemp(os.TempDir(), "glint-rule-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	old := os.Stdout
	os.Stdout = file
	callErr := fn()
	os.Stdout = old
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, copyErr := io.Copy(&output, file)
	_ = file.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	return output.String(), callErr
}
