package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSortsByDateAndSkipsBrokenSlices(t *testing.T) {
	path := writeFile(t, "curve.jsonl", `{"date":"2026-02-01","per_kloc_crit_high":1.5}

{"date":"2026-01-01","per_kloc_crit_high":0.0}
{"date":"2026-01-15","error":"json_parse_failed","sloc":10}
`)
	s, err := load(path, "per_kloc_crit_high")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range s.points {
		got = append(got, p.date.Format("2006-01-02"))
	}
	if s.label != "curve" || s.skipped != 1 || !reflect.DeepEqual(got, []string{"2026-01-01", "2026-02-01"}) || s.points[1].value != 1.5 {
		t.Errorf("series = %+v", s)
	}
}

func TestLoadNamesTheFieldsOfARecordWithoutTheMetric(t *testing.T) {
	path := writeFile(t, "c.jsonl", `{"date":"2026-01-15","error":"json_parse_failed","sloc":10}`+"\n")
	_, err := load(path, "per_kloc_total")
	if err == nil || !strings.Contains(err.Error(), "available: date, error, sloc") {
		t.Errorf("err = %v", err)
	}
	if _, err := load(writeFile(t, "e.jsonl", "\n"), "sloc"); !errors.Is(err, errEmpty) {
		t.Errorf("an empty file: err = %v", err)
	}
	if _, err := load(writeFile(t, "s.jsonl", `{"date":"2026-01-15","commit":"abc"}`+"\n"), "commit"); err == nil {
		t.Error("a field that is not a number must fail")
	}
}

func TestDrawCarriesEveryPoint(t *testing.T) {
	path := writeFile(t, "a.jsonl", `{"date":"2026-01-01","sloc":100}
{"date":"2026-03-01","sloc":250}
`)
	s, err := load(path, "sloc")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := draw(&b, []series{s}, "sloc", "A & B", false); err != nil {
		t.Fatal(err)
	}
	svg := b.String()
	for _, want := range []string{"<title>2026-01-01 100</title>", "<title>2026-03-01 250</title>", "A &amp; B", "non-test Go lines", `data-series="a"`} {
		if !strings.Contains(svg, want) {
			t.Errorf("svg has no %q", want)
		}
	}
}

func TestYTicksEndAtARoundNumberAboveTheMaximum(t *testing.T) {
	for _, c := range []struct {
		max      float64
		want     []float64
		decimals int
	}{
		{1.14, []float64{0, 0.5, 1, 1.5}, 1},
		{80153, []float64{0, 20000, 40000, 60000, 80000, 100000}, 0},
		{0, []float64{0, 1}, 0},
	} {
		got, decimals := yTicks(c.max)
		if !reflect.DeepEqual(got, c.want) || decimals != c.decimals {
			t.Errorf("yTicks(%v) = %v, %d; want %v, %d", c.max, got, decimals, c.want, c.decimals)
		}
	}
}
