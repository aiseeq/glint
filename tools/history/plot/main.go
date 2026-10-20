// Command plot draws the quality curve from measure output.
//
// It reads the JSONL measure writes and draws the heavy-findings curve
// (critical+high per 1000 non-test Go lines) over time as SVG; --metric
// plots any other numeric field of the records. Each point carries its
// date and value as a tooltip.
//
// Usage:
//
//	plot curve.jsonl -o curve.svg
//	plot curve.jsonl --metric per_kloc_total -o total.svg
//	plot a.jsonl b.jsonl -o compare.svg   # one line per file
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aiseeq/glint/tools/history/internal/hist"
)

var metricLabels = map[string]string{
	"per_kloc_crit_high": "critical+high findings per 1000 lines",
	"per_kloc_total":     "all findings per 1000 lines",
	"sloc":               "non-test Go lines",
}

var colors = []string{"#2a78d6", "#eb6834", "#3b9e4f", "#8b5cb8"}

func main() {
	fs := flag.NewFlagSet("plot", flag.ExitOnError)
	out := fs.String("o", "curve.svg", "output SVG")
	metric := fs.String("metric", "per_kloc_crit_high", "record field to plot")
	title := fs.String("title", "", "chart title")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: plot FILE.jsonl... [-o curve.svg] [--metric per_kloc_crit_high] [--title TEXT]")
		fs.PrintDefaults()
	}
	files, err := hist.Parse(fs, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(files) == 0 || !strings.HasSuffix(*out, ".svg") {
		fs.Usage()
		os.Exit(2)
	}
	var lines []series
	for _, path := range files {
		s, err := load(path, *metric)
		if errors.Is(err, errEmpty) {
			fmt.Fprintf(os.Stderr, "warning: %s is empty, skipping\n", path)
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "plot:", err)
			os.Exit(1)
		}
		if s.skipped > 0 {
			fmt.Fprintf(os.Stderr, "%s: skipped %d broken slice(s)\n", path, s.skipped)
		}
		lines = append(lines, s)
	}
	f, err := os.Create(*out)
	if err == nil {
		err = draw(f, lines, *metric, *title, len(files) > 1)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "plot:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", *out)
}

var errEmpty = errors.New("no records")

type point struct {
	date  time.Time
	value float64
}

// series is the curve of one file: its points by date and the number of
// records without the metric (slices whose tree glint failed on).
type series struct {
	label   string
	points  []point
	skipped int
}

func load(path, metric string) (series, error) {
	f, err := os.Open(path)
	if err != nil {
		return series{}, err
	}
	defer func() { _ = f.Close() }() // read only
	var records []map[string]json.RawMessage
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 16<<20)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return series{}, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return series{}, err
	}
	if len(records) == 0 {
		return series{}, errEmpty
	}
	s := series{label: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))}
	for _, rec := range records {
		raw, ok := rec[metric]
		if !ok {
			s.skipped++
			continue
		}
		var p point
		var date string
		if err := json.Unmarshal(rec["date"], &date); err != nil {
			return series{}, fmt.Errorf("%s: record without a date: %w", path, err)
		}
		if p.date, err = time.Parse(time.DateOnly, date); err != nil {
			return series{}, fmt.Errorf("%s: %w", path, err)
		}
		if err := json.Unmarshal(raw, &p.value); err != nil {
			return series{}, fmt.Errorf("%s: %s of %s is not a number: %s", path, metric, date, raw)
		}
		s.points = append(s.points, p)
	}
	if len(s.points) == 0 {
		available := make([]string, 0, len(records[len(records)-1]))
		for k := range records[len(records)-1] {
			available = append(available, k)
		}
		sort.Strings(available)
		return series{}, fmt.Errorf("%s: no field '%s' in any record; available: %s", path, metric, strings.Join(available, ", "))
	}
	sort.SliceStable(s.points, func(i, j int) bool { return s.points[i].date.Before(s.points[j].date) })
	return s, nil
}

// Chart geometry, in SVG units.
const (
	width, height              = 1000, 500
	left, right, top, bottomPx = 80, 50, 40, 60
)

func draw(w io.Writer, lines []series, metric, title string, legend bool) error {
	var first, last time.Time
	maxValue := 0.0
	for _, s := range lines {
		for _, p := range s.points {
			if first.IsZero() || p.date.Before(first) {
				first = p.date
			}
			if p.date.After(last) {
				last = p.date
			}
			maxValue = math.Max(maxValue, p.value)
		}
	}
	ticks, decimals := yTicks(maxValue)
	yMax := ticks[len(ticks)-1]
	span := last.Sub(first)
	if span == 0 {
		span = 24 * time.Hour
	}
	x := func(d time.Time) float64 {
		return left + float64(d.Sub(first))/float64(span)*(width-left-right)
	}
	y := func(v float64) float64 {
		return height - bottomPx - v/yMax*(height-top-bottomPx)
	}
	label := metricLabels[metric]
	if label == "" {
		label = metric
	}

	b := &strings.Builder{}
	fmt.Fprintf(b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="sans-serif" font-size="12">`+"\n", width, height)
	fmt.Fprintf(b, `<rect width="%d" height="%d" fill="#fff"/>`+"\n", width, height)
	if title != "" {
		fmt.Fprintf(b, `<text x="%d" y="24" text-anchor="middle" font-size="16">%s</text>`+"\n", width/2, html.EscapeString(title))
	}
	for _, t := range ticks {
		fmt.Fprintf(b, `<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="#000" stroke-opacity="0.15" stroke-width="0.5"/>`+"\n", left, width-right, y(t), y(t))
		fmt.Fprintf(b, `<text x="%d" y="%.1f" text-anchor="end" dominant-baseline="middle">%s</text>`+"\n", left-8, y(t), strconv.FormatFloat(t, 'f', decimals, 64))
	}
	for _, d := range xTicks(first, last) {
		fmt.Fprintf(b, `<text x="%.1f" y="%d" text-anchor="middle">%s</text>`+"\n", x(d), height-bottomPx+20, d.Format(time.DateOnly))
	}
	fmt.Fprintf(b, `<line x1="%d" x2="%d" y1="%d" y2="%d" stroke="#000"/>`+"\n", left, width-right, height-bottomPx, height-bottomPx)
	fmt.Fprintf(b, `<line x1="%d" x2="%d" y1="%d" y2="%d" stroke="#000"/>`+"\n", left, left, top, height-bottomPx)
	fmt.Fprintf(b, `<text transform="translate(20 %d) rotate(-90)" text-anchor="middle">%s</text>`+"\n", (height-bottomPx+top)/2, html.EscapeString(label))
	for i, s := range lines {
		color := colors[i%len(colors)]
		coords := make([]string, len(s.points))
		for j, p := range s.points {
			coords[j] = fmt.Sprintf("%.1f,%.1f", x(p.date), y(p.value))
		}
		fmt.Fprintf(b, `<g data-series="%s">`+"\n", html.EscapeString(s.label))
		fmt.Fprintf(b, `<polyline points="%s" fill="none" stroke="%s" stroke-width="2"/>`+"\n", strings.Join(coords, " "), color)
		for _, p := range s.points {
			fmt.Fprintf(b, `<circle cx="%.1f" cy="%.1f" r="3" fill="%s"><title>%s %s</title></circle>`+"\n",
				x(p.date), y(p.value), color, p.date.Format(time.DateOnly), strconv.FormatFloat(p.value, 'f', -1, 64))
		}
		b.WriteString("</g>\n")
		if legend {
			ly := top + 4 + i*18
			fmt.Fprintf(b, `<line x1="%d" x2="%d" y1="%d" y2="%d" stroke="%s" stroke-width="2"/>`, width-right-160, width-right-136, ly, ly, color)
			fmt.Fprintf(b, `<text x="%d" y="%d" dominant-baseline="middle">%s</text>`+"\n", width-right-130, ly, html.EscapeString(s.label))
		}
	}
	b.WriteString("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// yTicks returns ticks from 0 to a round number at or above limit, about
// five of them, and the decimals their labels need.
func yTicks(limit float64) ([]float64, int) {
	if limit <= 0 {
		return []float64{0, 1}, 0
	}
	raw := limit / 5
	magnitude := math.Pow(10, math.Floor(math.Log10(raw)))
	step := magnitude * 10
	for _, m := range []float64{1, 2, 5} {
		if raw <= m*magnitude {
			step = m * magnitude
			break
		}
	}
	decimals := max(0, int(-math.Floor(math.Log10(step))))
	var ticks []float64
	for i := 0; ; i++ {
		t := float64(i) * step
		ticks = append(ticks, t)
		if t >= limit {
			return ticks, decimals
		}
	}
}

// xTicks returns every day of a chart up to a week long, six evenly
// spread dates of a longer one, and none for a chart without points.
func xTicks(first, last time.Time) []time.Time {
	if first.IsZero() {
		return nil
	}
	days := int(last.Sub(first).Hours() / 24)
	n := days
	if n > 6 {
		n = 5
	}
	if n == 0 {
		return []time.Time{first}
	}
	ticks := make([]time.Time, 0, n+1)
	for i := 0; i <= n; i++ {
		ticks = append(ticks, first.AddDate(0, 0, days*i/n))
	}
	return ticks
}
