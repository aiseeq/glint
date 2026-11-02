package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/spf13/cobra"
)

// runJournalRetention is how many local days, today included, the daily
// journal keeps.
const runJournalRetention = 400

// calendarDaysSince counts the local days from since through today, both
// included. Days are counted on dates, not hours: a DST change makes a local
// day 23 or 25 hours long.
func calendarDaysSince(since, today time.Time) int {
	sy, sm, sd := since.Date()
	ty, tm, td := today.Date()
	from := time.Date(sy, sm, sd, 0, 0, 0, 0, time.UTC)
	to := time.Date(ty, tm, td, 0, 0, 0, 0, time.UTC)
	return int(to.Sub(from).Hours()/24) + 1
}

type dailyRoot struct {
	Runs     int            `json:"runs"`
	Findings map[string]int `json:"findings"`
}

type dailyRecord struct {
	Day      string                `json:"day"`
	Runs     int                   `json:"runs"`
	WallMS   int64                 `json:"wall_ms"`
	TempRuns int                   `json:"temp_runs"`
	RuleMS   map[string]int64      `json:"rule_ms"`
	Roots    map[string]*dailyRoot `json:"roots"`
}

type dailyHeader struct {
	Folded    string            `json:"folded"`
	FirstSeen map[string]string `json:"first_seen"`
}

type statsCoverage struct {
	From            string `json:"from"`
	To              string `json:"to"`
	DaysWithRuns    int    `json:"days_with_runs"`
	DaysWithoutRuns int    `json:"days_without_runs"`
	Complete        bool   `json:"complete"`
}

type statsRuleFinding struct {
	Rule  string `json:"rule"`
	Roots int    `json:"roots"`
	Days  int    `json:"days"`
}

type statsRuleEmpty struct {
	Rule  string `json:"rule"`
	Since string `json:"since"`
	Days  int    `json:"days"`
}

type statsCPU struct {
	Rule     string  `json:"rule"`
	MS       int64   `json:"ms"`
	Share    float64 `json:"share"`
	MSPerRun int64   `json:"ms_per_run"`
}

type statsReport struct {
	Days                 int                `json:"days"`
	Coverage             statsCoverage      `json:"coverage"`
	Runs                 int                `json:"runs"`
	TempRuns             int                `json:"temp_runs"`
	RulesWithFindings    []statsRuleFinding `json:"rules_with_findings"`
	RulesWithoutFindings []statsRuleEmpty   `json:"rules_without_findings"`
	CPU                  []statsCPU         `json:"cpu"`
	CPUNote              string             `json:"cpu_note"`
}

var statsDays int
var statsOutput string
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Report rule findings and CPU from the run journal",
	RunE:  runStats,
}

func init() {
	statsCmd.Flags().IntVar(&statsDays, "days", 30, "Local calendar days to include")
	statsCmd.Flags().StringVarP(&statsOutput, "output", "o", "console", "Output format: console or json")
	rootCmd.AddCommand(statsCmd)
}

func runStats(cmd *cobra.Command, _ []string) (retErr error) {
	if statsDays < 1 {
		return usageError{fmt.Errorf("--days must be positive")}
	}
	if statsOutput != "console" && statsOutput != "json" {
		return usageError{fmt.Errorf("unknown stats output %q", statsOutput)}
	}
	path, enabled, err := runLogPath()
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("run journal is disabled")
	}
	path, err = absoluteRunJournalPath(path, "stats")
	if err != nil {
		return err
	}
	if err := ensureRunJournalDirectory(path, "stats"); err != nil {
		return err
	}
	lock, err := openRunJournalLock(path, "stats")
	if err != nil {
		return err
	}
	locked := false
	defer func() {
		if locked {
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("unlock run journal: %w", err))
			}
		}
		if err := lock.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close run journal lock: %w", err))
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		return fmt.Errorf("lock run journal for reading: %w", err)
	}
	locked = true
	report, err := makeStatsReport(path, statsDays, time.Now())
	if err != nil {
		return err
	}
	w := io.Writer(os.Stdout)
	if cmd != nil && cmd.OutOrStdout() != nil {
		w = cmd.OutOrStdout()
	}
	if statsOutput == "json" {
		return json.NewEncoder(w).Encode(report)
	}
	return printStats(w, report)
}

func makeStatsReport(path string, days int, now time.Time) (statsReport, error) {
	start := localDay(now).AddDate(0, 0, -(days - 1))
	end := localDay(now)
	data := make(map[string]*dailyRecord)
	rootCache := make(map[string]bool)
	header := dailyHeader{FirstSeen: make(map[string]string)}
	if err := readDaily(strings.TrimSuffix(path, ".jsonl")+"-daily.jsonl", data, &header); err != nil {
		return statsReport{}, fmt.Errorf("read daily run journal: %w", err)
	}
	rotated := path + ".1"
	if fingerprint, err := journalFingerprint(rotated); err == nil && fingerprint != header.Folded {
		if err := foldRawFile(rotated, data, rootCache, nil); err != nil {
			return statsReport{}, fmt.Errorf("read rotated run journal: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return statsReport{}, fmt.Errorf("fingerprint rotated run journal: %w", err)
	}
	if err := foldRawFile(path, data, rootCache, nil); err != nil {
		return statsReport{}, fmt.Errorf("read run journal: %w", err)
	}
	for _, rule := range rules.All() {
		name := rule.Name()
		if _, ok := header.FirstSeen[name]; !ok {
			header.FirstSeen[name] = start.Format("2006-01-02")
		}
	}
	return buildStats(data, header, days, start, end)
}

func localDay(t time.Time) time.Time {
	y, m, d := t.In(time.Local).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local)
}

func isPermanentRoot(root string) bool {
	if root == "" {
		return false
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	for _, base := range []string{os.TempDir(), "/var/tmp"} {
		base, err = filepath.Abs(base)
		if err == nil && (abs == base || strings.HasPrefix(abs, base+string(os.PathSeparator))) {
			return false
		}
	}
	info, err := os.Stat(filepath.Join(abs, ".git"))
	return err == nil && info.IsDir()
}

func cachedPermanentRoot(cache map[string]bool, root string) bool {
	if permanent, ok := cache[root]; ok {
		return permanent
	}
	permanent := isPermanentRoot(root)
	cache[root] = permanent
	return permanent
}

func newDaily(day string) *dailyRecord {
	return &dailyRecord{Day: day, RuleMS: make(map[string]int64), Roots: make(map[string]*dailyRoot)}
}

// addEntry adds a run to its day. firstDays, when not nil, gets the earliest
// day each rule shows time or findings in, temporary roots included: a run
// anywhere shows the rule existed, though only permanent roots are counted.
func addEntry(data map[string]*dailyRecord, entry runJournalEntry, rootCache map[string]bool, firstDays map[string]string) error {
	t, err := time.Parse(time.RFC3339, entry.Time)
	if err != nil {
		return fmt.Errorf("parse run timestamp %q: %w", entry.Time, err)
	}
	day := t.In(time.Local).Format("2006-01-02")
	if firstDays != nil {
		for rule := range entry.RuleMS {
			noteFirstDay(firstDays, rule, day)
		}
		for rule := range entry.Findings {
			noteFirstDay(firstDays, rule, day)
		}
	}
	d := data[day]
	if d == nil {
		d = newDaily(day)
		data[day] = d
	}
	if !cachedPermanentRoot(rootCache, entry.Root) {
		d.TempRuns++
		return nil
	}
	d.Runs++
	d.WallMS += entry.WallMS
	r := d.Roots[entry.Root]
	if r == nil {
		r = &dailyRoot{Findings: make(map[string]int)}
		d.Roots[entry.Root] = r
	}
	r.Runs++
	for name, count := range entry.Findings {
		if count > r.Findings[name] {
			r.Findings[name] = count
		}
	}
	for name, ms := range entry.RuleMS {
		d.RuleMS[name] += ms
	}
	return nil
}

func noteFirstDay(firstDays map[string]string, rule, day string) {
	if prev, ok := firstDays[rule]; !ok || day < prev {
		firstDays[rule] = day
	}
}

func mergeDaily(dst, src *dailyRecord) {
	dst.Runs += src.Runs
	dst.TempRuns += src.TempRuns
	dst.WallMS += src.WallMS
	for name, ms := range src.RuleMS {
		dst.RuleMS[name] += ms
	}
	for root, sr := range src.Roots {
		r := dst.Roots[root]
		if r == nil {
			r = &dailyRoot{Findings: make(map[string]int)}
			dst.Roots[root] = r
		}
		r.Runs += sr.Runs
		for name, count := range sr.Findings {
			if count > r.Findings[name] {
				r.Findings[name] = count
			}
		}
	}
}

func foldRawFile(path string, data map[string]*dailyRecord, rootCache map[string]bool, firstDays map[string]string) (retErr error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close %s: %w", path, err))
		}
	}()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		var e runJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return fmt.Errorf("decode %s line %d: %w", path, lineNumber, err)
		}
		if err := addEntry(data, e, rootCache, firstDays); err != nil {
			return fmt.Errorf("process %s line %d: %w", path, lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	return nil
}

func readDaily(path string, data map[string]*dailyRecord, header *dailyHeader) (retErr error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close %s: %w", path, err))
		}
	}()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	first := true
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if first {
			first = false
			if err := json.Unmarshal(scanner.Bytes(), header); err == nil && header.Folded != "" {
				continue
			}
		}
		var d dailyRecord
		if err := json.Unmarshal(scanner.Bytes(), &d); err != nil {
			return fmt.Errorf("decode %s line %d: %w", path, lineNumber, err)
		}
		if d.Day == "" {
			return fmt.Errorf("decode %s line %d: daily record has no day", path, lineNumber)
		}
		if d.RuleMS == nil {
			d.RuleMS = make(map[string]int64)
		}
		if d.Roots == nil {
			d.Roots = make(map[string]*dailyRoot)
		}
		if current := data[d.Day]; current == nil {
			data[d.Day] = &d
		} else {
			mergeDaily(current, &d)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	return nil
}

func journalFingerprint(path string) (fingerprint string, retErr error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close %s: %w", path, err))
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("journal file identity unavailable")
	}
	buf := make([]byte, 4096)
	n, readErr := f.Read(buf)
	if readErr != nil && readErr != io.EOF {
		return "", fmt.Errorf("read fingerprint from %s: %w", path, readErr)
	}
	h := sha256.Sum256(buf[:n])
	return fmt.Sprintf("%d:%d:%d:%s", stat.Dev, stat.Ino, info.Size(), hex.EncodeToString(h[:])), nil
}

func foldRotatedJournal(path string) error {
	rotated := path + ".1"
	fingerprint, err := journalFingerprint(rotated)
	if err != nil {
		return fmt.Errorf("fingerprint rotated run journal: %w", err)
	}
	dailyPath := strings.TrimSuffix(path, ".jsonl") + "-daily.jsonl"
	data := make(map[string]*dailyRecord)
	header := dailyHeader{FirstSeen: make(map[string]string)}
	if err := readDaily(dailyPath, data, &header); err != nil {
		return fmt.Errorf("read daily run journal: %w", err)
	}
	if header.Folded == fingerprint {
		return nil
	}
	firstDays := make(map[string]string)
	if err := foldRawFile(rotated, data, make(map[string]bool), firstDays); err != nil {
		return fmt.Errorf("fold rotated run journal: %w", err)
	}
	// A rule new to the map was born at most this fold ago, or earlier when
	// the folded runs show it: its time or findings on an earlier day.
	today := time.Now().In(time.Local).Format("2006-01-02")
	for _, rule := range rules.All() {
		if _, ok := header.FirstSeen[rule.Name()]; !ok {
			header.FirstSeen[rule.Name()] = today
			if day, ok := firstDays[rule.Name()]; ok {
				header.FirstSeen[rule.Name()] = min(day, today)
			}
		}
	}
	header.Folded = fingerprint
	cutoff := localDay(time.Now()).AddDate(0, 0, -(runJournalRetention - 1))
	for day := range data {
		parsed, err := time.ParseInLocation("2006-01-02", day, time.Local)
		if err != nil {
			return fmt.Errorf("parse daily journal date %q: %w", day, err)
		}
		if parsed.Before(cutoff) {
			delete(data, day)
		}
	}
	return writeDailyAtomic(dailyPath, header, data)
}

func writeDailyAtomic(path string, header dailyHeader, data map[string]*dailyRecord) (retErr error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runs-daily-*")
	if err != nil {
		return fmt.Errorf("create temporary daily journal: %w", err)
	}
	closed := false
	renamed := false
	defer func() {
		if !closed {
			if err := tmp.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close temporary daily journal: %w", err))
			}
		}
		if !renamed {
			if err := os.Remove(tmp.Name()); err != nil && !os.IsNotExist(err) {
				retErr = errors.Join(retErr, fmt.Errorf("remove temporary daily journal: %w", err))
			}
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary daily journal permissions: %w", err)
	}
	writer := bufio.NewWriter(tmp)
	if err := json.NewEncoder(writer).Encode(header); err != nil {
		return fmt.Errorf("encode daily journal header: %w", err)
	}
	days := make([]string, 0, len(data))
	for day := range data {
		days = append(days, day)
	}
	sort.Strings(days)
	for _, day := range days {
		if err := json.NewEncoder(writer).Encode(data[day]); err != nil {
			return fmt.Errorf("encode daily journal day %s: %w", day, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush daily journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync daily journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return fmt.Errorf("close daily journal: %w", err)
	}
	closed = true
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace daily journal: %w", err)
	}
	renamed = true
	return nil
}

func buildStats(data map[string]*dailyRecord, header dailyHeader, days int, start, end time.Time) (statsReport, error) {
	report := statsReport{Days: days, RulesWithFindings: []statsRuleFinding{}, RulesWithoutFindings: []statsRuleEmpty{}, CPU: []statsCPU{}, CPUNote: "CPU is a lower estimate: the journal records only rules taking at least 5 ms per run."}
	rootSet := make(map[string]map[string]bool)
	ruleDays := make(map[string]map[string]bool)
	cpuMS := make(map[string]int64)
	populated := make(map[string]bool)
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		key := day.Format("2006-01-02")
		d := data[key]
		if d == nil {
			continue
		}
		populated[key] = true
		report.Runs += d.Runs
		report.TempRuns += d.TempRuns
		for name, ms := range d.RuleMS {
			cpuMS[name] += ms
		}
		for root, r := range d.Roots {
			for name, count := range r.Findings {
				if count > 0 {
					if rootSet[name] == nil {
						rootSet[name] = make(map[string]bool)
					}
					rootSet[name][root] = true
					if ruleDays[name] == nil {
						ruleDays[name] = make(map[string]bool)
					}
					ruleDays[name][key] = true
				}
			}
		}
	}
	if len(populated) > 0 {
		keys := make([]string, 0, len(populated))
		for d := range populated {
			keys = append(keys, d)
		}
		sort.Strings(keys)
		report.Coverage.From = keys[0]
		report.Coverage.To = keys[len(keys)-1]
		report.Coverage.DaysWithRuns = len(keys)
	}
	report.Coverage.DaysWithoutRuns = days - report.Coverage.DaysWithRuns
	report.Coverage.Complete = report.Coverage.From == start.Format("2006-01-02") && report.Coverage.DaysWithoutRuns == 0
	for name, roots := range rootSet {
		report.RulesWithFindings = append(report.RulesWithFindings, statsRuleFinding{name, len(roots), len(ruleDays[name])})
	}
	sort.Slice(report.RulesWithFindings, func(i, j int) bool { return report.RulesWithFindings[i].Rule < report.RulesWithFindings[j].Rule })
	for _, rule := range rules.All() {
		name := rule.Name()
		if len(rootSet[name]) > 0 {
			continue
		}
		since := start.Format("2006-01-02")
		if first := header.FirstSeen[name]; first > since {
			since = first
		}
		first, err := time.ParseInLocation("2006-01-02", since, time.Local)
		if err != nil {
			return statsReport{}, fmt.Errorf("parse first-seen day for rule %s: %w", name, err)
		}
		// Counted to the report's end day, not the wall clock, so a report
		// reads the same whenever it is printed.
		n := min(max(calendarDaysSince(first, end), 1), days)
		report.RulesWithoutFindings = append(report.RulesWithoutFindings, statsRuleEmpty{name, since, n})
	}
	sort.Slice(report.RulesWithoutFindings, func(i, j int) bool {
		if report.RulesWithoutFindings[i].Since == report.RulesWithoutFindings[j].Since {
			return report.RulesWithoutFindings[i].Rule < report.RulesWithoutFindings[j].Rule
		}
		return report.RulesWithoutFindings[i].Since < report.RulesWithoutFindings[j].Since
	})
	var total int64
	for _, ms := range cpuMS {
		total += ms
	}
	for name, ms := range cpuMS {
		share := 0.0
		if total > 0 {
			share = float64(ms) / float64(total)
		}
		perRun := int64(0)
		if report.Runs > 0 {
			perRun = ms / int64(report.Runs)
		}
		report.CPU = append(report.CPU, statsCPU{name, ms, share, perRun})
	}
	sort.Slice(report.CPU, func(i, j int) bool {
		if report.CPU[i].MS == report.CPU[j].MS {
			return report.CPU[i].Rule < report.CPU[j].Rule
		}
		return report.CPU[i].MS > report.CPU[j].MS
	})
	return report, nil
}

func printStats(w io.Writer, report statsReport) error {
	if report.Coverage.From == "" {
		if _, err := fmt.Fprintf(w, "No data; no runs in the %d-day window.\n", report.Days); err != nil {
			return fmt.Errorf("write stats coverage: %w", err)
		}
	} else {
		if _, err := fmt.Fprintf(w, "Data from %s to %s, %d of %d days without runs.\n", report.Coverage.From, report.Coverage.To, report.Coverage.DaysWithoutRuns, report.Days); err != nil {
			return fmt.Errorf("write stats coverage: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "Permanent runs: %d; temporary runs: %d.\nRules with findings:\n", report.Runs, report.TempRuns); err != nil {
		return fmt.Errorf("write stats run counts: %w", err)
	}
	for _, r := range report.RulesWithFindings {
		if _, err := fmt.Fprintf(w, "  %s  %d roots, %d days\n", r.Rule, r.Roots, r.Days); err != nil {
			return fmt.Errorf("write stats rule %s: %w", r.Rule, err)
		}
	}
	if _, err := fmt.Fprintln(w, "Rules without findings:"); err != nil {
		return fmt.Errorf("write stats header: %w", err)
	}
	for _, r := range report.RulesWithoutFindings {
		if _, err := fmt.Fprintf(w, "  %s  since %s (%d days)\n", r.Rule, r.Since, r.Days); err != nil {
			return fmt.Errorf("write stats rule %s: %w", r.Rule, err)
		}
	}
	if _, err := fmt.Fprintln(w, "Rule CPU (lower estimate):"); err != nil {
		return fmt.Errorf("write stats CPU header: %w", err)
	}
	shown := min(len(report.CPU), 20)
	for _, r := range report.CPU[:shown] {
		if _, err := fmt.Fprintf(w, "  %s: %d ms, %.2f%%, %d ms/run\n", r.Rule, r.MS, r.Share*100, r.MSPerRun); err != nil {
			return fmt.Errorf("write stats CPU for rule %s: %w", r.Rule, err)
		}
	}
	if remaining := len(report.CPU) - shown; remaining > 0 {
		if _, err := fmt.Fprintf(w, "... %d more rules: -o json\n", remaining); err != nil {
			return fmt.Errorf("write stats CPU remainder: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w, report.CPUNote); err != nil {
		return fmt.Errorf("write stats CPU note: %w", err)
	}
	return nil
}
