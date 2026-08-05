package core

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// Walker traverses files in a project
type Walker struct {
	projectRoot string
	config      *Config
	parser      *Parser
	parseGo     bool

	// Worker pool size. The channels belong to one walk: walk creates them,
	// so the same walker can be reused.
	workers int

	// Statistics of the most recent walk
	stats WalkerStats
	mu    sync.Mutex
}

// WalkerStats contains statistics about the walk
type WalkerStats struct {
	TotalFiles   int
	ParsedFiles  int
	SkippedFiles int
	ErrorFiles   int
}

// NewWalker creates a new file walker
func NewWalker(projectRoot string, config *Config) *Walker {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	return &Walker{
		projectRoot: projectRoot,
		config:      config,
		parser:      SharedParser(),
		parseGo:     true,
		workers:     workers,
	}
}

// WithGoParsing controls whether the walker parses Go files into ASTs.
func (w *Walker) WithGoParsing(enabled bool) *Walker {
	w.parseGo = enabled
	return w
}

// WithWorkers sets the number of worker goroutines
func (w *Walker) WithWorkers(n int) *Walker {
	if n > 0 {
		w.workers = n
	}
	return w
}

// walk traverses all files and returns FileContexts through a channel. Each
// call owns its channels and resets the statistics, so a walker can be reused.
//
// Contract: the caller must drain both channels concurrently until they are
// closed. Both are buffered at 100; a consumer that reads them sequentially
// deadlocks as soon as one overflows, because workers block on sends. That is
// why walk is unexported — WalkSync is the safe public entry point.
func (w *Walker) walk() (<-chan *FileContext, <-chan error) {
	const channelBuffer = 100
	fileQueue := make(chan string, channelBuffer)
	results := make(chan *FileContext, channelBuffer)
	walkErrors := make(chan error, channelBuffer)

	w.mu.Lock()
	w.stats = WalkerStats{}
	w.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < w.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.work(fileQueue, results, walkErrors)
		}()
	}

	// Start file discovery
	go func() {
		if err := filepath.Walk(w.projectRoot, func(path string, info os.FileInfo, err error) error {
			return w.visitPath(fileQueue, walkErrors, path, info, err)
		}); err != nil {
			walkErrors <- err
		}
		close(fileQueue)
	}()

	// Wait for workers to finish and close channels
	go func() {
		wg.Wait()
		close(results)
		close(walkErrors)
	}()

	return results, walkErrors
}

// WalkSync walks files synchronously and returns all contexts
func (w *Walker) WalkSync() ([]*FileContext, []error) {
	var contexts []*FileContext
	var errors []error

	results, errChan := w.walk()

	// Collect results
	done := make(chan struct{})
	go func() {
		for err := range errChan {
			errors = append(errors, err)
		}
		close(done)
	}()

	for ctx := range results {
		contexts = append(contexts, ctx)
	}

	<-done

	return contexts, errors
}

// visitPath is called for each entry during walk and queues the analyzable
// files onto this walk's channel.
func (w *Walker) visitPath(fileQueue chan<- string, walkErrors chan<- error, path string, info os.FileInfo, err error) error {
	if err != nil {
		// Returning the error would abort the entire filepath.Walk (its
		// documented contract), silently losing every file after this point.
		// Report it and keep walking; the caller decides whether to fail.
		walkErrors <- fmt.Errorf("visit %q: %w", path, err)
		return nil
	}

	// Skip directories we don't need to traverse
	if info.IsDir() {
		if w.shouldSkipDir(info.Name()) {
			return filepath.SkipDir
		}
		return nil
	}

	// Skip non-analyzable files
	if !w.isAnalyzableFile(path) {
		return nil
	}

	// Check exclusion patterns
	relPath, err := filepath.Rel(w.projectRoot, path)
	if err != nil {
		return fmt.Errorf("make %q relative to project root: %w", path, err)
	}
	if w.config.ShouldExclude(relPath) {
		w.mu.Lock()
		w.stats.SkippedFiles++
		w.mu.Unlock()
		return nil
	}

	// Queue file for processing
	w.mu.Lock()
	w.stats.TotalFiles++
	w.mu.Unlock()

	fileQueue <- path

	return nil
}

// work processes files from this walk's queue.
func (w *Walker) work(fileQueue <-chan string, results chan<- *FileContext, walkErrors chan<- error) {
	for path := range fileQueue {
		ctx, err := w.processFile(path)
		if err != nil {
			w.mu.Lock()
			w.stats.ErrorFiles++
			w.mu.Unlock()
			walkErrors <- err
		}

		if ctx != nil {
			w.mu.Lock()
			w.stats.ParsedFiles++
			w.mu.Unlock()
			results <- ctx
		}
	}
}

// processFile reads and parses a single file
func (w *Walker) processFile(path string) (*FileContext, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ctx, err := NewFileContextChecked(path, w.projectRoot, content, w.config)
	if err != nil {
		return nil, err
	}

	// Parse Go files
	if ctx.IsGoFile() && w.parseGo {
		fset, astFile, err := w.parser.ParseGoFile(path, content)
		if err != nil {
			ctx.SetGoAST(nil, nil)
			return ctx, fmt.Errorf("parse Go file %q: %w", path, err)
		} else {
			ctx.SetGoAST(fset, astFile)
		}
	}

	return ctx, nil
}

// shouldSkipDir reports whether a directory is not descended into at all. The
// list comes from settings.skip_dirs, which defaults to DefaultSkipDirs — a
// project whose own package is called build/ or out/ can override it.
func (w *Walker) shouldSkipDir(name string) bool {
	return slices.Contains(w.config.SkipDirs(), name)
}

// isAnalyzableFile returns true if file should be analyzed
func (w *Walker) isAnalyzableFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))

	analyzableExtensions := []string{
		".go",
		".ts", ".tsx",
		".js", ".jsx",
		".md",
		".sql",  // migration hygiene rules (rules must guard by extension)
		".conf", // server configuration rules (rules must guard by extension)
	}

	for _, e := range analyzableExtensions {
		if ext == e {
			// Debug: uncomment to see which files are considered
			// fmt.Printf("DEBUG isAnalyzable: %s -> true (ext=%s)\n", path, ext)
			return true
		}
	}

	return false
}

// Stats returns the current walker statistics
func (w *Walker) Stats() WalkerStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}
