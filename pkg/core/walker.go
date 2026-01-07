package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Walker traverses files in a project
type Walker struct {
	projectRoot string
	config      *Config
	parser      *Parser

	// Worker pool
	workers    int
	fileQueue  chan string
	resultChan chan *FileContext
	errorChan  chan error
	wg         sync.WaitGroup

	// Statistics
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
		parser:      NewParser(),
		workers:     workers,
		fileQueue:   make(chan string, 100),
		resultChan:  make(chan *FileContext, 100),
		errorChan:   make(chan error, 100),
	}
}

// WithWorkers sets the number of worker goroutines
func (w *Walker) WithWorkers(n int) *Walker {
	if n > 0 {
		w.workers = n
	}
	return w
}

// Walk traverses all files and returns FileContexts through a channel
func (w *Walker) Walk() (<-chan *FileContext, <-chan error) {
	// Start workers
	for i := 0; i < w.workers; i++ {
		w.wg.Add(1)
		go w.worker()
	}

	// Start file discovery
	go func() {
		err := filepath.Walk(w.projectRoot, w.visitFile)
		if err != nil {
			w.errorChan <- err
		}
		close(w.fileQueue)
	}()

	// Wait for workers to finish and close channels
	go func() {
		w.wg.Wait()
		close(w.resultChan)
		close(w.errorChan)
	}()

	return w.resultChan, w.errorChan
}

// WalkSync walks files synchronously and returns all contexts
func (w *Walker) WalkSync() ([]*FileContext, []error) {
	var contexts []*FileContext
	var errors []error

	results, errChan := w.Walk()

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

// visitFile is called for each file during walk
func (w *Walker) visitFile(path string, info os.FileInfo, err error) error {
	if err != nil {
		return nil // Skip files with errors
	}

	// Skip directories we don't need to traverse
	if info.IsDir() {
		name := info.Name()
		if w.shouldSkipDir(name) {
			return filepath.SkipDir
		}
		return nil
	}

	// Skip non-analyzable files
	if !w.isAnalyzableFile(path) {
		return nil
	}

	// Check exclusion patterns
	relPath, _ := filepath.Rel(w.projectRoot, path)
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

	w.fileQueue <- path

	return nil
}

// worker processes files from the queue
func (w *Walker) worker() {
	defer w.wg.Done()

	for path := range w.fileQueue {
		ctx, err := w.processFile(path)
		if err != nil {
			w.mu.Lock()
			w.stats.ErrorFiles++
			w.mu.Unlock()
			w.errorChan <- err
			continue
		}

		if ctx != nil {
			w.mu.Lock()
			w.stats.ParsedFiles++
			w.mu.Unlock()
			w.resultChan <- ctx
		}
	}
}

// processFile reads and parses a single file
func (w *Walker) processFile(path string) (*FileContext, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ctx := NewFileContext(path, w.projectRoot, content, w.config)

	// Parse Go files
	if ctx.IsGoFile() {
		fset, astFile, err := w.parser.ParseGoFile(path, content)
		if err != nil {
			// Log error but continue with regex-based analysis
			ctx.SetGoAST(nil, nil)
		} else {
			ctx.SetGoAST(fset, astFile)
		}
	}

	return ctx, nil
}

// shouldSkipDir returns true if directory should be skipped entirely
func (w *Walker) shouldSkipDir(name string) bool {
	skipDirs := []string{
		".git",
		".svn",
		".hg",
		"node_modules",
		"vendor",
		".next",
		"out",
		"dist",
		"build",
		"bin",
		".idea",
		".vscode",
	}

	for _, skip := range skipDirs {
		if name == skip {
			return true
		}
	}

	return false
}

// isAnalyzableFile returns true if file should be analyzed
func (w *Walker) isAnalyzableFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))

	analyzableExtensions := []string{
		".go",
		".ts", ".tsx",
		".js", ".jsx",
	}

	for _, e := range analyzableExtensions {
		if ext == e {
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
