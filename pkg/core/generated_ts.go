package core

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	// tsNamedImport matches import { A, type B as C } from '...' and the
	// re-export export { A } from '...', with an optional default import.
	tsNamedImport = regexp.MustCompile(`\b(?:import|export)\s+(?:type\s+)?(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]`)
	// tsNamespaceImport matches import * as T from '...'.
	tsNamespaceImport = regexp.MustCompile(`\bimport\s+(?:type\s+)?\*\s+as\s+([\w$]+)\s+from\s*['"]([^'"]+)['"]`)
	// tsStarExport matches export * from '...'.
	tsStarExport = regexp.MustCompile(`\bexport\s+(?:type\s+)?\*\s+from\s*['"]([^'"]+)['"]`)
)

// GeneratedTSImports returns the names the hand-written TypeScript and
// JavaScript files among contexts import from generated TypeScript - a file
// with the "Code generated ... DO NOT EDIT." marker, or a module that
// re-exports one with export *. A code generator writes such a file from Go
// types (tygo, typegen), so the Go type of an imported name is in use though
// no Go code refers to it. A specifier that is not relative (a path alias
// like @app/api/types) names the module whose path ends in its segments
// after the first.
func GeneratedTSImports(contexts []*FileContext) map[string]bool {
	var scripts []*FileContext
	var sources tsSources
	for _, ctx := range contexts {
		if ctx == nil || (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) {
			continue
		}
		if ctx.IsTypeScriptFile() && ctx.IsGenerated() {
			sources.add(ctx.Path)
			continue
		}
		scripts = append(scripts, ctx)
	}
	if len(sources) == 0 {
		return nil
	}
	barrels := map[*FileContext]bool{}
	for grew := true; grew; {
		grew = false
		for _, ctx := range scripts {
			if barrels[ctx] {
				continue
			}
			for _, m := range tsStarExport.FindAllStringSubmatch(string(ctx.Content), -1) {
				if sources.imported(ctx.Path, m[1]) {
					barrels[ctx], grew = true, true
					sources.add(ctx.Path)
					break
				}
			}
		}
	}
	names := map[string]bool{}
	for _, ctx := range scripts {
		content := string(ctx.Content)
		for _, m := range tsNamedImport.FindAllStringSubmatch(content, -1) {
			if !sources.imported(ctx.Path, m[2]) {
				continue
			}
			for spec := range strings.SplitSeq(m[1], ",") {
				fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(spec), "type "))
				if len(fields) > 0 {
					names[fields[0]] = true
				}
			}
		}
		for _, m := range tsNamespaceImport.FindAllStringSubmatch(content, -1) {
			if sources.imported(ctx.Path, m[2]) {
				for _, name := range tsMembers(content, m[1]) {
					names[name] = true
				}
			}
		}
	}
	return names
}

// tsSources holds the module paths of generated TypeScript: a path without
// its extension, and the directory of an index file.
type tsSources []string

func (s *tsSources) add(file string) {
	key := filepath.ToSlash(trimScriptExt(file))
	*s = append(*s, key)
	if path.Base(key) == "index" {
		*s = append(*s, path.Dir(key))
	}
}

// imported reports an import specifier of the file at from that names one of
// the modules.
func (s tsSources) imported(from, spec string) bool {
	spec = trimScriptExt(spec)
	if strings.HasPrefix(spec, ".") {
		return slices.Contains(s, filepath.ToSlash(filepath.Join(filepath.Dir(from), spec)))
	}
	_, tail, ok := strings.Cut(spec, "/")
	return ok && slices.ContainsFunc(s, func(key string) bool { return strings.HasSuffix(key, "/"+tail) })
}

// trimScriptExt drops a TypeScript or JavaScript extension.
func trimScriptExt(file string) string {
	ext := filepath.Ext(file)
	if slices.Contains(TypeScriptExtensions, ext) || slices.Contains(JavaScriptExtensions, ext) {
		return strings.TrimSuffix(file, ext)
	}
	return file
}

// tsMembers returns the names read through a namespace import: ns.Name.
func tsMembers(content, ns string) []string {
	var names []string
	for rest := content; ; {
		i := strings.Index(rest, ns+".")
		if i < 0 {
			return names
		}
		before := byte(' ')
		if i > 0 {
			before = rest[i-1]
		}
		rest = rest[i+len(ns)+1:]
		end := strings.IndexFunc(rest, func(r rune) bool { return !IsScriptIdentRune(r) })
		if end < 0 {
			end = len(rest)
		}
		if end > 0 && !IsScriptIdentRune(rune(before)) && before != '.' {
			names = append(names, rest[:end])
		}
	}
}

// IsScriptIdentRune reports whether r is an ASCII identifier character used in scripts.
func IsScriptIdentRune(r rune) bool {
	return r == '_' || r == '$' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}
