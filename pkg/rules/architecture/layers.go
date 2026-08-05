package architecture

import "strings"

// LayerType represents an architectural layer
type LayerType int

const (
	// UnknownLayer is the layer of a file that matches no known convention.
	UnknownLayer LayerType = iota
	// HandlerLayer is the transport layer: HTTP handlers, routers, controllers.
	HandlerLayer
	// ServiceLayer is the business logic layer.
	ServiceLayer
	// RepositoryLayer is the data access layer that owns SQL and storage calls.
	RepositoryLayer
)

// determineLayerFromPath determines the architectural layer of a file path.
// It is the single source of layer classification for the rules of this
// package (layer-violation, import-direction).
func determineLayerFromPath(path string) LayerType {
	lowerPath := strings.ToLower(path)

	if strings.Contains(lowerPath, "handler") || strings.Contains(lowerPath, "/routing/") {
		return HandlerLayer
	}
	if strings.Contains(lowerPath, "service") {
		return ServiceLayer
	}
	if isRepositoryPath(lowerPath) {
		return RepositoryLayer
	}

	return UnknownLayer
}

// isRepositoryPath reports whether a path belongs to the repository layer.
// It matches whole path segments, not substrings: "internal/reports/" must
// not be classified as a repository just because "reports" contains "repo".
func isRepositoryPath(lowerPath string) bool {
	for _, segment := range strings.Split(lowerPath, "/") {
		if isRepositorySegment(strings.TrimSuffix(segment, ".go")) {
			return true
		}
	}
	return false
}

// isRepositorySegment reports whether a single path segment (directory name
// or file name without extension) denotes the repository layer.
func isRepositorySegment(segment string) bool {
	switch segment {
	case "repo", "repository", "repositories":
		return true
	}
	return strings.HasSuffix(segment, "_repo") || strings.HasSuffix(segment, "_repository")
}
