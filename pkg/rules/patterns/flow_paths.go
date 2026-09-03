package patterns

import (
	"strconv"
	"strings"
)

// maxFlowPaths caps how many alternative paths a path-list rule keeps alive at
// a control-flow join. Deduplication removes the usual cause of growth —
// branches that touch nothing the rule tracks — and the cap is the backstop for
// functions whose paths genuinely differ at every branch.
const maxFlowPaths = 512

// joinFlowPaths merges the two path lists meeting at a control-flow join.
// Paths with equal keys carry the same evidence and are indistinguishable to
// the rule, so only the first of each survives: without that a function with N
// branches ends up with 2^N paths (24 branches cost 4 GB before the cap).
func joinFlowPaths[T any](left, right []T, key func(T) string) []T {
	capacity := len(left) + len(right)
	if capacity > maxFlowPaths {
		capacity = maxFlowPaths
	}
	joined := make([]T, 0, capacity)
	seen := make(map[string]struct{}, capacity)
	for _, side := range [2][]T{left, right} {
		for _, path := range side {
			if len(joined) >= maxFlowPaths {
				return joined
			}
			pathKey := key(path)
			if _, duplicate := seen[pathKey]; duplicate {
				continue
			}
			seen[pathKey] = struct{}{}
			joined = append(joined, path)
		}
	}
	return joined
}

// flowPathKey builds a path key out of the parts a rule tracks. Parts are
// separated so that different splits cannot produce the same key.
func flowPathKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

// flowPosKey renders a token position (an int) as a key part.
func flowPosKey[T ~int](pos T) string {
	return strconv.Itoa(int(pos))
}
