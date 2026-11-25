package shellrules

import (
	"maps"
	"math"
	"slices"
)

// callGraph holds the plain calls of a script: for each function and the
// top level, "", the calls it makes and the calls made of it.
type callGraph struct {
	names []string
	out   [][]callEdge
	in    [][]callEdge
}

// callEdge is a call at site, to or from the function numbered peer.
type callEdge struct {
	peer int
	site uint
}

func newCallGraph(f *trapFlow) *callGraph {
	g := &callGraph{}
	index := make(map[string]int)
	node := func(name string) int {
		i, ok := index[name]
		if !ok {
			i = len(g.names)
			index[name] = i
			g.names = append(g.names, name)
			g.out = append(g.out, nil)
			g.in = append(g.in, nil)
		}
		return i
	}
	for _, callee := range slices.Sorted(maps.Keys(f.calls)) {
		to := node(callee)
		for _, call := range f.calls[callee] {
			from := node(f.where[call].fn)
			site := call.Pos().Offset()
			g.out[from] = append(g.out[from], callEdge{peer: to, site: site})
			g.in[to] = append(g.in[to], callEdge{peer: from, site: site})
		}
	}
	return g
}

// bodyTimes is bodyRuns for every function: the least, over the functions
// a walk back through the callers reaches, of the latest call on the way
// and the place the walk may stop there. A walk stops at zero at the top
// level and at a function never called plainly, and at a function on a
// cycle of calls at the latest call of the cycle back to it whose latest
// call is the earliest. The times spread forward from all stops at once.
func (g *callGraph) bodyTimes() map[string]uint {
	times := g.cycleStops()
	for i := range g.names {
		if len(g.in[i]) == 0 {
			times[i] = 0
		}
	}
	spreadTimes(times, g.out)
	runs := make(map[string]uint, len(g.names))
	for i, name := range g.names {
		runs[name] = times[i]
	}
	return runs
}

// cycleStops gives each function the latest call of the cycle of calls
// back to it whose latest call is the earliest, MaxUint where no cycle
// comes back. A cycle stays in one strongly connected component, so each
// is walked on its own.
func (g *callGraph) cycleStops() []uint {
	stops := make([]uint, len(g.names))
	comp, members := g.components()
	local := make([]int, len(g.names))
	for id, nodes := range members {
		for k, v := range nodes {
			local[v] = k
		}
		callers := make([][]callEdge, len(nodes))
		for k, v := range nodes {
			for _, e := range g.in[v] {
				if comp[e.peer] == id {
					callers[k] = append(callers[k], callEdge{peer: local[e.peer], site: e.site})
				}
			}
		}
		back := make([]uint, len(nodes))
		for k, v := range nodes {
			for i := range back {
				back[i] = math.MaxUint
			}
			back[k] = 0
			spreadTimes(back, callers)
			stops[v] = math.MaxUint
			for _, e := range g.out[v] {
				if comp[e.peer] == id {
					stops[v] = min(stops[v], max(back[local[e.peer]], e.site))
				}
			}
		}
	}
	return stops
}

// components numbers the strongly connected components of the calls
// (Tarjan) and lists the functions of each.
func (g *callGraph) components() (comp []int, members [][]int) {
	n := len(g.names)
	order, low := slices.Repeat([]int{-1}, n), make([]int, n)
	comp = slices.Repeat([]int{-1}, n)
	var stack []int
	next := 0
	var visit func(v int)
	visit = func(v int) {
		order[v], low[v] = next, next
		next++
		stack = append(stack, v)
		for _, e := range g.out[v] {
			switch w := e.peer; {
			case order[w] < 0:
				visit(w)
				low[v] = min(low[v], low[w])
			case comp[w] < 0:
				low[v] = min(low[v], order[w])
			}
		}
		if low[v] != order[v] {
			return
		}
		id := len(members)
		var nodes []int
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			comp[w] = id
			nodes = append(nodes, w)
			if w == v {
				break
			}
		}
		members = append(members, nodes)
	}
	for v := range n {
		if order[v] < 0 {
			visit(v)
		}
	}
	return comp, members
}

// spreadTimes spreads times along edges, earliest first: a function an
// edge leads to from one with time t gets the later of t and the site of
// the edge where that is earlier than its own time. MaxUint is no time.
func spreadTimes(times []uint, edges [][]callEdge) {
	var queue timeQueue
	for v, t := range times {
		queue.push(timeItem{node: v, time: t})
	}
	for len(queue) > 0 {
		item := queue.pop()
		if item.time > times[item.node] {
			continue
		}
		for _, e := range edges[item.node] {
			if t := max(item.time, e.site); t < times[e.peer] {
				times[e.peer] = t
				queue.push(timeItem{node: e.peer, time: t})
			}
		}
	}
}

// timeQueue is a binary heap of functions, the earliest time on top.
type timeQueue []timeItem

type timeItem struct {
	node int
	time uint
}

func (q *timeQueue) push(item timeItem) {
	*q = append(*q, item)
	h := *q
	for i := len(h) - 1; i > 0; {
		parent := (i - 1) / 2
		if h[parent].time <= h[i].time {
			break
		}
		h[parent], h[i] = h[i], h[parent]
		i = parent
	}
}

func (q *timeQueue) pop() timeItem {
	h := *q
	top := h[0]
	last := len(h) - 1
	h[0] = h[last]
	h = h[:last]
	for i := 0; ; {
		least := i
		for _, child := range [2]int{2*i + 1, 2*i + 2} {
			if child < len(h) && h[child].time < h[least].time {
				least = child
			}
		}
		if least == i {
			break
		}
		h[i], h[least] = h[least], h[i]
		i = least
	}
	*q = h
	return top
}
