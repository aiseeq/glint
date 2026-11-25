package shellrules

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The queue gives the functions back earliest time first, whatever order
// they come in.
func TestTimeQueueEarliestFirst(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		var queue timeQueue
		var want []uint
		for node := range r.IntN(40) + 1 {
			time := uint(r.IntN(20))
			queue.push(timeItem{node: node, time: time})
			want = append(want, time)
		}
		slices.Sort(want)
		var got []uint
		for len(queue) > 0 {
			got = append(got, queue.pop().time)
		}
		assert.Equal(t, want, got)
	}
}

// On random call graphs the times match a plain walk back from each
// function: the least, over the functions reached, of the latest call on
// the way and the place the walk may stop there.
func TestBodyTimesMatchWalkBack(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 500 {
		n := r.IntN(7) + 2
		g := &callGraph{names: make([]string, n), out: make([][]callEdge, n), in: make([][]callEdge, n)}
		for i := range n {
			g.names[i] = fmt.Sprintf("f%d", i)
		}
		g.names[0] = ""
		for range r.IntN(3 * n) {
			from, to := r.IntN(n), r.IntN(n-1)+1
			site := uint(r.IntN(30))
			g.out[from] = append(g.out[from], callEdge{peer: to, site: site})
			g.in[to] = append(g.in[to], callEdge{peer: from, site: site})
		}
		got := g.bodyTimes()
		for x := range n {
			assert.Equal(t, walkBack(g, x), got[g.names[x]], "function %d of %v", x, g.out)
		}
	}
}

func walkBack(g *callGraph, x int) uint {
	ways := latestWays(g, x)
	at := uint(math.MaxUint)
	for c, way := range ways {
		if way == math.MaxUint {
			continue
		}
		stop := uint(0)
		if len(g.in[c]) > 0 {
			stop = math.MaxUint
			back := latestWays(g, c)
			for _, e := range g.out[c] {
				stop = min(stop, max(back[e.peer], e.site))
			}
		}
		at = min(at, max(way, stop))
	}
	return at
}

// latestWays relaxes the calls back from x until nothing changes.
func latestWays(g *callGraph, x int) []uint {
	ways := slices.Repeat([]uint{math.MaxUint}, len(g.names))
	ways[x] = 0
	for changed := true; changed; {
		changed = false
		for v, way := range ways {
			for _, e := range g.in[v] {
				if way != math.MaxUint && max(way, e.site) < ways[e.peer] {
					ways[e.peer] = max(way, e.site)
					changed = true
				}
			}
		}
	}
	return ways
}
