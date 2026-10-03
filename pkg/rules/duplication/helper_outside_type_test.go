package duplication

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func helperOutsideLines(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewHelperOutsideTypePackageRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var lines []string
	for _, v := range violations {
		lines = append(lines, v.File+":"+strconv.Itoa(v.Line))
	}
	return lines
}

const geomPackage = `package geom

import "math"

type Point struct{ X, Y float64 }

func (p Point) Dist(q Point) float64 { return math.Hypot(p.X-q.X, p.Y-q.Y) }
`

// The same circle intersection kept in two consumer packages, each written
// from its own source: the text differs, so the copies only show by where
// they live - math on the fields of geom.Point outside geom.
func TestHelperOutsideTypePackage(t *testing.T) {
	files := map[string]string{
		"geom/point.go": geomPackage,
		"plan/mining.go": `package plan

import (
	"math"

	"example.com/rulestest/geom"
)

func circles(a, b geom.Point, r float64) (geom.Point, geom.Point, bool) {
	d := a.Dist(b)
	if d == 0 || r < d/2 {
		return geom.Point{}, geom.Point{}, false
	}
	h := math.Sqrt(r*r - (d/2)*(d/2))
	ux, uy := (b.X-a.X)/d, (b.Y-a.Y)/d
	mx, my := (a.X+b.X)/2, (a.Y+b.Y)/2
	return geom.Point{X: mx + h*uy, Y: my - h*ux}, geom.Point{X: mx - h*uy, Y: my + h*ux}, true
}
`,
		"terrain/ramp.go": `package terrain

import (
	"fmt"
	"math"

	"example.com/rulestest/geom"
)

func centroid(ps []geom.Point) geom.Point {
	var s geom.Point
	for _, p := range ps {
		s.X += p.X
		s.Y += p.Y
	}
	return geom.Point{X: s.X / float64(len(ps)), Y: s.Y / float64(len(ps))}
}

func circleIntersection(a, b geom.Point, r float64) (geom.Point, geom.Point, error) {
	d := a.Dist(b)
	if d == 0 || r < d/2 {
		return geom.Point{}, geom.Point{}, fmt.Errorf("no intersection of %v and %v", a, b)
	}
	k := math.Sqrt(r*r-(d/2)*(d/2)) / (d / 2)
	hx, hy := (b.X-a.X)/2, (b.Y-a.Y)/2
	return geom.Point{X: a.X + hx + hy*k, Y: a.Y + hy - hx*k}, geom.Point{X: a.X + hx - hy*k, Y: a.Y + hy + hx*k}, nil
}
`,
	}
	assert.Equal(t, []string{"plan/mining.go:9", "terrain/ramp.go:10", "terrain/ramp.go:19"}, helperOutsideLines(t, files))
}

// Code that only calls the type's API, that leans on its own package, that
// joins types of two packages or a library type, that ignores its argument,
// and the type's own package are where they belong.
func TestHelperOutsideTypePackageAllowed(t *testing.T) {
	files := map[string]string{
		"geom/point.go": geomPackage + `
func Mid(a, b Point) Point { return Point{X: (a.X + b.X) / 2, Y: (a.Y + b.Y) / 2} }
`,
		"frame/unit.go": `package frame

import "example.com/rulestest/geom"

type Unit struct{ Pos geom.Point }
`,
		"plan/plan.go": `package plan

import (
	"time"

	"example.com/rulestest/frame"
	"example.com/rulestest/geom"
)

const cell = 4

type Ctx struct{ Home geom.Point }

func behindLine(base, center, p geom.Point, half float64) bool {
	return p.Dist(base)-half >= center.Dist(base)
}

func cellOf(p geom.Point) [2]int { return [2]int{int(p.X / cell), int(p.Y / cell)} }

func nearer(c *Ctx, p geom.Point) bool { return p.X < c.Home.X }

func towardsUnit(u *frame.Unit, p geom.Point) float64 { return u.Pos.X - p.X }

func ahead(p geom.Point, d time.Duration) geom.Point { return geom.Point{X: p.X + d.Seconds(), Y: p.Y} }

func flatCost(geom.Point) float64 { return 0 }

func (c *Ctx) shift(p geom.Point) geom.Point { return geom.Point{X: p.X + 1, Y: p.Y} }
`,
	}
	assert.Empty(t, helperOutsideLines(t, files))
}

// A setter of a parameter table and rows of data built as literals of the
// type configure it - they read none of its fields.
func TestHelperOutsideTypePackageSettersAndLiterals(t *testing.T) {
	files := map[string]string{
		"geom/point.go": geomPackage + `
type Params struct {
	Speed float64
	Leg   [4]float64
}
`,
		"cmd/fit/fit.go": `package main

import "example.com/rulestest/geom"

func setSpeed(p *geom.Params, x float64) { p.Speed = x }

func setLeg(p *geom.Params, x float64) { p.Leg[2] = x }

func corners() []geom.Point { return []geom.Point{{X: 1, Y: 2}, {X: 3, Y: 4}} }

func start(p geom.Point) []geom.Point { return []geom.Point{p, {X: 0, Y: 0}} }

func main() {}
`,
	}
	assert.Empty(t, helperOutsideLines(t, files))
}

// A rule over an entity passed by pointer belongs to the service that changes
// it: the transaction's package is not where its approval is decided.
func TestHelperOutsideTypePackageEntityPointer(t *testing.T) {
	files := map[string]string{
		"domain/tx.go": `package domain

type Transaction struct {
	Status string
	Amount float64
}
`,
		"service/approve.go": `package service

import (
	"errors"

	"example.com/rulestest/domain"
)

func validateApprovable(tx *domain.Transaction) error {
	if tx.Status != "pending" || tx.Amount <= 0 {
		return errors.New("not approvable")
	}
	return nil
}
`,
	}
	assert.Empty(t, helperOutsideLines(t, files))
}
