package main

import "time"

// fakeClock returns a controllable now() and a function to advance it.
func fakeClock() (func() time.Time, func(d time.Duration)) {
	current := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return current },
		func(d time.Duration) { current = current.Add(d) }
}
