package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A live-updates hook: connect lists attempt among its dependencies and
// resets it on open, so every successful open recreates connect, and the
// effect depending on connect closes the stream and opens it again.
const callbackDependsOnStateSource = `import { useCallback, useEffect, useRef, useState } from 'react'

export function useLiveFeed(endpoint: string, maxAttempts = 5) {
  const [items, setItems] = useState<string[]>([])
  const [attempt, setAttempt] = useState(0)
  const sourceRef = useRef<EventSource | null>(null)

  const connect = useCallback(() => {
    const source = new EventSource(endpoint)
    source.onopen = () => {
      setAttempt(0)
    }
    source.onmessage = (event) => {
      setItems((prev) => [...prev, event.data])
    }
    source.onerror = () => {
      source.close()
      if (attempt < maxAttempts) {
        setAttempt((prev) => prev + 1)
        setTimeout(() => connect(), 1000)
      }
    }
    sourceRef.current = source
  }, [
    endpoint,
    attempt,
    maxAttempts,
  ])

  useEffect(() => {
    connect()
    return () => sourceRef.current?.close()
  }, [connect, endpoint])

  return items
}
`

func TestReactCallbackDependsOnState_CallbackInEffectDeps(t *testing.T) {
	ctx := rulestest.TextFile(t, "hooks/useLiveFeed.ts", callbackDependsOnStateSource)
	violations := NewReactCallbackDependsOnStateRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 26, violations[0].Line, "reported on the dependency the callback sets")
	assert.Contains(t, violations[0].Message, "attempt")
	assert.Contains(t, violations[0].Message, "setAttempt")
}

func TestReactCallbackDependsOnState_Silent(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{
			// Post-fix shape: the counter lives in a ref, the dependency is gone.
			name: "dependency dropped",
			code: `export function useFeed(endpoint: string) {
  const [attempt, setAttempt] = useState(0)
  const connect = useCallback(() => {
    setAttempt(0)
  }, [endpoint])
  useEffect(() => { connect() }, [connect])
  return attempt
}
`,
		},
		{
			// Recreated on every set, but nothing reruns because of it.
			name: "callback not in effect deps",
			code: `export function Counter() {
  const [count, setCount] = useState(0)
  const bump = useCallback(() => {
    setCount(count + 1)
  }, [count])
  return <button onClick={bump}>{count}</button>
}
`,
		},
		{
			name: "dependency read but not set",
			code: `export function useFeed(endpoint: string) {
  const [attempt, setAttempt] = useState(0)
  const connect = useCallback(() => {
    console.log(attempt)
  }, [attempt])
  useEffect(() => { connect() }, [connect])
  return setAttempt
}
`,
		},
		{
			// Same names in another component: the state is not the callback's.
			name: "state of another component",
			code: `function Other() {
  const [attempt, setAttempt] = useState(0)
  return <span onClick={() => setAttempt(1)}>{attempt}</span>
}

export function useFeed(attempt: number, setAttempt: (n: number) => void) {
  const connect = useCallback(() => {
    setAttempt(0)
  }, [attempt])
  useEffect(() => { connect() }, [connect])
}
`,
		},
		{
			name: "setter mentioned only in a comment",
			code: `export function useFeed(endpoint: string) {
  const [attempt, setAttempt] = useState(0)
  const connect = useCallback(() => {
    // setAttempt(0) happens in onopen elsewhere
    open(endpoint, attempt)
  }, [endpoint, attempt])
  useEffect(() => { connect() }, [connect])
  return setAttempt
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.TextFile(t, "hooks/useFeed.tsx", tt.code)
			assert.Empty(t, NewReactCallbackDependsOnStateRule().AnalyzeFile(ctx))
		})
	}
}

func TestReactCallbackDependsOnState_UseMemoAndLayoutEffect(t *testing.T) {
	code := `export function Table({ rows }: Props) {
  const [page, setPage] = React.useState<number>(1)
  const visible = React.useMemo(() => {
    if (rows.length < page * 10) setPage(1)
    return rows.slice((page - 1) * 10, page * 10)
  }, [rows, page])
  React.useLayoutEffect(() => {
    measure(visible)
  }, [visible])
  return visible
}
`
	ctx := rulestest.TextFile(t, "components/Table.tsx", code)
	violations := NewReactCallbackDependsOnStateRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
}
