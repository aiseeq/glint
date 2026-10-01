package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

type fileRule interface {
	AnalyzeFile(ctx *core.FileContext) []*core.Violation
}

func reportedLines(t *testing.T, rule fileRule, path, source string) []int {
	t.Helper()
	lines := []int{}
	for _, v := range rule.AnalyzeFile(rulestest.TextFile(t, path, source)) {
		lines = append(lines, v.Line)
	}
	return lines
}

// A load started by an effect and written to state with nothing to cancel
// it: the answer for the previous network lands after the one for the new
// network and overwrites it.
func TestReactEffectAsyncWithoutCleanup(t *testing.T) {
	source := `export function AddressPanel({ network }: { network: string }) {
  const [address, setAddress] = useState('')
  const [rates, setRates] = useState<Rate[]>([])
  const [user, setUser] = useState<User | null>(null)

  useEffect(() => {
    const load = async () => {
      const r = await api.get('/address?network=' + network)
      setAddress(r.address)
    }
    load()
  }, [network])

  useEffect(() => {
    fetchRates(network).then((r) => setRates(r))
  }, [network])

  useEffect(() => {
    let active = true
    const load = async () => {
      const r = await api.get('/me')
      if (active) setUser(r)
    }
    load()
    return () => {
      active = false
    }
  }, [network])

  useEffect(() => {
    const controller = new AbortController()
    fetch('/rates', { signal: controller.signal }).then((r) => setRates([]))
    return () => controller.abort()
  }, [network])

  useEffect(() => {
    track('viewed', { network })
  }, [network])

  useEffect(() => {
    ;(async () => {
      const ok = await checkSession()
      setUser(ok ? me : null)
    })()
  }, [])

  useEffect(() => {
    const request = ++requestRef.current
    fetchRates(network).then((r) => { if (request === requestRef.current) setRates(r) })
  }, [network])

  useEffect(() => {
    fetchRates(network).then((r) => { if (mountedRef.current) setRates(r) })
  }, [network])

  useEffect(() => {
    if (started.current) return
    started.current = true
    fetchRates(network).then((r) => setRates(r))
  }, [network])

  useEffect(() => {
    fetchRates(network).then((r) => setRates(r))
  })

  useEffect(() => {
    getSession().then((s) => setUser(s.user))
  }, [router, setUser, sessionRef])

  useEffect(() => {
    setUser(null)
    const go = async () => {
      const r = await api.get('/dashboard')
      router.replace(r.next)
    }
    go()
  }, [network])

  useEffect(() => {
    loadAddresses(network).then(list => {
      if (list.length === 0) return
      const requested = new URLSearchParams(window.location.search).get('address')
      setAddress(list.some(a => a === requested) ? requested : list[0])
    })
  }, [network])

  return <span>{address}</span>
}
`
	assert.Equal(t, []int{6, 14, 62, 79}, reportedLines(t, NewReactEffectAsyncWithoutCleanupRule(), "components/AddressPanel.tsx", source))
	assert.Empty(t, reportedLines(t, NewReactEffectAsyncWithoutCleanupRule(), "components/AddressPanel.test.tsx", source))
}

// typeof window differs between the server render and the first client
// render: the markup hydrates against a tree it does not match.
func TestReactRenderBranchesOnWindow(t *testing.T) {
	source := `export function Header({ isAuthenticated }: Props) {
  const onClick = () => {
    if (typeof window !== 'undefined') window.scrollTo(0, 0)
    remember(` + "`${path}${typeof window !== 'undefined' ? window.location.search : ''}`" + `)
  }
  return (
    <div suppressHydrationWarning>
      {typeof window !== 'undefined' && isAuthenticated && <Links />}
      {typeof window === 'undefined' ? null : <Clock />}
      <button onClick={onClick}>top</button>
    </div>
  )
}
`
	assert.Equal(t, []int{8, 9}, reportedLines(t, NewReactRenderBranchesOnWindowRule(), "components/Header.tsx", source))
}

// An updater function must be pure: React may call it twice (Strict Mode,
// a re-render) and every side effect inside runs twice.
func TestReactSetStateUpdaterSideEffect(t *testing.T) {
	source := `export function useStream(max: number) {
  const [attempt, setAttempt] = useState(0)
  const [error, setError] = useState<Error | null>(null)
  const [items, setItems] = useState<string[]>([])
  const timer = useRef<number>()

  const retry = () => {
    setAttempt((cur) => {
      if (cur < max) {
        timer.current = window.setTimeout(connect, 1000)
        return cur + 1
      }
      setError(new Error('gave up'))
      return cur
    })
    setItems((prev) => {
      const next = [...prev]
      next.sort()
      return next
    })
    setAttempt((cur) => cur + 1)
  }
  return { attempt, error, items, retry }
}
`
	assert.Equal(t, []int{8}, reportedLines(t, NewReactSetStateUpdaterSideEffectRule(), "hooks/useStream.ts", source))
}

// caches.match resolves undefined for a request that was never cached, and
// respondWith(undefined) fails the navigation with a network error.
func TestServiceWorkerRespondWithMaybeEmpty(t *testing.T) {
	source := `self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)))
})
self.addEventListener('fetch', (event) => {
  event.respondWith(caches.match(event.request).then((r) => r || fetch(event.request)))
})
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request).then((r) => r ?? offline())))
})
self.addEventListener('fetch', function (event) {
  event.respondWith(
    fetch(event.request).catch(function () {
      return caches.match(event.request)
    })
  )
})
`
	assert.Equal(t, []int{2, 13}, reportedLines(t, NewServiceWorkerRespondWithMaybeEmptyRule(), "public/sw.js", source))
}

// A reload on a timer, also inside the HTML of an offline page the worker
// serves: while the failure lasts the page reloads forever.
func TestPeriodicPageReload(t *testing.T) {
	source := "const offlinePage = `<html><body><script>\n" +
		"  function reload() { location.reload(); }\n" +
		"  window.addEventListener('online', reload);\n" +
		"  setInterval(function () {\n" +
		"    if (navigator.onLine) reload();\n" +
		"  }, 5000);\n" +
		"</script></body></html>`\n" +
		"setInterval(() => window.location.reload(), 60000)\n" +
		"setInterval(refreshPrices, 5000)\n" +
		"button.addEventListener('click', () => window.location.reload())\n"
	assert.Equal(t, []int{4, 8}, reportedLines(t, NewPeriodicPageReloadRule(), "public/sw.js", source))
}

// A fetched amount that starts at 0 is indistinguishable from a real zero:
// until the request answers the page shows "no funds".
func TestReactFetchedAmountStartsAtZero(t *testing.T) {
	source := `export default function WithdrawalPage() {
  const [availableBalance, setAvailableBalance] = useState(0)
  const [total, setTotal] = useState<number | null>(null)
  const [amount, setAmount] = useState(0)
  const [count, setCount] = useState(0)
  const [totalItems, setTotalItems] = useState(0)

  useEffect(() => {
    const load = async () => {
      const r = await api.get('/dashboard')
      setAvailableBalance(r.available)
      setTotal(r.total)
      setCount(r.count)
      setTotalItems(r.pagination.total)
    }
    load()
  }, [])

  return <Section balance={availableBalance} total={total} onChange={(v) => setAmount(v)} count={count} />
}
`
	assert.Equal(t, []int{2}, reportedLines(t, NewReactFetchedAmountStartsAtZeroRule(), "app/withdrawal/page.tsx", source))
}
