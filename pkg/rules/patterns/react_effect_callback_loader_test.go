package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The effect only calls a loader the component keeps in useCallback: the
// await and the setter live in the loader, and a slow answer for the old
// selection still lands after the new one.
func TestReactEffectAsyncWithoutCleanupCallbackLoader(t *testing.T) {
	source := `export default function Investments() {
  const [items, setItems] = useState([])
  const [notes, setNotes] = useState({})
  const [rates, setRates] = useState([])
  const loadData = useCallback(async () => {
    const res = await api.getItems(selectedId)
    setItems(res.items)
  }, [selectedId])
  useEffect(() => {
    loadData()
  }, [loadData])
  const loadNotes = useCallback(async (loaded) => {
    const res = await api.getNotes(loaded.map(x => x.id))
    setNotes(res)
  }, [])
  useEffect(() => {
    void loadNotes(items)
  }, [items, loadNotes])
  const requestRef = useRef(0)
  const loadRates = useCallback(async () => {
    const id = ++requestRef.current
    const res = await api.getRates(currency)
    if (id !== requestRef.current) return
    setRates(res)
  }, [currency])
  useEffect(() => {
    loadRates()
  }, [loadRates])
  const loadChains = useCallback(async () => {
    const res = await api.getChains()
    setRates(res)
  }, [])
  useEffect(() => { loadChains() }, [loadChains])
  const reload = useCallback(async () => {
    const res = await api.getSettings()
    setRates(res)
  }, [])
  useEffect(() => {
    if (enabled) void reload()
  }, [enabled, reload])
  const loadWallets = useCallback(async () => {
    const target = portfolioId
    const res = await api.getWallets(target)
    if (selectedRef.current !== target) return
    setRates(res)
  }, [portfolioId])
  useEffect(() => { void loadWallets() }, [loadWallets])
  return null
}
`
	assert.Equal(t, []int{9, 16}, reportedLines(t, NewReactEffectAsyncWithoutCleanupRule(), "app/investments/page.tsx", source))
}
