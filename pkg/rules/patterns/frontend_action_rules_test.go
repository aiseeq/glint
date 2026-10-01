package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A hook kept for compatibility hands out async actions that only log: the
// page awaits them, sees no error and tells the user the transfer went out.
// An empty async placeholder (a context value before hydration) is a common
// default and is not reported.
func TestFrontendActionOnlyLogs(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/hooks/useTransfers.ts", `export function useTransfers() {
  return {
    transfers: [],
    setAmount: () => {},
    handleTransfer: async () => {
      console.warn('Transfers are being updated')
    },
    loadTransfers: async () => {},
    copyToClipboard: async (text: string) => {
      await navigator.clipboard.writeText(text)
    },
    async refresh() {
      console.log('refresh is disabled')
    },
  }
}

export async function submitOrder(id: string) {
  // TODO
}

export async function ping(): Promise<void> {
  await fetch('/ping')
}
`)
	assert.Equal(t, []string{"src/hooks/useTransfers.ts:12", "src/hooks/useTransfers.ts:5"},
		foundLines(NewFrontendActionOnlyLogsRule().AnalyzeFile(ctx)))

	test := rulestest.TextFile(t, "src/hooks/useTransfers.test.ts", `const stub = { load: async () => {} }
`)
	assert.Empty(t, NewFrontendActionOnlyLogsRule().AnalyzeFile(test))
}

// A guard against concurrent calls that answers the second caller with a
// made-up result: the caller acts on "no MFA needed" while the real request
// is still running.
func TestFrontendInflightGuardFabricatesResult(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/auth/context.tsx", `export function useAuthLevel(client: Client) {
  const listInProgress = useRef(false)
  const loading = useRef(false)

  const level = async (current: string) => {
    if (listInProgress.current) {
      console.warn('already in progress')
      return { needsMfa: false, factors: [], level: current }
    }
    listInProgress.current = true
    try {
      return await client.listFactors()
    } finally {
      listInProgress.current = false
    }
  }

  const refresh = async () => {
    if (loading.current) {
      return
    }
    loading.current = true
    await client.refresh()
    loading.current = false
  }

  let pending = false
  async function save(): Promise<boolean> {
    if (pending) return true
    pending = true
    await client.save()
    pending = false
    return true
  }

  const isLoading = false
  const view = () => {
    if (isLoading) {
      return { rows: [] }
    }
    return { rows: client.rows }
  }
  return { level, refresh, save, view }
}
`)
	assert.Equal(t, []string{"src/auth/context.tsx:29", "src/auth/context.tsx:6"},
		foundLines(NewFrontendInflightGuardFabricatesResultRule().AnalyzeFile(ctx)))
}

// A check that runs only when a dependency is there: without it the code
// warns and goes on as if the check had passed.
func TestFrontendCheckSkippedWhenMissing(t *testing.T) {
	ctx := rulestest.TextFile(t, "static/faucet/script.js", `class Faucet {
  async canSend() {
    const provider = this.activeProvider();
    if (provider) {
      if (!await this.checkNetwork()) {
        return false;
      }
    } else {
      console.warn('Provider unavailable, proceeding');
      this.showToast('Wallet conflicts detected', 'warning');
    }
    return true;
  }

  async canStake() {
    const provider = this.activeProvider();
    if (provider) {
      if (!await this.checkNetwork()) {
        return false;
      }
    } else {
      this.showToast('Connect a wallet', 'error');
      return false;
    }
    return true;
  }

  render(user) {
    if (user) {
      this.greet(user);
    } else {
      console.log('anonymous');
    }
  }
}
`)
	assert.Equal(t, []string{"static/faucet/script.js:8"},
		foundLines(NewFrontendCheckSkippedWhenMissingRule().AnalyzeFile(ctx)))
}
