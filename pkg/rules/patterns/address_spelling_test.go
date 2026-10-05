package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// addressKeySource is a module's canonical address key: the one place that
// knows which address forms fold case.
const addressKeySource = `package keys

import "strings"

// AddressKey is the key form of an address: hex folds case, others keep it.
func AddressKey(address string) string {
	trimmed := strings.TrimSpace(address)
	if strings.HasPrefix(strings.ToLower(trimmed), "0x") {
		return strings.ToLower(trimmed)
	}
	return trimmed
}
`

// Two addresses compared as spelled, in a module that compares addresses
// through its own canonical form elsewhere.
func TestAddressComparedAsSpelled(t *testing.T) {
	assert.Equal(t, []string{"ledger/ledger.go:18", "ledger/ledger.go:28"}, projectRuleLines(t, NewAddressComparedAsSpelledRule(), map[string]string{
		"keys/keys.go": addressKeySource,
		"ledger/ledger.go": `package ledger

import (
	"fmt"
	"strings"

	"example.com/rulestest/keys"
)

type Change struct {
	OwnerAddress string
	Amount       string
}

func own(changes []Change, walletAddress string) []Change {
	var out []Change
	for _, c := range changes {
		if c.OwnerAddress != walletAddress {
			continue
		}
		out = append(out, c)
	}
	return out
}

func direction(fromAddress *string, walletAddress string) string {
	sender := strings.TrimSpace(*fromAddress)
	if fromAddress != nil && sender == walletAddress {
		return "out"
	}
	return "in"
}

func sameWallet(left, right string) bool {
	return keys.AddressKey(left) == keys.AddressKey(right)
}

func canonicalCompare(fromAddress, walletAddress string) bool {
	from := keys.AddressKey(fromAddress)
	walletAddress = keys.AddressKey(walletAddress)
	return from == walletAddress
}

func empty(walletAddress string) bool {
	return walletAddress == "" || walletAddress == zeroAddress
}

const zeroAddress = "0x0"

func byWallet(rows []Change) func(i, j int) bool {
	return func(i, j int) bool {
		if rows[i].OwnerAddress != rows[j].OwnerAddress {
			return rows[i].OwnerAddress < rows[j].OwnerAddress
		}
		return rows[i].Amount < rows[j].Amount
	}
}

func check(stored Change, walletAddress string) error {
	if stored.OwnerAddress != walletAddress {
		return fmt.Errorf("row of %s is not %s", stored.OwnerAddress, walletAddress)
	}
	return nil
}

func walletKey(address string) string { return keys.AddressKey(address) }

type pair struct{ wallet, chain string }

func renames(changes []Change) []string {
	firsts := map[pair]Change{}
	for _, c := range changes {
		k := pair{wallet: walletKey(c.OwnerAddress), chain: "x"}
		firsts[k] = c
	}
	var out []string
	for k, c := range firsts {
		if c.OwnerAddress == k.wallet {
			continue
		}
		out = append(out, k.wallet)
	}
	return out
}

type Fee struct{ WalletCurrency string }

func feeMatches(fee Fee, walletCurrency string) bool {
	return fee.WalletCurrency == walletCurrency
}

func known(address string, contractAddresses []string) bool {
	lower := strings.ToLower(address)
	for _, contractAddr := range contractAddresses {
		if lower == contractAddr {
			return true
		}
	}
	return false
}
`,
	}))
}

// A module with no canonical address form compares addresses as it stores
// them: nothing to check against.
func TestAddressComparedAsSpelledNeedsCanonicalForm(t *testing.T) {
	assert.Empty(t, projectRuleLines(t, NewAddressComparedAsSpelledRule(), map[string]string{
		"ledger/ledger.go": `package ledger

func own(ownerAddress, walletAddress string) bool {
	return ownerAddress == walletAddress
}
`,
	}))
}

// Lower-casing an address by hand where the module has a canonical address
// key: the hand-made key misses the forms the canonical one knows.
func TestAddressFoldedPastCanonicalKey(t *testing.T) {
	assert.Equal(t, []string{"sync/sync.go:12", "sync/sync.go:18", "sync/sync.go:29", "sync/sync.go:63", "sync/sync.go:79"}, projectRuleLines(t, NewAddressFoldedPastCanonicalKeyRule(), map[string]string{
		"keys/keys.go": addressKeySource,
		"sync/sync.go": `package sync

import (
	"net/mail"
	"strings"
)

type Holding struct{ Contract string }

func coverageKey(walletAddress, chain string) string {
	walletAddress = strings.TrimSpace(walletAddress)
	return strings.ToLower(walletAddress) + "\x00" + chain
}

func merge(wallets []string) map[string]bool {
	seen := make(map[string]bool)
	for _, w := range wallets {
		key := strings.ToLower(w)
		seen[key] = true
	}
	return seen
}

func isHex(walletAddress string) bool {
	return strings.HasPrefix(strings.ToLower(walletAddress), "0x")
}

func sourceID(h Holding) string {
	return "trc20:" + strings.ToLower(h.Contract)
}

func label(name string) string {
	return strings.ToLower(name)
}

func lowerCase(address string) bool {
	return address == strings.ToLower(address)
}

func priceID(prefix, address string) string {
	if strings.HasPrefix(address, "0x") {
		address = strings.ToLower(address)
	}
	return prefix + ":" + address
}

func zeroHex(address string) bool {
	return strings.TrimPrefix(strings.ToLower(address), "0x") == ""
}

func email(raw string) string {
	parsed, err := mail.ParseAddress(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Address)
}

func mergeLists(envWallets, dbWallets []string) map[string]bool {
	seen := map[string]bool{}
	for _, list := range [][]string{envWallets, dbWallets} {
		for _, w := range list {
			seen[strings.ToLower(w)] = true
		}
	}
	return seen
}

func byChain(evmWallets, otherWallets []string) int {
	n := 0
	for _, list := range map[string][]string{"evm": evmWallets, "other": otherWallets} {
		n += len(list)
	}
	return n
}

func hexKey(walletAddress string) string {
	if len(walletAddress) == 42 {
		walletAddress = strings.ToLower(walletAddress)
	}
	return walletAddress
}
`,
	}))
}

// Without a canonical address key, lower-casing is the module's own form. A
// parser of one chain's addresses that fails on the others is not a key of
// every address.
func TestAddressFoldedPastCanonicalKeyNeedsKey(t *testing.T) {
	assert.Empty(t, projectRuleLines(t, NewAddressFoldedPastCanonicalKeyRule(), map[string]string{
		"chainx/address.go": `package chainx

import (
	"fmt"
	"strings"
)

// NormalizeAddress brings both spellings of a chainx address to the raw one.
func NormalizeAddress(address string) (string, error) {
	if !strings.Contains(address, ":") {
		return "", fmt.Errorf("not a chainx address: %q", address)
	}
	return strings.ToLower(address), nil
}
`,
		"sync/sync.go": `package sync

import "strings"

func coverageKey(walletAddress string) string {
	return strings.ToLower(walletAddress)
}
`,
	}))
}

// An entry point that takes addresses as the caller spelled them and writes
// with them, while a sibling entry point of the same service first brings its
// address to the canonical spelling.
func TestAddressEntrySkipsCanonicalSpelling(t *testing.T) {
	assert.Equal(t, []string{"svc/svc.go:31", "svc/svc.go:40"}, projectRuleLines(t, NewAddressEntrySkipsCanonicalSpellingRule(), map[string]string{
		"svc/svc.go": `package svc

import (
	"context"
	"strings"
)

type Row struct{ Wallet string }

type Repo struct{}

func (Repo) CreateBatch(ctx context.Context, rows []Row) error { return nil }
func (Repo) StoredSpelling(ctx context.Context, wallet string) string { return wallet }
func (Repo) GetRows(ctx context.Context, wallet string) []Row { return nil }

type Service struct{ repo Repo }

func (s *Service) canonicalWalletSpelling(ctx context.Context, walletAddress string) string {
	return s.repo.StoredSpelling(ctx, strings.TrimSpace(walletAddress))
}

func (s *Service) SyncWallet(ctx context.Context, walletAddress string) error {
	walletAddress = s.canonicalWalletSpelling(ctx, walletAddress)
	return s.repo.CreateBatch(ctx, []Row{{Wallet: walletAddress}})
}

func (s *Service) BackfillGas(ctx context.Context, wallets []string) error {
	if len(wallets) == 0 {
		return nil
	}
	for _, wallet := range wallets {
		if err := s.repo.CreateBatch(ctx, []Row{{Wallet: wallet}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Reimport(ctx context.Context, walletAddress string) error {
	return s.repo.CreateBatch(ctx, []Row{{Wallet: walletAddress}})
}

func (s *Service) History(ctx context.Context, walletAddress string) []Row {
	return s.repo.GetRows(ctx, walletAddress)
}

func (s *Service) Resync(ctx context.Context, walletAddress string) error {
	return s.SyncWallet(ctx, walletAddress)
}
`,
	}))
}

// A fold in a function whose query folds the column the same way mirrors
// the database: the argument for LOWER(address) IN (...) and the key of the
// rows it selects must be spelled as the database spells them.
func TestAddressFoldedPastCanonicalKeyMirrorsSQLFold(t *testing.T) {
	assert.Equal(t, []string{"repo/repo.go:14"}, projectRuleLines(t, NewAddressFoldedPastCanonicalKeyRule(), map[string]string{
		"keys/keys.go": addressKeySource,
		"repo/repo.go": `package repo

import "strings"

func labels(addresses []string, query func(string, []string) map[string]string) map[string]string {
	lower := make([]string, len(addresses))
	for i, address := range addresses {
		lower[i] = strings.ToLower(address)
	}
	return query("SELECT address, label FROM aliases WHERE LOWER(address) = ANY($1)", lower)
}

func cacheKey(walletAddress string) string {
	return strings.ToLower(walletAddress)
}
`,
	}))
}
