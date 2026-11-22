package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/spf13/cobra"

	"github.com/aiseeq/glint/internal/cachekey"
	"github.com/aiseeq/glint/pkg/rules"
)

// buildManifest is the result cache key the graft build appended to this
// binary (cmd/glintbuild, internal/depgraph): the driver's hash, which names
// the cache files, and each rule's hash by the call that registered it.
// Ordinary go builds carry none.
type buildManifest struct {
	driver string
	all    string
	// rules maps a rule name to the hash of its own code.
	rules    map[string]string
	manifest *cachekey.Manifest
	trusted  bool
	err      error
}

var (
	manifestOnce   sync.Once
	loadedManifest buildManifest
	// readManifest reads the cache key of the running binary; tests replace it.
	readManifest = func() (*cachekey.Manifest, error) {
		path, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate the glint binary: %w", err)
		}
		return cachekey.Read(path)
	}
)

func cacheKeyManifest() buildManifest {
	manifestOnce.Do(func() { loadedManifest = loadManifest() })
	return loadedManifest
}

func loadManifest() buildManifest {
	manifest, err := readManifest()
	if err != nil {
		if errors.Is(err, cachekey.ErrNone) {
			err = nil
		}
		return buildManifest{rules: map[string]string{}, err: err}
	}
	loaded := buildManifest{driver: manifest.Driver, all: manifest.All, rules: make(map[string]string), manifest: manifest, trusted: true}
	for _, rule := range rules.All() {
		if site := manifestSite(manifest, rule.Name()); site != nil {
			loaded.rules[rule.Name()] = site.Hash
		}
	}
	return loaded
}

// manifestSite returns the registration site of the rule of name.
func manifestSite(manifest *cachekey.Manifest, name string) *cachekey.Site {
	registered, ok := rules.RegistrationSiteOf(name)
	if !ok {
		return nil
	}
	return manifest.SiteAt(registered.File, registered.Line)
}

// runCacheDeps prints the functions whose source each cache key covers:
// "driver" changes every key, a rule's list only its own. A function is
// "<import path>/<file>:<line of func>", as go tool covdata func names it. A
// rule the build found no registration for is keyed by the whole build.
func runCacheDeps(cmd *cobra.Command, _ []string) error {
	loaded := cacheKeyManifest()
	if loaded.err != nil {
		return loaded.err
	}
	if !loaded.trusted {
		return errors.New("this glint carries no cache key: build it with go run ./cmd/glintbuild")
	}
	manifest := loaded.manifest
	out := struct {
		Driver []string            `json:"driver"`
		Rules  map[string][]string `json:"rules"`
	}{Driver: manifest.Names(manifest.DriverFuncs), Rules: make(map[string][]string)}
	all := slices.Sorted(slices.Values(manifest.Funcs))
	for _, rule := range rules.All() {
		if site := manifestSite(manifest, rule.Name()); site != nil {
			out.Rules[rule.Name()] = manifest.Names(site.Funcs)
		} else {
			out.Rules[rule.Name()] = all
		}
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", " ")
	return encoder.Encode(out)
}
