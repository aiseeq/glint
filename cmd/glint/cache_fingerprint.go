package main

import (
	"encoding/base64"
	"encoding/json"
)

// cacheBuildManifest is set only by the graft build task after it has captured
// Go's package BuildIDs. Ordinary go builds leave it empty.
var cacheBuildManifest string

type buildManifest struct {
	core     string
	packages map[string]string
	trusted  bool
}

func cacheKeyManifest() buildManifest {
	manifest := buildManifest{packages: make(map[string]string)}
	if cacheBuildManifest == "" {
		return manifest
	}
	data, err := base64.StdEncoding.DecodeString(cacheBuildManifest)
	if err == nil {
		var raw struct {
			Core     string            `json:"core"`
			Packages map[string]string `json:"packages"`
		}
		if json.Unmarshal(data, &raw) == nil && raw.Core != "" && len(raw.Packages) > 0 {
			manifest.core, manifest.packages, manifest.trusted = raw.Core, raw.Packages, true
		}
	}
	return manifest
}
