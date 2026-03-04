package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
)

const diskCacheTTL = 24 * time.Hour

type diskEntry struct {
	FetchedAt time.Time           `json:"fetched_at"`
	Header    map[string][]string `json:"header,omitempty"`
	Body      []byte              `json:"body"`
}

func newDiskCache(dir string) attest.CollateralCache {
	return &diskCache{dir: dir}
}

type diskCache struct{ dir string }

func (c *diskCache) path(url string) string {
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
	return filepath.Join(c.dir, key+".json")
}

func (c *diskCache) Get(url string) (map[string][]string, []byte, bool) {
	path := c.path(url)

	// Check mtime before reading to skip expired entries without I/O + unmarshal.
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > diskCacheTTL {
		return nil, nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false
	}
	var entry diskEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, nil, false
	}
	return entry.Header, entry.Body, true
}

func (c *diskCache) Set(url string, header map[string][]string, body []byte) {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return
	}
	path := c.path(url)
	data, err := json.Marshal(diskEntry{FetchedAt: time.Now(), Header: header, Body: body})
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
