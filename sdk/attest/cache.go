package attest

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"

	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

const (
	defaultCacheTTL  = 24 * time.Hour
	defaultCacheSize = 100
)

// CollateralCache caches TEE collateral responses (Intel PCS for TDX, AMD KDS
// for SEV-SNP). The default is an in-memory LRU. Call SetCollateralCache to
// replace it with a custom implementation (e.g. disk-backed).
type CollateralCache interface {
	Get(url string) (header map[string][]string, body []byte, ok bool)
	// Set caches a response. header may be nil (e.g. AMD KDS responses).
	Set(url string, header map[string][]string, body []byte)
}

// SetCollateralCache replaces the default in-memory cache.
// Must be called before any verification; not goroutine-safe during setup.
func SetCollateralCache(c CollateralCache) {
	tdxGetter.cache = c
	sevsnpGetter.cache = c
}

// cacheEntry holds the cached HTTP response data.
type cacheEntry struct {
	header map[string][]string
	body   []byte
}

// memoryCache implements CollateralCache with an in-memory LRU.
type memoryCache struct {
	lru *lru.LRU[string, cacheEntry]
}

func (m *memoryCache) Get(url string) (map[string][]string, []byte, bool) {
	if entry, ok := m.lru.Get(url); ok {
		return entry.header, entry.body, true
	}
	return nil, nil, false
}

func (m *memoryCache) Set(url string, header map[string][]string, body []byte) {
	m.lru.Add(url, cacheEntry{header: header, body: body})
}

func newMemoryCache() *memoryCache {
	return &memoryCache{lru: lru.NewLRU[string, cacheEntry](defaultCacheSize, nil, defaultCacheTTL)}
}

// Shared getters for Intel PCS and AMD KDS requests.
var (
	tdxGetter = &tdxCachingGetter{
		cache: newMemoryCache(),
		inner: tdxtrust.DefaultHTTPSGetter(),
	}
	sevsnpGetter = &sevsnpCachingGetter{
		cache: newMemoryCache(),
		inner: sevtrust.DefaultHTTPSGetter(),
	}
)

// tdxCachingGetter implements tdxtrust.HTTPSGetter with caching.
type tdxCachingGetter struct {
	cache CollateralCache
	inner tdxtrust.HTTPSGetter
}

func (g *tdxCachingGetter) Get(url string) (map[string][]string, []byte, error) {
	if header, body, ok := g.cache.Get(url); ok {
		return header, body, nil
	}
	header, body, err := g.inner.Get(url)
	if err == nil {
		g.cache.Set(url, header, body)
	}
	return header, body, err
}

// sevsnpCachingGetter implements sevtrust.HTTPSGetter with caching.
type sevsnpCachingGetter struct {
	cache CollateralCache
	inner sevtrust.HTTPSGetter
}

func (g *sevsnpCachingGetter) Get(url string) ([]byte, error) {
	if _, body, ok := g.cache.Get(url); ok {
		return body, nil
	}
	body, err := g.inner.Get(url)
	if err == nil {
		g.cache.Set(url, nil, body)
	}
	return body, err
}
