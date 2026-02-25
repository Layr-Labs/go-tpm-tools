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

// cacheEntry holds the cached HTTP response data.
type cacheEntry struct {
	header map[string][]string
	body   []byte
}

// Shared cache and getters for Intel PCS and AMD KDS requests.
var (
	collateralCache = lru.NewLRU[string, cacheEntry](defaultCacheSize, nil, defaultCacheTTL)
	tdxGetter       = &tdxCachingGetter{cache: collateralCache, inner: tdxtrust.DefaultHTTPSGetter()}
	sevsnpGetter    = &sevsnpCachingGetter{cache: collateralCache, inner: sevtrust.DefaultHTTPSGetter()}
)

// tdxCachingGetter implements tdxtrust.HTTPSGetter with caching.
type tdxCachingGetter struct {
	cache *lru.LRU[string, cacheEntry]
	inner tdxtrust.HTTPSGetter
}

func (g *tdxCachingGetter) Get(url string) (map[string][]string, []byte, error) {
	if entry, ok := g.cache.Get(url); ok {
		return entry.header, entry.body, nil
	}
	header, body, err := g.inner.Get(url)
	if err == nil {
		g.cache.Add(url, cacheEntry{header: header, body: body})
	}
	return header, body, err
}

// sevsnpCachingGetter implements sevtrust.HTTPSGetter with caching.
type sevsnpCachingGetter struct {
	cache *lru.LRU[string, cacheEntry]
	inner sevtrust.HTTPSGetter
}

func (g *sevsnpCachingGetter) Get(url string) ([]byte, error) {
	if entry, ok := g.cache.Get(url); ok {
		return entry.body, nil
	}
	body, err := g.inner.Get(url)
	if err == nil {
		g.cache.Add(url, cacheEntry{body: body})
	}
	return body, err
}
