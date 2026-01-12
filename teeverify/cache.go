package teeverify

import (
	"sync"
	"time"

	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

const defaultCacheTTL = 1 * time.Hour

// httpCache provides TTL-based caching for HTTP responses.
type httpCache struct {
	entries sync.Map
	ttl     time.Duration
}

type cacheEntry struct {
	header map[string][]string
	body   []byte
	expiry time.Time
}

func (c *httpCache) get(url string) (map[string][]string, []byte, bool) {
	if v, ok := c.entries.Load(url); ok {
		e := v.(cacheEntry)
		if time.Now().Before(e.expiry) {
			return e.header, e.body, true
		}
		c.entries.Delete(url)
	}
	return nil, nil, false
}

func (c *httpCache) set(url string, header map[string][]string, body []byte) {
	c.entries.Store(url, cacheEntry{header, body, time.Now().Add(c.ttl)})
}

// Shared cache and getters for Intel PCS and AMD KDS requests.
var (
	collateralCache = &httpCache{ttl: defaultCacheTTL}
	tdxGetter       = &tdxCachingGetter{cache: collateralCache, inner: tdxtrust.DefaultHTTPSGetter()}
	sevsnpGetter    = &sevsnpCachingGetter{cache: collateralCache, inner: sevtrust.DefaultHTTPSGetter()}
)

// tdxCachingGetter implements tdxtrust.HTTPSGetter with caching.
type tdxCachingGetter struct {
	cache *httpCache
	inner tdxtrust.HTTPSGetter
}

func (g *tdxCachingGetter) Get(url string) (map[string][]string, []byte, error) {
	if header, body, ok := g.cache.get(url); ok {
		return header, body, nil
	}
	header, body, err := g.inner.Get(url)
	if err == nil {
		g.cache.set(url, header, body)
	}
	return header, body, err
}

// sevsnpCachingGetter implements sevtrust.HTTPSGetter with caching.
type sevsnpCachingGetter struct {
	cache *httpCache
	inner sevtrust.HTTPSGetter
}

func (g *sevsnpCachingGetter) Get(url string) ([]byte, error) {
	if _, body, ok := g.cache.get(url); ok {
		return body, nil
	}
	body, err := g.inner.Get(url)
	if err == nil {
		g.cache.set(url, nil, body)
	}
	return body, err
}
