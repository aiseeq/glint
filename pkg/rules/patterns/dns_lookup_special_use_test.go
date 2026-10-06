package patterns

import "testing"

// A signup check asks DNS for the MX of the domain of a user's e-mail and
// caches only the answers: a .local domain goes to mDNS and waits out the
// whole timeout, the failure is not cached, and every request pays it again.
// Filtering the special-use zones before the lookup, or caching the failure
// too, ends it.
func TestDNSLookupOfSpecialUseDomain(t *testing.T) {
	assertWanted(t, NewDNSLookupOfSpecialUseDomainRule(), `package signup

import (
	"context"
	"net"
	"strings"
	"time"
)

type resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

type Checker struct {
	resolver resolver
	timeout  time.Duration
	cache    map[string]bool
}

func domainOf(email string) string {
	_, domain, _ := strings.Cut(email, "@")
	return strings.ToLower(domain)
}

func (c *Checker) Check(ctx context.Context, email string) bool {
	domain := domainOf(email)
	if verdict, ok := c.cache[domain]; ok {
		return verdict
	}
	lookupCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	records, err := c.resolver.LookupMX(lookupCtx, domain) // want
	if err != nil {
		return false
	}
	verdict := len(records) > 0
	c.remember(domain, verdict)
	return verdict
}

func (c *Checker) remember(domain string, verdict bool) { c.cache[domain] = verdict }

func (c *Checker) CheckFiltered(ctx context.Context, email string) bool {
	domain := domainOf(email)
	if isSpecialUse(domain) {
		return false
	}
	records, err := c.resolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}
	c.cache[domain] = len(records) > 0
	return len(records) > 0
}

func (c *Checker) CheckCachingFailure(ctx context.Context, email string) bool {
	domain := domainOf(email)
	records, err := c.resolver.LookupMX(ctx, domain)
	if err != nil {
		c.cache[domain] = false
		return false
	}
	c.cache[domain] = len(records) > 0
	return len(records) > 0
}

func Resolve(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func isSpecialUse(domain string) bool {
	for _, zone := range []string{"local", "test", "invalid", "localhost"} {
		if domain == zone || strings.HasSuffix(domain, "."+zone) {
			return true
		}
	}
	return false
}
`)
}
