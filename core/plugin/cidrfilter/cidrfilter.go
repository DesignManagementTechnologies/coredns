package cidrfilter

import (
	"context"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// CidrFilter plugin struct
type CidrFilter struct {
	Next         plugin.Handler
	Primary      string
	Secondary    string
	AllowedCIDRs []*net.IPNet
}

// Name returns the plugin name
func (c *CidrFilter) Name() string { return "cidrfilter" }

// ServeDNS handles DNS queries
func (c *CidrFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Query Primary
	resp, err := queryUpstream(r, c.Primary)
	if err == nil && responseAllowed(resp, c.AllowedCIDRs) {
		w.WriteMsg(resp)
		return dns.RcodeSuccess, nil
	}

	// Fallback to Secondary
	resp, err = queryUpstream(r, c.Secondary)
	if err == nil && resp != nil {
		w.WriteMsg(resp)
		return dns.RcodeSuccess, nil
	}

	// If both fail → pass to next plugin
	return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, r)
}

// queryUpstream sends a DNS request to a given server
func queryUpstream(r *dns.Msg, server string) (*dns.Msg, error) {
	c := new(dns.Client)
	req := r.Copy()
	req.RecursionDesired = true
	resp, _, err := c.Exchange(req, server)
	return resp, err
}

// responseAllowed checks if any A/AAAA answer is within allowed CIDRs
func responseAllowed(resp *dns.Msg, allowed []*net.IPNet) bool {
	if resp == nil || len(resp.Answer) == 0 {
		return false
	}
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if inAllowedCIDR(rr.A, allowed) {
				return true
			}
		case *dns.AAAA:
			if inAllowedCIDR(rr.AAAA, allowed) {
				return true
			}
		}
	}
	return false
}

// inAllowedCIDR checks if IP is in any allowed range
func inAllowedCIDR(ip net.IP, allowed []*net.IPNet) bool {
	for _, n := range allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// setup parses Corefile and registers the plugin
func setup(c *caddy.Controller) error {
	cfg := dnsserver.GetConfig(c)

	for c.Next() {
		filter := &CidrFilter{}
		for c.NextBlock() {
			switch strings.ToLower(c.Val()) {
			case "primary":
				if !c.NextArg() {
					return c.ArgErr()
				}
				filter.Primary = c.Val()
				if !strings.Contains(filter.Primary, ":") {
					filter.Primary += ":53"
				}
			case "secondary":
				if !c.NextArg() {
					return c.ArgErr()
				}
				filter.Secondary = c.Val()
				if !strings.Contains(filter.Secondary, ":") {
					filter.Secondary += ":53"
				}
			case "allowed":
				if !c.NextArg() {
					return c.ArgErr()
				}
				_, cidr, err := net.ParseCIDR(c.Val())
				if err != nil {
					return err
				}
				filter.AllowedCIDRs = append(filter.AllowedCIDRs, cidr)
			default:
				return c.Errf("unknown property '%s'", c.Val())
			}
		}

		// Register plugin in chain
		cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
			filter.Next = next
			return filter
		})
	}

	return nil
}

func init() {
	plugin.Register("cidrfilter", setup)
}

