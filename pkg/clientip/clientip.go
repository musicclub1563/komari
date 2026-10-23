// Package clientip resolves the client address of an HTTP request with a
// single trusted-proxy policy.
//
// gin's Context.ClientIP already implements that policy for the router, but the
// plugin HTTP hooks run before gin's middleware and only have an
// *http.Request. A second hand-written copy of the algorithm in the hook layer
// is what allowed the two layers to disagree: the hook copy skipped
// unparsable X-Forwarded-For entries and kept walking left, so a caller could
// get a left-hand entry it chose itself accepted as the client address.
//
// This package mirrors gin's rules exactly:
//
//   - The connection peer is the client unless it is a configured proxy.
//   - Forwarded headers are only read when the peer is a trusted proxy.
//   - Headers are scanned right to left, skipping trusted proxies; the first
//     valid untrusted address wins and the scan stops there.
//   - An unparsable entry invalidates the whole header instead of being
//     skipped, so the resolver falls back to the next header and finally to the
//     connection peer. It never accepts a value further left than the point
//     where parsing failed.
//
// The equivalence with gin is covered by TestRemoteIPMatchesGinClientIP.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// remoteIPHeaders are consulted in order, matching gin's default
// RemoteIPHeaders.
var remoteIPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}

// Resolver is an immutable trusted-proxy list. The zero value (and a nil
// *Resolver) trusts nothing, which is the safe default: forwarded headers are
// ignored and the connection peer is always reported.
type Resolver struct {
	nets    []*net.IPNet
	entries []string
}

// New builds a resolver from IP or CIDR entries. Every entry is validated; an
// invalid entry is an error so the caller can fail closed instead of silently
// dropping part of the list.
func New(entries []string) (*Resolver, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		network, err := parseEntry(entry)
		if err != nil {
			return nil, err
		}
		nets = append(nets, network)
		normalized = append(normalized, network.String())
	}
	return &Resolver{nets: nets, entries: normalized}, nil
}

func parseEntry(entry string) (*net.IPNet, error) {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: expected an IP address or CIDR", entry)
		}
		return network, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("invalid trusted proxy %q: expected an IP address or CIDR", entry)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// Entries returns the validated list in CIDR form ("10.0.0.0/8",
// "192.0.2.7/32"), suitable for gin's Engine.SetTrustedProxies.
func (r *Resolver) Entries() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.entries...)
}

// Trusted reports whether ip belongs to a configured proxy.
func (r *Resolver) Trusted(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}
	for _, network := range r.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve returns the client address for a request. The result is the canonical
// textual form of the address; gin returns the header text verbatim, but the
// addresses compared by the equivalence test are identical.
//
// An empty string means the connection address could not be parsed, matching
// gin's Context.ClientIP.
func (r *Resolver) Resolve(remoteAddr string, header http.Header) string {
	peer := PeerAddress(remoteAddr)
	if peer == nil {
		return ""
	}
	if !r.Trusted(peer) {
		return peer.String()
	}
	for _, name := range remoteIPHeaders {
		if client, ok := r.fromHeader(header.Get(name)); ok {
			return client
		}
	}
	return peer.String()
}

// PeerAddress extracts the connection address from a RemoteAddr value. Like
// gin's Context.RemoteIP it requires a host:port pair and returns nil otherwise.
func PeerAddress(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// fromHeader scans one forwarded header from right to left. It returns ok=false
// when the header is empty or contains an entry that does not parse; in that
// case the caller must not use any value from this header.
func (r *Resolver) fromHeader(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	items := strings.Split(value, ",")
	for index := len(items) - 1; index >= 0; index-- {
		ip := net.ParseIP(strings.TrimSpace(items[index]))
		if ip == nil {
			// Malformed chain: stop here instead of skipping the entry and
			// continuing to values further to the left, which the client can
			// control.
			return "", false
		}
		// A trusted proxy at the right edge forwards for the address to its
		// left; the leftmost entry is the far end of the chain.
		if index == 0 || !r.Trusted(ip) {
			return ip.String(), true
		}
	}
	return "", false
}
