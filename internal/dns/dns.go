package dns

import (
	"context"
	"net"
)

// Result holds all DNS records for a domain.
type Result struct {
	A   []string `json:"a"`
	MX  []string `json:"mx"`
	TXT []string `json:"txt"`
	NS  []string `json:"ns"`
}

// Lookup queries all DNS record types for the given domain.
func Lookup(domain string) (Result, error) {
	var r Result
	resolver := net.DefaultResolver

	// A records
	addrs, err := resolver.LookupHost(context.Background(), domain)
	if err == nil {
		r.A = addrs
	}

	// MX records
	mxs, err := resolver.LookupMX(context.Background(), domain)
	if err == nil {
		for _, mx := range mxs {
			r.MX = append(r.MX, mx.Host)
		}
	}

	// TXT records
	txts, err := resolver.LookupTXT(context.Background(), domain)
	if err == nil {
		r.TXT = txts
	}

	// NS records
	nss, err := resolver.LookupNS(context.Background(), domain)
	if err == nil {
		for _, ns := range nss {
			r.NS = append(r.NS, ns.Host)
		}
	}

	return r, nil
}
