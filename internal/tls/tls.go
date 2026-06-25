package tls

import (
	"crypto/tls"
	"fmt"
	"time"
)

// Result holds TLS certificate data.
type Result struct {
	Issuer  string
	Expires string
	SANs    []string
}

// Lookup connects to domain:443 and extracts certificate info.
func Lookup(domain string) (Result, error) {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		return Result{}, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	issuer := "unknown"
	if len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}

	return Result{
		Issuer:  issuer,
		Expires: cert.NotAfter.Format(time.DateOnly),
		SANs:    cert.DNSNames,
	}, nil
}
