package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pfei/pivoteer/internal/asn"
	"github.com/pfei/pivoteer/internal/certs"
	"github.com/pfei/pivoteer/internal/dns"
	"github.com/pfei/pivoteer/internal/tls"
	"github.com/pfei/pivoteer/internal/whois"
)

// Report aggregates all reconnaissance results for a domain.
type Report struct {
	Domain     string       `json:"domain"`
	DNS        dns.Result   `json:"dns"`
	WHOIS      whois.Result `json:"whois"`
	TLS        tls.Result   `json:"tls"`
	Subdomains []string     `json:"subdomains"`
	ASN        asn.Result   `json:"asn"`
}

func printReport(domain string, d dns.Result, w whois.Result, t tls.Result, subs []string, a asn.Result) {
	fmt.Printf("Target: %s\n", domain)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Println("\n[WHOIS]")
	fmt.Printf("  Registrar   : %s\n", w.Registrar)
	fmt.Printf("  Created     : %s\n", w.Created)
	fmt.Printf("  Expires     : %s\n", w.Expires)
	fmt.Printf("  Name servers: %s\n", strings.Join(w.NameServers, ", "))

	fmt.Println("\n[DNS]")
	fmt.Printf("  A   : %s\n", strings.Join(d.A, ", "))
	fmt.Printf("  MX  : %s\n", strings.Join(d.MX, ", "))
	fmt.Printf("  NS  : %s\n", strings.Join(d.NS, ", "))
	fmt.Printf("  TXT : %s\n", strings.Join(d.TXT, ", "))

	fmt.Println("\n[TLS]")
	fmt.Printf("  Issuer  : %s\n", t.Issuer)
	fmt.Printf("  Expires : %s\n", t.Expires)
	fmt.Printf("  SANs    : %s\n", strings.Join(t.SANs, ", "))

	fmt.Println("\n[SUBDOMAINS] (via hackertarget)")
	for _, sub := range subs {
		fmt.Printf("  %s\n", sub)
	}

	fmt.Println("\n[ASN]")
	fmt.Printf("  IP      : %s\n", a.IP)
	fmt.Printf("  Org     : %s\n", a.Org)
	fmt.Printf("  Country : %s\n", a.Country)
	fmt.Printf("  City    : %s\n", a.City)
}

func main() {
	domain := flag.String("d", "", "target domain (e.g. lemonde.fr)")
	jsonOut := flag.Bool("json", false, "output results as JSON")
	outFile := flag.String("o", "", "write JSON output to file")
	bruteForce := flag.Bool("bruteforce", false, "enable DNS bruteforce subdomain discovery")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: pivoteer -d <domain>")
		os.Exit(1)
	}

	dnsResult, err := dns.Lookup(*domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns error: %v\n", err)
		os.Exit(1)
	}

	// run WHOIS, CERTS, ASN, TLS concurrently
	type whoisOut struct {
		res whois.Result
		err error
	}
	type certsOut struct {
		res []string
		err error
	}
	type asnOut struct {
		res asn.Result
		err error
	}
	type tlsOut struct {
		res tls.Result
		err error
	}

	whoisCh := make(chan whoisOut, 1)
	certsCh := make(chan certsOut, 1)
	asnCh := make(chan asnOut, 1)
	tlsCh := make(chan tlsOut, 1)

	go func() {
		res, err := whois.Lookup(*domain)
		whoisCh <- whoisOut{res, err}
	}()

	go func() {
		res, err := certs.Lookup(*domain, *bruteForce)
		certsCh <- certsOut{res, err}
	}()

	go func() {
		if len(dnsResult.A) == 0 {
			asnCh <- asnOut{}
			return
		}
		res, err := asn.Lookup(dnsResult.A[0])
		asnCh <- asnOut{res, err}
	}()

	go func() {
		res, err := tls.Lookup(*domain)
		tlsCh <- tlsOut{res, err}
	}()

	// collect results
	whoisResult := <-whoisCh
	certsResult := <-certsCh
	asnResult := <-asnCh
	tlsResult := <-tlsCh

	if *jsonOut || *outFile != "" {
		report := Report{
			Domain:     *domain,
			DNS:        dnsResult,
			WHOIS:      whoisResult.res,
			TLS:        tlsResult.res,
			Subdomains: certsResult.res,
			ASN:        asnResult.res,
		}

		if *outFile != "" {
			f, err := os.Create(*outFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot create file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(report)
			fmt.Fprintf(os.Stderr, "output written to %s\n", *outFile)
		} else {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(report)
		}
	} else {
		printReport(*domain, dnsResult, whoisResult.res, tlsResult.res, certsResult.res, asnResult.res)
	}
}
