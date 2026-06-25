package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pfei/pivoteer/internal/asn"
	"github.com/pfei/pivoteer/internal/certs"
	"github.com/pfei/pivoteer/internal/dns"
	"github.com/pfei/pivoteer/internal/whois"
)

func main() {
	domain := flag.String("d", "", "target domain (e.g. lemonde.fr)")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: pivoteer -d <domain>")
		os.Exit(1)
	}

	fmt.Printf("Target: %s\n", *domain)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	dnsResult, err := dns.Lookup(*domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n[DNS]")
	fmt.Printf("  A   : %v\n", dnsResult.A)
	fmt.Printf("  MX  : %v\n", dnsResult.MX)
	fmt.Printf("  TXT : %v\n", dnsResult.TXT)
	fmt.Printf("  NS  : %v\n", dnsResult.NS)

	// run WHOIS, CERTS, ASN concurrently
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

	whoisCh := make(chan whoisOut, 1)
	certsCh := make(chan certsOut, 1)
	asnCh := make(chan asnOut, 1)

	go func() {
		res, err := whois.Lookup(*domain)
		whoisCh <- whoisOut{res, err}
	}()

	go func() {
		res, err := certs.Lookup(*domain)
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

	// collect results
	whoisResult := <-whoisCh
	certsResult := <-certsCh
	asnResult := <-asnCh

	fmt.Println("\n[WHOIS]")
	if whoisResult.err != nil {
		fmt.Fprintf(os.Stderr, "whois error: %v\n", whoisResult.err)
	} else {
		fmt.Printf("  Registrar   : %s\n", whoisResult.res.Registrar)
		fmt.Printf("  Created     : %s\n", whoisResult.res.Created)
		fmt.Printf("  Expires     : %s\n", whoisResult.res.Expires)
		fmt.Printf("  Name servers: %s\n", strings.Join(whoisResult.res.NameServers, ", "))
	}

	fmt.Println("\n[SUBDOMAINS] (via hackertarget)")
	if certsResult.err != nil {
		fmt.Fprintf(os.Stderr, "certs error: %v\n", certsResult.err)
	} else {
		for _, sub := range certsResult.res {
			fmt.Printf("  %s\n", sub)
		}
	}

	fmt.Println("\n[ASN]")
	if asnResult.err != nil {
		fmt.Fprintf(os.Stderr, "asn error: %v\n", asnResult.err)
	} else if asnResult.res.IP == "" {
		fmt.Println("  no A record found")
	} else {
		fmt.Printf("  IP      : %s\n", asnResult.res.IP)
		fmt.Printf("  Org     : %s\n", asnResult.res.Org)
		fmt.Printf("  Country : %s\n", asnResult.res.Country)
		fmt.Printf("  City    : %s\n", asnResult.res.City)
	}
}
