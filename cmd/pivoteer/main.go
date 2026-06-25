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

	fmt.Println("\n[WHOIS]")
	whoisResult, err := whois.Lookup(*domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "whois error: %v\n", err)
	} else {
		fmt.Printf("  Registrar   : %s\n", whoisResult.Registrar)
		fmt.Printf("  Created     : %s\n", whoisResult.Created)
		fmt.Printf("  Expires     : %s\n", whoisResult.Expires)
		fmt.Printf("  Name servers: %s\n", strings.Join(whoisResult.NameServers, ", "))
	}

	fmt.Println("\n[SUBDOMAINS])")
	subdomains, err := certs.Lookup(*domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certs error: %v\n", err)
	} else {
		for _, sub := range subdomains {
			fmt.Printf("  %s\n", sub)
		}
	}

	fmt.Println("\n[ASN]")
	if len(dnsResult.A) > 0 {
		asnResult, err := asn.Lookup(dnsResult.A[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "asn error: %v\n", err)
		} else {
			fmt.Printf("  IP      : %s\n", asnResult.IP)
			fmt.Printf("  Org     : %s\n", asnResult.Org)
			fmt.Printf("  Country : %s\n", asnResult.Country)
			fmt.Printf("  City    : %s\n", asnResult.City)
		}
	} else {
		fmt.Println("  no A record found")
	}
}
