package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pfei/pivoteer/internal/dns"
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
}
