package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	domain := flag.String("d", "", "target domain (e.g. lemonde.fr)")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: pivoteer -d <domain>")
		os.Exit(1)
	}

	fmt.Printf("Target: %s\n", *domain)
}
