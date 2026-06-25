package certs

import (
	"bufio"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Lookup queries hackertarget.com for subdomains of the given domain.
// Returns a sorted, deduplicated list of discovered names.
func Lookup(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("hackertarget request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget returned status %d", resp.StatusCode)
	}

	// response is CSV: subdomain,ip — one per line
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			if name != "" {
				seen[name] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	results := make([]string, 0, len(seen))
	for name := range seen {
		results = append(results, name)
	}
	sort.Strings(results)

	return results, nil
}
