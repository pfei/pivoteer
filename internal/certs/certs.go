package certs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// entry represents a single record returned by crt.sh JSON API.
type entry struct {
	NameValue string `json:"name_value"`
}

func lookupCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse error: %w", err)
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name != "" {
				seen[name] = true
			}
		}
	}

	return sortedKeys(seen), nil
}

func lookupHackertarget(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("hackertarget request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget returned status %d", resp.StatusCode)
	}

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

	results := sortedKeys(seen)
	if len(results) == 1 && strings.Contains(results[0], "API count exceeded") {
		return nil, fmt.Errorf("hackertarget rate limit exceeded")
	}

	return results, nil
}

// sortedKeys returns a sorted slice of map keys.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// common subdomain prefixes to bruteforce
var wordlist = []string{
	"www", "api", "mail", "smtp", "pop", "imap",
	"ftp", "sftp", "ssh", "vpn", "dev", "staging",
	"preprod", "prod", "admin", "dashboard", "portal",
	"blog", "shop", "store", "cdn", "static", "assets",
	"media", "img", "images", "video", "stream",
	"app", "apps", "mobile", "m", "wap",
	"ns1", "ns2", "mx", "mx1", "mx2",
	"auth", "login", "sso", "id", "oauth",
	"status", "monitor", "metrics", "logs",
	"git", "gitlab", "github", "ci", "jenkins",
	"jira", "confluence", "wiki", "docs",
	"s3", "bucket", "backup", "db", "database",
}

func bruteforce(domain string) ([]string, error) {
	type result struct {
		name string
		ok   bool
	}

	ch := make(chan result, len(wordlist))

	for _, prefix := range wordlist {
		go func() {
			fqdn := fmt.Sprintf("%s.%s", prefix, domain)
			_, err := net.LookupHost(fqdn)
			ch <- result{fqdn, err == nil}
		}()
	}

	var found []string
	for range wordlist {
		r := <-ch
		if r.ok {
			found = append(found, r.name)
		}
	}

	sort.Strings(found)
	return found, nil
}

// Lookup tries crt.sh first, falls back to hackertarget.
func Lookup(domain string, bruteForce bool) ([]string, error) {
	results, err := lookupCrtSh(domain)
	if err == nil && len(results) > 0 {
		return results, nil
	}

	results, err = lookupHackertarget(domain)
	if err == nil {
		return results, nil // accepte même liste vide, pas de fallback
	}

	if bruteForce {
		return bruteforce(domain)
	}

	return nil, fmt.Errorf("all sources failed; use -bruteforce to enable DNS bruteforce")
}
