package whois

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const ianaWhois = "whois.iana.org:43"

// query sends a whois request to the given server and returns the raw response.
func query(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "%s\r\n", domain)

	raw, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("read from %s: %w", server, err)
	}

	return string(raw), nil
}

// referralServer extracts the referral whois server from an IANA response.
func referralServer(response string) string {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]) + ":43"
			}
		}
	}
	return ""
}

// Result holds parsed WHOIS data.
type Result struct {
	Registrar   string   `json:"registrar"`
	Created     string   `json:"created"`
	Expires     string   `json:"expires"`
	NameServers []string `json:"name_servers"`
	Raw         string   `json:"-"` // json encoder will ignore this field
}

// parse extracts key fields from raw whois text.
func parse(raw string) Result {
	r := Result{Raw: raw}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		switch {
		case strings.HasPrefix(lower, "registrar:"):
			if r.Registrar == "" {
				r.Registrar = val
			}
		case strings.HasPrefix(lower, "creation date:"),
			strings.HasPrefix(lower, "created:"):
			if r.Created == "" {
				r.Created = val
			}
		case strings.HasPrefix(lower, "expiry date:"),
			strings.HasPrefix(lower, "expires:"),
			strings.HasPrefix(lower, "registrar registration expiration date:"):
			if r.Expires == "" {
				r.Expires = val
			}
		case strings.HasPrefix(lower, "name server:"):
			r.NameServers = append(r.NameServers, strings.ToLower(val))
		case strings.HasPrefix(lower, "nserver:"):
			r.NameServers = append(r.NameServers, strings.ToLower(val))
		}

	}
	return r
}

// Lookup performs a two-step WHOIS lookup: IANA first, then the referral server.
func Lookup(domain string) (Result, error) {
	// step 1: ask IANA which server handles this TLD
	ianaResp, err := query(ianaWhois, domain)
	if err != nil {
		return Result{}, fmt.Errorf("iana whois: %w", err)
	}

	referral := referralServer(ianaResp)
	if referral == "" {
		// no referral — parse IANA response directly
		return parse(ianaResp), nil
	}

	// step 2: query the authoritative server
	raw, err := query(referral, domain)
	if err != nil {
		return Result{}, fmt.Errorf("whois %s: %w", referral, err)
	}

	return parse(raw), nil
}
