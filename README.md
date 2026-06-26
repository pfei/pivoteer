# pivoteer

OSINT domain reconnaissance tool written in Go.

Given a domain, pivoteer aggregates public data from DNS, WHOIS, TLS certificates,
and ASN records — with a focus on **pivot discovery**: finding related domains
and infrastructure from a single starting point.

## What is a pivot?

In OSINT, a **pivot** means using one piece of information to discover others
that aren't publicly linked. pivoteer automates the most useful technical pivots:

- **TLS SANs** — a certificate covering multiple domains reveals related infrastructure
- **ASN** — domains sharing the same autonomous system may share the same operator
- **Subdomains** — staging, admin, or API endpoints not referenced publicly
- **WHOIS / NS** — registrar and name server patterns link domains to the same actor

## Usage

```bash
pivoteer -d example.com
pivoteer -d example.com -json
pivoteer -d example.com -o report.json
pivoteer -d example.com -bruteforce
```

### Flags

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-json` | Output as JSON to stdout |
| `-o file` | Write JSON output to file |
| `-bruteforce` | Enable DNS bruteforce subdomain discovery |

## Real-world demo: spotting a disinformation clone

The [Doppelganger operation](https://www.disinfo.eu/doppelganger/) (documented by
EU DisinfoLab) created clones of major news outlets to spread disinformation.
`spiegel.ltd` impersonated the German weekly Der Spiegel.

Running pivoteer on both domains makes the difference immediately visible:

**Legitimate outlet:**

```
$ pivoteer -d spiegel.de

[WHOIS]
  Registrar   : DENIC eG
[DNS]
  MX  : spiegel-de.mail.protection.outlook.com (Microsoft 365)
  NS  : pns101.cloudns.net (professional DNS provider)
[TLS]
  Issuer  : DigiCert Inc
  SANs    : spiegel.de, www.spiegel.de, prod.www.spiegel.de
[ASN]
  Org     : AS34309 Link11 GmbH (professional anti-DDoS hosting)
```

**Doppelganger clone:**

```
$ pivoteer -d spiegel.ltd

[WHOIS]
  Registrar   : (hidden / no response)
[DNS]
  MX  : (none — this domain never sends email)
  NS  : ns1.park-my-domain.net (domain parking service)
[TLS]
  Issuer  : Let's Encrypt
  SANs    : *.spiegel.ltd, spiegel.ltd (wildcard only)
[ASN]
  Org     : AS24940 Hetzner Online GmbH (generic VPS hosting)
```

No registrar transparency, no email infrastructure, parked nameservers,
generic hosting — the infrastructure profile of a disposable clone.

## Data sources

| Module | Source | Notes |
|--------|--------|-------|
| DNS | Go stdlib `net` | A, MX, TXT, NS records |
| WHOIS | Direct TCP port 43 | IANA referral chain |
| Subdomains | crt.sh → hackertarget | CT logs, DNS fallback |
| TLS | Direct TLS handshake | SANs extracted from certificate |
| ASN | ipinfo.io | Free tier, 1000 req/day |

All sources are public. No API key required.

## Install

```bash
go install github.com/pfei/pivoteer/cmd/pivoteer@latest
```

Or build from source:

```bash
git clone https://github.com/pfei/pivoteer
cd pivoteer
go build -o pivoteer cmd/pivoteer/main.go
```

## Legal

See [DISCLAIMER.md](DISCLAIMER.md). pivoteer queries only public data sources.
Use responsibly and in accordance with applicable law.

## License

MIT — see [LICENSE](LICENSE).
