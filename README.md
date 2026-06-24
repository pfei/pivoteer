# pivoteer

OSINT domain reconnaissance tool written in Go.

Given a domain, pivoteer aggregates public data from DNS, WHOIS, TLS certificates,
and ASN records — with a focus on **pivot discovery**: finding related domains
and infrastructure from a single starting point.

## Usage

```bash
pivoteer -d lemonde.fr
```

## Features (roadmap)

- DNS records (A, MX, TXT, NS)
- WHOIS registration data
- TLS certificate SANs (pivot point)
- Subdomain discovery via crt.sh
- ASN / IP geolocation

## Install

```bash
go install github.com/pfei/pivoteer/cmd/pivoteer@latest
```

## Legal

See [DISCLAIMER.md](DISCLAIMER.md).

## License

MIT — see [LICENSE](LICENSE).
