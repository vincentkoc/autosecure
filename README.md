<h1 align="center">Autosecure</h1>

<p align="center">
  <strong>Threat-feed IP blocking for Linux and macOS firewalls.</strong>
</p>

<p align="center">
  <a href="https://github.com/vincentkoc/autosecure/actions/workflows/validation.yml"><img src="https://github.com/vincentkoc/autosecure/actions/workflows/validation.yml/badge.svg" alt="Validation"></a>
  <a href="https://github.com/vincentkoc/autosecure/releases"><img src="https://img.shields.io/github/v/release/vincentkoc/autosecure" alt="Release"></a>
  <a href="https://github.com/vincentkoc/autosecure/blob/master/LICENSE.md"><img src="https://img.shields.io/github/license/vincentkoc/autosecure" alt="License"></a>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-blue" alt="Platform">
</p>

<p align="center">
  <a href="https://github.com/vincentkoc/autosecure/issues">Issues</a> ·
  <a href="https://github.com/vincentkoc/autosecure/releases">Releases</a>
</p>

## Install

<details open>
<summary>Homebrew (macOS)</summary>

```bash
brew tap vincentkoc/homebrew-tap
brew install autosecure
```

</details>

<details>
<summary>APT (Debian/Ubuntu)</summary>

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/vincentkoc/autosecure/setup.deb.sh' | sudo -E bash
sudo apt-get update
sudo apt-get install autosecure
```

</details>

<details>
<summary>RPM (RHEL/Fedora)</summary>

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/vincentkoc/autosecure/setup.rpm.sh' | sudo -E bash
sudo dnf install autosecure
```

</details>

<details>
<summary>Script only</summary>

```bash
curl -fsSL -o autosecure.sh https://raw.githubusercontent.com/vincentkoc/autosecure/master/autosecure.sh
chmod +x autosecure.sh
sudo ./autosecure.sh
```

</details>

## Why Autosecure?

Threat feeds are useful, but manually translating them into firewall rules is repetitive and fragile. Autosecure handles download, parsing, validation, and rule refresh in one script with backend support for `iptables`, `nft`, and `pf`.

## What You Get

- Firewall backend auto-detection: `iptables`, `nftables`, `pf`
- IPv4 blocklist ingestion with optional IPv6 support (`ip6tables`)
- Optional `ipset` acceleration for large lists
- Safe refresh flow with cached fallback if feeds fail
- Quiet cron-friendly mode

## Quick Start

macOS (`pf`) one-time bootstrap:

```bash
make pf-bootstrap
```

Then apply rules:

```bash
sudo autosecure.sh -q
```

Or force a backend:

```bash
sudo AUTOSECURE_FIREWALL_BACKEND=pf autosecure.sh -q
sudo AUTOSECURE_FIREWALL_BACKEND=nft autosecure.sh -q
sudo AUTOSECURE_FIREWALL_BACKEND=iptables autosecure.sh -q
```

## Configuration

Environment variables:

- `AUTOSECURE_FIREWALL_BACKEND=auto|iptables|nft|pf` (default: `auto`)
- `AUTOSECURE_RULE_POSITION=append|top` (default: `append`)
- `AUTOSECURE_XTABLES_WAIT=<seconds>` (default: `5`)
- `AUTOSECURE_IPV6_ENABLE=0|1` (default: `0`)
- `AUTOSECURE_IPSET_ENABLE=0|1` (default: `0`)
- `AUTOSECURE_EXTRA_FEEDS=<url1,url2,...>`
- `AUTOSECURE_EGF=0|1` (default: `1`)

## Feed Sources

- `https://www.spamhaus.org/drop/drop.txt`
- `https://www.spamhaus.org/drop/edrop.txt`
- `http://feeds.dshield.org/block.txt`

Note: ZeusTracker feed is intentionally disabled because the endpoint is no longer available.

## Scheduled Updates

```bash
crontab -e
0 3 * * * /usr/local/bin/autosecure.sh -q
```

## Validation and Tests

```bash
make validate
make test
make test-urls
make pf-bootstrap  # macOS only
```

Offline URL-test mode:

```bash
AUTOSECURE_SKIP_NETWORK_TESTS=1 bash tests/test_urls.sh
```

Pre-commit:

```bash
pre-commit install
pre-commit run --all-files
```

## Troubleshooting

Flush chains:

```bash
sudo iptables -F Autosecure
sudo iptables -F AutosecureAct
```

Detach chain jumps:

```bash
sudo iptables -D INPUT -j Autosecure
sudo iptables -D FORWARD -j Autosecure
sudo iptables -D OUTPUT -j Autosecure
```

Delete chains:

```bash
sudo iptables -X Autosecure
sudo iptables -X AutosecureAct
```

## Contributing

Open an issue for bugs or a pull request for improvements.

Donations:

- BTC: `14v9knBDAmJAMxWovuLfy7YkLDyfq8phNb`
- ETH: `0xe6fbd8de8157934767867022b7a8e8691d8df3dc`
- EFF: https://supporters.eff.org/donate/button

## License

GNU GPL v3. See `LICENSE.md`.

<p align="center">
  <sub>Based on the original work by <a href="https://github.com/cowgill">cowgill</a> and contributors.</sub>
</p>
