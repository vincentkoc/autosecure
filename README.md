<h1 align="center">🔑 Autosecure</h1>

<p align="center">
  <strong>Public threat-feed and blocklists to automatic IP blocking for Linux and macOS firewalls.</strong>
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

## Why Autosecure?

Threat feeds and blocklists are useful, but manually translating them into firewall rules is repetitive and fragile. Autosecure handles download, parsing, validation, and rule refresh in one script with backend support for `iptables`, `nft`, and `pf` (macOS). Autosecure is very lightweight and can be setup to run daily on a cron to auto-update, its designed to not impact any existing firewall rules and will manage its own set.

Based on [spamhaus script](https://github.com/cowgill/spamhaus) and the original work by <a href="https://github.com/cowgill">cowgill</a> and contributors which is no longer maintained.

## Install Autosecure Package

<details>
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

## Current Feed Sources

- `https://www.spamhaus.org/drop/drop.txt`
- `https://www.spamhaus.org/drop/edrop.txt`
- `http://feeds.dshield.org/block.txt`

Additional URLs to parse can be passed in using the enviroment variable `AUTOSECURE_EXTRA_FEEDS` as comma seperated strings. Just a note the `ZeusTracker` feed is intentionally disabled because the endpoint is no longer available.

## What You Get

- Firewall backend auto-detection: `iptables`, `nftables`, `pf`
- IPv4 blocklist ingestion with optional IPv6 support (`ip6tables`)
- Optional `ipset` acceleration for large lists
- Safe refresh flow with cached fallback if feeds fail
- Quiet cron-friendly mode

## Configuration

### Environment variables

- `AUTOSECURE_FIREWALL_BACKEND=auto|iptables|nft|pf` (default: `auto`)
- `AUTOSECURE_RULE_POSITION=append|top` (default: `append`)
- `AUTOSECURE_XTABLES_WAIT=<seconds>` (default: `5`)
- `AUTOSECURE_IPV6_ENABLE=0|1` (default: `0`)
- `AUTOSECURE_IPSET_ENABLE=0|1` (default: `0`)
- `AUTOSECURE_EXTRA_FEEDS=<url1,url2,...>`
- `AUTOSECURE_EGF=0|1` (default: `1`)


### Force a backend:

```bash
sudo AUTOSECURE_FIREWALL_BACKEND=pf autosecure.sh -q
sudo AUTOSECURE_FIREWALL_BACKEND=nft autosecure.sh -q
sudo AUTOSECURE_FIREWALL_BACKEND=iptables autosecure.sh -q
```

### macOS Firewall Setup (`pf`/`pfctl`)

On macOS, the backend `auto` (out of the box setup) selects `pf`, then:
- (if its your first run) `/etc/pf.conf` is populated with: `anchor "autosecure"` to load rulesfrom "/etc/pf.anchors/autosecure"`
- Runtime rules are loaded into the `autosecure` anchor and table `autosecure_bad_hosts` via `pfctl`.
- The common `pfctl -f` warning about flushing startup rules is filtered from output, while real `pfctl` errors are still shown.

### Scheduled Updates via Cron (Linux and Mac)

Example of running everyday at 03:00am
```bash
crontab -e
0 3 * * * /usr/local/bin/autosecure.sh -q
```

## Troubleshooting

Flush chains (iptables):

```bash
sudo iptables -F Autosecure
sudo iptables -F AutosecureAct
```

Detach chain jumps (iptables):

```bash
sudo iptables -D INPUT -j Autosecure
sudo iptables -D FORWARD -j Autosecure
sudo iptables -D OUTPUT -j Autosecure
```

Delete chains (iptables):

```bash
sudo iptables -X Autosecure
sudo iptables -X AutosecureAct
```

## Contributing

Open an issue for bugs or a pull request for improvements.

---

Made with 💙 by <a href="https://github.com/vincentkoc">Vincent Koc</a> · <a href="LICENSE">GPL-3.0</a>
