# Autosecure Bad-IP Blocking

[![Donate BTC](https://img.shields.io/badge/donate-BTC-orange.svg)](https://github.com/koconder/autosecure#contributing-and-donations) [![Donate ETH](https://img.shields.io/badge/donate-ETH-orange.svg)](https://etherdonation.com/d?to=0xe6fbd8de8157934767867022b7a8e8691d8df3dc)

Autosecure is a Bash script that downloads known bad-IP blocklists and applies them to Linux `iptables`.

## What It Does

- Creates and refreshes two custom chains: `Autosecure` and `AutosecureAct`
- Attaches `Autosecure` to `INPUT` and `FORWARD` (and `OUTPUT` when egress filtering is enabled)
- Downloads and processes these feeds:
  - Spamhaus DROP: `https://www.spamhaus.org/drop/drop.txt`
  - Spamhaus EDROP: `https://www.spamhaus.org/drop/edrop.txt`
  - DShield Block List: `http://feeds.dshield.org/block.txt`
  - Abuse.ch ZeusTracker blocklist: disabled (endpoint no longer available)
- Logs and drops matching traffic through `AutosecureAct`

## Requirements

- Linux host with `iptables`
- Root privileges (`sudo`)
- `wget` or `curl`, plus `awk`, `grep`, and `sort`

## Installation

```bash
# Download the script
curl -LO https://github.com/koconder/autosecure/raw/master/autosecure.sh

# Make it executable
chmod +x autosecure.sh

# Apply rules
sudo ./autosecure.sh

# Verify chain contents
sudo iptables -L Autosecure -n
```

## Run-Time Flags

- Quiet mode (recommended for cron):

```bash
./autosecure.sh -q
```

## Automatic Updating

Use `crontab` to refresh rules daily:

```bash
crontab -e

# Run every day at 03:00
0 3 * * * /{install location}/autosecure.sh -q
```

## Troubleshooting

Flush Autosecure chains:

```bash
sudo iptables -F Autosecure
sudo iptables -F AutosecureAct
```

Detach Autosecure from base chains (if needed):

```bash
sudo iptables -D INPUT -j Autosecure
sudo iptables -D FORWARD -j Autosecure
sudo iptables -D OUTPUT -j Autosecure
```

Delete Autosecure chains:

```bash
sudo iptables -X Autosecure
sudo iptables -X AutosecureAct
```

## Notes

- This project currently manages IPv4 rules via `iptables` only.
- Feed availability/format can change over time. A failed feed is skipped and other feeds still apply.

## Validation

Run validations manually:

```bash
bash -n autosecure.sh
shellcheck autosecure.sh
bash tests/test_parsing.sh
bash tests/test_urls.sh
```

For offline local runs, skip URL checks with:

```bash
AUTOSECURE_SKIP_NETWORK_TESTS=1 bash tests/test_urls.sh
```

Use pre-commit for the same checks on each commit:

```bash
pre-commit install
pre-commit run --all-files
```

## Contributing and Donations

If you want to contribute, open an issue or submit a pull request.

- BTC: `14v9knBDAmJAMxWovuLfy7YkLDyfq8phNb`
- ETH: `0xe6fbd8de8157934767867022b7a8e8691d8df3dc`
- EFF: https://supporters.eff.org/donate/button

## License and Contributors

This project is licensed under GNU GPL v3. See `LICENSE.md`.

Based on initial work from @cowgill and Vivek Gite (nixCraft), with contributions from:

- David (@cowgill)
- Vincent Koc (@koconder)
- Volkan (@volkan-k)
- Anasxrt (@Anasxrt)
- ShamimIslam (@ShamimIslam)
