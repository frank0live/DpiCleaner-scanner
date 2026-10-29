# 🧭 DPI Cleaner Scanner

**Find clean IPs for Xray/V2Ray, validate REALITY/SNI targets, and export
ready-to-paste configs — from a desktop app or straight from the terminal.**

One shared engine. Two frontends:

- 🖥️ **Desktop** — Tkinter UI (sidebar shell, dark graphite theme) for
  interactive scanning, sorting and export.
- ⌨️ **CLI** — headless `python -m dpicleaner` for servers, cron jobs and
  scripts: NDJSON/JSON out, zero GUI dependencies on the core path.

```text
$ python -m dpicleaner ip 104.16.0.0/28 --count 3
{"ip": "104.16.0.5", "packet_loss": 0.0, "avg_ping": 12.4, "status": "Online", ...}

$ python -m dpicleaner reality --link 'vless://...' --names www.a.com,www.b.com
{"sni": "www.a.com", "verdict": "VALID", "packet_loss": 0.0, "avg_ping": 84.1, ...}
```

## ✨ Features

| | |
|---|---|
| 🌐 **Clean-IP scan** | TCP + TLS handshake pings over CIDR ranges or lists, multi-threaded (up to 1000 threads), ranked by loss → jitter → latency. |
| 🎯 **SNI / REALITY mode** | Per candidate: TCP probe, real browser-fingerprint TLS (JA3 via curl_cffi), ALPN probe — separate TCP/TLS columns and a verdict per row. |
| 🔐 **Real REALITY validation** | Pinned xray-core, local client built from **your** VLESS/Trojan link with only `serverName` swapped → `VALID` / `FLAKY` / `INVALID` / `TIMEOUT` / `NETWORK_ERROR` per SNI. |
| ⚡ **Speed test** | Low Accuracy (multi-connection) or High Accuracy — real throughput through a live REALITY tunnel. |
| 🧹 **Clean configs** | Rewrites `vless://` / `vmess://` / `trojan://` / `ss://` links onto the IPs that answered. |
| 🔍 **SNI discovery** | Pulls subdomains from crt.sh certificate logs as candidate names. |
| 📋 **One-click JSON** | Ready-to-paste `realitySettings` snippet (`target` + `serverNames`). |
| ⌨️ **Headless CLI** | `ip` / `sni` / `reality` subcommands — same engine the GUI runs on. |

## ⚡ Quick start

**Desktop app**

```bash
pip install curl_cffi
python -m dpicleaner
```

**Headless CLI** (no Tkinter needed)

```bash
pip install curl_cffi                      # only for browser-fingerprint TLS
python -m dpicleaner ip 1.1.1.1 8.8.8.8    # probe + rank
python -m dpicleaner sni host.example --names www.a.com,www.b.com
python -m dpicleaner reality --link 'vless://...' --names www.a.com,www.b.com
```

On first REALITY validation or High-Accuracy speed test, xray-core
(pinned `v26.9.8`) is downloaded automatically from the official XTLS release.

## 🗂 Layout

```text
dpicleaner/
├── __init__.py          version
├── __main__.py          GUI vs CLI dispatch
├── cli.py               headless subcommands
├── core/                engine — no Tkinter imports
│   ├── targets.py       IP/CIDR + host parsing, crt.sh discovery
│   ├── netprobe.py      TCP / TLS / JA3 probes, ALPN
│   ├── links.py         config-link rewriting
│   ├── xraycore.py      xray-core acquisition + tunnel lifecycle
│   ├── reality.py       REALITY handshake validation, verdicts
│   └── speedtest.py     throughput through a live tunnel
└── ui/
    ├── theme.py         palette + font stack
    └── app.py           Tkinter shell and pages
```

## 🧠 How it works

- **IP/CIDR:** expand input → parallel TCP + TLS probes → rank by stability →
  rewrite your links onto the winner.
- **SNI/REALITY:** resolve target → per candidate TCP / JA3 TLS / ALPN →
  optional real REALITY handshake through xray-core → verdict table → export.

## 📌 Notes

- REALITY validation only makes sense with **your own** link; only `serverName`
  changes. Keys stay yours — the app never sends them anywhere.
- External requests: `crt.sh` (SNI discovery), `api.github.com` (pinned
  xray-core download), `speed.cloudflare.com` (speed test). No telemetry.
- ✅ Engine validated end-to-end before publishing — REALITY positive/negative
  controls against a live server, tunnel speed test, TXT & JSON export.

## 🔗 Contact

📬 [@master_supports](https://t.me/master_supports)

---

## فارسی

**DPI Cleaner Scanner** — پیدا کردن IP تمیز برای Xray/V2Ray، اعتبارسنجی
SNI/REALITY و تولید کانفیگ آماده — هم از دسکتاپ، هم از ترمینال.

- 🖥️ **دسکتاپ:** پوستهٔ سایدباری با تم گرافیتی تیره، اسکن تعاملی، مرتب‌سازی و خروجی.
- ⌨️ **CLI:** `python -m dpicleaner ip|sni|reality` — خروجی JSON/NDJSON، بدون نیاز به Tkinter.
- 🔐 اعتبارسنجی واقعی REALITY با xray-core (نسخهٔ pin شده) — فقط `serverName` عوض می‌شود.
- ⚡ اسپیدتست واقعی از دل تونل · 🧹 تولید کانفیگ تمیز · 🔍 کشف SNI از crt.sh.

```bash
pip install curl_cffi
python -m dpicleaner                       # GUI
python -m dpicleaner reality --link 'vless://...' --names a.com,b.com
```

## Support

- 💬 Telegram: [@master_supports](https://t.me/master_supports)
