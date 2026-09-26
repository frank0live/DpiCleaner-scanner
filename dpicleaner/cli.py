"""Command-line interface for the DPI Cleaner Scanner core engine.

Headless usage — ideal for servers, cron jobs and scripting:

    python -m dpicleaner ip 1.1.1.1 8.8.8.8 --count 3
    python -m dpicleaner sni 203.0.113.7 --names www.a.com,www.b.com
    python -m dpicleaner reality --link 'vless://...' --names www.a.com,www.b.com

Output is NDJSON (one JSON object per line) by default, or a pretty
JSON array with --json.
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__ as APP_VERSION
from .core import netprobe, reality, targets, xraycore


def _probe_sort(row):
    """Same ranking the GUI uses for IP/TLS rows: loss, then latency, then jitter."""
    return (row["packet_loss"], row["avg_ping"], row.get("jitter") or 0)


def _emit(rows, as_json):
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    for row in rows:
        print(json.dumps(row, default=str))


def _split_names(chunks):
    names = []
    for chunk in chunks or []:
        names.extend(part for part in chunk.replace(",", " ").split() if part)
    return list(dict.fromkeys(names))


def cmd_ip(args):
    ips, bad, truncated = targets.parse_ip_input(" ".join(args.addresses))
    if not ips:
        print(f"error: no usable IPs in input (invalid: {bad})", file=sys.stderr)
        return 2
    for item, total, kept in truncated:
        print(f"note: {item} has {total} addresses; scanning the first {kept}", file=sys.stderr)

    def probe(ip):
        return netprobe.tcp_handshake_ping(ip, args.port, args.count, args.timeout)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        rows = list(pool.map(probe, ips))
    rows.sort(key=_probe_sort)
    _emit(rows, args.json)
    return 0


def cmd_sni(args):
    host, err = targets.resolve_host(args.target)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    names = _split_names(args.names)
    if not names:
        print("error: --names is required for sni mode", file=sys.stderr)
        return 2
    if not netprobe.HAVE_CURL_CFFI:
        print("warning: curl_cffi is not installed — browser-fingerprint TLS "
              "results will be degraded", file=sys.stderr)

    rows = []
    for sni in names:
        res = netprobe.sni_target_test(host, args.port, sni, args.count, args.timeout)
        res["sni"] = sni
        res["target"] = args.target
        rows.append(res)
    rows.sort(key=_probe_sort)
    _emit(rows, args.json)
    return 0


def cmd_reality(args):
    link = args.link
    if not link:
        print("error: --link (or a link on stdin) is required", file=sys.stderr)
        return 2
    params = reality.parse_reality_link(link.strip())
    if params.get("error"):
        print(f"error: {params['error']}", file=sys.stderr)
        return 2
    names = _split_names(args.names)
    if not names:
        print("error: --names is required for reality mode", file=sys.stderr)
        return 2

    try:
        xray_path, _detail = xraycore.ensure_xray_binary()
    except Exception as exc:  # noqa: BLE001 - surface the real reason to the user
        print(f"error: could not obtain xray-core: {exc}", file=sys.stderr)
        return 2

    host = args.target or params.get("address")
    port = args.port or params.get("port")

    rows = []
    for sni in names:
        res = reality.reality_sni_test(xray_path, params, host, port, sni,
                                       args.count, args.timeout,
                                       probe_timeout_ms=args.probe_timeout)
        row = reality.reality_result_to_row(res)
        row["sni"] = sni
        row["target"] = f"{host}:{port}"
        rows.append(row)
    rows.sort(key=reality.reality_sort_key)
    _emit(rows, args.json)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dpicleaner",
        description=f"DPI Cleaner Scanner v{APP_VERSION} — headless core engine.",
    )
    parser.add_argument("-V", "--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ip", help="TCP-probe IPs / CIDR ranges and rank them.")
    p.add_argument("addresses", nargs="+", help="IPs or CIDRs, e.g. 1.1.1.1 or 104.16.0.0/28")
    p.add_argument("--port", type=int, default=443, help="TCP port (default 443)")
    p.add_argument("--count", type=int, default=3, help="probes per address (default 3)")
    p.add_argument("--timeout", type=int, default=3000, help="per-probe timeout in ms (default 3000)")
    p.add_argument("--threads", type=int, default=64, help="worker threads (default 64)")
    p.add_argument("--json", action="store_true", help="pretty JSON array instead of NDJSON")
    p.set_defaults(func=cmd_ip)

    p = sub.add_parser("sni", help="TLS-test SNI candidates against a target host.")
    p.add_argument("target", help="domain or IP to connect to")
    p.add_argument("--names", action="append", required=True,
                   help="SNI names (repeatable and/or comma-separated)")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--timeout", type=int, default=4000, help="per-probe timeout in ms")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_sni)

    p = sub.add_parser("reality", help="Validate SNI candidates with a real REALITY handshake.")
    p.add_argument("--link", help="your vless:// or trojan:// REALITY link")
    p.add_argument("target", nargs="?", help="override the host (default: from the link)")
    p.add_argument("--names", action="append", required=True,
                   help="SNI names (repeatable and/or comma-separated)")
    p.add_argument("--port", type=int, default=0, help="override the port (default: from the link)")
    p.add_argument("--count", type=int, default=3, help="handshake attempts per name (default 3)")
    p.add_argument("--timeout", type=int, default=3000, help="TCP precheck timeout in ms")
    p.add_argument("--probe-timeout", type=int, default=6000, help="REALITY probe timeout in ms")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_reality)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
