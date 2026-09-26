"""Target parsing, host resolution and crt.sh based SNI discovery."""

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


CIDR_ASK_THRESHOLD = 5000


_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
                         r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$')


_TWO_LABEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.in",
    "co.nz", "com.au", "com.br", "com.cn", "com.mx", "com.tw",
}


def parse_ip_input(ip_input, max_per_cidr=CIDR_ASK_THRESHOLD):
    """Parse IPs / CIDR ranges. A range is only ever truncated when it
    exceeds max_per_cidr; smaller ranges are used in full.
    Returns (ip_list, invalid_items, truncated_info)."""
    all_ips = []
    truncated_info = []
    raw_inputs = re.split(r'[,\s]+', ip_input.strip())
    errors = []
    for item in raw_inputs:
        item = item.strip()
        if not item:
            continue
        try:
            if '/' in item:
                network = ipaddress.ip_network(item, strict=False)
                total = network.num_addresses
                limit = total
                if total > max_per_cidr:
                    limit = max_per_cidr
                    truncated_info.append((item, total, limit))
                for i, ip in enumerate(network.hosts()):
                    if i >= limit:
                        break
                    all_ips.append(str(ip))
            else:
                all_ips.append(str(ipaddress.ip_address(item)))
        except ValueError:
            errors.append(item)
    return list(dict.fromkeys(all_ips)), errors, truncated_info


def parse_domain_list(text):
    """Parse a list of SNI/domain candidates, one per line/comma/space.
    Strips scheme prefixes and paths if pasted as a URL.
    Returns (domain_list, invalid_items)."""
    domains = []
    errors = []
    raw_inputs = re.split(r'[,\s]+', text.strip())
    for item in raw_inputs:
        item = item.strip()
        if not item:
            continue
        item = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', item)  # strip scheme
        item = item.split('/', 1)[0]                              # strip path
        item = item.split(':', 1)[0]                               # strip port
        if _DOMAIN_RE.match(item):
            domains.append(item)
        else:
            errors.append(item)
    return list(dict.fromkeys(domains)), errors


def parse_target_string(target_text, fallback_port):
    """Parse a 'host' or 'host:port' string (host may be a domain or an IP).
    Returns (host, port, error)."""
    text = target_text.strip()
    if not text:
        return None, None, "Target is empty"
    text = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', text)  
    text = text.split('/', 1)[0]                              
    host, port = text, fallback_port
    if ':' in text and not text.count(':') > 1:  
        maybe_host, maybe_port = text.rsplit(':', 1)
        if maybe_port.isdigit() and maybe_host:
            host, port = maybe_host, int(maybe_port)
    host = host.strip()
    if not host:
        return None, None, "Target host is empty"
    return host, port, None


def parse_target_list(text, fallback_port):
    """Parse multiple 'host' / 'host:port' entries, one per line (also
    accepts comma/space separated). Returns (targets, errors) where
    targets is a list of (raw_label, host, port) tuples, de-duplicated
    on (host, port), preserving order."""
    targets = []
    errors = []
    seen = set()
    raw_inputs = re.split(r'[,\n]+', text.strip())
    for item in raw_inputs:
        item = item.strip()
        if not item:
            continue
        host, port, err = parse_target_string(item, fallback_port)
        if err:
            errors.append(item)
            continue
        key = (host.lower(), port)
        if key in seen:
            continue
        seen.add(key)
        targets.append((item, host, port))
    return targets, errors


def resolve_host(host):
    """Return (ip, error). If host is already an IP, returns it unchanged."""
    try:
        ipaddress.ip_address(host)
        return host, None
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host), None
    except socket.gaierror as e:
        return None, str(e)


def guess_base_domain(host):
    """Best-effort registrable-domain guess (e.g. apps.apple.com -> apple.com)
    so subdomain discovery covers siblings, not just children of the exact host."""
    parts = host.lower().split('.')
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:])
    if last_two in _TWO_LABEL_TLDS and len(parts) >= 3:
        return last_three
    return last_two


def find_subdomains_via_crtsh(domain, timeout=15, limit=150):
    """Look up subdomains of `domain` from public certificate-transparency
    logs (crt.sh). Returns (domain_list, error). No API key / auth needed;
    this only reads publicly-logged certificate data.

    `error` is None on success (including the "legitimately no results"
    case, e.g. a 404 from crt.sh for a domain with no logged certs) so
    callers can tell "nothing found" apart from "the lookup itself broke".
    When something did go wrong, `error` is a short classified string:
    "NO_RESULTS: ...", "RATE_LIMIT: ...", "TEMPORARY_ERROR: ...",
    "TIMEOUT: ...", "CONNECTION_ERROR: ...", "PARSE_ERROR: ...".
    """
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # crt.sh returns 404 when it has no certs logged for the query -
            # that's a legitimate "no results", not a broken lookup.
            return [], None
        if e.code == 429:
            return [], "RATE_LIMIT: crt.sh is throttling requests right now"
        if 500 <= e.code < 600:
            return [], f"TEMPORARY_ERROR: crt.sh returned HTTP {e.code}"
        return [], f"HTTP_ERROR: crt.sh returned HTTP {e.code}"
    except (socket.timeout, TimeoutError):
        return [], "TIMEOUT: crt.sh did not respond in time"
    except urllib.error.URLError as e:
        return [], f"CONNECTION_ERROR: {e.reason}"
    except Exception as e:
        return [], str(e)

    try:
        entries = json.loads(raw)
    except Exception as e:
        return [], f"PARSE_ERROR: could not parse crt.sh response ({e})"

    counts = {}
    for entry in entries:
        name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for line in name_value.split("\n"):
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line and _DOMAIN_RE.match(line):
                counts[line] = counts.get(line, 0) + 1

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [name for name, _ in ranked][:limit], None


def find_subdomains_for_bases(bases, timeout=15, per_domain_limit=150, total_limit=400):
    """Run find_subdomains_via_crtsh for several base domains concurrently
    and merge the results (de-duplicated, order preserved: best rank per
    source domain first, sources interleaved).

    A failure (or an empty result) on one base domain never stops the
    others - each base is looked up independently and the failures are
    only reported back for display, not raised.

    Returns (merged_list, errors, empty_bases):
      - errors: list of (base_domain, classified_error_message) for bases
        whose lookup actually broke (timeout, rate limit, HTTP/connection
        error, parse error) - NOT bases that simply had zero certs logged.
      - empty_bases: list of base domains that were looked up successfully
        but came back with zero subdomains (e.g. crt.sh 404 / no matches).
    """
    per_base = {}
    errors = []
    empty_bases = []
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(bases)))) as executor:
        futures = {executor.submit(find_subdomains_via_crtsh, base, timeout,
                                    per_domain_limit): base for base in bases}
        for future in as_completed(futures):
            base = futures[future]
            domains, err = future.result()
            if err:
                errors.append((base, err))
            elif not domains:
                empty_bases.append(base)
            else:
                per_base[base] = domains

    merged = []
    seen = set()
    max_len = max((len(v) for v in per_base.values()), default=0)
    for i in range(max_len):
        for base in bases:
            lst = per_base.get(base, [])
            if i < len(lst):
                name = lst[i]
                if name not in seen:
                    seen.add(name)
                    merged.append(name)
                    if len(merged) >= total_limit:
                        return merged, errors, empty_bases
    return merged, errors, empty_bases
