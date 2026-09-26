"""Reachability probes: TCP / TLS / browser-fingerprint TLS / ALPN."""

import importlib
import socket
import ssl
import time

# Load curl_cffi dynamically so the scanner stays importable even when the
# interpreter running it is not the one curl_cffi was installed into.
try:
    _curl_cffi = importlib.import_module("curl_cffi")
    Curl = _curl_cffi.Curl
    CurlOpt = _curl_cffi.CurlOpt
    CurlInfo = _curl_cffi.CurlInfo
    HAVE_CURL_CFFI = True
except Exception:
    Curl = None
    CurlOpt = None
    CurlInfo = None
    HAVE_CURL_CFFI = False


def _ping_stats(times):
    """Given a list of successful round-trip times (ms), compute simple
    stability stats. Returns a dict with min/max/jitter/stddev, all None
    when there isn't enough data. `jitter` here is the mean absolute
    difference between consecutive samples (RFC3550-style), `stddev` is
    the classic population standard deviation - together they say a lot
    more about how usable a connection will be in practice than a single
    average ping does (a stable 60ms beats a bouncy 35-390ms average)."""
    if not times:
        return {"min_ping": None, "max_ping": None, "jitter": None, "stddev": None}
    avg = sum(times) / len(times)
    variance = sum((t - avg) ** 2 for t in times) / len(times)
    stddev = variance ** 0.5
    if len(times) > 1:
        jitter = sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)
    else:
        jitter = 0.0
    return {
        "min_ping": round(min(times), 1),
        "max_ping": round(max(times), 1),
        "jitter": round(jitter, 1),
        "stddev": round(stddev, 1),
    }


def check_port(ip, port, timeout=3.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def tcp_handshake_ping(ip, port, count, max_timeout):
    timeout = max_timeout / 1000
    times, success = [], 0
    for _ in range(count):
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
            times.append((time.perf_counter() - start) * 1000)
            success += 1
        except Exception:
            pass
    loss = round((1 - success / count) * 100, 1) if count else 100.0
    avg = round(sum(times) / len(times), 1) if times else float('inf')
    result = {
        "ip": ip, "packet_loss": loss, "avg_ping": avg,
        "status": "Online" if success > 0 else "Offline",
        "success": success, "count": count,
    }
    result.update(_ping_stats(times))
    return result


def tls_handshake_ping(ip, port, sni, count, max_timeout):
    """TLS-handshake `ip:port` using `sni` as the TLS server_hostname.
    Works both for 'many IPs, one SNI' and 'one IP, many SNIs' modes.

    NOTE ON REALITY TARGETS: this sends a plain Python/OpenSSL ClientHello,
    which does NOT mimic a real browser's TLS fingerprint (JA3) the way
    uTLS-based clients (fp=chrome/firefox in Xray etc.) do. A REALITY
    inbound may treat a non-browser-looking hello differently than it
    treats your real client. So a Timeout/Offline result here means
    "a generic TLS client couldn't complete a handshake with this
    SNI/IP/port combo in the time given" - it is a useful reachability
    signal, but it isn't a byte-for-byte replica of your real client, and
    isn't proof the SNI won't work with your actual config.

    IMPORTANT: even a successful handshake here only proves generic TLS
    reachability. It is NOT a REALITY handshake validation - REALITY
    additionally checks the client's X25519 key exchange against the
    server's configured public key/shortId, which a plain TLS test (or
    a browser-fingerprinted one) has no way to reproduce without your
    actual private key material. Treat "Online" as "TLS-reachable",
    not "REALITY-ready".
    """
    timeout = max_timeout / 1000
    times, success = [], 0
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    negotiated_versions = set()
    for _ in range(count):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                
                
                
                
                sock.settimeout(timeout)
                with ctx.wrap_socket(sock, server_hostname=sni) as tls_sock:
                    negotiated_versions.add(tls_sock.version())
            times.append((time.perf_counter() - start) * 1000)
            success += 1
        except Exception:
            pass
    loss = round((1 - success / count) * 100, 1) if count else 100.0
    avg = round(sum(times) / len(times), 1) if times else float('inf')
    result = {
        "ip": ip, "packet_loss": loss, "avg_ping": avg,
        "status": "Online" if success > 0 else "Offline",
        "success": success, "count": count,
        "tls_version": "/".join(sorted(negotiated_versions)) if negotiated_versions else "-",
    }
    result.update(_ping_stats(times))
    return result


def browser_tls_ping(ip, port, sni, count, max_timeout, impersonate="chrome"):
    """TLS-handshake `ip:port` using `sni` as the SNI/Host, but with a REAL
    browser TLS fingerprint (JA3/JA4 + extension order), via curl_cffi
    (a binding for curl-impersonate, BoringSSL under the hood - not
    Python's OpenSSL). This is the same class of ClientHello that
    Xray/V2Ray sends when your REALITY client config uses
    fingerprint (fp) = chrome / safari / firefox / etc.

    CURLOPT_RESOLVE pins `sni:port` to `ip` so curl connects to the exact
    IP you're testing while still sending `sni` as both the Host header
    and the TLS SNI - exactly how a REALITY client reaches a specific
    destination IP while pretending to be that domain.

    CURLOPT_CONNECT_ONLY stops curl right after the TCP+TLS handshake
    completes - no HTTP request/response is sent, so this measures the
    handshake only, same as the plain-TLS version above.

    IMPORTANT: same caveat as tls_handshake_ping - a successful handshake
    here proves the SNI/IP/port combo is TLS-reachable with a realistic
    browser fingerprint, but it still isn't a REALITY protocol validation
    (no X25519/public-key/shortId check happens). Use it to rule targets
    IN or OUT for further testing in your real client, not as a final
    verdict on whether a REALITY config will work end-to-end.
    """
    if not HAVE_CURL_CFFI:
        raise RuntimeError(
            "curl_cffi is not installed. Run: pip install curl_cffi --break-system-packages "
            "(or just: pip install curl_cffi)"
        )

    timeout = max_timeout / 1000
    times, success = [], 0
    url = f"https://{sni}:{port}/".encode()
    resolve_entry = f"{sni}:{port}:{ip}".encode()

    for _ in range(count):
        c = Curl()
        try:
            c.setopt(CurlOpt.URL, url)
            c.setopt(CurlOpt.RESOLVE, [resolve_entry])
            c.setopt(CurlOpt.CONNECT_ONLY, 1)
            c.setopt(CurlOpt.CONNECTTIMEOUT_MS, int(max_timeout))
            c.setopt(CurlOpt.TIMEOUT_MS, int(max_timeout))
            c.setopt(CurlOpt.SSL_VERIFYPEER, 0)
            c.setopt(CurlOpt.SSL_VERIFYHOST, 0)
            c.impersonate(impersonate)

            start = time.perf_counter()
            c.perform()
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)
            success += 1
        except Exception:
            pass
        finally:
            c.close()

    loss = round((1 - success / count) * 100, 1) if count else 100.0
    avg = round(sum(times) / len(times), 1) if times else float('inf')
    result = {
        "ip": ip, "packet_loss": loss, "avg_ping": avg,
        "status": "Online" if success > 0 else "Offline",
        "success": success, "count": count,
        "fingerprint": impersonate,
    }
    result.update(_ping_stats(times))
    return result


def alpn_probe(ip, port, sni, timeout_s=3.0):
    """Single best-effort ALPN probe using a plain OpenSSL ClientHello
    (NOT browser-fingerprinted). This is purely informational - some
    REALITY/anti-censorship setups react differently to a generic hello
    than to a real browser one, so a mismatch here doesn't necessarily
    mean anything is wrong. Returns the negotiated ALPN protocol string
    (e.g. "h2", "http/1.1") or None if the handshake failed or no ALPN
    was negotiated."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            return None
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            with ctx.wrap_socket(sock, server_hostname=sni) as tls_sock:
                return tls_sock.selected_alpn_protocol()
    except Exception:
        return None


def sni_target_test(connect_host, port, sni, count, max_timeout, impersonate="chrome"):
    """The real per-(target, SNI) test used by SNI/REALITY mode. Unlike a
    single browser_tls_ping call, this reports TCP reachability and
    TLS+SNI reachability SEPARATELY, since they can legitimately disagree
    (e.g. DPI/firewalls that let a real-looking TLS ClientHello through
    but drop/reset a bare TCP probe, or vice versa) - collapsing them into
    one Online/Offline value hides exactly the kind of mismatch you were
    asking about (a config that reaches your server on 8007 with a real
    REALITY handshake, while a bare socket.connect() to 8007 times out).

    Returns a dict with the TLS result's usual keys (ip, packet_loss,
    avg_ping, status, jitter, ...) as the PRIMARY result - used for
    sorting/ranking, unchanged from before - plus:
      tcp_status / tcp_packet_loss / tcp_avg_ping : raw TCP-only reachability
      alpn        : best-effort ALPN from a single generic-client probe (may be None)
      verdict     : a short human label combining TCP + TLS results

    Still NOT a REALITY handshake validation (see browser_tls_ping) - the
    verdict tells you whether the SNI/IP/port combo is worth trying in
    your real client, not that REALITY itself will succeed.
    """
    tcp_res = tcp_handshake_ping(connect_host, port, count, max_timeout)
    tls_res = browser_tls_ping(connect_host, port, sni, count, max_timeout, impersonate)
    alpn = alpn_probe(connect_host, port, sni, timeout_s=max(max_timeout / 1000, 1.0))

    tcp_online = tcp_res["status"] == "Online"
    tls_online = tls_res["status"] == "Online"
    if tls_online and tcp_online:
        verdict = "GOOD TARGET"
    elif tls_online and not tcp_online:
        verdict = "VALID TLS TARGET"   # TLS+SNI works even though a bare TCP probe didn't
    elif not tls_online and tcp_online:
        verdict = "TCP OK / TLS FAILED"
    else:
        verdict = "OFFLINE"

    result = dict(tls_res)  # TLS stats stay primary (status/avg_ping/jitter/etc.)
    result["tcp_status"] = tcp_res["status"]
    result["tcp_packet_loss"] = tcp_res["packet_loss"]
    result["tcp_avg_ping"] = tcp_res["avg_ping"]
    result["alpn"] = alpn or "-"
    result["verdict"] = verdict
    return result


BROWSER_FINGERPRINTS = [
    "chrome", "chrome124", "chrome131", "chrome136",
    "safari", "safari_ios", "firefox",
]
