"""REALITY link parsing, real-handshake SNI validation, verdicts."""

import json
import os
import time
import urllib.parse

from .netprobe import (Curl, CurlOpt, CurlInfo, HAVE_CURL_CFFI, check_port,
                       tcp_handshake_ping)
from .xraycore import (XRAY_LOCAL_HOST, XRAY_TUNNEL_READY_TIMEOUT_S,
                       _find_free_local_port, run_xray_process,
                       stop_xray_process)


REALITY_TCP_PRECHECK_ATTEMPTS = 3


REALITY_TCP_PRECHECK_MIN_TIMEOUT_MS = 3000


REALITY_PROBE_URL = "http://cp.cloudflare.com/generate_204"


REALITY_VERDICT_RANK = {"VALID": 0, "FLAKY": 1, "INVALID": 2, "PROBE_TIMEOUT": 3, "TIMEOUT": 4, "NETWORK_ERROR": 5}


def parse_reality_link(config_link):
    """Parse a vless:// or trojan:// link that uses REALITY (security=reality)
    into the fields needed to build an xray client outbound.

    Returns a dict with: protocol ('vless' or 'trojan'), uuid (vless only) /
    password (trojan only), address, port, flow, fingerprint, public_key,
    short_id, spider_x, network, sni, error.
    `error` is None on success, or a short human-readable message
    ("Not a vless:///trojan:// link", "Missing REALITY publicKey", ...) on
    failure.
    """
    out = {"error": None}
    try:
        if config_link.startswith("vless://"):
            protocol = "vless"
        elif config_link.startswith("trojan://"):
            protocol = "trojan"
        else:
            return {"error": "This is not a vless:// or trojan:// link."}

        parsed = urllib.parse.urlparse(config_link)
        if '@' not in parsed.netloc:
            return {"error": "Link is missing the credentials@host part."}
        userinfo, hostport = parsed.netloc.rsplit('@', 1)
        if ':' not in hostport:
            return {"error": "Link is missing a port."}
        address, port_s = hostport.rsplit(':', 1)
        out["protocol"] = protocol
        out["address"] = address
        out["port"] = int(port_s)
        if protocol == "vless":
            out["uuid"] = userinfo
        else:  # trojan
            out["password"] = urllib.parse.unquote(userinfo)

        q = urllib.parse.parse_qs(parsed.query)
        def first(key, default=""):
            v = q.get(key)
            return v[0] if v else default

        security = first("security", "").lower()
        if security != "reality":
            return {"error": f"Link security is '{security or 'none'}', not 'reality'. "
                              f"High Accuracy speed test only supports REALITY configs."}

        pbk = first("pbk")
        if not pbk:
            return {"error": "Link is missing the REALITY Public Key (pbk=...)."}

        out["network"] = first("type", "tcp")
        out["flow"] = first("flow", "") if protocol == "vless" else ""
        out["fingerprint"] = first("fp", "chrome")
        out["public_key"] = pbk
        out["short_id"] = first("sid", "")
        out["spider_x"] = first("spx", "")
        out["sni"] = first("sni", "")
        out["error"] = None
        return out
    except Exception as e:
        return {"error": f"Could not parse link: {e}"}


parse_vless_reality_link = parse_reality_link


def build_xray_client_config(vless_params, target_ip, target_port, sni, local_socks_port):
    """Build a minimal xray-core JSON config: one SOCKS inbound on
    127.0.0.1:local_socks_port, and one VLESS or Trojan (+REALITY) outbound
    pointed at target_ip:target_port using `sni` as the REALITY serverName
    (so we can test several SNI candidates against the same server)."""
    protocol = vless_params.get("protocol", "vless")

    if protocol == "trojan":
        outbound_settings = {
            "servers": [{
                "address": target_ip,
                "port": target_port,
                "password": vless_params["password"]
            }]
        }
    else:
        outbound_settings = {
            "vnext": [{
                "address": target_ip,
                "port": target_port,
                "users": [{
                    "id": vless_params["uuid"],
                    "encryption": "none",
                    "flow": vless_params.get("flow", "")
                }]
            }]
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": XRAY_LOCAL_HOST,
            "port": local_socks_port,
            "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"},
            "sniffing": {"enabled": False}
        }],
        "outbounds": [{
            "protocol": protocol,
            "settings": outbound_settings,
            "streamSettings": {
                "network": vless_params.get("network", "tcp"),
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": vless_params.get("fingerprint", "chrome"),
                    "publicKey": vless_params["public_key"],
                    "shortId": vless_params.get("short_id", ""),
                    "spiderX": vless_params.get("spider_x", "")
                }
            }
        }]
    }


def reality_probe_through_tunnel(local_socks_port, timeout_ms=6000):
    """Send one lightweight HTTP request THROUGH an already-up xray SOCKS
    tunnel to confirm the REALITY handshake was actually accepted on the
    server side (see module-level note above for why this is necessary -
    "TLS completed" is not the same as "REALITY accepted").

    Returns (ok: bool, error: str|None). ok=True only when the request
    through the tunnel actually completed with a plausible HTTP status;
    any connection reset, timeout, or proxy error is treated as a
    rejected/fallback REALITY session, not a network glitch - both
    because that IS the expected client-visible symptom of rejection,
    and because callers already ran a TCP precheck before this stage,
    so most sources of "genuine" network failure are already excluded.
    """
    if not HAVE_CURL_CFFI:
        return False, "curl_cffi not installed"
    proxy_url = f"socks5h://{XRAY_LOCAL_HOST}:{local_socks_port}"
    c = Curl()
    try:
        c.setopt(CurlOpt.URL, REALITY_PROBE_URL.encode())
        c.setopt(CurlOpt.PROXY, proxy_url.encode())
        c.setopt(CurlOpt.CONNECTTIMEOUT_MS, int(timeout_ms))
        c.setopt(CurlOpt.TIMEOUT_MS, int(timeout_ms))
        c.setopt(CurlOpt.SSL_VERIFYPEER, 0)
        c.setopt(CurlOpt.SSL_VERIFYHOST, 0)
        c.perform()
        status = None
        try:
            status = c.getinfo(CurlInfo.RESPONSE_CODE)
        except Exception:
            pass
        if status is not None and 200 <= int(status) < 400:
            return True, None
        return False, f"unexpected response through tunnel (status={status})"
    except Exception as e:
        return False, str(e)
    finally:
        c.close()


def _classify_probe_error(error_text):
    text=(error_text or "").lower()
    if any(x in text for x in ("timed out","timeout","operation timed out","curl error 28")):
        return "PROBE_TIMEOUT"
    if any(x in text for x in ("connection reset","connection refused","proxy error",
                               "could not connect","failed to connect","recv failure")):
        return "REALITY_REJECTED_OR_FALLBACK"
    return "PROBE_ERROR"


def reality_sni_test(xray_path,vless_params,connect_host,connect_port,sni,attempts,
                     tcp_timeout_ms,xray_ready_timeout_s=XRAY_TUNNEL_READY_TIMEOUT_S,
                     probe_timeout_ms=6000):
    precheck_timeout_ms=max(tcp_timeout_ms,REALITY_TCP_PRECHECK_MIN_TIMEOUT_MS)
    tcp_res=tcp_handshake_ping(connect_host,connect_port,REALITY_TCP_PRECHECK_ATTEMPTS,precheck_timeout_ms)
    tcp_ok=tcp_res["success"]>0
    result={"sni":sni,"connect_host":connect_host,"connect_port":connect_port,
            "tcp":{"ok":tcp_ok,"latency_ms":tcp_res["avg_ping"] if tcp_ok else None,
                   "success":tcp_res["success"],"attempts":tcp_res["count"]},
            "reality":{"attempts":0,"success":0,"failed":0,"timeouts":0,"network_errors":0,
                       "latencies":[],"avg_ms":None,"jitter_ms":None},
            "verdict":"NETWORK_ERROR","failure_reason":None,"attempt_diagnostics":[],"last_error":None}
    if not tcp_ok:
        result["failure_reason"]="TCP_PRECHECK_FAILED"
        result["last_error"]=(f"TCP_PRECHECK_FAILED: {connect_host}:{connect_port} failed all "
                              f"{REALITY_TCP_PRECHECK_ATTEMPTS} attempts ({precheck_timeout_ms}ms each).")
        return result
    if not xray_path or not os.path.isfile(xray_path):
        result["failure_reason"]="XRAY_BINARY_ERROR"
        result["last_error"]=f"XRAY_BINARY_ERROR: binary not found at {xray_path}"
        return result

    success=failed=timeouts=network_errors=0
    latencies=[]; diagnostics=[]
    for n in range(1,max(1,attempts)+1):
        result["reality"]["attempts"]+=1
        local_port=_find_free_local_port()
        config=build_xray_client_config(vless_params,connect_host,connect_port,sni,local_port)
        process,config_path,ok,err=run_xray_process(xray_path,config,ready_timeout=xray_ready_timeout_s)
        if not ok:
            cat="XRAY_START_TIMEOUT" if err and "XRAY_START_TIMEOUT:" in err else "XRAY_START_ERROR"
            if cat=="XRAY_START_TIMEOUT": timeouts+=1
            else: network_errors+=1
            diagnostics.append({"attempt":n,"phase":"xray_start","category":cat,
                                "error":err or "unknown Xray startup error"})
            stop_xray_process(None,config_path)
            continue
        try:
            started=time.perf_counter()
            probe_ok,probe_err=reality_probe_through_tunnel(local_port,probe_timeout_ms)
            elapsed=(time.perf_counter()-started)*1000
            if probe_ok:
                success+=1; latencies.append(elapsed)
                diagnostics.append({"attempt":n,"phase":"reality_probe","category":"VALID",
                                    "error":None,"latency_ms":round(elapsed,1)})
            else:
                failed+=1; cat=_classify_probe_error(probe_err)
                diagnostics.append({"attempt":n,"phase":"reality_probe","category":cat,
                                    "error":probe_err or "unknown probe failure",
                                    "latency_ms":round(elapsed,1)})
        finally:
            stop_xray_process(process,config_path)

    r=result["reality"]
    r.update({"success":success,"failed":failed,"timeouts":timeouts,"network_errors":network_errors,
              "latencies":[round(x,1) for x in latencies]})
    if latencies:
        r["avg_ms"]=round(sum(latencies)/len(latencies),1)
        r["jitter_ms"]=round(sum(abs(latencies[i]-latencies[i-1]) for i in range(1,len(latencies)))/
                             (len(latencies)-1),1) if len(latencies)>1 else 0.0

    total=r["attempts"]
    if success==total and success>0:
        verdict,reason="VALID",None
    elif success>0:
        verdict,reason="FLAKY","MIXED_ATTEMPTS"
    elif total>0 and timeouts==total:
        verdict,reason="TIMEOUT","XRAY_START_TIMEOUT"
    else:
        probe_cats=[d["category"] for d in diagnostics if d["phase"]=="reality_probe"]
        if probe_cats and all(x=="PROBE_TIMEOUT" for x in probe_cats):
            verdict,reason="PROBE_TIMEOUT","REALITY_PROBE_TIMEOUT"
        elif total>0 and network_errors==total:
            verdict,reason="NETWORK_ERROR","XRAY_START_ERROR"
        else:
            verdict,reason="INVALID",(probe_cats[-1] if probe_cats else "REALITY_REJECTED_OR_FALLBACK")
    result["verdict"]=verdict
    result["failure_reason"]=reason
    result["attempt_diagnostics"]=diagnostics
    result["last_error"]=diagnostics[-1].get("error") if diagnostics else None
    return result


def reality_result_to_row(res):
    """Adapt a reality_sni_test() result into the same row shape the
    existing results table / sort / export code already understands, so
    real REALITY validation can reuse that UI instead of needing a
    parallel one. `ip`/'domain' column carries the SNI (as before),
    `status` mirrors REALITY success (not generic TLS), and `verdict`
    is now one of VALID/FLAKY/INVALID/TIMEOUT/NETWORK_ERROR rather than
    the old GOOD/OFFLINE-style labels."""
    reality = res["reality"]
    attempts = reality["attempts"] or 1
    success = reality["success"]
    avg = reality.get("avg_ms")
    jitter = reality.get("jitter_ms")
    loss = round((1 - success / attempts) * 100, 1) if attempts else 100.0
    row = {
        "ip": res["sni"],
        "packet_loss": loss,
        "avg_ping": avg if avg is not None else float('inf'),
        "status": "Online" if success > 0 else "Offline",
        "success": success,
        "count": attempts,
        "jitter": jitter,
        "min_ping": None, "max_ping": None, "stddev": None,
        "tcp_status": "Online" if res["tcp"]["ok"] else "Offline",
        "tcp_packet_loss": 0.0 if res["tcp"]["ok"] else 100.0,
        "tcp_avg_ping": res["tcp"]["latency_ms"] if res["tcp"]["ok"] else float('inf'),
        "alpn": "-",
        "verdict": res["verdict"],
        "failure_reason": res.get("failure_reason"),
        "connect_host": res["connect_host"],
        "port": res["connect_port"],
        "reality_last_error": res.get("last_error"),
        "attempt_diagnostics": res.get("attempt_diagnostics", []),
    }
    return row


def reality_sort_key(row):
    """Ranking key for REALITY-validated rows: VALID beats FLAKY beats
    TIMEOUT/NETWORK_ERROR beats INVALID, no matter the latency - only
    WITHIN the same verdict tier do we then sort by speed/jitter. This
    is the fix for the old bug where a low-latency INVALID SNI could
    outrank a slightly-slower VALID one."""
    rank = REALITY_VERDICT_RANK.get(row.get("verdict"), 5)
    ping = row["avg_ping"] if row["avg_ping"] != float('inf') else float('inf')
    jitter = row.get("jitter")
    jitter = jitter if jitter is not None else float('inf')
    return (rank, ping, jitter)
