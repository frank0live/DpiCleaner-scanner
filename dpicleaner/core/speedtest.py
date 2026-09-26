"""Throughput measurement through a live REALITY tunnel."""

import os
import time

from .netprobe import Curl, CurlOpt
from .xraycore import (XRAY_LOCAL_HOST, _find_free_local_port,
                       run_xray_process, stop_xray_process)
from .reality import build_xray_client_config


SPEEDTEST_DEFAULT_DOWNLOAD_MB = "20"


SPEEDTEST_DEFAULT_UPLOAD_MB = "10"


SPEEDTEST_DEFAULT_HOST = "speed.cloudflare.com"


SPEEDTEST_DOWNLOAD_PATH = "/__down?bytes={bytes}"


SPEEDTEST_UPLOAD_PATH = "/__up"


def high_accuracy_speed_test(xray_path, vless_params, target_ip, target_port, sni,
                              download_mb, upload_mb, timeout_ms=15000):
    """High Accuracy speed test: spins up a REAL xray-core VLESS/Trojan
    +REALITY client tunnel to target_ip:target_port using `sni` as
    serverName, then measures real download/upload throughput of
    speed.cloudflare.com THROUGH that tunnel's local SOCKS proxy.

    This only produces a meaningful result if target_ip:target_port is
    actually your own REALITY server (matching the publicKey/shortId in
    vless_params) - against any other server the REALITY handshake will
    simply fail (which is reported as an error, not a crash).
    """
    result = {"ip": sni, "download_mbps": 0.0, "upload_mbps": 0.0,
              "download_ok": False, "upload_ok": False, "error": None}

    if not xray_path or not os.path.isfile(xray_path):
        result["error"] = f"xray binary not found at: {xray_path}"
        return result

    local_port = _find_free_local_port()
    config = build_xray_client_config(vless_params, target_ip, target_port, sni, local_port)
    process, config_path, ok, err = run_xray_process(xray_path, config)
    if not ok:
        result["error"] = err
        return result

    try:
        proxy_url = f"socks5h://{XRAY_LOCAL_HOST}:{local_port}"
        timeout_s_ms = timeout_ms

        # ---- Download (through the tunnel) ----
        try:
            download_bytes = int(download_mb * 1024 * 1024)
            path = SPEEDTEST_DOWNLOAD_PATH.format(bytes=download_bytes)
            url = f"https://{SPEEDTEST_DEFAULT_HOST}{path}".encode()
            counted = {"n": 0}

            def on_write(chunk):
                counted["n"] += len(chunk)
                return len(chunk)

            c = Curl()
            try:
                c.setopt(CurlOpt.URL, url)
                c.setopt(CurlOpt.PROXY, proxy_url.encode())
                c.setopt(CurlOpt.CONNECTTIMEOUT_MS, int(timeout_s_ms))
                c.setopt(CurlOpt.TIMEOUT_MS, int(timeout_s_ms) * 4)
                c.setopt(CurlOpt.WRITEFUNCTION, on_write)
                start = time.perf_counter()
                c.perform()
                elapsed = time.perf_counter() - start
                if counted["n"] > 0 and elapsed > 0:
                    result["download_mbps"] = round((counted["n"] * 8 / 1_000_000) / elapsed, 2)
                    result["download_ok"] = True
            finally:
                c.close()
        except Exception as e:
            result["error"] = f"download failed: {e}"

        # ---- Upload (through the tunnel) ----
        try:
            upload_bytes = int(upload_mb * 1024 * 1024)
            payload = os.urandom(min(upload_bytes, 1024 * 1024))
            sent = {"n": 0}

            def on_read(size):
                remaining = upload_bytes - sent["n"]
                if remaining <= 0:
                    return b""
                chunk = payload[:min(size, remaining, len(payload))]
                if not chunk:
                    chunk = b"\0" * min(size, remaining)
                sent["n"] += len(chunk)
                return chunk

            url = f"https://{SPEEDTEST_DEFAULT_HOST}{SPEEDTEST_UPLOAD_PATH}".encode()
            c = Curl()
            try:
                c.setopt(CurlOpt.URL, url)
                c.setopt(CurlOpt.PROXY, proxy_url.encode())
                c.setopt(CurlOpt.CONNECTTIMEOUT_MS, int(timeout_s_ms))
                c.setopt(CurlOpt.TIMEOUT_MS, int(timeout_s_ms) * 4)
                c.setopt(CurlOpt.UPLOAD, 1)
                c.setopt(CurlOpt.INFILESIZE, upload_bytes)
                c.setopt(CurlOpt.READFUNCTION, on_read)
                start = time.perf_counter()
                c.perform()
                elapsed = time.perf_counter() - start
                if sent["n"] > 0 and elapsed > 0:
                    result["upload_mbps"] = round((sent["n"] * 8 / 1_000_000) / elapsed, 2)
                    result["upload_ok"] = True
            finally:
                c.close()
        except Exception as e:
            prev = result["error"]
            result["error"] = (prev + "; " if prev else "") + f"upload failed: {e}"

    finally:
        stop_xray_process(process, config_path)

    return result
