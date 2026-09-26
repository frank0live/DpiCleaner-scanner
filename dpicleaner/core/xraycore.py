"""xray-core acquisition and the local tunnel process lifecycle."""

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from .netprobe import check_port


XRAY_PINNED_VERSION = "v26.9.8"


XRAY_GITHUB_API = "https://api.github.com/repos/XTLS/Xray-core/releases/tags/"


XRAY_LOCAL_HOST = "127.0.0.1"


XRAY_TUNNEL_READY_TIMEOUT_S = 12.0


XRAY_SOCKS_PORT_RANGE = (18080, 18980)


def find_xray_binary():
    """Find a usable Xray binary in PATH."""
    for name in ("xray", "xray.exe", "Xray", "Xray.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _xray_cache_dir():
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    return base / "xray-core"


def _xray_asset_name():
    system, machine = platform.system().lower(), platform.machine().lower()
    if system == "windows":
        return "Xray-windows-64.zip" if machine in ("amd64", "x86_64") else "Xray-windows-32.zip"
    if system == "darwin":
        return "Xray-macos-arm64-v8a.zip" if machine in ("arm64", "aarch64") else "Xray-macos-64.zip"
    if system == "linux":
        if machine in ("arm64", "aarch64"):
            return "Xray-linux-arm64-v8a.zip"
        if machine in ("386", "i386", "i686"):
            return "Xray-linux-32.zip"
        return "Xray-linux-64.zip"
    raise RuntimeError(f"Unsupported platform: {platform.system()} / {platform.machine()}")


def _run_xray_version(path):
    try:
        cp=subprocess.run([path,"version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, timeout=8,
                          creationflags=(0x08000000 if os.name=="nt" else 0))
        text=(cp.stdout or "").strip()
        return (cp.returncode==0, text[-1500:] or f"exit code {cp.returncode}")
    except Exception as e:
        return False, str(e)


def ensure_xray_binary(force_download=False):
    """Return a verified Xray path; download pinned release if needed."""
    found=find_xray_binary()
    if found and not force_download:
        ok,detail=_run_xray_version(found)
        if ok: return found,detail

    cache=_xray_cache_dir()
    cache.mkdir(parents=True,exist_ok=True)
    exe=cache/("xray.exe" if os.name=="nt" else "xray")

    if exe.is_file() and not force_download:
        if os.name!="nt":
            try: exe.chmod(exe.stat().st_mode|0o111)
            except Exception: pass
        ok,detail=_run_xray_version(str(exe))
        if ok: return str(exe),detail

    asset_name=_xray_asset_name()
    api=XRAY_GITHUB_API+XRAY_PINNED_VERSION
    try:
        req=urllib.request.Request(api,headers={"Accept":"application/vnd.github+json","User-Agent":"DPI-Cleaner-Scanner"})
        with urllib.request.urlopen(req,timeout=20) as r:
            release=json.loads(r.read().decode("utf-8"))
        asset=next((x for x in release.get("assets",[]) if x.get("name")==asset_name),None)
        if not asset:
            raise RuntimeError(f"Asset {asset_name} not found in {XRAY_PINNED_VERSION}")

        archive=cache/asset_name
        req=urllib.request.Request(asset["browser_download_url"],headers={"User-Agent":"DPI-Cleaner-Scanner"})
        with urllib.request.urlopen(req,timeout=90) as r, open(archive,"wb") as f:
            shutil.copyfileobj(r,f)

        with zipfile.ZipFile(archive,"r") as z:
            member=next((m for m in z.namelist() if Path(m).name.lower() in ("xray","xray.exe")),None)
            if not member: raise RuntimeError("Downloaded archive contains no xray executable")
            with z.open(member) as srcf, open(exe,"wb") as dstf:
                shutil.copyfileobj(srcf,dstf)
        try: archive.unlink()
        except Exception: pass
        if os.name!="nt":
            exe.chmod(exe.stat().st_mode|0o111)

        ok,detail=_run_xray_version(str(exe))
        if not ok:
            try: exe.unlink()
            except Exception: pass
            raise RuntimeError(f"Downloaded Xray self-test failed: {detail}")
        return str(exe),detail
    except Exception as e:
        raise RuntimeError(f"Automatic Xray setup failed ({XRAY_PINNED_VERSION}/{asset_name}): {e}") from e


def _find_free_local_port(port_range=XRAY_SOCKS_PORT_RANGE):
    """Find a free TCP port on 127.0.0.1 within port_range. Falls back
    to letting the OS pick an ephemeral port if the whole range is busy."""
    lo, hi = port_range
    for port in range(lo, hi):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((XRAY_LOCAL_HOST, port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((XRAY_LOCAL_HOST, 0))
        return s.getsockname()[1]


def run_xray_process(xray_path, config_dict, ready_timeout=XRAY_TUNNEL_READY_TIMEOUT_S):
    """Start Xray and preserve stderr/stdout when startup fails."""
    import tempfile
    config_path=None
    process=None
    try:
        if not xray_path or not os.path.isfile(xray_path):
            return None,None,False,f"XRAY_BINARY_ERROR: binary not found: {xray_path}"
        fd,config_path=tempfile.mkstemp(prefix="dpicleaner_xray_",suffix=".json")
        with os.fdopen(fd,"w",encoding="utf-8") as f: json.dump(config_dict,f)
        flags=0x08000000 if os.name=="nt" else 0
        process=subprocess.Popen([xray_path,"run","-c",config_path],
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 creationflags=flags)
        port=config_dict["inbounds"][0]["port"]
        deadline=time.monotonic()+ready_timeout
        while time.monotonic()<deadline:
            rc=process.poll()
            if rc is not None:
                try: out,err=process.communicate(timeout=1)
                except Exception: out,err=b"",b""
                text=((err or b"").decode("utf-8","replace").strip() or
                      (out or b"").decode("utf-8","replace").strip())
                return None,config_path,False,(f"XRAY_START_ERROR: xray exited before SOCKS "
                    f"became ready (exit_code={rc}). Output:\n{text[-5000:] or 'no output'}")
            if check_port(XRAY_LOCAL_HOST,port,timeout=0.2):
                return process,config_path,True,None
            time.sleep(0.10)
        try:
            process.terminate(); out,err=process.communicate(timeout=3)
        except Exception:
            try: process.kill(); out,err=process.communicate(timeout=2)
            except Exception: out,err=b"",b""
        text=((err or b"").decode("utf-8","replace").strip() or
              (out or b"").decode("utf-8","replace").strip())
        return None,config_path,False,(f"XRAY_START_TIMEOUT: SOCKS {XRAY_LOCAL_HOST}:{port} "
            f"did not become ready within {ready_timeout:.1f}s. Xray output:\n"
            f"{text[-5000:] or 'no stderr/stdout output; process stayed alive'}")
    except FileNotFoundError:
        return None,config_path,False,f"XRAY_BINARY_ERROR: executable not found: {xray_path}"
    except PermissionError as e:
        return None,config_path,False,f"XRAY_BINARY_ERROR: permission denied: {e}"
    except Exception as e:
        return None,config_path,False,f"XRAY_LAUNCH_ERROR: {type(e).__name__}: {e}"


def stop_xray_process(process, config_path):
    """Terminate the xray process (if still running) and always delete
    the temp config file, since it contains REALITY connection secrets."""
    try:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except Exception:
                process.kill()
    except Exception:
        pass
    if config_path:
        try:
            os.remove(config_path)
        except Exception:
            pass
