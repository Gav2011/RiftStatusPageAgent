#!/usr/bin/env python3
"""
Rift status monitor - a tiny ping node.
"""
import sys
if sys.version_info < (3, 5):
    sys.stderr.write("Rift monitor needs Python 3.5 or newer.\n")
    sys.exit(1)

import json, os, time, ssl, socket, argparse, subprocess, urllib.request, urllib.error
import http.client
from urllib.parse import urlsplit

__version__ = "1.0.2"

BASE         = "https://rift.modeminc.com/status"
ENROLL_TOKEN = "rmon_b90e9f136bf210fd3f73511e01eda5ee"   # shared bootstrap gate (the CODE is the real auth)

VERSION_URL       = "https://raw.githubusercontent.com/Gav2011/Versions/refs/heads/main/RiftApps"
VERSION_KEY       = "RiftStatusPageAgent"          # key name in that file for this script
UPDATE_CHECK_SECS = 6 * 3600                        # how often the running service rechecks for updates

_insecure = os.environ.get("RIFT_MONITOR_INSECURE") == "1"


def config_path():
    env = os.environ.get("RIFT_MONITOR_CONFIG")
    if env:
        return env
    if os.name == "nt":  # Windows
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "RiftMonitor", "config.json")
    return os.path.join(os.path.expanduser("~"), ".config", "rift-monitor", "config.json")


def _ctx():
    # Verified by default; fall back to an unverified context on systems with no CA bundle
    # (some routers) or when RIFT_MONITOR_INSECURE=1.
    if _insecure:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_TLS_CLIENT") else ssl.PROTOCOL_TLS)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    try:
        return ssl.create_default_context()
    except Exception:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS if hasattr(ssl, "PROTOCOL_TLS") else ssl.PROTOCOL_SSLv23)
        return c


def _open(req, timeout):
    global _insecure
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=_ctx())
    except urllib.error.URLError as e:
        # No CA bundle -> retry once without verification, then stick with it.
        if isinstance(getattr(e, "reason", None), ssl.SSLError) and not _insecure:
            _insecure = True
            sys.stderr.write("warn: TLS cert not verifiable here - continuing without verification.\n")
            return urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        raise


def api_request(method, path, headers=None, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    # Cloudflare bans the default "Python-urllib" UA (error 1010) - always send our own.
    req.add_header("User-Agent", "Rift-Monitor/1.0")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with _open(req, timeout) as r:
        return r.status, json.loads((r.read().decode() or "{}"))


def _version_tuple(v):
    parts = []
    for p in (v or "").strip().split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _parse_version_file(text):
    """Format: blank lines and lines starting with // are ignored; everything else is KEY=VALUE."""
    info = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        info[k.strip()] = v.strip()
    return info


def check_for_update():
    """Returns (new_version, download_url) if a newer version is published, else None.
    Never raises - a failed/slow update check should never take the monitor down."""
    try:
        req = urllib.request.Request(VERSION_URL, headers={"User-Agent": "Rift-Monitor/1.0"})
        with _open(req, 10) as r:
            text = r.read().decode("utf-8", "replace")
        info = _parse_version_file(text)
        remote_v    = info.get(VERSION_KEY)
        remote_link = info.get(VERSION_KEY + "Link")
        if not remote_v or not remote_link or remote_link == "?":
            return None
        if _version_tuple(remote_v) > _version_tuple(__version__):
            return remote_v, remote_link
    except Exception as e:
        sys.stderr.write("warn: update check failed: %s\n" % e)
    return None


def apply_update(new_version, url):
    """Download the new script, make sure it's at least syntactically valid Python, then
    atomically replace this file on disk and re-exec in place (same PID, so systemd/Task
    Scheduler doesn't see it as a crash). Returns False (never raises) if anything looks off,
    so the currently-running version just keeps going."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Rift-Monitor/1.0"})
        with _open(req, 30) as r:
            new_code = r.read()
        try:
            compile(new_code, "rift-monitor.py", "exec")
        except SyntaxError as e:
            sys.stderr.write("warn: downloaded update did not parse as Python, skipping: %s\n" % e)
            return False

        script = os.path.abspath(__file__)
        tmp = script + ".new"
        with open(tmp, "wb") as f:
            f.write(new_code)
        os.replace(tmp, script)   # atomic on POSIX and Windows when same volume
        print("Updated rift-monitor.py %s -> %s. Restarting..." % (__version__, new_version))
        os.execv(sys.executable, [sys.executable, script] + sys.argv[1:])
        # execv replaces this process on success and never returns
    except Exception as e:
        sys.stderr.write("warn: update failed, staying on current version: %s\n" % e)
        return False


def load_config():
    try:
        with open(config_path()) as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        p = config_path()
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(p, "w") as f:
            json.dump(cfg, f, indent=2)
        try:
            os.chmod(p, 0o600)   # best-effort; a no-op on Windows
        except Exception:
            pass
    except Exception as e:
        sys.stderr.write("warn: could not save config: %s\n" % e)


def enroll(args):
    tty      = sys.stdin.isatty()
    code     = args.code or os.environ.get("RIFT_MONITOR_CODE")
    name     = args.name or os.environ.get("RIFT_MONITOR_NAME")
    location = args.location or os.environ.get("RIFT_MONITOR_LOCATION")
    if not code:
        if tty:
            code = input("Enter your monitor code: ").strip()
        else:
            sys.stderr.write("No code. Set RIFT_MONITOR_CODE or pass --code (headless run).\n")
            sys.exit(2)
    if not name:
        name = (input("Name this node (e.g. 'home-server-1'): ").strip() if tty else "") or socket.gethostname()
    if not location:
        location = (input("Where is it located? (e.g. 'Toronto, Canada'): ").strip() if tty else "")
    print("Enrolling '%s'..." % name)
    try:
        _, res = api_request("POST", "/monitor/enroll", {"X-Enroll-Token": ENROLL_TOKEN},
                      {"code": code, "name": name, "location": location})
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except Exception: pass
        try: msg = json.loads(body).get("message") or json.loads(body).get("error") or e.reason
        except Exception: msg = (body[:200].strip() or e.reason)
        sys.stderr.write("Enroll failed (%s): %s\n" % (e.code, msg))
        if e.code == 403:
            sys.stderr.write("-> The code isn't valid/created yet. Make it in Admin -> Platform -> Status monitor nodes.\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write("Enroll failed: %s\n" % e)
        sys.exit(1)
    cfg = {"token": res["token"], "monitor_id": res["monitor_id"],
           "interval": int(res.get("interval", 30)), "targets": res.get("targets", []),
           "name": name, "location": location}
    save_config(cfg)
    print("Enrolled as '%s' (id %s). Saved to %s" % (name, res["monitor_id"], config_path()))
    return cfg


_conn_cache = {}   # (scheme, host, path) -> http.client.HTTPConnection/HTTPSConnection, reused across pings
                    # so we're not paying a fresh TCP+TLS handshake on every single ping -
                    # that overhead was inflating latency readings 3-4x vs. real network RTT.
                    # Keyed per-path (not just per-host) because different targets on the same
                    # host (e.g. a plain-HTTP health check vs. a WebSocket upgrade endpoint) can
                    # leave a shared keep-alive connection in a broken state for every other
                    # target that reuses it. Isolating by path contains a bad target to itself.

_debug = os.environ.get("RIFT_MONITOR_DEBUG") == "1"


def _get_conn(scheme, host, path, timeout):
    key = (scheme, host, path)
    conn = _conn_cache.get(key)
    if conn is None:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, timeout=timeout, context=_ctx())
        else:
            conn = http.client.HTTPConnection(host, timeout=timeout)
        _conn_cache[key] = conn
    return conn


def _do_ping_request(scheme, host, path, timeout):
    conn = _get_conn(scheme, host, path, timeout)
    conn.request("GET", path, headers={"User-Agent": "Rift-Monitor/1.0", "Connection": "keep-alive"})
    r = conn.getresponse()
    r.read()   # drain the body so the connection is reusable for the next ping
    return r.status


def ping(url, timeout=10):
    """(milliseconds, up). up = host answered at all (even 4xx); only 5xx / no answer = down.
    Reuses a persistent connection per (host, path) so steady-state pings measure real
    request/response round-trip time instead of repeated TCP+TLS handshake overhead. The very
    first ping to a target still pays that setup cost once, same as a browser would on first
    load. Connections are isolated per path so one misbehaving target (e.g. a plain GET against
    a WebSocket-upgrade endpoint) can't poison the keep-alive connection used by other targets
    on the same host."""
    parts = urlsplit(url)
    host = parts.netloc
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    key = (parts.scheme, host, path)
    t0 = time.time()
    try:
        status = _do_ping_request(parts.scheme, host, path, timeout)
        return (time.time() - t0) * 1000, (status < 500)
    except Exception as e1:
        # Connection may be stale (server closed idle keep-alive) or this is the first attempt -
        # drop it and retry once fresh before calling it down.
        old = _conn_cache.pop(key, None)
        if old is not None:
            try: old.close()
            except Exception: pass
        t0 = time.time()
        try:
            status = _do_ping_request(parts.scheme, host, path, timeout)
            return (time.time() - t0) * 1000, (status < 500)
        except Exception as e2:
            _conn_cache.pop(key, None)
            if _debug:
                sys.stderr.write("debug: ping %s failed twice: first=%r retry=%r\n" % (url, e1, e2))
            return (time.time() - t0) * 1000, False


def run(cfg, args):
    token    = cfg["token"]
    interval = int(cfg.get("interval", 30))
    targets  = cfg.get("targets", [])
    auth     = {"Authorization": "Bearer " + token}
    print("Monitoring %d targets every %ds. Ctrl+C to stop." % (len(targets), interval))
    last_refresh = 0
    last_update_check = time.time()   # main() already checked once on startup
    while True:
        if time.time() - last_refresh > 600:   # re-pull targets/interval every ~10 min
            try:
                _, res = api_request("GET", "/monitor/config", auth)
                if res.get("targets"):  targets  = res["targets"];       cfg["targets"]  = targets
                if res.get("interval"): interval = int(res["interval"]); cfg["interval"] = interval
                save_config(cfg)
                last_refresh = time.time()
            except Exception:
                pass

        if os.environ.get("RIFT_MONITOR_NO_UPDATE") != "1" and time.time() - last_update_check > UPDATE_CHECK_SECS:
            last_update_check = time.time()
            upd = check_for_update()
            if upd:
                apply_update(*upd)   # re-execs in place on success; falls through and keeps running on failure

        results = []
        for tg in targets:
            ms, ok = ping(tg["url"])
            results.append({"id": tg["id"], "ms": round(ms, 1), "ok": ok})

        try:
            _, res = api_request("POST", "/monitor/report", auth, {"results": results})
            if res.get("interval"):
                interval = int(res["interval"])
            print(time.strftime("%H:%M:%S"),
                  "  ".join("%s=%.0fms%s" % (r["id"], r["ms"], "" if r["ok"] else " DOWN") for r in results))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print("Token rejected - re-enrolling.")
                cfg = enroll(args); token = cfg["token"]; auth = {"Authorization": "Bearer " + token}
            else:
                print("Report failed:", e.code)
        except Exception as e:
            print("Report failed:", e)

        time.sleep(interval)


# ---------------------------------------------------------------------------
# Linux: systemd service
# ---------------------------------------------------------------------------

def _linux_service_path():
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root:
        return "/etc/systemd/system/rift-monitor.service", True
    return os.path.expanduser("~/.config/systemd/user/rift-monitor.service"), False


def _linux_service_exists():
    path, _ = _linux_service_path()
    return os.path.exists(path)


def install_service(args):
    """Enroll (if needed) then install a systemd service so it runs on boot + auto-restarts.
    Run as root (sudo) for a system service, or as your user for a --user service."""
    if os.name != "posix":
        sys.stderr.write("Linux/systemd only. On Windows use install_windows_task() instead.\n"); sys.exit(2)
    if os.system("command -v systemctl >/dev/null 2>&1") != 0:
        sys.stderr.write("systemd not found (e.g. OpenWrt). Run it with your init instead, or:\n"
                         "  nohup python3 %s --background >/tmp/rift-monitor.log 2>&1 &\n" % os.path.abspath(__file__))
        sys.exit(2)
    cfg = load_config()
    if not cfg.get("token"):
        cfg = enroll(args)   # prompt for code/name/location now, so the service runs headless later
    script = os.path.abspath(__file__)
    py = sys.executable or "python3"
    path, is_root = _linux_service_path()
    unit = ("[Unit]\nDescription=Rift status monitor\nAfter=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nExecStart=%s %s --background\nRestart=always\nRestartSec=15\n\n"
            "[Install]\nWantedBy=%s\n") % (py, script, "multi-user.target" if is_root else "default.target")
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w") as f:
        f.write(unit)
    if is_root:
        os.system("systemctl daemon-reload && systemctl enable --now rift-monitor.service")
        print("Installed as a SYSTEM service. Check it:  systemctl status rift-monitor")
    else:
        os.system("systemctl --user daemon-reload && systemctl --user enable --now rift-monitor.service")
        os.system("loginctl enable-linger \"$USER\" >/dev/null 2>&1")   # keep running after logout
        print("Installed as a USER service. Check it:  systemctl --user status rift-monitor")


# ---------------------------------------------------------------------------
# Windows: scheduled task
# ---------------------------------------------------------------------------

TASK_NAME = "RiftMonitor"


def _windows_task_exists():
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


def install_windows_task(args):
    """Enroll (if needed) then register a Scheduled Task that runs at login, hidden
    (no console window), and keeps running until logoff. On Windows there's no
    always-on daemon manager without extra tooling, so 'runs at login' is the
    practical equivalent of the Linux systemd service."""
    if os.name != "nt":
        sys.stderr.write("Windows only. On Linux use install_service() instead.\n"); sys.exit(2)
    cfg = load_config()
    if not cfg.get("token"):
        cfg = enroll(args)
    script = os.path.abspath(__file__)
    py_dir = os.path.dirname(sys.executable)
    pythonw = os.path.join(py_dir, "pythonw.exe")   # runs with no visible console window
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    tr = '"%s" "%s" --background' % (pythonw, script)
    subprocess.run(["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr,
                     "/SC", "ONLOGON", "/RL", "LIMITED", "/F"], check=False)
    subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], check=False)
    print("Installed as a scheduled task named '%s' (starts at login, runs hidden)." % TASK_NAME)
    print("Check it any time in Task Scheduler, or run:  schtasks /Query /TN %s" % TASK_NAME)


# ---------------------------------------------------------------------------
# First-run prompt: explain what's about to happen, then install if agreed
# ---------------------------------------------------------------------------

def offer_auto_install(args):
    if os.name == "nt":
        proceed = None
        try:
            import ctypes
            text = ("Set up Rift Monitor to run automatically in the background and\n"
                     "start at login? It will keep pinging its targets and reporting\n"
                     "latency even after you close this window.\n\n"
                     "Yes = install it to run in the background\n"
                     "No  = just run once in this window (stops when you close it)")
            MB_YESNO, MB_ICONQUESTION, IDYES = 0x04, 0x20, 6
            res = ctypes.windll.user32.MessageBoxW(0, text, "Rift Monitor Setup", MB_YESNO | MB_ICONQUESTION)
            proceed = (res == IDYES)
        except Exception:
            proceed = None
        if proceed is None:
            ans = input("Install Rift Monitor to run in the background and start at login? [Y/n]: ").strip().lower()
            proceed = ans in ("", "y", "yes")
        if proceed:
            install_windows_task(args)
            print("Done - Rift Monitor is now running in the background. You can close this window.")
            try:
                input("Press Enter to close...")
            except Exception:
                pass
            return
    else:
        ans = input("Install Rift Monitor as a background service that starts on boot? [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            install_service(args)
            print("Done - you can safely close this terminal/SSH session now.")
            return

    # Declined (or non-interactive fallback): just run once in the foreground.
    cfg = load_config()
    if not cfg.get("token"):
        cfg = enroll(args)
    run(cfg, args)


def main():
    print("Rift Monitor v%s" % __version__)
    ap = argparse.ArgumentParser(description="Rift status monitor node")
    ap.add_argument("--code", help="enrollment code (or env RIFT_MONITOR_CODE)")
    ap.add_argument("--name", help="node name (or env RIFT_MONITOR_NAME)")
    ap.add_argument("--location", help="where it's located, e.g. 'Toronto, Canada' (or env RIFT_MONITOR_LOCATION)")
    ap.add_argument("--install", action="store_true",
                     help="install as a background service/task now (systemd on Linux, scheduled task on Windows) and exit")
    ap.add_argument("--no-auto-install", action="store_true",
                     help="skip the install prompt, just run once in the foreground")
    ap.add_argument("--background", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--no-update", action="store_true", help="skip the startup update check (or set RIFT_MONITOR_NO_UPDATE=1)")
    args = ap.parse_args()

    if not args.no_update and os.environ.get("RIFT_MONITOR_NO_UPDATE") != "1":
        upd = check_for_update()
        if upd:
            apply_update(*upd)   # re-execs in place on success; on failure just falls through below

    if args.install:
        if os.name == "posix":
            install_service(args)
        else:
            install_windows_task(args)
        return

    if args.background:
        # Invoked by the installed service/task itself - no prompts, just run.
        cfg = load_config()
        if not cfg.get("token"):
            cfg = enroll(args)
        while True:
            try:
                run(cfg, args)
            except KeyboardInterrupt:
                return
            except Exception as e:
                sys.stderr.write("Loop error (%s) - retrying in 30s.\n" % e)
                time.sleep(30)
                cfg = load_config() or cfg
        return

    already_installed = _windows_task_exists() if os.name == "nt" else _linux_service_exists()

    if not args.no_auto_install and not already_installed and sys.stdin.isatty():
        offer_auto_install(args)
        return

    cfg = load_config()
    if not cfg.get("token"):
        cfg = enroll(args)
    while True:
        try:
            run(cfg, args)
        except KeyboardInterrupt:
            print("\nStopped.")
            return
        except Exception as e:
            print("Loop error (%s) - retrying in 30s." % e)
            time.sleep(30)
            cfg = load_config() or cfg


if __name__ == "__main__":
    main()
