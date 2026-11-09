#!/usr/bin/env python3
"""
Wi-Fi Monitor for macOS — live per-app network traffic, Wi-Fi link info and speed test.

Pure standard library. Data sources (all built into macOS):
  * nettop          per-process / per-connection byte counters (1 s deltas)
  * netstat         total bytes on the Wi-Fi interface
  * CoreWLAN        Wi-Fi link details (signal, channel, PHY mode, tx rate), read
                    without triggering a scan
  * networkQuality  Apple's speed test (download, upload, latency, responsiveness)

Run:  python3 wifimon.py            (opens http://127.0.0.1:8765 in your browser)
      python3 wifimon.py --no-browser --port 9000
"""

import argparse
import ctypes
import fcntl
import ipaddress
import json
import os
import plistlib
import pty
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import threading
import time
import uuid
import webbrowser
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
HISTORY_SECONDS = 300          # per-app / total history kept in memory
SPARK_SECONDS = 60             # points sent for the sparkline in the app table
CONN_TTL = 60                  # forget a connection after this many idle seconds
SESSIONS_FILE = os.path.join(HERE, "recordings.json")
SPEEDTESTS_FILE = os.path.join(HERE, "speedtests.json")
ICON_DIR = os.path.join(tempfile.gettempdir(), "wifimon-icons")
TUNNEL_RE = re.compile(r"^(utun|ipsec|ppp|tun|tap|wg)\d")

# Background daemons that actually carry traffic for a user-facing app.
ALIASES = {
    "avconferenced": ("FaceTime / Apple calls", "/System/Applications/FaceTime.app", False),
    "com.apple.WebKit.Networking": ("Safari / WebKit", "/Applications/Safari.app", False),
    "mDNSResponder": ("DNS (mDNSResponder)", None, True),
    "kernel_task": ("macOS kernel", None, True),
    "nsurlsessiond": ("Background downloads (nsurlsessiond)", None, True),
    "cloudd": ("iCloud sync (cloudd)", None, True),
    "bird": ("iCloud Drive (bird)", None, True),
    "apsd": ("Apple Push (apsd)", None, True),
    "softwareupdated": ("Software Update", None, True),
}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Process → app resolution
# --------------------------------------------------------------------------- #
try:
    _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
except OSError:  # pragma: no cover
    _libproc = None


def pid_path(pid):
    if not _libproc or pid <= 0:
        return None
    buf = ctypes.create_string_buffer(4096)
    n = _libproc.proc_pidpath(pid, buf, 4096)
    return buf.value.decode("utf-8", "replace") if n > 0 else None


class AppInfo:
    __slots__ = ("key", "name", "bundle", "system")

    def __init__(self, key, name, bundle, system):
        self.key, self.name, self.bundle, self.system = key, name, bundle, system


_app_cache = {}


def resolve_app(pid, procname):
    ck = (pid, procname)
    hit = _app_cache.get(ck)
    if hit:
        return hit
    path = pid_path(pid)
    bundle = None
    if path:
        m = re.match(r"^(.*?\.app)(?:/|$)", path)
        exe = os.path.basename(path)
        if m:
            bundle = m.group(1)
            name = os.path.basename(bundle)[:-4]
            system = bundle.startswith("/System/Library/")
        else:
            name = exe
            system = path.startswith(("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/Library/Apple/"))
        base = exe
    else:
        name, system, base = procname, pid == 0, procname
    if base in ALIASES:
        name, alias_bundle, system = ALIASES[base]
        if alias_bundle and os.path.isdir(alias_bundle):
            bundle = alias_bundle
    info = AppInfo(name, name, bundle, system)
    if len(_app_cache) > 5000:
        _app_cache.clear()
    _app_cache[ck] = info
    return info


# --------------------------------------------------------------------------- #
# Reverse DNS (best effort, cached, off the hot path)
# --------------------------------------------------------------------------- #
_dns_cache = {}
_dns_pool = ThreadPoolExecutor(max_workers=4)


def _dns_lookup(ip):
    try:
        _dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except Exception:
        _dns_cache[ip] = ""


def host_label(ip):
    if not ip or ip in ("*",):
        return ""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return ""
    if addr.is_loopback:
        return "this Mac"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private or addr.is_link_local:
        return "local network"
    if ip not in _dns_cache:
        _dns_cache[ip] = None
        _dns_pool.submit(_dns_lookup, ip)
    return _dns_cache.get(ip) or ""


# --------------------------------------------------------------------------- #
# Wi-Fi interface helpers
# --------------------------------------------------------------------------- #
def detect_wifi_iface():
    try:
        out = subprocess.run(["networksetup", "-listallhardwareports"],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"Hardware Port: (?:Wi-Fi|AirPort)\s*\nDevice: (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "en0"


def iface_bytes(iface):
    """Cumulative (in, out) bytes for an interface, or None."""
    try:
        out = subprocess.run(["netstat", "-I", iface, "-b", "-n"],
                             capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if "<Link#" in line:
            t = line.split()
            try:
                if len(t) >= 11:
                    return int(t[6]), int(t[9])
                if len(t) == 10:
                    return int(t[5]), int(t[8])
            except ValueError:
                return None
    return None


# CoreWLAN (via the Objective-C runtime) reads the current link without triggering a
# Wi-Fi scan. `system_profiler SPAirPortDataType` scans for nearby networks, which
# adds bursts of 30-130 ms latency, so it is only a fallback.
_PHY = {1: "802.11a", 2: "802.11b", 3: "802.11g", 4: "802.11n", 5: "802.11ac",
        6: "802.11ax", 7: "802.11be"}
_SEC = {0: "Open", 1: "WEP", 2: "WPA Personal", 3: "WPA/WPA2 Personal", 4: "WPA2 Personal",
        5: "Personal", 6: "Dynamic WEP", 7: "WPA Enterprise", 8: "WPA/WPA2 Enterprise",
        9: "WPA2 Enterprise", 10: "Enterprise", 11: "WPA3 Personal", 12: "WPA3 Enterprise",
        13: "WPA2/WPA3 Personal", 14: "OWE", 15: "OWE Transition"}
_BAND = {1: "2GHz", 2: "5GHz", 3: "6GHz"}
_WIDTH = {1: "20MHz", 2: "40MHz", 3: "80MHz", 4: "160MHz", 5: "320MHz"}


class _CoreWLAN:
    def __init__(self):
        from ctypes import c_bool, c_char_p, c_double, c_long, c_void_p
        self.objc = objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        ctypes.CDLL("/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN")
        objc.objc_getClass.restype = c_void_p
        objc.objc_getClass.argtypes = [c_char_p]
        objc.sel_registerName.restype = c_void_p
        objc.sel_registerName.argtypes = [c_char_p]
        objc.objc_autoreleasePoolPush.restype = c_void_p
        objc.objc_autoreleasePoolPop.argtypes = [c_void_p]
        addr = ctypes.cast(objc.objc_msgSend, c_void_p).value
        self.fn = {t: ctypes.CFUNCTYPE(t, c_void_p, c_void_p)(addr)
                   for t in (c_void_p, c_long, c_double, c_bool, c_char_p)}
        self.T = dict(obj=c_void_p, int=c_long, float=c_double, bool=c_bool, str=c_char_p)
        self.cls = objc.objc_getClass(b"CWWiFiClient")
        if not self.cls:
            raise OSError("CoreWLAN unavailable")

    def send(self, obj, sel, kind="obj"):
        if not obj:
            return None
        t = self.T[kind]
        return self.fn[t](obj, self.objc.sel_registerName(sel.encode()))

    def read(self):
        pool = self.objc.objc_autoreleasePoolPush()
        try:
            itf = self.send(self.send(self.cls, "sharedWiFiClient"), "interface")
            if not itf:
                return None
            name = (self.send(self.send(itf, "interfaceName"), "UTF8String", "str") or b"").decode()
            ch = self.send(itf, "wlanChannel")
            rssi = self.send(itf, "rssiValue", "int")
            if not self.send(itf, "powerOn", "bool") or not ch or not rssi:
                return {"iface": name, "connected": False}
            ssid = self.send(itf, "ssid")
            num = self.send(ch, "channelNumber", "int")
            band = _BAND.get(self.send(ch, "channelBand", "int"))
            width = _WIDTH.get(self.send(ch, "channelWidth", "int"))
            extra = ", ".join(x for x in (band, width) if x)
            return {
                "iface": name, "connected": True,
                "ssid": (self.send(ssid, "UTF8String", "str") or b"").decode() or None if ssid else None,
                "rssi": rssi, "noise": self.send(itf, "noiseMeasurement", "int"),
                "tx_rate": round(self.send(itf, "transmitRate", "float") or 0),
                "phy": _PHY.get(self.send(itf, "activePHYMode", "int")),
                "security": _SEC.get(self.send(itf, "security", "int")),
                "channel": f"{num} ({extra})" if extra else str(num),
            }
        finally:
            self.objc.objc_autoreleasePoolPop(pool)


try:
    _cwlan = _CoreWLAN()
except Exception:  # pragma: no cover
    _cwlan = None


def wifi_details_fast():
    """Current Wi-Fi link via CoreWLAN (no scan). None if unavailable."""
    if not _cwlan:
        return None
    try:
        return _cwlan.read()
    except Exception:
        return None


def wifi_details(iface):
    """Fallback via system_profiler. Slow, and it triggers a Wi-Fi scan."""
    try:
        raw = subprocess.run(["system_profiler", "-json", "SPAirPortDataType"],
                             capture_output=True, text=True, timeout=30).stdout
        data = json.loads(raw)
    except Exception:
        return None
    for block in data.get("SPAirPortDataType", []):
        for itf in block.get("spairport_airport_interfaces", []):
            if itf.get("_name") != iface:
                continue
            cur = itf.get("spairport_current_network_information") or {}
            status = itf.get("spairport_status_information", "")
            info = {
                "connected": status == "spairport_status_connected",
                "ssid": cur.get("_name") if cur.get("_name") not in (None, "<redacted>") else None,
                "phy": cur.get("spairport_network_phymode"),
                "channel": cur.get("spairport_network_channel"),
                "tx_rate": cur.get("spairport_network_rate"),
                "security": (cur.get("spairport_security_mode") or "")
                .replace("spairport_security_mode_", "").replace("_", " ").upper() or None,
            }
            sn = cur.get("spairport_signal_noise") or ""
            m = re.match(r"\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", sn)
            if m:
                info["rssi"], info["noise"] = int(m.group(1)), int(m.group(2))
            return info
    return None


def _own_tty():
    """Child side: make the pty our controlling terminal, so nettop gets SIGHUP and
    exits if this monitor dies for any reason (even kill -9)."""
    os.setsid()
    fcntl.ioctl(1, termios.TIOCSCTTY, 0)


# --------------------------------------------------------------------------- #
# Monitor: owns all state
# --------------------------------------------------------------------------- #
class AppState:
    def __init__(self, info):
        self.info = info
        self.hist = deque(maxlen=HISTORY_SECONDS)  # (t, in_Bps, out_Bps)
        self.tot_in = 0
        self.tot_out = 0
        self.last_active = 0.0
        self.conns = {}  # key -> dict


class Monitor:
    def __init__(self):
        self.lock = threading.RLock()
        self.iface = detect_wifi_iface()
        self.apps = {}
        self.total_hist = deque(maxlen=HISTORY_SECONDS)
        self.total_in = 0
        self.total_out = 0
        self.started = time.time()
        self.wifi = None
        self.nettop_ok = False
        self.tunnels_in_external = False
        self._tun_lock = threading.Lock()
        self._tun_pending = {}
        self._prev_if = None
        self._prev_t = None
        self.recording = None
        self.speed = {"state": "idle"}
        self.sessions = self._load(SESSIONS_FILE)
        self.speedtests = self._load(SPEEDTESTS_FILE)

    # ---- persistence -------------------------------------------------------
    @staticmethod
    def _load(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return []

    @staticmethod
    def _save(path, data):
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, path)

    # ---- threads -----------------------------------------------------------
    def start(self):
        # Stream A: every non-loopback interface (process totals then exclude localhost
        # traffic, even for short-lived connections that closed within the second).
        threading.Thread(target=self._nettop_loop, daemon=True,
                         args=(["-t", "external"], self._ingest, True)).start()
        # Stream B: all interfaces, used only to pick up VPN tunnel (utun/ipsec) traffic
        # in case macOS does not count tunnels as "external".
        threading.Thread(target=self._nettop_loop, daemon=True,
                         args=([], self._ingest_tunnels, False)).start()
        threading.Thread(target=self._wifi_loop, daemon=True).start()

    def _wifi_loop(self):
        while True:
            info = wifi_details_fast()
            if info is not None:
                delay = 3
            else:  # CoreWLAN unavailable: fall back, rarely, to the scanning tool
                info, delay = wifi_details(self.iface), 120
            with self.lock:
                self.wifi = info
            time.sleep(delay)

    def _nettop_loop(self, extra, on_sample, primary):
        while True:
            try:
                self._run_nettop(extra, on_sample, primary)
            except Exception as e:  # keep going no matter what
                log("nettop error:", e)
            if primary:
                self.nettop_ok = False
            time.sleep(1)

    def _run_nettop(self, extra, on_sample, primary):
        # nettop block-buffers when writing to a pipe, so give it a pseudo-terminal.
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            ["nettop", "-L", "0", "-d", "-s", "1", "-n", "-x", *extra,
             "-J", "interface,state,bytes_in,bytes_out"],
            stdout=slave, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, close_fds=True,
            preexec_fn=_own_tty)
        os.close(slave)
        buf = b""
        sample = None          # list of [procname, pid, in, out, conns[]]
        sample_t = None
        sample_no = 0
        try:
            while True:
                r, _, _ = select.select([master], [], [], 0.25)
                if not r:
                    # Quiet line after a burst → the sample is complete.
                    if sample is not None:
                        if sample_no > 1:  # first sample holds totals since boot
                            on_sample(sample, sample_t)
                        sample = None
                    if proc.poll() is not None:
                        return
                    continue
                try:
                    data = os.read(master, 65536)
                except OSError:
                    return
                if not data:
                    return
                buf += data
                lines = buf.split(b"\n")
                buf = lines.pop()
                for raw in lines:
                    line = raw.decode("utf-8", "replace").rstrip("\r")
                    if not line:
                        continue
                    if line.startswith(","):
                        if sample is not None and sample_no > 1:
                            on_sample(sample, sample_t)
                        sample, sample_t = [], time.time()
                        sample_no += 1
                        if primary:
                            self.nettop_ok = True
                        continue
                    if sample is None:
                        continue
                    parts = line.split(",")
                    if len(parts) < 5:
                        continue
                    if parts[0][:4] in ("tcp4", "tcp6", "udp4", "udp6") and " " in parts[0]:
                        if sample:
                            sample[-1][4].append(parts)
                        continue
                    name, _, pid = parts[0].rpartition(".")
                    try:
                        pid = int(pid)
                        bin_, bout = int(parts[3] or 0), int(parts[4] or 0)
                    except ValueError:
                        continue
                    sample.append([name, pid, bin_, bout, []])
        finally:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
            os.close(master)

    def _ingest_tunnels(self, sample, t):
        """Collect per-process bytes on VPN tunnel interfaces from the all-interface stream."""
        found = {}
        for name, pid, _bin, _bout, conns in sample:
            for c in conns:
                if not TUNNEL_RE.match(c[1]):
                    continue
                try:
                    cin, cout = int(c[3] or 0), int(c[4] or 0)
                except ValueError:
                    continue
                if cin or cout:
                    acc = found.setdefault((name, pid), [0, 0, []])
                    acc[0] += cin
                    acc[1] += cout
                    acc[2].append(c)
        with self._tun_lock:
            for k, v in found.items():
                prev = self._tun_pending.get(k)
                if prev:  # stream A hasn't consumed the previous second yet
                    prev[0] += v[0]
                    prev[1] += v[1]
                    prev[2] = v[2]
                else:
                    self._tun_pending[k] = v

    # ---- per-second ingestion ---------------------------------------------
    def _ingest(self, sample, t):
        dt = 1.0
        if self._prev_t:
            dt = min(max(t - self._prev_t, 0.5), 3.0)
        self._prev_t = t

        tun = {}
        if not self.tunnels_in_external:
            with self._tun_lock:
                tun, self._tun_pending = self._tun_pending, {}
            if tun:
                present = {(row[0], row[1]) for row in sample}
                for (name, pid) in tun:
                    if (name, pid) not in present:
                        sample.append([name, pid, 0, 0, []])

        per_app = {}
        for name, pid, bin_, bout, conns in sample:
            extra = tun.get((name, pid))
            if extra:
                bin_ += extra[0]
                bout += extra[1]
                conns = conns + extra[2]
            lo_in = lo_out = 0
            parsed = []
            for c in conns:
                iface = c[1]
                if not extra and not self.tunnels_in_external and TUNNEL_RE.match(iface):
                    self.tunnels_in_external = True  # this macOS already counts tunnels
                try:
                    cin, cout = int(c[3] or 0), int(c[4] or 0)
                except ValueError:
                    cin = cout = 0
                if iface.startswith("lo"):
                    lo_in += cin
                    lo_out += cout
                    continue
                if cin or cout:
                    parsed.append((c[0], iface, c[2], cin, cout))
            ext_in, ext_out = max(bin_ - lo_in, 0), max(bout - lo_out, 0)
            if not ext_in and not ext_out and not parsed:
                continue
            info = resolve_app(pid, name)
            acc = per_app.setdefault(info.key, [info, 0, 0, []])
            acc[1] += ext_in
            acc[2] += ext_out
            acc[3].extend(parsed)

        if_now = iface_bytes(self.iface)
        if_in = if_out = 0
        if if_now and self._prev_if:
            if_in = max(if_now[0] - self._prev_if[0], 0)
            if_out = max(if_now[1] - self._prev_if[1], 0)
        if if_now:
            self._prev_if = if_now

        with self.lock:
            self.total_in += if_in
            self.total_out += if_out
            self.total_hist.append((t, if_in / dt, if_out / dt))
            for key, (info, bin_, bout, conns) in per_app.items():
                st = self.apps.get(key)
                if st is None:
                    st = self.apps[key] = AppState(info)
                st.tot_in += bin_
                st.tot_out += bout
                st.last_active = t
                st.hist.append((t, bin_ / dt, bout / dt))
                for desc, iface, state, cin, cout in conns:
                    ck = desc + "|" + iface
                    c = st.conns.get(ck)
                    if c is None:
                        proto, _, rest = desc.partition(" ")
                        local, _, remote = rest.partition("<->")
                        c = st.conns[ck] = {"proto": proto, "local": local, "remote": remote,
                                            "iface": iface, "tot_in": 0, "tot_out": 0}
                    c["state"] = state
                    c["in"], c["out"] = cin / dt, cout / dt
                    c["tot_in"] += cin
                    c["tot_out"] += cout
                    c["seen"] = t
            # apps with no traffic this second get a zero point so charts stay continuous
            for key, st in self.apps.items():
                if key not in per_app and st.hist and t - st.hist[-1][0] > 0.5 and t - st.last_active < HISTORY_SECONDS:
                    st.hist.append((t, 0.0, 0.0))
                for ck in [k for k, c in st.conns.items() if c["seen"] < t - 0.1]:
                    c = st.conns[ck]
                    c["in"] = c["out"] = 0.0
                    if t - c["seen"] > CONN_TTL:
                        del st.conns[ck]
            rec = self.recording
            if rec:
                a = per_app.get(rec["key"])
                rin, rout = (a[1] / dt, a[2] / dt) if a else (0.0, 0.0)
                rec["samples"].append((round(t - rec["start"], 2), rin, rout))
                rec["bytes_in"] += a[1] if a else 0
                rec["bytes_out"] += a[2] if a else 0

    # ---- views -------------------------------------------------------------
    def snapshot(self, sel=None):
        now = time.time()
        with self.lock:
            apps = []
            for key, st in self.apps.items():
                h = list(st.hist)[-SPARK_SECONDS:]
                cur_in, cur_out = (h[-1][1], h[-1][2]) if h and now - h[-1][0] < 2.5 else (0.0, 0.0)
                apps.append({
                    "key": key, "name": st.info.name, "system": st.info.system,
                    "icon": bool(st.info.bundle),
                    "in": cur_in, "out": cur_out,
                    "tot_in": st.tot_in, "tot_out": st.tot_out,
                    "idle": now - st.last_active,
                    "spark_in": [round(p[1]) for p in h],
                    "spark_out": [round(p[2]) for p in h],
                })
            th = self.total_hist[-1] if self.total_hist else (0, 0, 0)
            selected = None
            if sel and sel in self.apps:
                st = self.apps[sel]
                conns = []
                for c in st.conns.values():
                    rhost = c["remote"]
                    ip = re.sub(r"[:.]\d+$|[:.]\*$", "", rhost) if rhost not in ("*:*", "*.*") else ""
                    conns.append({
                        "proto": c["proto"].upper(), "remote": rhost if ip else "(any)",
                        "local": c["local"], "host": host_label(ip), "iface": c["iface"],
                        "state": c.get("state") or "", "in": c["in"], "out": c["out"],
                        "tot_in": c["tot_in"], "tot_out": c["tot_out"],
                    })
                conns.sort(key=lambda c: (-(c["in"] + c["out"]), -(c["tot_in"] + c["tot_out"])))
                selected = {"key": sel, "conns": conns[:40]}
            rec = None
            if self.recording:
                r = self.recording
                n = max(len(r["samples"]), 1)
                rec = {"key": r["key"], "name": r["name"], "label": r["label"],
                       "elapsed": now - r["start"],
                       "avg_in": r["bytes_in"] / n, "avg_out": r["bytes_out"] / n,
                       "bytes_in": r["bytes_in"], "bytes_out": r["bytes_out"]}
            speed = dict(self.speed)
            if speed.get("state") == "running":
                speed["elapsed"] = now - speed["started"]
            return {
                "now": now, "iface": self.iface, "wifi": self.wifi, "nettop_ok": self.nettop_ok,
                "uptime": now - self.started,
                "total": {"in": th[1] if now - th[0] < 2.5 else 0.0,
                          "out": th[2] if now - th[0] < 2.5 else 0.0,
                          "tot_in": self.total_in, "tot_out": self.total_out},
                "apps": apps, "selected": selected, "recording": rec, "speed": speed,
            }

    def history(self, key):
        with self.lock:
            if key == "__total__":
                h = list(self.total_hist)
            elif key in self.apps:
                h = list(self.apps[key].hist)
            else:
                h = []
        return {"t": [round(p[0], 2) for p in h], "in": [round(p[1]) for p in h],
                "out": [round(p[2]) for p in h]}

    def reset_totals(self):
        with self.lock:
            self.total_in = self.total_out = 0
            for st in self.apps.values():
                st.tot_in = st.tot_out = 0
                for c in st.conns.values():
                    c["tot_in"] = c["tot_out"] = 0

    # ---- recording ---------------------------------------------------------
    def start_recording(self, key, label):
        with self.lock:
            if key not in self.apps:
                raise ValueError("unknown app")
            self.recording = {"key": key, "name": self.apps[key].info.name,
                              "label": (label or "").strip()[:80] or self.apps[key].info.name,
                              "start": time.time(), "samples": [], "bytes_in": 0, "bytes_out": 0}

    def stop_recording(self, discard=False):
        with self.lock:
            r, self.recording = self.recording, None
        if not r or discard:
            return None
        s = r["samples"]
        n = len(s)
        if n < 3:
            raise ValueError("Recording too short (need at least 3 seconds).")
        ins = [x[1] for x in s]
        outs = [x[2] for x in s]
        # thin the stored curve to at most ~600 points
        step = max(1, n // 600)
        sess = {
            "id": uuid.uuid4().hex[:10], "app": r["name"], "key": r["key"], "label": r["label"],
            "started": r["start"], "duration": n,
            "avg_in": r["bytes_in"] / n, "avg_out": r["bytes_out"] / n,
            "peak_in": max(ins), "peak_out": max(outs),
            "median_in": sorted(ins)[n // 2], "median_out": sorted(outs)[n // 2],
            "bytes_in": r["bytes_in"], "bytes_out": r["bytes_out"],
            "curve_in": [round(sum(ins[i:i + step]) / len(ins[i:i + step])) for i in range(0, n, step)],
            "curve_out": [round(sum(outs[i:i + step]) / len(outs[i:i + step])) for i in range(0, n, step)],
        }
        with self.lock:
            self.sessions.append(sess)
            self._save(SESSIONS_FILE, self.sessions)
        return sess

    def delete_session(self, sid):
        with self.lock:
            self.sessions = [s for s in self.sessions if s["id"] != sid]
            self._save(SESSIONS_FILE, self.sessions)

    def rename_session(self, sid, label):
        with self.lock:
            for s in self.sessions:
                if s["id"] == sid:
                    s["label"] = (label or "").strip()[:80] or s["label"]
            self._save(SESSIONS_FILE, self.sessions)

    # ---- speed test --------------------------------------------------------
    def start_speedtest(self):
        with self.lock:
            if self.speed.get("state") == "running":
                return False
            self.speed = {"state": "running", "started": time.time()}
        threading.Thread(target=self._speedtest, daemon=True).start()
        return True

    def _speedtest(self):
        try:
            p = subprocess.run(["networkQuality", "-c", "-s"], capture_output=True,
                               text=True, timeout=180)
            d = json.loads(p.stdout)
            if "dl_throughput" not in d:
                raise RuntimeError(d.get("error_description") or p.stderr.strip() or "no result")
            res = {
                "time": time.time(),
                "down_bps": d.get("dl_throughput"), "up_bps": d.get("ul_throughput"),
                "latency_ms": d.get("base_rtt"),
                "dl_rpm": d.get("dl_responsiveness"), "ul_rpm": d.get("ul_responsiveness"),
                "server": d.get("test_endpoint"), "iface": d.get("interface_name"),
            }
            with self.lock:
                self.speed = {"state": "done", "result": res}
                self.speedtests.append(res)
                self.speedtests = self.speedtests[-50:]
                self._save(SPEEDTESTS_FILE, self.speedtests)
        except Exception as e:
            with self.lock:
                self.speed = {"state": "error", "error": str(e)[:300]}


# --------------------------------------------------------------------------- #
# App icons
# --------------------------------------------------------------------------- #
_icon_lock = threading.Lock()


def icon_png(bundle):
    os.makedirs(ICON_DIR, exist_ok=True)
    out = os.path.join(ICON_DIR, re.sub(r"[^A-Za-z0-9]+", "_", bundle) + ".png")
    with _icon_lock:
        if os.path.exists(out):
            return out if os.path.getsize(out) > 0 else None
        src = None
        try:
            with open(os.path.join(bundle, "Contents", "Info.plist"), "rb") as f:
                pl = plistlib.load(f)
            name = pl.get("CFBundleIconFile") or pl.get("CFBundleIconName")
            res = os.path.join(bundle, "Contents", "Resources")
            if name:
                cand = os.path.join(res, name if name.endswith(".icns") else name + ".icns")
                if os.path.exists(cand):
                    src = cand
            if not src and os.path.isdir(res):
                icns = [f for f in os.listdir(res) if f.endswith(".icns")]
                if icns:
                    src = os.path.join(res, sorted(icns, key=lambda f: ("app" not in f.lower(), f))[0])
        except Exception:
            src = None
        ok = False
        if src:
            r = subprocess.run(["sips", "-s", "format", "png", "-Z", "64", src, "--out", out],
                               capture_output=True, timeout=10)
            ok = r.returncode == 0 and os.path.exists(out)
        if not ok:
            open(out, "wb").close()  # negative cache
            return None
        return out


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #
MON = None


class Handler(BaseHTTPRequestHandler):
    server_version = "WiFiMonitor/1.0"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/api/snapshot":
            self._json(MON.snapshot(q.get("sel")))
        elif u.path == "/api/history":
            self._json(MON.history(q.get("key", "__total__")))
        elif u.path == "/api/recordings":
            with MON.lock:
                self._json(list(MON.sessions))
        elif u.path == "/api/speedtests":
            with MON.lock:
                self._json(list(MON.speedtests))
        elif u.path == "/api/icon":
            key = q.get("key", "")
            with MON.lock:
                st = MON.apps.get(key)
                bundle = st.info.bundle if st else None
            path = icon_png(bundle) if bundle else None
            if not path:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "max-age=86400")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        b = self._body()
        try:
            if u.path == "/api/speedtest":
                self._json({"started": MON.start_speedtest()})
            elif u.path == "/api/record/start":
                MON.start_recording(b.get("key"), b.get("label"))
                self._json({"ok": True})
            elif u.path == "/api/record/stop":
                self._json({"ok": True, "session": MON.stop_recording(bool(b.get("discard")))})
            elif u.path == "/api/recordings/delete":
                MON.delete_session(b.get("id"))
                self._json({"ok": True})
            elif u.path == "/api/recordings/rename":
                MON.rename_session(b.get("id"), b.get("label"))
                self._json({"ok": True})
            elif u.path == "/api/reset":
                MON.reset_totals()
                self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)
        except ValueError as e:
            self._json({"error": str(e)}, 400)


def main():
    global MON
    ap = argparse.ArgumentParser(description="Live per-app Wi-Fi traffic monitor + speed test")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    if sys.platform != "darwin":
        sys.exit("This tool uses macOS-only utilities (nettop, networkQuality).")

    MON = Monitor()
    MON.start()

    srv = None
    for port in range(args.port, args.port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if not srv:
        sys.exit("No free port found.")
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    log(f"Wi-Fi Monitor running on {url}  (interface {MON.iface}) — press Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log("stopped")


if __name__ == "__main__":
    main()
