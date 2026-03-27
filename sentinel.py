#!/usr/bin/env python3
"""
Network Sentinel  v2.0 — Live Network Intrusion Monitor

Upgrades over v1:
  • 10 threat types  (+ UDP flood, brute-force, malware ports,
                        DNS tunneling, data exfil, horizontal scan)
  • Live bandwidth sparkline graph  (Canvas widget)
  • Stats bar  — pkt/s · KB/s · active hosts · threat counters
  • Packet filter  — live search by IP / protocol
  • Pause / Resume  packet display without stopping capture
  • Save PCAP  — one-click capture export via scapy wrpcap
  • Desktop notifications  via notify-send (CRITICAL only)
    • Bell alert  on every CRITICAL threat
    • Right-click threat actions  (copy, neutralize, rollback)
    • Neutralization capability panel  (ufw/iptables/nft/ss/conntrack)
  • Settings dialog  — tune all detection thresholds live
  • Per-host traffic column  in hosts table
  • Session counter  in stats bar

Requires: sudo python3 sentinel.py   (raw packet capture needs root)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import socket
import os
import sys
import subprocess
import shutil
import json
import csv
import html
import re
import signal
import ipaddress
import queue
from collections import defaultdict, deque
from datetime import datetime

# ── Optional scapy imports ────────────────────────────────────────────────────
try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Ether, get_if_list, wrpcap
    SCAPY_AVAILABLE = True
    try:
        from scapy.all import DNS, DNSQR
        DNS_AVAILABLE = True
    except Exception:
        DNS_AVAILABLE = False
except ImportError:
    SCAPY_AVAILABLE = False
    DNS_AVAILABLE   = False

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN PORT DATABASE
# ─────────────────────────────────────────────────────────────────────────────

MALICIOUS_PORTS = {
    1337:  "Back Orifice / Leet port",
    4444:  "Metasploit default listener",
    5555:  "Android ADB / common RAT",
    6667:  "IRC-based botnet C2",
    6666:  "IRC / botnet C2",
    7777:  "Common RAT/backdoor",
    9999:  "Common RAT/backdoor",
    31337: "Back Orifice classic",
    12345: "NetBus RAT",
    12346: "NetBus RAT",
    27374: "Sub7 RAT",
    4899:  "Radmin remote admin (often abused)",
    2745:  "Bagle worm",
    3127:  "MyDoom worm",
    65535: "Unusual max-port traffic",
}

BRUTE_FORCE_PORTS = {
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    21:    "FTP",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
}

HONEYPOT_DECOY_PORTS = {
    21: {
        "service": "FTP Admin Portal",
        "banner": "220 ProFTPD 1.3.3c Server (Legacy Build)",
        "lure": "Anonymous upload appears enabled; writable backup folder exposed.",
    },
    22: {
        "service": "Legacy SSH Gateway",
        "banner": "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7",
        "lure": "Old key exchange suites advertised; weak hardening profile signaled.",
    },
    23: {
        "service": "Telnet Maintenance Console",
        "banner": "BusyBox telnetd 1.19 maintenance shell",
        "lure": "Plaintext admin maintenance login prompt appears exposed.",
    },
    80: {
        "service": "Admin Web Console",
        "banner": "Apache/2.2.14 (Ubuntu) PHP/5.3.2",
        "lure": "Debug routes and test admin endpoints appear publicly listed.",
    },
    443: {
        "service": "Secure Control API",
        "banner": "nginx/1.4.6 TLSv1.0 compatibility mode",
        "lure": "Deprecated TLS policy appears active with relaxed cipher hints.",
    },
    445: {
        "service": "SMB Fileshare",
        "banner": "Samba 3.6.3 workgroup=LEGACY",
        "lure": "Guest share discovery appears open with permissive naming.",
    },
    1433: {
        "service": "MSSQL Data Node",
        "banner": "Microsoft SQL Server 2008 R2",
        "lure": "Named instance metadata appears enumerable from remote hosts.",
    },
    3306: {
        "service": "MySQL Data Node",
        "banner": "5.5.62-log MySQL Community Server",
        "lure": "Legacy auth plugin hints and open schema names appear leaked.",
    },
    3389: {
        "service": "RDP Jump Host",
        "banner": "RDP 5.2 Terminal Services",
        "lure": "NLA appears disabled; interactive credential prompt exposed.",
    },
    5432: {
        "service": "PostgreSQL Cluster",
        "banner": "PostgreSQL 9.2.24",
        "lure": "Replication and monitoring roles appear discoverable.",
    },
    5900: {
        "service": "VNC Remote Access",
        "banner": "RFB 003.003 VNC Server",
        "lure": "Legacy viewer negotiation appears to allow weak auth flow.",
    },
    6379: {
        "service": "Redis Cache",
        "banner": "Redis 2.8.19 standalone",
        "lure": "CONFIG and INFO style metadata appears remotely readable.",
    },
    8080: {
        "service": "DevOps Control Plane",
        "banner": "Jenkins 1.651.3",
        "lure": "Legacy plugin endpoints and script console hints appear exposed.",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR / FONT PALETTE
# ─────────────────────────────────────────────────────────────────────────────

BG     = "#07161d"
BG2    = "#0f222c"
BG3    = "#173543"
BG4    = "#2a5667"
FG     = "#e6f4f7"
FG2    = "#8ca7b3"
GREEN  = "#56d48d"
RED    = "#ff6b6b"
ORANGE = "#ffb357"
BLUE   = "#7dcfff"
PURPLE = "#c4a7ff"
CYAN   = "#63e6ea"
TEAL   = "#123b46"

FONT_MONO = ("JetBrains Mono", 10)
FONT_UI   = ("IBM Plex Sans",  10)
FONT_H1   = ("IBM Plex Sans",  17, "bold")
FONT_H2   = ("IBM Plex Sans",  11, "bold")
FONT_SM   = ("IBM Plex Sans",   8)

NEUTRALIZE_NONE      = "none"
NEUTRALIZE_SELF      = "self_quarantine"
NEUTRALIZE_BLOCK     = "block_only"
NEUTRALIZE_KILL      = "kill_only"
NEUTRALIZE_BLOCKKILL = "block_and_kill"
NEUTRALIZE_NETWORK   = "network_isolate"

THREAT_ACTION_MODE = {
    "New Device Joined Network": NEUTRALIZE_NONE,
    "Capture Error": NEUTRALIZE_NONE,
}

# ─────────────────────────────────────────────────────────────────────────────
# STATS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class StatsEngine:
    """Tracks packets/sec, bytes/sec and rolling history for the graph."""

    HISTORY = 60

    def __init__(self):
        self._lock        = threading.Lock()
        self._pkt_times   = deque()
        self._byte_log    = deque()
        self.bps_history  = deque([0] * self.HISTORY, maxlen=self.HISTORY)
        self.pps_history  = deque([0] * self.HISTORY, maxlen=self.HISTORY)
        self.total_pkts   = 0
        self.total_bytes  = 0
        self.host_bytes   = defaultdict(int)
        self.sessions     = set()

    def record(self, pkt_len, src_ip=None, dst_ip=None, sport=None, dport=None):
        now = time.time()
        with self._lock:
            self.total_pkts  += 1
            self.total_bytes += pkt_len
            self._pkt_times.append(now)
            self._byte_log.append((now, pkt_len))
            if src_ip:
                self.host_bytes[src_ip] += pkt_len
            if src_ip and dst_ip and sport and dport:
                self.sessions.add((src_ip, sport, dst_ip, dport))

    def tick(self):
        now    = time.time()
        cutoff = now - 1.0
        with self._lock:
            while self._pkt_times and self._pkt_times[0] < cutoff:
                self._pkt_times.popleft()
            while self._byte_log and self._byte_log[0][0] < cutoff:
                self._byte_log.popleft()
            pps = len(self._pkt_times)
            bps = sum(b for _, b in self._byte_log)
            self.bps_history.append(bps)
            self.pps_history.append(pps)
            return pps, bps

    @staticmethod
    def fmt_bytes(b):
        if b >= 1_048_576: return f"{b/1_048_576:.1f} MB"
        if b >= 1024:      return f"{b/1024:.1f} KB"
        return f"{int(b)} B"

# ─────────────────────────────────────────────────────────────────────────────
# THREAT DETECTION ENGINE  v2.0
# ─────────────────────────────────────────────────────────────────────────────

class ThreatDetector:
    PORT_SCAN_THRESHOLD   = 20
    PORT_SCAN_WINDOW      = 60
    HORIZ_SCAN_THRESHOLD  = 15
    HORIZ_SCAN_WINDOW     = 60
    SYN_FLOOD_THRESHOLD   = 60
    SYN_FLOOD_WINDOW      = 10
    ICMP_FLOOD_THRESHOLD  = 80
    ICMP_FLOOD_WINDOW     = 10
    UDP_FLOOD_THRESHOLD   = 150
    UDP_FLOOD_WINDOW      = 10
    BRUTE_FORCE_THRESHOLD = 20
    BRUTE_FORCE_WINDOW    = 60
    DNS_TUNNEL_LENGTH     = 50
    DNS_TUNNEL_THRESHOLD  = 40
    DNS_TUNNEL_WINDOW     = 30
    EXFIL_MB_THRESHOLD    = 20
    EXFIL_WINDOW          = 60
    ALERT_COOLDOWN        = 30
    STARTUP_GRACE_SEC     = 20
    ALERT_CONFIRM_WINDOW  = 45
    ALERT_CONFIRM_HITS    = 2

    def __init__(self, on_threat, on_packet, stats):
        self.on_threat = on_threat
        self.on_packet = on_packet
        self._stats    = stats
        self._host_lock = threading.Lock()
        self._resolve_cache = {}
        self._resolve_pending = set()
        self._resolve_queue = queue.Queue(maxsize=2048)
        self._resolver_thread = threading.Thread(target=self._resolver_loop, daemon=True)
        self._resolver_thread.start()
        self.arp_table   = {}
        self.known_hosts = {}
        self._port_scan  = defaultdict(lambda: {"events": deque()})
        self._horiz_scan = defaultdict(lambda: {"events": deque()})
        self._syn        = defaultdict(deque)
        self._icmp       = defaultdict(deque)
        self._udp        = defaultdict(deque)
        self._brute      = defaultdict(lambda: defaultdict(deque))
        self._dns_q      = defaultdict(deque)
        self._exfil      = defaultdict(deque)
        self._malware_seen = set()
        self._cooldowns  = {}
        self._pending_patterns = defaultdict(deque)
        self._started_at = time.time()
        self._fp_suppression_enabled = True
        self._trusted_local_ips = self._discover_trusted_local_ips()

    def _resolver_loop(self):
        while True:
            ip = self._resolve_queue.get()
            if ip is None:
                self._resolve_queue.task_done()
                return
            hostname = "Unresolved"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            with self._host_lock:
                self._resolve_cache[ip] = hostname
                self._resolve_pending.discard(ip)
                for info in self.known_hosts.values():
                    if info.get("ip") == ip:
                        info["hostname"] = hostname
            self._resolve_queue.task_done()

    def _request_resolve(self, ip):
        if not ip:
            return
        with self._host_lock:
            if ip in self._resolve_cache or ip in self._resolve_pending:
                return
            self._resolve_pending.add(ip)
        try:
            self._resolve_queue.put_nowait(ip)
        except Exception:
            with self._host_lock:
                self._resolve_pending.discard(ip)

    def process(self, pkt):
        summary = self._packet_summary(pkt)
        if summary:
            self.on_packet(summary)
        if ARP in pkt:
            self._check_arp(pkt)
        if IP in pkt:
            self._track_host(pkt)
            self._check_ip(pkt)

    def _can_alert(self, kind, src):
        key  = (kind, src)
        last = self._cooldowns.get(key, 0)
        if time.time() - last > self.ALERT_COOLDOWN:
            self._cooldowns[key] = time.time()
            return True
        return False

    def _confirm_pattern(self, kind, src):
        key = (kind, src)
        now = time.time()
        q = self._pending_patterns[key]
        q.append(now)
        cutoff = now - self.ALERT_CONFIRM_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.ALERT_CONFIRM_HITS:
            q.clear()
            return True
        return False

    def _discover_trusted_local_ips(self):
        trusted = {"127.0.0.1", "0.0.0.0"}
        # Default gateway is often chatty and should not trigger recon alerts.
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        trusted.add(parts[idx + 1])
        except Exception:
            pass
        # Local DNS resolvers can generate high-volume DNS traffic.
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver "):
                        ip = line.split()[1]
                        trusted.add(ip)
        except Exception:
            pass
        return trusted

    def _is_multicast_or_broadcast(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_multicast or ip.endswith(".255")
        except Exception:
            return False

    def _suppress_noisy_alert(self, src, dst=""):
        if not self._fp_suppression_enabled:
            return False
        if time.time() - self._started_at < self.STARTUP_GRACE_SEC:
            return True
        if src in self._trusted_local_ips:
            return True
        if dst and self._is_multicast_or_broadcast(dst):
            return True
        return False

    def _resolve(self, ip):
        with self._host_lock:
            cached = self._resolve_cache.get(ip)
        if cached:
            return cached
        self._request_resolve(ip)
        return "Unresolved"

    def host_count(self):
        with self._host_lock:
            return len(self.known_hosts)

    def host_items_snapshot(self):
        with self._host_lock:
            return list(self.known_hosts.items())

    def _is_private(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    def _mac_for(self, ip):
        return self.arp_table.get(ip, "Unknown")

    def _packet_summary(self, pkt):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            if IP in pkt:
                proto = ("TCP"  if TCP  in pkt else
                         "UDP"  if UDP  in pkt else
                         "ICMP" if ICMP in pkt else "IP")
                sp = (pkt[TCP].sport if TCP in pkt else
                      pkt[UDP].sport if UDP in pkt else "-")
                dp = (pkt[TCP].dport if TCP in pkt else
                      pkt[UDP].dport if UDP in pkt else "-")
                fl = str(pkt[TCP].flags) if TCP in pkt else ""
                return {"ts": ts, "src": pkt[IP].src, "dst": pkt[IP].dst,
                        "proto": proto, "sport": sp, "dport": dp,
                        "flags": fl, "length": len(pkt)}
            if ARP in pkt:
                return {"ts": ts, "src": pkt[ARP].psrc, "dst": pkt[ARP].pdst,
                        "proto": "ARP", "sport": "-", "dport": "-",
                        "flags": "req" if pkt[ARP].op == 1 else "reply",
                        "length": len(pkt)}
        except Exception:
            pass
        return None

    def _track_host(self, pkt):
        try:
            if Ether not in pkt or IP not in pkt:
                return
            mac = pkt[Ether].src
            ip  = pkt[IP].src
            now = datetime.now().strftime("%H:%M:%S")
            with self._host_lock:
                is_new = mac not in self.known_hosts
                if is_new:
                    hostname = self._resolve_cache.get(ip, "Unresolved")
                    self.known_hosts[mac] = {
                        "ip": ip, "mac": mac, "hostname": hostname,
                        "first_seen": now, "last_seen": now,
                    }
                else:
                    self.known_hosts[mac]["last_seen"] = now
                    self.known_hosts[mac]["ip"] = ip
                    self.known_hosts[mac]["hostname"] = self._resolve_cache.get(ip, self.known_hosts[mac].get("hostname", "Unresolved"))
            self._request_resolve(ip)
            if is_new and self._can_alert("new_device", ip):
                self.on_threat(self._t_new_device(ip, mac, self._resolve(ip)))
        except Exception:
            pass

    def _check_arp(self, pkt):
        try:
            if pkt[ARP].op != 2:
                return
            src_ip  = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            if src_ip in self.arp_table:
                old = self.arp_table[src_ip]
                if old != src_mac and old != "ff:ff:ff:ff:ff:ff":
                    if self._can_alert("arp_spoof", src_ip):
                        self.on_threat(self._t_arp_spoof(src_ip, src_mac, old))
            self.arp_table[src_ip] = src_mac
        except Exception:
            pass

    def _check_ip(self, pkt):
        src = pkt[IP].src
        dst = pkt[IP].dst
        pkt_len = len(pkt)
        self._stats.record(pkt_len, src_ip=src, dst_ip=dst,
                           sport=pkt[TCP].sport if TCP in pkt else None,
                           dport=pkt[TCP].dport if TCP in pkt else
                                 pkt[UDP].dport if UDP in pkt else None)
        if ICMP in pkt:
            self._check_icmp_flood(src)
        if TCP in pkt:
            flags = str(pkt[TCP].flags)
            sp    = pkt[TCP].sport
            dp    = pkt[TCP].dport
            if "S" in flags and "A" not in flags:
                self._check_syn_flood(src, pkt)
                self._check_brute_force(src, dp)
            self._check_port_scan(src, dp)
            self._check_horiz_scan(src, dst, dp)
            self._check_malware_port(src, dst, dp, "TCP")
            self._check_malware_port(src, dst, sp, "TCP")
        if UDP in pkt:
            dp = pkt[UDP].dport
            sp = pkt[UDP].sport
            self._check_udp_flood(src)
            self._check_port_scan(src, dp)
            self._check_malware_port(src, dst, dp, "UDP")
            if DNS_AVAILABLE and DNS in pkt:
                try:
                    if pkt[DNS].qr == 0 and DNSQR in pkt:
                        name = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                        self._check_dns_tunnel(src, name)
                except Exception:
                    pass
        if self._is_private(src) and not self._is_private(dst):
            self._check_exfil(src, pkt_len)

    def _check_port_scan(self, src, dport):
        now = time.time()
        d   = self._port_scan[src]
        d["events"].append((now, dport))
        cutoff = now - self.PORT_SCAN_WINDOW
        while d["events"] and d["events"][0][0] < cutoff:
            d["events"].popleft()
        recent_ports = {port for _, port in d["events"]}
        if len(recent_ports) >= self.PORT_SCAN_THRESHOLD and len(d["events"]) >= 10:
            if self._suppress_noisy_alert(src):
                return
            if self._confirm_pattern("port_scan", src) and self._can_alert("port_scan", src):
                ports = sorted(recent_ports)[:15]
                self.on_threat(self._t_port_scan(src, self._mac_for(src),
                                                  self._resolve(src), ports))
            d["events"].clear()

    def _check_horiz_scan(self, src, dst, dport):
        if self._is_multicast_or_broadcast(dst):
            return
        now = time.time()
        key = (src, dport)
        d   = self._horiz_scan[key]
        d["events"].append((now, dst))
        cutoff = now - self.HORIZ_SCAN_WINDOW
        while d["events"] and d["events"][0][0] < cutoff:
            d["events"].popleft()
        recent_hosts = {host for _, host in d["events"]}
        if len(recent_hosts) >= self.HORIZ_SCAN_THRESHOLD:
            if self._suppress_noisy_alert(src, dst):
                return
            if self._confirm_pattern(f"horiz_scan_{dport}", src) and self._can_alert("horiz_scan_%d" % dport, src):
                self.on_threat(
                    self._t_horiz_scan(src, self._mac_for(src),
                                       self._resolve(src), dport,
                                       sorted(recent_hosts)[:10]))
            d["events"].clear()

    def _check_syn_flood(self, src, pkt):
        now = time.time()
        q   = self._syn[src]
        q.append(now)
        cutoff = now - self.SYN_FLOOD_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.SYN_FLOOD_THRESHOLD:
            if self._suppress_noisy_alert(src, pkt[IP].dst):
                return
            if self._confirm_pattern("syn_flood", src) and self._can_alert("syn_flood", src):
                tp = pkt[TCP].dport if TCP in pkt else "?"
                self.on_threat(self._t_syn_flood(src, self._mac_for(src),
                                                  self._resolve(src),
                                                  pkt[IP].dst, tp, len(q)))
            q.clear()

    def _check_icmp_flood(self, src):
        now = time.time()
        q   = self._icmp[src]
        q.append(now)
        cutoff = now - self.ICMP_FLOOD_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.ICMP_FLOOD_THRESHOLD:
            if self._suppress_noisy_alert(src):
                return
            if self._confirm_pattern("icmp_flood", src) and self._can_alert("icmp_flood", src):
                self.on_threat(self._t_icmp_flood(src, self._mac_for(src),
                                                   self._resolve(src), len(q)))
            q.clear()

    def _check_udp_flood(self, src):
        now = time.time()
        q   = self._udp[src]
        q.append(now)
        cutoff = now - self.UDP_FLOOD_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.UDP_FLOOD_THRESHOLD:
            if self._suppress_noisy_alert(src):
                return
            if self._confirm_pattern("udp_flood", src) and self._can_alert("udp_flood", src):
                self.on_threat(self._t_udp_flood(src, self._mac_for(src),
                                                  self._resolve(src), len(q)))
            q.clear()

    def _check_brute_force(self, src, dport):
        if dport not in BRUTE_FORCE_PORTS:
            return
        now = time.time()
        q   = self._brute[src][dport]
        q.append(now)
        cutoff = now - self.BRUTE_FORCE_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.BRUTE_FORCE_THRESHOLD:
            if self._suppress_noisy_alert(src):
                return
            if self._confirm_pattern(f"brute_{dport}", src) and self._can_alert("brute_%d" % dport, src):
                svc = BRUTE_FORCE_PORTS[dport]
                self.on_threat(self._t_brute_force(src, self._mac_for(src),
                                                    self._resolve(src),
                                                    dport, svc, len(q)))
            q.clear()

    def _check_malware_port(self, src, dst, port, proto):
        if port not in MALICIOUS_PORTS:
            return
        key = (src, port)
        if key in self._malware_seen:
            return
        if self._can_alert("malware_port_%d" % port, src):
            self._malware_seen.add(key)
            desc = MALICIOUS_PORTS[port]
            self.on_threat(self._t_malware_port(src, dst, self._mac_for(src),
                                                 self._resolve(src), port,
                                                 proto, desc))

    def _check_dns_tunnel(self, src, name):
        if self._suppress_noisy_alert(src):
            return
        parts   = name.rstrip(".").split(".")
        longest = max((len(p) for p in parts), default=0)
        if longest >= self.DNS_TUNNEL_LENGTH:
            if self._confirm_pattern("dns_long", src) and self._can_alert("dns_long", src):
                self.on_threat(self._t_dns_tunnel(src, self._mac_for(src),
                                                   self._resolve(src), name,
                                                   "abnormally long DNS label"))
            return
        now = time.time()
        q   = self._dns_q[src]
        q.append(now)
        cutoff = now - self.DNS_TUNNEL_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.DNS_TUNNEL_THRESHOLD:
            if self._confirm_pattern("dns_flood", src) and self._can_alert("dns_flood", src):
                self.on_threat(self._t_dns_tunnel(src, self._mac_for(src),
                                                   self._resolve(src), name,
                                                   "high DNS query rate"))
            q.clear()

    def _check_exfil(self, src, pkt_len):
        if self._suppress_noisy_alert(src):
            return
        now = time.time()
        q   = self._exfil[src]
        q.append((now, pkt_len))
        cutoff = now - self.EXFIL_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        total_mb = sum(b for _, b in q) / 1_048_576
        if total_mb >= self.EXFIL_MB_THRESHOLD:
            if self._confirm_pattern("exfil", src) and self._can_alert("exfil", src):
                self.on_threat(self._t_exfil(src, self._mac_for(src),
                                              self._resolve(src), total_mb))
            q.clear()

    # ── Threat builders ───────────────────────────────────────────────────────

    @staticmethod
    def _ts():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _t_arp_spoof(self, ip, new_mac, old_mac):
        return {
            "level": "CRITICAL", "type": "ARP Spoofing / Man-in-the-Middle",
            "ts": self._ts(), "src_ip": ip, "src_mac": new_mac,
            "hostname": self._resolve(ip),
            "what": (
                f"ARP spoofing detected!\n\n"
                f"  IP {ip} was mapped to  {old_mac}\n"
                f"  but is now claiming   {new_mac}.\n\n"
                "The attacker is poisoning your ARP cache so traffic is silently "
                "redirected through their machine. Passwords, session cookies and "
                "unencrypted communications are being intercepted in real time."
            ),
            "action": [
                f"1.  Disconnect the rogue device (MAC {new_mac}) immediately.",
                f"2.  Block it on your router/switch:  deny MAC {new_mac}",
                "3.  Change ALL passwords used on this network.",
                "4.  Inspect ARP cache:  arp -n",
                f"5.  Set a static ARP entry for your gateway:\n"
                    f"        sudo arp -s <gateway_ip> <real_gateway_mac>",
                "6.  Enable Dynamic ARP Inspection (DAI) on your managed switch.",
                "7.  Use HTTPS and a VPN on this network going forward.",
            ]
        }

    def _t_port_scan(self, ip, mac, hostname, ports):
        return {
            "level": "WARNING", "type": "Port Scan / Vertical Reconnaissance",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"Port scanning from  {ip}  ({hostname})  MAC {mac}.\n\n"
                f"  Ports probed: {', '.join(map(str, ports))}\n\n"
                f"  {len(ports)}+ unique ports in {self.PORT_SCAN_WINDOW}s. "
                "The attacker is mapping exposed services to find vulnerabilities."
            ),
            "action": [
                f"1.  Confirm {ip} is an authorised device.",
                f"2.  Block at firewall:  sudo ufw deny from {ip}",
                "3.  Audit open services:  sudo ss -tlnp",
                "4.  Close any services you don't need exposed.",
                "5.  Install fail2ban:  sudo apt install fail2ban && sudo systemctl enable --now fail2ban",
            ]
        }

    def _t_horiz_scan(self, ip, mac, hostname, port, targets):
        svc = BRUTE_FORCE_PORTS.get(port, "service")
        return {
            "level": "WARNING", "type": "Horizontal Scan / Network Sweep",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"Horizontal scan from  {ip}  ({hostname}).\n\n"
                f"  Target port  : {port}  ({svc})\n"
                f"  Hosts probed : {', '.join(targets[:8])}\n\n"
                "The attacker is sweeping for all hosts with this port open — "
                "typical pre-exploitation reconnaissance."
            ),
            "action": [
                f"1.  Block source:  sudo ufw deny from {ip}",
                f"2.  Review hosts with port {port} open:  sudo nmap -p {port} <subnet>",
                "3.  Close unnecessary services on discovered hosts.",
                "4.  Segment the network so internal hosts cannot reach each other freely.",
            ]
        }

    def _t_syn_flood(self, ip, mac, hostname, target, tp, count):
        return {
            "level": "CRITICAL", "type": "SYN Flood / TCP Denial of Service",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"SYN flood from  {ip}  ({hostname}).\n\n"
                f"  Target  : {target}:{tp}\n"
                f"  Burst   : {count} SYNs in {self.SYN_FLOOD_WINDOW}s\n\n"
                "Half-open TCP connections are exhausting the target's connection "
                "table, preventing legitimate traffic from connecting."
            ),
            "action": [
                "1.  Enable SYN cookies:  sudo sysctl -w net.ipv4.tcp_syncookies=1",
                f"2.  Block attacker:  sudo ufw deny from {ip}",
                "3.  Rate-limit SYNs:\n"
                    "        sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT\n"
                    "        sudo iptables -A INPUT -p tcp --syn -j DROP",
                "4.  Persist:  echo 'net.ipv4.tcp_syncookies=1' | sudo tee -a /etc/sysctl.conf",
            ]
        }

    def _t_icmp_flood(self, ip, mac, hostname, count):
        return {
            "level": "WARNING", "type": "ICMP Flood / Ping Flood DoS",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"ICMP flood from  {ip}  ({hostname})  MAC {mac}.\n\n"
                f"  Burst: {count} ICMP packets in {self.ICMP_FLOOD_WINDOW}s.\n\n"
                "Ping flood is overwhelming the network with ICMP traffic, "
                "consuming bandwidth and CPU on targeted devices."
            ),
            "action": [
                f"1.  Block ICMP from {ip}:  sudo ufw deny from {ip} to any proto icmp",
                "2.  Rate-limit all ICMP:\n"
                    "        sudo iptables -A INPUT -p icmp --icmp-type echo-request "
                    "-m limit --limit 1/s -j ACCEPT\n"
                    "        sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
                "3.  If external, ask your ISP to filter upstream.",
            ]
        }

    def _t_udp_flood(self, ip, mac, hostname, count):
        return {
            "level": "WARNING", "type": "UDP Flood / Amplification DoS",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"UDP flood from  {ip}  ({hostname})  MAC {mac}.\n\n"
                f"  Burst: {count} UDP packets in {self.UDP_FLOOD_WINDOW}s.\n\n"
                "High-volume UDP traffic is consuming bandwidth. This may be a "
                "direct flood or a reflection/amplification attack using spoofed sources."
            ),
            "action": [
                f"1.  Block UDP flood source:  sudo ufw deny from {ip}",
                "2.  Rate-limit inbound UDP:\n"
                    "        sudo iptables -A INPUT -p udp -m limit --limit 100/s -j ACCEPT\n"
                    "        sudo iptables -A INPUT -p udp -j DROP",
                "3.  If source IPs appear spoofed, enable BCP38 RPF on your router.",
                "4.  Contact your ISP for upstream mitigation if external.",
            ]
        }

    def _t_brute_force(self, ip, mac, hostname, port, svc, count):
        return {
            "level": "CRITICAL", "type": f"Brute Force Attack — {svc} (port {port})",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"Brute force attack on {svc} (port {port}) from  {ip}  ({hostname}).\n\n"
                f"  MAC address : {mac}\n"
                f"  Attempts    : {count} connection attempts in {self.BRUTE_FORCE_WINDOW}s.\n\n"
                f"The attacker is systematically trying credentials against your "
                f"{svc} service to gain unauthorised remote access."
            ),
            "action": [
                f"1.  Block the attacker immediately:  sudo ufw deny from {ip}",
                f"2.  Change {svc} credentials on all targeted hosts immediately.",
                "3.  Install fail2ban:  sudo apt install fail2ban",
                f"4.  If {svc} is not needed externally, bind to localhost only.",
                "5.  For SSH — enforce key-based auth:\n"
                    "        PasswordAuthentication no  in /etc/ssh/sshd_config",
                "6.  Review auth logs:  sudo journalctl -u sshd | tail -50",
            ]
        }

    def _t_malware_port(self, src, dst, mac, hostname, port, proto, desc):
        return {
            "level": "CRITICAL", "type": f"Known Malware/C2 Port — {port}/{proto}",
            "ts": self._ts(), "src_ip": src, "src_mac": mac, "hostname": hostname,
            "what": (
                f"Traffic on well-known malware/C2 port  {port}/{proto}.\n\n"
                f"  Source      : {src}  ({hostname})\n"
                f"  Destination : {dst}\n"
                f"  Associated  : {desc}\n\n"
                f"Port {port} is commonly used by malware or remote-access tools. "
                "This host may be compromised and communicating with a C2 server."
            ),
            "action": [
                f"1.  Isolate {src} from the network immediately.",
                f"2.  Block:  sudo ufw deny from {src} to any port {port}",
                "3.  Scan for rootkits:\n"
                    "        sudo apt install chkrootkit rkhunter\n"
                    "        sudo chkrootkit && sudo rkhunter --check",
                "4.  Check unexpected listeners:  sudo ss -tlnp",
                "5.  Consider reimaging the host if compromise is confirmed.",
            ]
        }

    def _t_dns_tunnel(self, ip, mac, hostname, name, reason):
        return {
            "level": "WARNING", "type": "DNS Tunneling / Covert Channel",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"Suspected DNS tunneling from  {ip}  ({hostname}).\n\n"
                f"  MAC address     : {mac}\n"
                f"  Suspicious query: {name[:80]}\n"
                f"  Reason          : {reason}\n\n"
                "DNS tunneling encodes data inside DNS queries to bypass firewalls "
                "and establish covert C2 channels or exfiltrate data over port 53."
            ),
            "action": [
                f"1.  Inspect DNS traffic:  sudo tcpdump -i any -n 'src {ip} and udp port 53'",
                "2.  Block the suspicious DNS destination at your firewall.",
                "3.  Restrict DNS — force all hosts to use your internal resolver only.",
                "4.  Scan the source host for malware.",
            ]
        }

    def _t_exfil(self, ip, mac, hostname, total_mb):
        return {
            "level": "CRITICAL", "type": "Data Exfiltration Detected",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"Large outbound data transfer from internal host  {ip}  ({hostname}).\n\n"
                f"  MAC address   : {mac}\n"
                f"  Data sent     : {total_mb:.1f} MB in {self.EXFIL_WINDOW}s\n\n"
                "An internal host is sending an unusually large volume of data to "
                "an external destination. This may indicate data theft, ransomware "
                "backup, or a compromised device uploading sensitive files."
            ),
            "action": [
                f"1.  Block {ip} immediately:  sudo ufw deny from {ip}",
                "2.  Capture the traffic for forensics:\n"
                    f"        sudo tcpdump -i any -w exfil_capture.pcap src {ip}",
                "3.  Identify the sending process:\n"
                    "        sudo ss -tpn | grep <dest_ip>",
                "4.  Disconnect the host if compromise is suspected.",
                "5.  Preserve disk state before any remediation.",
                "6.  Report the incident per your IR policy.",
            ]
        }

    def _t_new_device(self, ip, mac, hostname):
        return {
            "level": "INFO", "type": "New Device Joined Network",
            "ts": self._ts(), "src_ip": ip, "src_mac": mac, "hostname": hostname,
            "what": (
                f"A previously unseen device appeared on your network.\n\n"
                f"  IP address : {ip}\n"
                f"  MAC address: {mac}\n"
                f"  Hostname   : {hostname}\n\n"
                "This could be a legitimate device or an unauthorised intruder."
            ),
            "action": [
                "1.  Confirm this device belongs to someone authorised.",
                f"2.  Look up MAC manufacturer (first 6 chars): {mac[:8]}",
                "3.  If unrecognised, block its MAC on your router.",
                "4.  Enable MAC address filtering on your Wi-Fi access point.",
                "5.  If unauthorised, change your Wi-Fi passphrase immediately.",
            ]
        }


# ─────────────────────────────────────────────────────────────────────────────
# BANDWIDTH SPARKLINE GRAPH
# ─────────────────────────────────────────────────────────────────────────────

class BandwidthGraph(tk.Canvas):
    def __init__(self, parent, stats, **kwargs):
        kwargs.setdefault("height", 90)
        kwargs.setdefault("bg",     BG3)
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self._stats = stats

    def refresh(self):
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 10 or h < 10:
            return
        self.delete("all")
        history = list(self._stats.bps_history)
        n       = len(history)
        if n < 2:
            return
        max_val = max(history) or 1
        step    = w / max(n - 1, 1)
        pad_y   = 16
        self.create_rectangle(0, 0, w, h, fill=BG2, outline="")
        # grid
        for i in range(1, 4):
            y = h - pad_y - (h - pad_y) * i // 4
            self.create_line(0, y, w, y, fill=BG4, width=1, dash=(2, 4))
        # points
        pts = []
        for i, val in enumerate(history):
            x = i * step
            y = h - pad_y - (val / max_val) * (h - pad_y - 4)
            pts.extend([x, y])
        if len(pts) >= 4:
            self.create_polygon([0, h] + pts + [w, h], fill=TEAL, outline="")
            self.create_line(pts, fill="#2b8d97", width=6, smooth=True)
            self.create_line(pts, fill=CYAN, width=2, smooth=True)
            self.create_oval(pts[-2] - 4, pts[-1] - 4, pts[-2] + 4, pts[-1] + 4,
                             fill=CYAN, outline="")
        current = history[-1]
        self.create_text(w - 4, 2, anchor="ne",
                         text=f"▲ {StatsEngine.fmt_bytes(current)}/s",
                         fill=FG, font=FONT_SM)
        self.create_text(4, 2, anchor="nw",
                         text=f"max {StatsEngine.fmt_bytes(max_val)}/s",
                         fill=FG2, font=FONT_SM)
        self.create_text(4, h - 2, anchor="sw",
                         text="60 s bandwidth", fill=FG2, font=FONT_SM)


class HoverTip:
    def __init__(self, widget, text, delay=450):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self._cancel()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self._after_id is not None:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self):
        if self._tip is not None or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self._tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            bg=BG3,
            fg=FG,
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=6,
            font=FONT_SM,
            wraplength=320,
        )
        label.pack()

    def _hide(self, _event=None):
        self._cancel()
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS DIALOG
# ─────────────────────────────────────────────────────────────────────────────

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent, detector):
        super().__init__(parent)
        self.title("Sentinel — Detection Settings")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._det = detector
        self._build()
        self.transient(parent)
        self.grab_set()
        self.focus_set()

    def _build(self):
        pad = {"padx": 12, "pady": 5}
        tk.Label(self, text="Detection Thresholds",
                 font=FONT_H2, fg=BLUE, bg=BG).grid(
            row=0, column=0, columnspan=2, sticky="w", **pad)
        fields = [
            ("Port scan — unique ports / 60 s",    "PORT_SCAN_THRESHOLD"),
            ("Horizontal scan — unique IPs / 60 s","HORIZ_SCAN_THRESHOLD"),
            ("SYN flood — SYNs / 10 s",            "SYN_FLOOD_THRESHOLD"),
            ("ICMP flood — pings / 10 s",           "ICMP_FLOOD_THRESHOLD"),
            ("UDP flood — packets / 10 s",          "UDP_FLOOD_THRESHOLD"),
            ("Brute force — attempts / 60 s",       "BRUTE_FORCE_THRESHOLD"),
            ("Exfil alert — MB sent / 60 s",        "EXFIL_MB_THRESHOLD"),
            ("DNS tunnel — queries / 30 s",         "DNS_TUNNEL_THRESHOLD"),
            ("Alert cooldown — seconds",            "ALERT_COOLDOWN"),
        ]
        self._vars = {}
        for row, (label, attr) in enumerate(fields, start=1):
            tk.Label(self, text=label, fg=FG2, bg=BG,
                     anchor="w").grid(row=row, column=0, sticky="w", **pad)
            var = tk.IntVar(value=getattr(self._det, attr, 0))
            self._vars[attr] = var
            ttk.Spinbox(self, from_=1, to=99999, textvariable=var,
                        width=8).grid(row=row, column=1, sticky="e", **pad)

        fp_row = len(fields) + 1
        tk.Label(self, text="False-Positive Tuning",
                 font=FONT_H2, fg=CYAN, bg=BG).grid(
            row=fp_row, column=0, columnspan=2, sticky="w", **pad)

        fp_fields = [
            ("Startup grace (seconds)", "STARTUP_GRACE_SEC"),
            ("Confirm window (seconds)", "ALERT_CONFIRM_WINDOW"),
            ("Confirm hits required", "ALERT_CONFIRM_HITS"),
        ]
        base_row = fp_row + 1
        for idx, (label, attr) in enumerate(fp_fields):
            row = base_row + idx
            tk.Label(self, text=label, fg=FG2, bg=BG,
                     anchor="w").grid(row=row, column=0, sticky="w", **pad)
            var = tk.IntVar(value=getattr(self._det, attr, 0))
            self._vars[attr] = var
            ttk.Spinbox(self, from_=1, to=99999, textvariable=var,
                        width=8).grid(row=row, column=1, sticky="e", **pad)

        self._fp_enabled_var = tk.BooleanVar(value=bool(getattr(self._det, "_fp_suppression_enabled", True)))
        ttk.Checkbutton(
            self,
            text="Enable false-positive suppression",
            variable=self._fp_enabled_var,
        ).grid(row=base_row + len(fp_fields), column=0, columnspan=2, sticky="w", padx=12, pady=(2, 6))

        trusted_ips = sorted(getattr(self._det, "_trusted_local_ips", set()))
        self._trusted_ips_var = tk.StringVar(value=", ".join(trusted_ips))
        tk.Label(self, text="Trusted local IPs (comma-separated)", fg=FG2, bg=BG,
                 anchor="w").grid(row=base_row + len(fp_fields) + 1, column=0, sticky="w", **pad)
        ttk.Entry(self, textvariable=self._trusted_ips_var, width=42).grid(
            row=base_row + len(fp_fields) + 1, column=1, sticky="e", **pad)

        bf = tk.Frame(self, bg=BG)
        bf.grid(row=base_row + len(fp_fields) + 2, column=0, columnspan=2, pady=10)
        ttk.Button(bf, text="Apply & Close", style="Go.TButton",
                   command=self._apply).pack(side=tk.LEFT, padx=6)
        ttk.Button(bf, text="Cancel", style="Dim.TButton",
                   command=self.destroy).pack(side=tk.LEFT, padx=4)

    def _apply(self):
        for attr, var in self._vars.items():
            try:
                setattr(self._det, attr, var.get())
            except Exception:
                pass

        try:
            self._det._fp_suppression_enabled = bool(self._fp_enabled_var.get())
        except Exception:
            pass

        try:
            raw = self._trusted_ips_var.get().strip()
            trusted = set()
            if raw:
                for part in raw.split(","):
                    ip = part.strip()
                    if not ip:
                        continue
                    ipaddress.ip_address(ip)
                    trusted.add(ip)
            self._det._trusted_local_ips = trusted
        except Exception:
            messagebox.showwarning(
                "Invalid Trusted IP List",
                "Trusted IP list contains invalid entries and was not updated.",
            )
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

class NetworkSentinel(tk.Tk):

    MAX_PACKETS = 600
    MAX_PKT_BUF = 600
    MAX_PKT_QUEUE = 5000
    MAX_THREAT_QUEUE = 2000
    MAX_RESPONSE_LOG_LINES = 160
    GRAPH_MS    = 1000
    BLOCK_TTL_DEFAULT_SEC = 3600
    BASELINE_WARMUP_DEFAULT_SEC = 300
    FORENSIC_BURST_PACKETS = 220

    def __init__(self):
        super().__init__()
        self.title("Network Sentinel v2.0 — Live Intrusion Monitor")
        self.configure(bg=BG)
        self.geometry("1500x900")
        self.minsize(1000, 640)
        self._compact_mode = False
        self._layout_mode = tk.StringVar(value="auto")

        self._running      = False
        self._paused       = False
        self._filter_str   = ""
        self._detector     = None
        self._stats        = StatsEngine()
        self._sniff_thread = None
        self._lock         = threading.Lock()
        self._pkt_queue    = deque(maxlen=self.MAX_PKT_QUEUE)
        self._threat_queue = deque(maxlen=self.MAX_THREAT_QUEUE)
        self._dropped_pkt_queue = 0
        self._dropped_threat_queue = 0
        self._pkt_count    = 0
        self._pkt_buffer   = deque(maxlen=self.MAX_PKT_BUF)
        self._raw_pkts     = deque(maxlen=self.MAX_PKT_BUF)
        self._known_mac_rows = {}
        self._tc           = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
        self._threats      = []
        self._neutralize_log_path = os.path.expanduser("~/Documents/sentinel_actions.log")
        self._neutralize_history  = defaultdict(list)
        self._neutralize_store_path = os.path.expanduser("~/Documents/sentinel_transactions.jsonl")
        self._response_log_path = os.path.expanduser("~/Documents/sentinel_response_log.jsonl")
        self._response_log_entries = []
        self._response_log_filter = "all"
        self._response_log_search = ""
        self._response_log_selected_line = None
        self._response_log_line_map = {}
        self._allowlist_path = os.path.expanduser("~/Documents/sentinel_allowlist.json")
        self._allowlist = {"ips": [], "macs": [], "hostnames": []}
        self._dry_run = False
        self._policy_profile = "Balanced"
        self._block_ttl_sec = self.BLOCK_TTL_DEFAULT_SEC
        self._active_blocks = {}
        self._response_queue = queue.Queue()
        self._response_worker = threading.Thread(target=self._response_worker_loop, daemon=True)
        self._response_worker.start()
        self._local_ips = self._discover_local_ips()
        self._gateway_ip = self._discover_gateway_ip()
        self._mac_address = self._get_mac_address()
        self._network_isolation_enabled = False
        self._active_arp_spoofs = {}  # {src_ip: {'thread': thread, 'stop': Event}}
        self._active_iface = None
        
        # ─── PERSISTENT THREAT REPUTATION DATABASE ─────────────────────────
        self._threat_db_path = os.path.expanduser("~/Documents/sentinel_threats.json")
        self._threat_database = {}  # {src_ip: {count, severity, first_seen, last_seen, types, blocked}}
        self._load_threat_database()
        
        # ─── AUTO-QUARANTINE SYSTEM ────────────────────────────────────────
        self._quarantine_enabled = True
        self._quarantine_critical_threshold = 5  # block after 5 CRITICAL in 60s
        self._quarantine_scan_threshold = 50  # block after 50 ports scanned in 30s
        self._quarantine_bruteforce_threshold = 10  # block after 10 brute-force attempts in 60s
        self._queued_neutralizations = set()
        
        # ─── RATE LIMITING STATE ──────────────────────────────────────────
        self._rate_limit_enabled = False
        self._rate_limit_rules = {}  # {src_ip: {pps_limit, created_at}}
        
        # ─── NETWORK BASELINE / ANOMALY DETECTION ────────────────────────
        self._baseline_enabled = True
        self._baseline_learned = False
        self._baseline_warmup_sec = self.BASELINE_WARMUP_DEFAULT_SEC
        self._baseline_started_at = None
        self._baseline_ips = set()  # "normal" IPs on network
        self._baseline_ports = defaultdict(set)  # {ip: set(ports)}
        self._baseline_protocols = defaultdict(set)  # {ip: set(protocols)}
        self._anomalies = []  # list of detected anomalies
        
        # ─── HONEYPOT DECOY SERVICES ──────────────────────────────────────
        self._honeypot_enabled = False
        self._honeypot_decoys = {}  # {port: interactions_count}
        self._honeypot_interactions = []  # list of honeypot hit logs
        self._honeypot_hits = defaultdict(deque)  # {(src_ip, port): deque[timestamps]}
        self._honeypot_alert_cooldown = {}  # {(src_ip, port): ts}
        self._honeypot_window_sec = 90
        self._honeypot_trap_threshold = 3
        self._honeypot_alert_cooldown_sec = 25
        self._honeypot_auto_isolate = True
        self._honeypot_escalation_mode = NEUTRALIZE_BLOCKKILL
        self._honeypot_force_network_isolation = True
        self._honeypot_min_engagement_sec = 75
        self._honeypot_min_unique_ports = 2
        self._honeypot_max_grace_hits = 8
        self._honeypot_source_state = {}  # {src_ip: {first_seen, last_seen, ports, total_hits}}
        
        # ─── AUTOMATED RESPONSE PLAYBOOKS ────────────────────────────────
        self._playbooks = {
            "critical_response": {
                "name": "CRITICAL Threat Response",
                "actions": ["pcap_burst", "block_local", "kill_sessions", "network_isolate", "export_report"]
            },
            "scan_response": {
                "name": "Port Scan Response",
                "actions": ["block_local", "rate_limit", "log_threat"]
            },
            "mass_attack_response": {
                "name": "Mass Attack Response",
                "actions": ["auto_quarantine_top5", "reduce_alert_noise", "enable_honeypot"]
            }
        }
        self._active_playbooks = {}  # {src_ip: playbook_name}
        
        # ─── REAL-TIME ALERT STATE ────────────────────────────────────────
        self._alert_callback_enabled = True  # for one-click response
        self._pending_one_click_actions = {}  # {threat_id: (threat, mode)}
        
        self._load_allowlist()
        self._load_neutralization_history()
        self._load_response_log_history()
        self._apply_profile_tuning()

        self._build_styles()
        self._build_ui()
        self._refresh_response_log_view()
        self._build_menu()
        self.bind("<Configure>", self._on_window_resize)
        self.bind_all("<Control-f>", self._focus_response_log_search)
        self.bind_all("<Escape>", self._clear_response_log_search_shortcut)
        self.after(10, lambda: self._apply_compact_mode(self.winfo_width() < 1380))
        self._poll()
        self._tick_stats()

    def _build_menu(self):
        menubar = tk.Menu(self)
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_radiobutton(
            label="Layout: Auto",
            variable=self._layout_mode,
            value="auto",
            accelerator="Ctrl+1",
            command=self._apply_layout_mode,
        )
        view_menu.add_radiobutton(
            label="Layout: Compact",
            variable=self._layout_mode,
            value="compact",
            accelerator="Ctrl+2",
            command=self._apply_layout_mode,
        )
        view_menu.add_radiobutton(
            label="Layout: Full",
            variable=self._layout_mode,
            value="full",
            accelerator="Ctrl+3",
            command=self._apply_layout_mode,
        )
        menubar.add_cascade(label="View", menu=view_menu)
        self.config(menu=menubar)

        # Keyboard layout toggles
        self.bind_all("<Control-Key-1>", self._set_layout_auto_shortcut)
        self.bind_all("<Control-Key-2>", self._set_layout_compact_shortcut)
        self.bind_all("<Control-Key-3>", self._set_layout_full_shortcut)

    def _build_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(
            ".",
            background=BG,
            foreground=FG,
            font=FONT_UI,
            fieldbackground=BG2,
            borderwidth=0,
        )
        for widget_name in ("TFrame", "TLabel"):
            s.configure(widget_name, background=BG, foreground=FG)
        s.configure("Card.TFrame", background=BG2, relief="flat")
        s.configure("Control.TLabelframe", background=BG2, borderwidth=1, relief="solid")
        s.configure(
            "Control.TLabelframe.Label",
            background=BG2,
            foreground=FG2,
            font=("IBM Plex Sans", 9, "bold"),
        )
        s.configure(
            "TCombobox",
            fieldbackground=BG3,
            background=BG3,
            foreground=FG,
            selectbackground=BLUE,
            arrowcolor=CYAN,
            bordercolor=BG4,
            lightcolor=BG4,
            darkcolor=BG4,
        )
        s.configure(
            "TSpinbox",
            fieldbackground=BG3,
            background=BG3,
            foreground=FG,
            arrowcolor=CYAN,
        )
        s.configure(
            "TEntry",
            fieldbackground=BG3,
            foreground=FG,
            insertcolor=FG,
            bordercolor=BG4,
            lightcolor=BG4,
            darkcolor=BG4,
        )
        s.configure(
            "Go.TButton",
            background=GREEN,
            foreground="#04120a",
            font=("IBM Plex Sans", 10, "bold"),
            padding=(12, 7),
        )
        s.configure(
            "Stop.TButton",
            background=RED,
            foreground="#fff",
            font=("IBM Plex Sans", 10, "bold"),
            padding=(12, 7),
        )
        s.configure(
            "Dim.TButton",
            background=BG3,
            foreground=FG,
            font=("IBM Plex Sans", 9),
            padding=(9, 5),
        )
        s.configure(
            "Pause.TButton",
            background=ORANGE,
            foreground="#000",
            font=("IBM Plex Sans", 9, "bold"),
            padding=(10, 5),
        )
        s.configure(
            "ToggleOn.TButton",
            background="#238636",
            foreground="#f0fff4",
            font=("IBM Plex Sans", 9, "bold"),
            padding=(8, 5),
        )
        s.configure(
            "ToggleOff.TButton",
            background=BG4,
            foreground=FG,
            font=("IBM Plex Sans", 9),
            padding=(8, 5),
        )
        s.map("Go.TButton", background=[("active", "#2ea043")])
        s.map("Stop.TButton", background=[("active", "#da3633")])
        s.map("Dim.TButton", background=[("active", BG4)], foreground=[("active", FG)])
        s.map("Pause.TButton", background=[("active", "#b07d1c")])
        s.map("ToggleOn.TButton", background=[("active", "#2ea043")])
        s.map("ToggleOff.TButton", background=[("active", BG3)], foreground=[("active", FG)])
        s.configure(
            "Treeview",
            background=BG2,
            foreground=FG,
            fieldbackground=BG2,
            rowheight=24,
            font=FONT_MONO,
            borderwidth=0,
        )
        s.configure(
            "Treeview.Heading",
            background=BG4,
            foreground=FG,
            font=("IBM Plex Sans", 9, "bold"),
            relief="flat",
        )
        s.map("Treeview", background=[("selected", BG3)], foreground=[("selected", CYAN)])
        s.map(
            "Treeview.Heading",
            background=[("active", "#34657a")],
            foreground=[("active", FG)],
        )

    def _build_ui(self):
        # Title bar
        tb = tk.Frame(self, bg=BG2, pady=10)
        tb.pack(fill=tk.X)
        title_wrap = tk.Frame(tb, bg=BG2)
        title_wrap.pack(side=tk.LEFT, padx=14)
        tk.Label(title_wrap, text="REAL-TIME NETWORK DEFENSE",
                 font=("IBM Plex Sans", 8, "bold"), fg=FG2, bg=BG2).pack(anchor="w")
        tk.Label(title_wrap, text="⚡  Network Sentinel  v2.0",
                 font=FONT_H1, fg=CYAN, bg=BG2).pack(anchor="w")
        self._subtitle_lbl = tk.Label(title_wrap, text="Live intrusion detection, triage, and response",
                 font=FONT_UI, fg=FG2, bg=BG2)
        self._subtitle_lbl.pack(anchor="w", pady=(1, 0))
        self._title_badge = tk.Label(tb, text="MONITORING SURFACE",
                 font=("IBM Plex Sans", 8, "bold"), fg=BG, bg=CYAN,
                 padx=10, pady=5)
        self._title_badge.pack(side=tk.RIGHT, padx=14)
        tk.Frame(self, bg=BG4, height=2).pack(fill=tk.X)

        # Control bar
        ctrl = ttk.Frame(self, style="Card.TFrame", padding=(12, 10))
        ctrl.pack(fill=tk.X, padx=10, pady=(8, 4))

        top_row = ttk.Frame(ctrl, style="Card.TFrame")
        top_row.pack(fill=tk.X)
        bottom_row = ttk.Frame(ctrl, style="Card.TFrame")
        bottom_row.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(top_row, text="Interface:", foreground=FG2).pack(side=tk.LEFT)
        self._iface_var = tk.StringVar()
        ifaces = self._get_ifaces()
        self._iface_cb = ttk.Combobox(top_row, textvariable=self._iface_var,
                                       values=ifaces, width=14, state="readonly")
        if ifaces:
            self._iface_cb.current(0)
        self._iface_cb.pack(side=tk.LEFT, padx=(4, 10))

        self._btn_start = ttk.Button(top_row, text="▶  Start",
                                     style="Go.TButton", command=self._start)
        self._btn_start.pack(side=tk.LEFT, padx=2)
        self._btn_stop = ttk.Button(top_row, text="■  Stop",
                                    style="Stop.TButton", command=self._stop,
                                    state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=2)
        self._btn_pause = ttk.Button(top_row, text="⏸  Pause Feed",
                                     style="Pause.TButton",
                                     command=self._toggle_pause,
                                     state=tk.DISABLED)
        self._btn_pause.pack(side=tk.LEFT, padx=2)

        ttk.Separator(top_row, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=8)
        self._btn_save_pcap = ttk.Button(top_row, text="💾 Save PCAP",
                                         style="Dim.TButton", command=self._save_pcap)
        self._btn_save_pcap.pack(side=tk.LEFT, padx=2)
        self._btn_settings = ttk.Button(top_row, text="⚙ Settings",
                                        style="Dim.TButton", command=self._open_settings)
        self._btn_settings.pack(side=tk.LEFT, padx=2)

        ttk.Separator(top_row, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=8)
        self._btn_tools = ttk.Button(top_row, text="Response Tools",
                         style="Dim.TButton", command=self._show_neutralize_capabilities)
        self._btn_tools.pack(side=tk.LEFT, padx=2)
        self._btn_incident_report = ttk.Button(top_row, text="Incident Report",
                               style="Dim.TButton", command=self._generate_incident_report)
        self._btn_incident_report.pack(side=tk.LEFT, padx=2)
        self._btn_export_threats = ttk.Button(top_row, text="Export Threats",
                              style="Dim.TButton", command=self._export_threats)
        self._btn_export_threats.pack(side=tk.LEFT, padx=2)
        self._btn_clear_threats = ttk.Button(top_row, text="Clear Threats",
                             style="Dim.TButton", command=self._clear_threats)
        self._btn_clear_threats.pack(side=tk.LEFT, padx=2)

        self._status_var = tk.StringVar(value="● Idle")
        self._status_lbl = tk.Label(top_row, textvariable=self._status_var,
                                     font=("IBM Plex Sans", 10, "bold"),
                                     fg=FG2, bg=BG2)
        self._status_lbl.pack(side=tk.RIGHT, padx=8)

        ttk.Label(bottom_row, text="Response Policy:", foreground=FG2).pack(side=tk.LEFT, padx=(0, 6))
        self._btn_dry_run = ttk.Button(bottom_row, text="Dry Run: OFF",
                   style="ToggleOff.TButton", command=self._toggle_dry_run)
        self._btn_dry_run.pack(side=tk.LEFT, padx=2)
        self._btn_ttl = ttk.Button(bottom_row, text=f"TTL: {self._block_ttl_sec//60}m",
                   style="Dim.TButton", command=self._cycle_block_ttl)
        self._btn_ttl.pack(side=tk.LEFT, padx=2)
        self._btn_profile = ttk.Button(bottom_row, text=f"Profile: {self._policy_profile}",
                   style="Dim.TButton", command=self._cycle_policy_profile)
        self._btn_profile.pack(side=tk.LEFT, padx=2)
        self._btn_network_isolation = ttk.Button(bottom_row, text="Network Isolation: OFF",
                   style="ToggleOff.TButton", command=self._toggle_network_isolation)
        self._btn_network_isolation.pack(side=tk.LEFT, padx=2)
        self._btn_auto_quarantine = ttk.Button(bottom_row, text="Auto-Quarantine: ON",
                   style="ToggleOn.TButton", command=self._toggle_auto_quarantine)
        self._btn_auto_quarantine.pack(side=tk.LEFT, padx=2)
        self._btn_rate_limit = ttk.Button(bottom_row, text="Rate Limit: OFF",
                   style="ToggleOff.TButton", command=self._toggle_rate_limit)
        self._btn_rate_limit.pack(side=tk.LEFT, padx=2)
        self._btn_honeypot_mode = ttk.Button(bottom_row, text="Honeypot Mode: Block+Kill",
               style="Dim.TButton", command=self._cycle_honeypot_escalation_mode)
        self._btn_honeypot_mode.pack(side=tk.LEFT, padx=2)
        self._btn_honeypot = ttk.Button(bottom_row, text="Honeypot: OFF",
                   style="ToggleOff.TButton", command=self._toggle_honeypot)
        self._btn_honeypot.pack(side=tk.LEFT, padx=2)
        self._install_policy_tooltips()
        self._sync_policy_button_texts()
        self._sync_action_button_texts()
        self._refresh_toggle_button_styles()

        # Stats bar
        sb = tk.Frame(self, bg=BG, pady=4)
        sb.pack(fill=tk.X)

        def _stat(parent, label, var, color=FG2):
            f = tk.Frame(parent, bg=BG2, highlightthickness=1, highlightbackground=BG4,
                         padx=8, pady=4)
            f.pack(side=tk.LEFT, padx=4)
            tk.Label(f, text=label, fg=FG2, bg=BG2, font=FONT_SM).pack(side=tk.LEFT)
            tk.Label(f, textvariable=var, fg=color, bg=BG2,
                     font=("JetBrains Mono", 10, "bold")).pack(side=tk.LEFT, padx=(4, 0))

        self._sv_pps   = tk.StringVar(value="0")
        self._sv_bps   = tk.StringVar(value="0 B")
        self._sv_hosts = tk.StringVar(value="0")
        self._sv_sess  = tk.StringVar(value="0")
        self._sv_pkts  = tk.StringVar(value="0")
        self._sv_drop_pkts = tk.StringVar(value="0")
        self._sv_drop_threats = tk.StringVar(value="0")
        self._sv_crit  = tk.StringVar(value="0")
        self._sv_warn  = tk.StringVar(value="0")
        self._sv_info  = tk.StringVar(value="0")

        _stat(sb, "Pkts/s:",    self._sv_pps)
        _stat(sb, "Bandwidth:", self._sv_bps,   CYAN)
        _stat(sb, "Hosts:",     self._sv_hosts, GREEN)
        _stat(sb, "Sessions:",  self._sv_sess)
        _stat(sb, "Total Pkts:",self._sv_pkts)
        _stat(sb, "Drop Pkts:", self._sv_drop_pkts, ORANGE)
        _stat(sb, "Drop Threats:", self._sv_drop_threats, ORANGE)
        tk.Frame(sb, bg=BG4, width=2).pack(side=tk.LEFT, fill=tk.Y, padx=8)
        tk.Label(sb, text="Threats →", fg=FG2, bg=BG, font=FONT_SM).pack(side=tk.LEFT)
        _stat(sb, "🔴 CRIT:", self._sv_crit, RED)
        _stat(sb, "🟠 WARN:", self._sv_warn, ORANGE)
        _stat(sb, "🔵 INFO:", self._sv_info, CYAN)

        ttk.Separator(self, orient="horizontal").pack(fill=tk.X)

        # Main panes
        main = tk.PanedWindow(self, orient=tk.HORIZONTAL,
                               bg=BG, sashwidth=5, sashrelief="flat")
        main.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        left  = tk.Frame(main, bg=BG)
        right = tk.Frame(main, bg=BG)
        main.add(left,  minsize=420, width=780)
        main.add(right, minsize=360)

        self._build_left(left)
        self._build_right(right)

        # Footer
        tk.Frame(self, bg=BG3, pady=2).pack(fill=tk.X, side=tk.BOTTOM)
        self._footer_lbl = tk.Label(
            self,
            text="Network Sentinel v2.0  |  For authorised monitoring only  |  sudo python3 sentinel.py",
            fg=FG2, bg=BG3, font=FONT_SM,
        )
        self._footer_lbl.pack(side=tk.BOTTOM, anchor="w", padx=10)

    def _install_policy_tooltips(self):
        HoverTip(self._btn_dry_run,
                 "Dry Run: simulate response actions without changing firewall, routes, or sessions.")
        HoverTip(self._btn_ttl,
                 "TTL: how long successful self-quarantine or block actions stay active before Sentinel rolls them back automatically.")
        HoverTip(self._btn_profile,
                 "Profile: cycles operating posture. Home is most conservative for fewer false positives; Lab and Production are more aggressive.")
        HoverTip(self._btn_network_isolation,
                 "Network Isolation: when enabled, block actions may also isolate the attacker at the network level via ARP-based isolation. Self-quarantine stays local only.")
        HoverTip(self._btn_auto_quarantine,
                 "Auto-Quarantine: automatically escalates and blocks sources once configured threat thresholds are exceeded.")
        HoverTip(self._btn_rate_limit,
                 "Rate Limit: throttle suspicious traffic on this machine instead of fully blocking it.")
        HoverTip(self._btn_honeypot_mode,
             "Honeypot Mode: choose whether repeat decoy hits trigger Self-Quarantine or Block+Kill escalation.")
        HoverTip(self._btn_honeypot,
                 "Honeypot: enables deceptive decoy services that appear vulnerable, then uses stealth engagement to delay hard containment and extend attacker dwell time.")

    def _build_left(self, parent):
        tk.Label(parent, text="Bandwidth  (60 s rolling)",
                 font=FONT_H2, fg=FG2, bg=BG).pack(anchor="w", padx=6, pady=(2, 0))
        self._graph = BandwidthGraph(parent, self._stats, height=90)
        self._graph.pack(fill=tk.X, padx=4, pady=(0, 4))

        fbar = tk.Frame(parent, bg=BG)
        fbar.pack(fill=tk.X, padx=4, pady=(0, 3))
        tk.Label(fbar, text="Filter:", fg=FG2, bg=BG).pack(side=tk.LEFT)
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", self._on_filter_change)
        ttk.Entry(fbar, textvariable=self._filter_var, width=30).pack(
            side=tk.LEFT, padx=(4, 8))
        tk.Label(fbar, text="IP / protocol / port  (live)",
                 fg=FG2, bg=BG, font=FONT_SM).pack(side=tk.LEFT)

        tk.Label(parent, text="Live Packet Feed",
                 font=FONT_H2, fg=BLUE, bg=BG).pack(anchor="w", padx=6, pady=(2, 2))
        self._build_packet_panel(parent)

    def _build_packet_panel(self, parent):
        frame  = tk.Frame(parent, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=4)
        cols   = ("ts",  "src", "dst", "proto","sport","dport","flags","len")
        hdrs   = ("Time","Source IP","Dest IP","Proto","S.Port","D.Port","Flags","Len")
        widths = (72, 132, 132, 54, 60, 60, 82, 46)
        xsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)
        ysb = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        self._pkt_tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            yscrollcommand=ysb.set, xscrollcommand=xsb.set,
            selectmode="browse")
        ysb.config(command=self._pkt_tree.yview)
        xsb.config(command=self._pkt_tree.xview)
        for col, hdr, w in zip(cols, hdrs, widths):
            self._pkt_tree.heading(col, text=hdr)
            self._pkt_tree.column(col, width=w, minwidth=36, anchor="w")
        for tag, color in [("TCP", FG), ("UDP", CYAN), ("ICMP", ORANGE), ("ARP", PURPLE)]:
            self._pkt_tree.tag_configure(tag, foreground=color)
        self._pkt_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

    def _build_right(self, parent):
        vp = tk.PanedWindow(parent, orient=tk.VERTICAL,
                             bg=BG, sashwidth=5, sashrelief="flat")
        vp.pack(fill=tk.BOTH, expand=True)
        hf = tk.Frame(vp, bg=BG)
        tf = tk.Frame(vp, bg=BG)
        vp.add(hf, minsize=120, height=200)
        vp.add(tf, minsize=220)
        self._build_hosts_panel(hf)
        self._build_threat_panel(tf)

    def _build_hosts_panel(self, parent):
        tk.Label(parent, text="Discovered Hosts",
                 font=FONT_H2, fg=GREEN, bg=BG).pack(anchor="w", padx=6, pady=(4, 2))
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=4)
        cols   = ("ip", "mac", "hostname", "traffic", "last")
        hdrs   = ("IP Address", "MAC Address", "Hostname", "Traffic", "Last Seen")
        widths = (120, 148, 148, 74, 74)
        sb = ttk.Scrollbar(frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._host_tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            yscrollcommand=sb.set, height=7)
        sb.config(command=self._host_tree.yview)
        for col, hdr, w in zip(cols, hdrs, widths):
            self._host_tree.heading(col, text=hdr)
            self._host_tree.column(col, width=w, minwidth=30, anchor="w")
        self._host_tree.pack(fill=tk.BOTH, expand=True)
        self._host_tree.bind("<Button-3>", self._host_context_menu)

        host_action_row = tk.Frame(parent, bg=BG)
        host_action_row.pack(fill=tk.X, padx=6, pady=(4, 2))
        self._btn_host_quarantine = ttk.Button(
            host_action_row,
            text="🛡 Quarantine Selected Host",
            style="Stop.TButton",
            command=self._manual_quarantine_selected,
        )
        self._btn_host_quarantine.pack(side=tk.LEFT)
        HoverTip(
            self._btn_host_quarantine,
            "Uses the current policy response for the selected host. For a local-only block, use a threat entry and choose Self-Quarantine: This PC Only.",
        )

    def _host_to_threat(self, vals):
        src_ip = str(vals[0]) if len(vals) > 0 else ""
        src_mac = str(vals[1]) if len(vals) > 1 else "Unknown"
        hostname = str(vals[2]) if len(vals) > 2 else "Unknown"
        return {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": "WARNING",
            "type": "Manual Host Quarantine",
            "src_ip": src_ip,
            "src_mac": src_mac,
            "hostname": hostname,
            "what": f"Operator initiated manual quarantine from host list for {src_ip}.",
            "action": [
                "1. Confirm the host is unauthorized or compromised.",
                "2. Contain immediately with block rules.",
                "3. Investigate endpoint and restore only after cleanup.",
            ],
        }

    def _build_threat_panel(self, parent):
        tk.Label(parent, text="⚠  Threat Alerts",
                 font=FONT_H2, fg=RED, bg=BG).pack(anchor="w", padx=6, pady=(4, 2))
        lf = tk.Frame(parent, bg=BG2, highlightthickness=1, highlightbackground=BG4)
        lf.pack(fill=tk.BOTH, padx=4, pady=(0, 4))
        t_cols   = ("ts", "level", "type", "src_ip")
        t_hdrs   = ("Time", "Level", "Threat Type", "Source IP")
        t_widths = (92, 72, 228, 132)
        tsb = ttk.Scrollbar(lf)
        tsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._threat_tree = ttk.Treeview(
            lf, columns=t_cols, show="headings",
            yscrollcommand=tsb.set, height=6, selectmode="browse")
        tsb.config(command=self._threat_tree.yview)
        for col, hdr, w in zip(t_cols, t_hdrs, t_widths):
            self._threat_tree.heading(col, text=hdr)
            self._threat_tree.column(col, width=w, minwidth=36, anchor="w")
        for tag, color in [("CRITICAL", RED), ("WARNING", ORANGE), ("INFO", CYAN)]:
            self._threat_tree.tag_configure(tag, foreground=color)
        self._threat_tree.pack(fill=tk.BOTH, expand=False, padx=6, pady=(6, 6))
        self._threat_tree.bind("<<TreeviewSelect>>", self._on_threat_select)
        self._threat_tree.bind("<Button-3>",          self._threat_context_menu)

        action_row = tk.Frame(parent, bg=BG)
        action_row.pack(fill=tk.X, padx=6, pady=(0, 4))
        self._btn_manual_quarantine = ttk.Button(
            action_row,
            text="🛡 Quarantine Selected",
            style="Stop.TButton",
            command=self._manual_quarantine_selected,
        )
        self._btn_manual_quarantine.pack(side=tk.LEFT)
        HoverTip(
            self._btn_manual_quarantine,
            "Uses the current policy response for the selected threat. Right-click a threat to access Self-Quarantine: This PC Only.",
        )

        tk.Label(
            parent,
            text="Tip: right-click a threat for Self-Quarantine: This PC Only. That blocks the attacker only on this machine.",
            fg=FG2,
            bg=BG,
            font=FONT_SM,
            anchor="w",
            justify=tk.LEFT,
        ).pack(fill=tk.X, padx=6, pady=(0, 4))

        ttk.Separator(parent, orient="horizontal").pack(fill=tk.X, padx=6, pady=(0, 4))

        # Detail
        dw = tk.Frame(parent, bg=BG2, highlightthickness=1, highlightbackground=BG4)
        dw.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        tk.Label(dw, text="Threat Detail",
                 font=FONT_H2, fg=ORANGE, bg=BG2).pack(anchor="w", padx=10, pady=(8, 4))
        self._detail = scrolledtext.ScrolledText(
            dw, bg=BG2, fg=FG, font=FONT_MONO, wrap=tk.WORD,
            relief="flat", state=tk.DISABLED,
            insertbackground=FG, selectbackground=BG3, padx=10, pady=8)
        self._detail.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        dt = self._detail
        dt.tag_configure("title",    foreground=RED,    font=("IBM Plex Sans", 11, "bold"))
        dt.tag_configure("section",  foreground=ORANGE, font=("IBM Plex Sans", 10, "bold"))
        dt.tag_configure("value",    foreground=CYAN)
        dt.tag_configure("body",     foreground=FG)
        dt.tag_configure("action",   foreground=GREEN,  font=FONT_MONO)
        dt.tag_configure("CRITICAL", foreground=RED,    font=("JetBrains Mono", 10, "bold"))
        dt.tag_configure("WARNING",  foreground=ORANGE, font=("JetBrains Mono", 10, "bold"))
        dt.tag_configure("INFO",     foreground=CYAN,   font=("JetBrains Mono", 10, "bold"))
        dt.tag_configure("divider",  foreground=BG3)

        ttk.Separator(parent, orient="horizontal").pack(fill=tk.X, padx=6, pady=(0, 4))

        rw = tk.Frame(parent, bg=BG2, highlightthickness=1, highlightbackground=BG4)
        rw.pack(fill=tk.BOTH, expand=False, padx=4, pady=(0, 4))
        tk.Label(rw, text="Response Log",
                 font=FONT_H2, fg=CYAN, bg=BG2).pack(anchor="w", padx=10, pady=(6, 2))
        filter_row = tk.Frame(rw, bg=BG2)
        filter_row.pack(fill=tk.X, padx=8, pady=(0, 1))
        self._btn_resp_filter_all = ttk.Button(filter_row, text="All",
                 style="ToggleOn.TButton", command=lambda: self._set_response_log_filter("all"))
        self._btn_resp_filter_all.pack(side=tk.LEFT, padx=2)
        self._btn_resp_filter_auto = ttk.Button(filter_row, text="Auto",
                 style="Dim.TButton", command=lambda: self._set_response_log_filter("auto"))
        self._btn_resp_filter_auto.pack(side=tk.LEFT, padx=2)
        self._btn_resp_filter_manual = ttk.Button(filter_row, text="Manual",
                 style="Dim.TButton", command=lambda: self._set_response_log_filter("manual"))
        self._btn_resp_filter_manual.pack(side=tk.LEFT, padx=2)
        self._btn_resp_filter_rollback = ttk.Button(filter_row, text="Rollback",
                 style="Dim.TButton", command=lambda: self._set_response_log_filter("rollback"))
        self._btn_resp_filter_rollback.pack(side=tk.LEFT, padx=2)
        self._btn_resp_filter_failure = ttk.Button(filter_row, text="Failure",
                 style="Dim.TButton", command=lambda: self._set_response_log_filter("failure"))
        self._btn_resp_filter_failure.pack(side=tk.LEFT, padx=2)
        action_row = tk.Frame(rw, bg=BG2)
        action_row.pack(fill=tk.X, padx=8, pady=(0, 3))
        tk.Label(action_row, text="Search:", fg=FG2, bg=BG2, font=FONT_SM).pack(side=tk.LEFT, padx=(0, 4))
        self._response_log_search_var = tk.StringVar(value=self._response_log_search)
        self._response_log_search_var.trace_add("write", self._on_response_log_search_change)
        self._entry_resp_search = ttk.Entry(action_row, textvariable=self._response_log_search_var, width=24)
        self._entry_resp_search.pack(side=tk.LEFT, padx=(0, 8))
        self._btn_resp_clear_search = ttk.Button(action_row, text="Clear Search",
                 style="Dim.TButton", command=self._clear_response_log_search)
        self._btn_resp_clear_search.pack(side=tk.LEFT, padx=2)
        self._btn_resp_export = ttk.Button(action_row, text="Export Log",
                 style="Dim.TButton", command=self._export_filtered_response_log)
        self._btn_resp_export.pack(side=tk.RIGHT, padx=2)
        self._btn_resp_clear = ttk.Button(action_row, text="Clear Log",
                 style="Dim.TButton", command=self._clear_response_log)
        self._btn_resp_clear.pack(side=tk.RIGHT, padx=2)
        self._btn_resp_clear_filtered = ttk.Button(action_row, text="Clear Filtered",
                 style="Dim.TButton", command=self._clear_filtered_response_log)
        self._btn_resp_clear_filtered.pack(side=tk.RIGHT, padx=2)
        self._btn_resp_copy_failure = ttk.Button(action_row, text="Copy Failure Details",
                 style="Dim.TButton", command=self._copy_selected_response_log_details)
        self._btn_resp_copy_failure.pack(side=tk.RIGHT, padx=2)
        self._response_log = scrolledtext.ScrolledText(
            rw, bg=BG2, fg=FG, font=FONT_MONO, wrap=tk.WORD,
            relief="flat", state=tk.DISABLED, height=5,
            insertbackground=FG, selectbackground=BG3, padx=10, pady=8)
        self._response_log.pack(fill=tk.BOTH, expand=False, padx=4, pady=(0, 4))
        self._response_log.bind("<ButtonRelease-1>", self._on_response_log_click)
        self._response_log.bind("<Double-Button-1>", self._on_response_log_double_click)
        rl = self._response_log
        rl.tag_configure("queued", foreground=ORANGE)
        rl.tag_configure("running", foreground=BLUE)
        rl.tag_configure("success", foreground=GREEN)
        rl.tag_configure("warning", foreground=ORANGE)
        rl.tag_configure("failure", foreground=RED)
        rl.tag_configure("info", foreground=CYAN)
        rl.tag_configure("selected", background=BG3, foreground=FG)
        tk.Label(rw, text="Response Details",
                 font=FONT_H2, fg=FG2, bg=BG2).pack(anchor="w", padx=10, pady=(2, 2))
        self._response_detail = scrolledtext.ScrolledText(
            rw, bg=BG2, fg=FG, font=FONT_MONO, wrap=tk.WORD,
            relief="flat", state=tk.DISABLED, height=3,
            insertbackground=FG, selectbackground=BG3, padx=10, pady=8)
        self._response_detail.pack(fill=tk.BOTH, expand=False, padx=4, pady=(0, 4))

    # ── Controls ──────────────────────────────────────────────────────────────

    def _get_ifaces(self):
        if SCAPY_AVAILABLE:
            return get_if_list()
        try:
            out = subprocess.check_output(["ip", "-o", "link", "show"],
                                           text=True, stderr=subprocess.DEVNULL)
            ifaces = []
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    iface = parts[1].strip().split("@")[0]
                    if iface:
                        ifaces.append(iface)
            return ifaces
        except Exception:
            return ["eth0", "wlan0", "lo"]

    def _start(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Missing Dependency",
                "scapy is not installed.\n\nFix:\n  pip install scapy\n\n"
                "Then run:  sudo python3 sentinel.py")
            return
        if os.geteuid() != 0:
            messagebox.showerror("Root Required",
                "Raw packet capture needs root.\n\nRun:\n  sudo python3 sentinel.py")
            return
        iface = self._iface_var.get()
        if not iface:
            messagebox.showwarning("No Interface", "Select a network interface.")
            return
        self._running  = True
        self._active_iface = iface
        self._baseline_started_at = time.time()
        self._baseline_learned = False
        self._baseline_ips.clear()
        self._baseline_ports.clear()
        self._baseline_protocols.clear()
        self._anomalies.clear()
        with self._lock:
            self._pkt_queue.clear()
            self._threat_queue.clear()
            self._dropped_pkt_queue = 0
            self._dropped_threat_queue = 0
        self._stats    = StatsEngine()
        self._detector = ThreatDetector(
            on_threat=self._queue_threat,
            on_packet=self._queue_packet,
            stats=self._stats)
        self._apply_profile_tuning()
        self._graph._stats = self._stats
        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._btn_pause.config(state=tk.NORMAL)
        self._iface_cb.config(state=tk.DISABLED)
        self._set_status("● Monitoring", GREEN)
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, args=(iface,), daemon=True)
        self._sniff_thread.start()

    def _stop(self):
        self._running = False
        self._paused  = False
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._btn_pause.config(state=tk.DISABLED, text="⏸  Pause Feed")
        self._iface_cb.config(state="readonly")
        self._set_status("● Stopped", ORANGE)
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=1.3)
        self._sniff_thread = None

    def _toggle_pause(self):
        self._paused = not self._paused
        if self._paused:
            self._btn_pause.config(text="▶  Resume Feed")
            self._set_status("● Paused", ORANGE)
        else:
            self._btn_pause.config(text="⏸  Pause Feed")
            self._set_status("● Monitoring", GREEN)
            self._rerender_packets()

    def _set_status(self, text, color):
        self._status_var.set(text)
        self._status_lbl.config(fg=color)

    def _load_response_log_history(self):
        if not os.path.exists(self._response_log_path):
            return
        entries = []
        needs_rewrite = False
        try:
            with open(self._response_log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(entry, dict) and entry.get("message"):
                        normalized_ts, changed = self._normalize_response_log_timestamp(entry.get("ts"))
                        entry["ts"] = normalized_ts
                        needs_rewrite = needs_rewrite or changed
                        entries.append(entry)
        except Exception:
            return
        self._response_log_entries = entries[-self.MAX_RESPONSE_LOG_LINES:]
        if needs_rewrite:
            self._rewrite_response_log_history()

    def _persist_response_log_entry(self, entry):
        try:
            with open(self._response_log_path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=True) + "\n")
        except Exception:
            pass

    def _rewrite_response_log_history(self):
        try:
            with open(self._response_log_path, "w") as f:
                for entry in self._response_log_entries:
                    f.write(json.dumps(entry, ensure_ascii=True) + "\n")
        except Exception:
            pass

    @staticmethod
    def _response_log_timestamp():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _normalize_response_log_timestamp(ts):
        raw = str(ts or "").strip()
        if not raw:
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S"), True
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(raw, fmt)
                normalized = parsed.strftime("%Y-%m-%d %H:%M:%S")
                return normalized, raw != normalized
            except Exception:
                pass
        for fmt in ("%H:%M:%S", "%H:%M"):
            try:
                parsed = datetime.strptime(raw, fmt)
                normalized = datetime.now().strftime("%Y-%m-%d") + parsed.strftime(" %H:%M:%S")
                return normalized, True
            except Exception:
                pass
        return raw, False

    def _response_log_matches_filter(self, entry):
        if self._response_log_filter == "all":
            return True
        if self._response_log_filter == "failure":
            return entry.get("status") in ("failure", "partial") or entry.get("tag") == "failure"
        return entry.get("kind") == self._response_log_filter

    def _response_log_matches_search(self, entry):
        query = self._response_log_search.strip().lower()
        if not query:
            return True
        haystack = " ".join([
            str(entry.get("ts", "")),
            str(entry.get("kind", "")),
            str(entry.get("status", "")),
            str(entry.get("message", "")),
            str(entry.get("details", "")),
        ]).lower()
        return query in haystack

    def _filtered_response_log_entries(self):
        return [
            entry for entry in self._response_log_entries
            if self._response_log_matches_filter(entry) and self._response_log_matches_search(entry)
        ]

    def _response_log_counts(self):
        entries = self._response_log_entries
        return {
            "all": len(entries),
            "auto": sum(1 for entry in entries if entry.get("kind") == "auto"),
            "manual": sum(1 for entry in entries if entry.get("kind") == "manual"),
            "rollback": sum(1 for entry in entries if entry.get("kind") == "rollback"),
            "failure": sum(1 for entry in entries if entry.get("status") in ("failure", "partial") or entry.get("tag") == "failure"),
        }

    def _set_response_log_detail(self, text):
        if not hasattr(self, "_response_detail"):
            return
        widget = self._response_detail
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        if text:
            widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def _refresh_response_log_filter_buttons(self):
        counts = self._response_log_counts()
        mapping = {
            "all": self._btn_resp_filter_all,
            "auto": self._btn_resp_filter_auto,
            "manual": self._btn_resp_filter_manual,
            "rollback": self._btn_resp_filter_rollback,
            "failure": self._btn_resp_filter_failure,
        }
        labels = {
            "all": "All",
            "auto": "Auto",
            "manual": "Manual",
            "rollback": "Rollback",
            "failure": "Failure",
        }
        for name, btn in mapping.items():
            btn.config(text=f"{labels[name]} ({counts.get(name, 0)})")
            btn.config(style="ToggleOn.TButton" if self._response_log_filter == name else "Dim.TButton")

    def _sync_response_log_button_texts(self):
        if not hasattr(self, "_btn_resp_export"):
            return
        if self._compact_mode:
            self._btn_resp_copy_failure.config(text="Copy Details")
            self._btn_resp_clear_filtered.config(text="Clear Filtered")
            self._btn_resp_clear.config(text="Clear All")
            self._btn_resp_export.config(text="Export")
            self._btn_resp_clear_search.config(text="Reset Search")
            self._entry_resp_search.config(width=18)
            self._response_log.config(height=4)
            self._response_detail.config(height=2)
        else:
            self._btn_resp_copy_failure.config(text="Copy Failure Details")
            self._btn_resp_clear_filtered.config(text="Clear Filtered")
            self._btn_resp_clear.config(text="Clear Log")
            self._btn_resp_export.config(text="Export Log")
            self._btn_resp_clear_search.config(text="Clear Search")
            self._entry_resp_search.config(width=24)
            self._response_log.config(height=5)
            self._response_detail.config(height=3)

    def _apply_response_log_selection(self):
        if not hasattr(self, "_response_log"):
            return
        widget = self._response_log
        widget.tag_remove("selected", "1.0", tk.END)
        if self._response_log_selected_line in self._response_log_line_map:
            start = f"{self._response_log_selected_line}.0"
            end = f"{self._response_log_selected_line}.end"
            widget.tag_add("selected", start, end)

    def _refresh_response_log_view(self):
        if not hasattr(self, "_response_log"):
            return
        widget = self._response_log
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        self._response_log_line_map = {}
        line_no = 1
        visible_entries = self._filtered_response_log_entries()
        for entry in visible_entries:
            ts = str(entry.get("ts", ""))
            kind = str(entry.get("kind", "info")).upper()
            msg = str(entry.get("message", "")).replace("\n", " ")
            line = f"[{ts}] [{kind}] {msg}\n"
            widget.insert(tk.END, line, entry.get("tag", "info"))
            self._response_log_line_map[line_no] = entry
            line_no += 1
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)
        if self._response_log_selected_line not in self._response_log_line_map:
            self._response_log_selected_line = next(iter(self._response_log_line_map), None)
        self._apply_response_log_selection()
        entry = self._selected_response_log_entry()
        self._set_response_log_detail((entry or {}).get("details") or (entry or {}).get("message", ""))
        self._refresh_response_log_filter_buttons()

    def _append_response_log(self, message, tag="info", kind="manual", status="info", details="", persist=True, ts=None):
        entry = {
            "ts": ts or self._response_log_timestamp(),
            "message": str(message),
            "tag": tag,
            "kind": kind,
            "status": status,
            "details": str(details or ""),
        }
        self._response_log_entries.append(entry)
        if len(self._response_log_entries) > self.MAX_RESPONSE_LOG_LINES:
            self._response_log_entries = self._response_log_entries[-self.MAX_RESPONSE_LOG_LINES:]
        if persist:
            self._persist_response_log_entry(entry)
        self._refresh_response_log_view()

    def _set_response_log_filter(self, filter_name):
        self._response_log_filter = filter_name
        self._refresh_response_log_view()

    def _on_response_log_search_change(self, *_args):
        self._response_log_search = self._response_log_search_var.get()
        self._refresh_response_log_view()

    def _clear_response_log_search(self):
        self._response_log_search_var.set("")

    def _focus_response_log_search(self, _event=None):
        if hasattr(self, "_entry_resp_search"):
            self._entry_resp_search.focus_set()
            self._entry_resp_search.selection_range(0, tk.END)
        return "break"

    def _clear_response_log_search_shortcut(self, _event=None):
        focus_widget = self.focus_get()
        if focus_widget is getattr(self, "_entry_resp_search", None) or self._response_log_search:
            self._clear_response_log_search()
            return "break"
        return None

    def _selected_response_log_entry(self):
        if self._response_log_selected_line is None:
            return None
        return self._response_log_line_map.get(self._response_log_selected_line)

    def _on_response_log_click(self, event):
        try:
            index = self._response_log.index(f"@{event.x},{event.y}")
            self._response_log_selected_line = int(index.split(".")[0])
        except Exception:
            self._response_log_selected_line = None
        self._apply_response_log_selection()
        entry = self._selected_response_log_entry()
        self._set_response_log_detail((entry or {}).get("details") or (entry or {}).get("message", ""))

    def _on_response_log_double_click(self, event):
        self._on_response_log_click(event)
        self._copy_selected_response_log_details()

    def _copy_selected_response_log_details(self):
        entry = self._selected_response_log_entry()
        if not entry:
            messagebox.showinfo("Response Log", "Select a response log entry first.")
            return
        details = entry.get("details") or entry.get("message")
        self._copy(details)
        self._set_status("● Response details copied", CYAN)

    def _clear_response_log(self):
        if not messagebox.askyesno("Clear Response Log", "Clear the in-app response log and remove its persisted history?"):
            return
        self._response_log_entries = []
        self._response_log_selected_line = None
        try:
            if os.path.exists(self._response_log_path):
                os.remove(self._response_log_path)
        except Exception:
            pass
        self._refresh_response_log_view()
        self._set_response_log_detail("")
        self._set_status("● Response log cleared", ORANGE)

    def _clear_filtered_response_log(self):
        entries = self._filtered_response_log_entries()
        if not entries:
            messagebox.showinfo("Clear Filtered Response Log", "No response log entries match the current filter.")
            return
        if self._response_log_filter == "all":
            self._clear_response_log()
            return
        if not messagebox.askyesno(
            "Clear Filtered Response Log",
            f"Remove {len(entries)} response log entries matching the '{self._response_log_filter}' filter?",
        ):
            return
        self._response_log_entries = [entry for entry in self._response_log_entries if not self._response_log_matches_filter(entry)]
        self._response_log_selected_line = None
        self._rewrite_response_log_history()
        self._refresh_response_log_view()
        self._set_status(f"● Cleared {len(entries)} filtered response entries", ORANGE)

    def _export_filtered_response_log(self):
        entries = self._filtered_response_log_entries()
        if not entries:
            messagebox.showinfo("Export Response Log", "No response log entries match the current filter.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Response Log",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("CSV report", "*.csv")],
            initialfile=f"sentinel_response_log_{self._response_log_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                with open(path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["ts", "kind", "status", "tag", "message", "details"])
                    writer.writeheader()
                    for entry in entries:
                        writer.writerow({key: entry.get(key, "") for key in ("ts", "kind", "status", "tag", "message", "details")})
            else:
                with open(path, "w") as f:
                    json.dump(entries, f, indent=2, ensure_ascii=True)
        except Exception as e:
            messagebox.showerror("Export Response Log", f"Could not export response log:\n{e}")
            return
        self._set_status(f"● Exported {len(entries)} response entries", GREEN)

    def _response_log_tag_for_tx(self, tx):
        status = tx.get("status")
        if status == "confirmed":
            return "success"
        if status == "partial":
            return "warning"
        if status == "failed":
            return "failure"
        return "info"

    def _response_log_kind_for_tx(self, tx):
        mode = tx.get("mode")
        if mode in ("rollback", "auto-expire-rollback"):
            return "rollback"
        return tx.get("origin", "manual")

    def _tx_failure_details(self, tx):
        lines = []
        for step in tx.get("steps", []):
            if step.get("ok"):
                continue
            detail = str(step.get("err", "")).strip() or "step failed"
            lines.append(f"{step.get('step', 'unknown')}: {detail}")
        for check in tx.get("verify", []):
            if check.get("ok"):
                continue
            lines.append(f"verify {check.get('check', 'unknown')}: failed")
        return "\n".join(lines)

    def _sync_policy_button_texts(self):
        if not hasattr(self, "_btn_dry_run"):
            return
        compact_mode_label = "Self-Q" if self._honeypot_escalation_mode == NEUTRALIZE_SELF else "Block+Kill"
        full_mode_label = "Self-Quarantine" if self._honeypot_escalation_mode == NEUTRALIZE_SELF else "Block+Kill"
        if self._compact_mode:
            self._btn_dry_run.config(text=f"Dry: {'ON' if self._dry_run else 'OFF'}")
            self._btn_network_isolation.config(text=f"Net Iso: {'ON' if self._network_isolation_enabled else 'OFF'}")
            self._btn_auto_quarantine.config(text=f"Auto-Q: {'ON' if self._quarantine_enabled else 'OFF'}")
            self._btn_rate_limit.config(text=f"Rate: {'ON' if self._rate_limit_enabled else 'OFF'}")
            self._btn_honeypot_mode.config(text=f"Honey Mode: {compact_mode_label}")
            self._btn_honeypot.config(text=f"Honey: {'ON' if self._honeypot_enabled else 'OFF'}")
        else:
            self._btn_dry_run.config(text=f"Dry Run: {'ON' if self._dry_run else 'OFF'}")
            self._btn_network_isolation.config(text=f"Network Isolation: {'ON' if self._network_isolation_enabled else 'OFF'}")
            self._btn_auto_quarantine.config(text=f"Auto-Quarantine: {'ON' if self._quarantine_enabled else 'OFF'}")
            self._btn_rate_limit.config(text=f"Rate Limit: {'ON' if self._rate_limit_enabled else 'OFF'}")
            self._btn_honeypot_mode.config(text=f"Honeypot Mode: {full_mode_label}")
            self._btn_honeypot.config(text=f"Honeypot: {'ON' if self._honeypot_enabled else 'OFF'}")
        self._btn_ttl.config(text=f"TTL: {self._block_ttl_sec//60}m")
        self._btn_profile.config(text=f"Profile: {self._policy_profile}")

    def _sync_action_button_texts(self):
        if not hasattr(self, "_btn_tools"):
            return
        if self._compact_mode:
            self._btn_save_pcap.config(text="💾 Save")
            self._btn_tools.config(text="Tools")
            self._btn_incident_report.config(text="Report")
            self._btn_export_threats.config(text="Export")
            self._btn_clear_threats.config(text="Clear")
        else:
            self._btn_save_pcap.config(text="💾 Save PCAP")
            self._btn_tools.config(text="Response Tools")
            self._btn_incident_report.config(text="Incident Report")
            self._btn_export_threats.config(text="Export Threats")
            self._btn_clear_threats.config(text="Clear Threats")

    def _apply_compact_mode(self, compact):
        if compact == self._compact_mode:
            return
        self._compact_mode = compact
        self._iface_cb.config(width=10 if compact else 14)
        if compact:
            self._subtitle_lbl.pack_forget()
            self._footer_lbl.config(text="Network Sentinel v2.0  |  Authorised monitoring only")
            self._threat_tree.column("type", width=174)
            self._threat_tree.column("src_ip", width=114)
            self._host_tree.column("hostname", width=120)
        else:
            self._subtitle_lbl.pack(side=tk.LEFT)
            self._footer_lbl.config(text="Network Sentinel v2.0  |  For authorised monitoring only  |  sudo python3 sentinel.py")
            self._threat_tree.column("type", width=228)
            self._threat_tree.column("src_ip", width=132)
            self._host_tree.column("hostname", width=148)
        self._sync_policy_button_texts()
        self._sync_action_button_texts()
        self._sync_response_log_button_texts()

    def _on_window_resize(self, event):
        if event.widget is not self:
            return
        if self._layout_mode.get() == "auto":
            self._apply_compact_mode(event.width < 1380)

    def _apply_layout_mode(self):
        mode = self._layout_mode.get()
        if mode == "compact":
            self._apply_compact_mode(True)
        elif mode == "full":
            self._apply_compact_mode(False)
        else:
            self._apply_compact_mode(self.winfo_width() < 1380)

    def _set_layout_auto_shortcut(self, _event=None):
        self._layout_mode.set("auto")
        self._apply_layout_mode()

    def _set_layout_compact_shortcut(self, _event=None):
        self._layout_mode.set("compact")
        self._apply_layout_mode()

    def _set_layout_full_shortcut(self, _event=None):
        self._layout_mode.set("full")
        self._apply_layout_mode()

    def _refresh_toggle_button_styles(self):
        state_buttons = [
            ("_btn_dry_run", self._dry_run),
            ("_btn_network_isolation", self._network_isolation_enabled),
            ("_btn_auto_quarantine", self._quarantine_enabled),
            ("_btn_rate_limit", self._rate_limit_enabled),
            ("_btn_honeypot", self._honeypot_enabled),
        ]
        for attr, enabled in state_buttons:
            if hasattr(self, attr):
                btn = getattr(self, attr)
                btn.config(style="ToggleOn.TButton" if enabled else "ToggleOff.TButton")

    def _open_settings(self):
        if self._detector is None:
            self._detector = ThreatDetector(lambda _: None, lambda _: None, self._stats)
        SettingsDialog(self, self._detector)

    def _save_pcap(self):
        if not self._raw_pkts:
            messagebox.showinfo("No Packets", "No packets captured yet.")
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.expanduser(f"~/Documents/sentinel_capture_{ts}.pcap")
        try:
            wrpcap(path, list(self._raw_pkts))
            messagebox.showinfo("Saved", f"PCAP saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Failed", str(e))

    def _toggle_dry_run(self):
        self._dry_run = not self._dry_run
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()
        messagebox.showinfo("Dry Run", "Dry run mode is now ON." if self._dry_run else "Dry run mode is now OFF.")

    def _cycle_block_ttl(self):
        options = [600, 1800, 3600, 21600, 86400]
        try:
            idx = options.index(self._block_ttl_sec)
        except ValueError:
            idx = 2
        self._block_ttl_sec = options[(idx + 1) % len(options)]
        self._sync_policy_button_texts()

    def _cycle_policy_profile(self):
        profiles = ["Home", "Balanced", "Lab", "Production"]
        try:
            idx = profiles.index(self._policy_profile)
        except ValueError:
            idx = 1
        self._policy_profile = profiles[(idx + 1) % len(profiles)]
        self._apply_profile_tuning()
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()

    def _apply_profile_tuning(self):
        if self._policy_profile == "Home":
            # Conservative profile to reduce false positives on home networks.
            self._block_ttl_sec = 1800
            self._quarantine_enabled = False
            self._rate_limit_enabled = False
            self._baseline_warmup_sec = 420
            if self._detector:
                self._detector.PORT_SCAN_THRESHOLD = 35
                self._detector.HORIZ_SCAN_THRESHOLD = 28
                self._detector.SYN_FLOOD_THRESHOLD = 120
                self._detector.ICMP_FLOOD_THRESHOLD = 140
                self._detector.UDP_FLOOD_THRESHOLD = 260
                self._detector.BRUTE_FORCE_THRESHOLD = 36
                self._detector.DNS_TUNNEL_LENGTH = 64
                self._detector.DNS_TUNNEL_THRESHOLD = 90
                self._detector.EXFIL_MB_THRESHOLD = 120
                self._detector.ALERT_COOLDOWN = 90
                self._detector.STARTUP_GRACE_SEC = 60
                self._detector.ALERT_CONFIRM_WINDOW = 75
                self._detector.ALERT_CONFIRM_HITS = 3
        elif self._policy_profile == "Balanced":
            self._block_ttl_sec = 3600
            self._baseline_warmup_sec = 300
        elif self._policy_profile == "Lab":
            self._block_ttl_sec = 21600
            self._baseline_warmup_sec = 180
        elif self._policy_profile == "Production":
            self._block_ttl_sec = 600
            self._baseline_warmup_sec = 240

    def _toggle_network_isolation(self):
        """Toggle network-level isolation mode (ARP spoofing)."""
        self._network_isolation_enabled = not self._network_isolation_enabled
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()
        mode_text = "ON" if self._network_isolation_enabled else "OFF"
        messagebox.showinfo("Network Isolation", 
            f"Network isolation mode is now {mode_text}.\n\n"
            f"{'When enabled: Blocked threats will be isolated from the entire network via ARP spoofing.' if self._network_isolation_enabled else 'When disabled: Blocks use local firewall only (iptables/ufw).'}")

    def _toggle_auto_quarantine(self):
        """Toggle automatic quarantine system."""
        self._quarantine_enabled = not self._quarantine_enabled
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()
        mode = "ON" if self._quarantine_enabled else "OFF"
        messagebox.showinfo("Auto-Quarantine", 
            f"Auto-quarantine is now {mode}.\n\n"
            f"Thresholds:\n"
            f"• CRITICAL threats: {self._quarantine_critical_threshold}\n"
            f"• Port scans: {self._quarantine_scan_threshold} ports\n"
            f"• Brute force: {self._quarantine_bruteforce_threshold} attempts")

    def _toggle_rate_limit(self):
        """Toggle rate limiting."""
        self._rate_limit_enabled = not self._rate_limit_enabled
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()
        mode = "ON" if self._rate_limit_enabled else "OFF"
        messagebox.showinfo("Rate Limiting", 
            f"Rate limiting is now {mode}.\n\n"
            f"Suspicious traffic will be throttled instead of completely blocked,\n"
            f"making attacks slower without disconnecting legitimate users.")

    def _toggle_honeypot(self):
        """Toggle honeypot decoy services."""
        self._honeypot_enabled = not self._honeypot_enabled
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()
        mode = "ON" if self._honeypot_enabled else "OFF"
        escalation_text = "Self-Quarantine" if self._honeypot_escalation_mode == NEUTRALIZE_SELF else "Block+Kill"
        messagebox.showinfo("Honeypot Decoys", 
            f"Honeypot services are now {mode}.\n\n"
            f"{'Deceptive services are now advertising vulnerable-looking banners and misconfiguration bait on decoy ports. Stealth engagement now delays hard containment to keep hostile scanners busy longer. Trap escalation mode is set to ' + escalation_text + '.' if self._honeypot_enabled else 'Honeypot services disabled.'}")

    def _cycle_honeypot_escalation_mode(self):
        """Switch honeypot trap response mode between self-quarantine and block+kill."""
        if self._honeypot_escalation_mode == NEUTRALIZE_SELF:
            self._honeypot_escalation_mode = NEUTRALIZE_BLOCKKILL
            mode_text = "Block+Kill"
        else:
            self._honeypot_escalation_mode = NEUTRALIZE_SELF
            mode_text = "Self-Quarantine"
        self._sync_policy_button_texts()
        self._refresh_toggle_button_styles()
        messagebox.showinfo(
            "Honeypot Escalation Mode",
            f"Honeypot escalation is now set to {mode_text}.\n\n"
            f"Repeat decoy hits will queue this response mode automatically.",
        )

    def _discover_local_ips(self):
        ips = {"127.0.0.1"}
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                ip = info[4][0]
                if ":" not in ip:
                    ips.add(ip)
        except Exception:
            pass
        if self._has_cmd("ip"):
            r = self._run_cmd(["ip", "-4", "-o", "addr", "show"])
            if r["ok"]:
                for line in r["out"].splitlines():
                    parts = line.split()
                    if "inet" in parts:
                        idx = parts.index("inet")
                        if idx + 1 < len(parts):
                            ips.add(parts[idx + 1].split("/")[0])
        return ips

    def _discover_gateway_ip(self):
        if not self._has_cmd("ip"):
            return None
        r = self._run_cmd(["ip", "route", "show", "default"])
        if not r["ok"]:
            return None
        parts = r["out"].split()
        if "via" in parts:
            i = parts.index("via")
            if i + 1 < len(parts):
                return parts[i + 1]
        return None

    def _get_mac_address(self):
        """Get local MAC address for ARP spoofing."""
        if not SCAPY_AVAILABLE:
            return None
        try:
            from scapy.all import get_if_hwaddr, get_if_list
            interfaces = get_if_list()
            for iface in interfaces:
                if iface == "lo":
                    continue
                try:
                    mac = get_if_hwaddr(iface)
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
                except Exception:
                    continue
            return None
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════════════════════
    # PERSISTENCE & REPUTATION SYSTEM
    # ═══════════════════════════════════════════════════════════════════════════════

    def _load_threat_database(self):
        """Load persistent threat reputation database from disk."""
        if not os.path.exists(self._threat_db_path):
            self._threat_database = {}
            return
        try:
            with open(self._threat_db_path, "r") as f:
                self._threat_database = json.load(f)
        except Exception:
            self._threat_database = {}

    def _save_threat_database(self):
        """Persist threat database to disk."""
        try:
            with open(self._threat_db_path, "w") as f:
                json.dump(self._threat_database, f, indent=2, default=str)
        except Exception:
            pass

    def _record_threat_reputation(self, src_ip, threat_type, severity):
        """Record threat in reputation database."""
        try:
            src_ip_str = str(src_ip)
            if src_ip_str not in self._threat_database:
                self._threat_database[src_ip_str] = {
                    "first_seen": datetime.now().isoformat(),
                    "attack_count": 0,
                    "threat_types": [],
                    "severities": [],
                    "blocked_count": 0
                }
            
            db_entry = self._threat_database[src_ip_str]
            db_entry["last_seen"] = datetime.now().isoformat()
            db_entry["attack_count"] = db_entry.get("attack_count", 0) + 1
            if threat_type not in db_entry.get("threat_types", []):
                if "threat_types" not in db_entry:
                    db_entry["threat_types"] = []
                db_entry["threat_types"].append(threat_type)
            if severity not in db_entry.get("severities", []):
                if "severities" not in db_entry:
                    db_entry["severities"] = []
                db_entry["severities"].append(severity)
            
            self._save_threat_database()
        except Exception:
            pass

    def _get_threat_reputation_score(self, src_ip):
        """Calculate reputation score for IP (0-100, higher = more dangerous)."""
        src_ip_str = str(src_ip)
        if src_ip_str not in self._threat_database:
            return 0
        
        db = self._threat_database[src_ip_str]
        score = min(100, db.get("attack_count", 0) * 5)
        
        if "CRITICAL" in db.get("severities", []):
            score = min(100, score + 30)
        if "Port Scan" in db.get("threat_types", []):
            score = min(100, score + 15)
        if db.get("blocked_count", 0) > 3:
            score = min(100, score + 20)
        
        return score

    # ═══════════════════════════════════════════════════════════════════════════════
    # AUTO-QUARANTINE SYSTEM
    # ═══════════════════════════════════════════════════════════════════════════════

    def _check_auto_quarantine(self, src_ip, threat_type):
        """Check if IP should be auto-quarantined based on thresholds."""
        if not self._quarantine_enabled:
            return False
        
        src_ip_str = str(src_ip)
        db = self._threat_database.get(src_ip_str, {})
        
        # Check CRITICAL threshold
        if threat_type == "CRITICAL" and db.get("attack_count", 0) >= self._quarantine_critical_threshold:
            return True, "CRITICAL threshold exceeded"
        
        # Check port scan threshold  
        if "Port Scan" in db.get("threat_types", []) and db.get("attack_count", 0) >= self._quarantine_scan_threshold:
            return True, "Port scan threshold exceeded"
        
        # Check brute force threshold
        if "Brute Force" in db.get("threat_types", []) and db.get("attack_count", 0) >= self._quarantine_bruteforce_threshold:
            return True, "Brute force threshold exceeded"
        
        return False, ""

    def _is_neutralization_active_or_queued(self, src_ip):
        src_ip = str(src_ip).strip()
        if not src_ip:
            return False
        return src_ip in self._active_blocks or src_ip in self._queued_neutralizations

    def _queue_neutralization(self, t, mode, notify=True, origin="manual"):
        src_ip = str(t.get("src_ip", "")).strip()
        if not self._valid_ip(src_ip):
            if notify:
                messagebox.showwarning("Neutralize Unavailable", f"Invalid source IP: {src_ip}")
            return False
        if self._is_neutralization_active_or_queued(src_ip):
            if notify:
                messagebox.showinfo("Neutralization Already Active", f"A response for {src_ip} is already active or queued.")
            self._append_response_log(
                f"Skipped duplicate response for {src_ip}",
                "warning",
                kind=origin,
                status="partial",
            )
            return False
        self._queued_neutralizations.add(src_ip)
        self._response_queue.put({"threat": dict(t), "mode": mode, "origin": origin})
        self._set_status("● Neutralization queued", ORANGE)
        self._append_response_log(
            f"Queued {self._mode_label(mode)} for {src_ip} ({t.get('type', 'Unknown Threat')})",
            "queued",
            kind=origin,
            status="queued",
        )
        return True

    def _record_successful_block(self, src_ip):
        src_ip = str(src_ip).strip()
        if not src_ip:
            return
        if src_ip not in self._threat_database:
            self._threat_database[src_ip] = {
                "first_seen": datetime.now().isoformat(),
                "attack_count": 0,
                "threat_types": [],
                "severities": [],
                "blocked_count": 0,
            }
        db_entry = self._threat_database[src_ip]
        db_entry["last_seen"] = datetime.now().isoformat()
        db_entry["blocked_count"] = db_entry.get("blocked_count", 0) + 1
        self._save_threat_database()

    # ═══════════════════════════════════════════════════════════════════════════════
    # RATE LIMITING
    # ═══════════════════════════════════════════════════════════════════════════════

    def _apply_rate_limit(self, src_ip, pps_limit=10):
        """Apply rate limit to source IP."""
        src_ip_str = str(src_ip)
        self._rate_limit_rules[src_ip_str] = {
            "pps_limit": pps_limit,
            "created_at": time.time()
        }
        
        iface = self._active_iface or self._iface_var.get() or "eth0"
        if self._has_cmd("tc") and iface and iface != "lo":
            try:
                self._run_cmd(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "12"])
                self._run_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1", "u32", "match", "ip", "src", src_ip, "flowid", "1:10"])
                self._run_cmd(["tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:10", "htb", "rate", f"{pps_limit}kbit"])
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════════════════════
    # NETWORK SEGMENTATION DETECTION
    # ═══════════════════════════════════════════════════════════════════════════════

    def _detect_lateral_movement(self, src_ip, dst_ip):
        """Detect if attacker is moving between network segments."""
        src_ip_str = str(src_ip)
        dst_ip_str = str(dst_ip)
        
        db = self._threat_database.get(src_ip_str, {})
        if "scanned_segments" not in db:
            db["scanned_segments"] = []
        
        # Extract subnet from IPs
        try:
            src_subnet = ".".join(dst_ip_str.split(".")[:3])
            if src_subnet not in db.get("scanned_segments", []):
                db["scanned_segments"].append(src_subnet)
                
                if len(db["scanned_segments"]) > 1:
                    return True, f"Lateral movement detected: attacking multiple subnets {db['scanned_segments']}"
        except Exception:
            pass
        
        return False, ""

    # ═══════════════════════════════════════════════════════════════════════════════
    # INCIDENT REPORT GENERATION
    # ═══════════════════════════════════════════════════════════════════════════════

    def _generate_incident_report(self):
        """Generate comprehensive incident report in HTML."""
        timestamp = datetime.now().isoformat()
        filename = os.path.expanduser(f"~/Documents/incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        esc = html.escape
        html = f"""
        <html>
        <head>
            <title>Network Sentinel Incident Report</title>
            <style>
                body {{ font-family: monospace; background: #1e1e1e; color: #e0e0e0; margin: 20px; }}
                h1 {{ color: #ff6b6b; border-bottom: 2px solid #ff6b6b; padding: 10px; }}
                h2 {{ color: #4ecdc4; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
                th, td {{ border: 1px solid #444; padding: 10px; text-align: left; }}
                th {{ background: #2d2d2d; color: #4ecdc4; }}
                tr:nth-child(even) {{ background: #252525; }}
                .critical {{ color: #ff6b6b; font-weight: bold; }}
                .warning {{ color: #ffd93d; }}
                .success {{ color: #6bcf7f; }}
            </style>
        </head>
        <body>
            <h1>🛡️ Network Sentinel Incident Report</h1>
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Total Threats Detected:</strong> {len(self._threat_database)}</p>
            
            <h2>Threat Timeline</h2>
            <table>
                <tr><th>Source IP</th><th>First Seen</th><th>Last Seen</th><th>Attack Count</th><th>Severity</th><th>Actions</th></tr>
        """
        
        for src_ip, data in self._threat_database.items():
            action_count = data.get("blocked_count", 0)
            severity = data.get("severities", ["Unknown"])[0] if data.get("severities") else "Unknown"
            severity_class = "critical" if severity == "CRITICAL" else "warning"
            
            html += f"""
                <tr>
                    <td>{esc(str(src_ip))}</td>
                    <td>{esc(str(data.get('first_seen', 'N/A')))}</td>
                    <td>{esc(str(data.get('last_seen', 'N/A')))}</td>
                    <td>{data.get('attack_count', 0)}</td>
                    <td class="{severity_class}">{esc(str(severity))}</td>
                    <td>{action_count} blocks</td>
                </tr>
            """
        
        html += """
            </table>
            <h2>Threat Types Detected</h2>
            <ul>
        """
        
        threat_types = set()
        for data in self._threat_database.values():
            threat_types.update(data.get("threat_types", []))
        
        for ttype in sorted(threat_types):
            html += f"<li>{esc(str(ttype))}</li>"
        
        html += f"""
            </ul>
            <h2>Recommendations</h2>
            <ul>
                <li>Review firewall rules and update accordingly</li>
                <li>Check affected systems for compromise</li>
                <li>Analyze forensic PCAP files for attack details</li>
                <li>Consider updating detection signatures</li>
            </ul>
            <p><small>Report generated by Network Sentinel v2.0</small></p>
        </body>
        </html>
        """
        
        try:
            with open(filename, "w") as f:
                f.write(html)
            messagebox.showinfo("Report Generated", f"Incident report saved to:\n{filename}")
            return filename
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════════════════════
    # HONEYPOT DECOY SERVICES
    # ═══════════════════════════════════════════════════════════════════════════════

    def _enable_honeypot_decoys(self):
        """Enable honeypot decoy services."""
        self._honeypot_enabled = True
        self._append_response_log(
            "Honeypot deception mode enabled (decoy services armed)",
            "info",
            kind="auto",
            status="info",
        )
        messagebox.showinfo(
            "Honeypot",
            "Honeypot deception mode enabled.\n"
            "Decoy services now bait attackers, collect telemetry, and can auto-contain repeat offenders.",
        )

    def _honeypot_source_session(self, src_ip, port=None, now=None):
        now = time.time() if now is None else float(now)
        src_ip = str(src_ip)
        state = self._honeypot_source_state.get(src_ip)
        if not state:
            state = {
                "first_seen": now,
                "last_seen": now,
                "ports": set(),
                "total_hits": 0,
            }
            self._honeypot_source_state[src_ip] = state
        state["last_seen"] = now
        state["total_hits"] += 1
        if port is not None:
            state["ports"].add(int(port))
        return state

    def _honeypot_should_escalate(self, hit_count, engagement_age_sec, unique_ports, total_hits):
        if hit_count < self._honeypot_trap_threshold:
            return False
        if total_hits >= self._honeypot_max_grace_hits:
            return True
        if engagement_age_sec >= self._honeypot_min_engagement_sec:
            return True
        if unique_ports >= self._honeypot_min_unique_ports:
            return True
        return False

    def _honeypot_service_for_port(self, port):
        profile = self._honeypot_profile_for_port(port)
        return profile.get("service", f"Unknown Decoy Service ({port})")

    def _honeypot_profile_for_port(self, port):
        data = HONEYPOT_DECOY_PORTS.get(int(port), {})
        if isinstance(data, dict):
            service = data.get("service", f"Unknown Decoy Service ({port})")
            banner = data.get("banner", f"Service token NS-{int(port):04d}")
            lure = data.get("lure", "Legacy misconfiguration indicators detected.")
            return {"service": service, "banner": banner, "lure": lure}
        # Backward-compatible fallback if simple string mappings are used.
        return {
            "service": str(data) if data else f"Unknown Decoy Service ({port})",
            "banner": f"Service token NS-{int(port):04d}",
            "lure": "Legacy misconfiguration indicators detected.",
        }

    def _honeypot_fingerprint(self, port, src_ip=None, hit_count=0):
        # Defensive deception text only; no exploit payloads or offensive actions.
        profile = self._honeypot_profile_for_port(port)
        service = profile.get("service", self._honeypot_service_for_port(port))
        banner = profile.get("banner", f"NS-{int(port):04d}")
        lure = profile.get("lure", "Legacy misconfiguration indicators detected.")
        token_seed = f"{src_ip or 'anon'}:{int(port)}"
        token = sum(ord(ch) for ch in token_seed) % 997
        if int(hit_count) >= 6:
            stage = "Service remains unstable under repeated probing; debug endpoint hints continue leaking."
        elif int(hit_count) >= 3:
            stage = "Service intermittently exposes maintenance metadata and weak auth hints."
        else:
            stage = "Service appears legacy and weakly hardened to external scans."
        return (
            f"{service} advertised banner: {banner}. "
            f"Exposed weakness claim: {lure} "
            f"Session token: NS-{int(port):04d}-{token:03d}. "
            f"Deception stage: {stage}"
        )

    def _honeypot_threat(self, src_ip, src_mac, hostname, dst_ip, port, hit_count, engagement_age=0, unique_ports=1, total_hits=1):
        level = "CRITICAL" if hit_count >= self._honeypot_trap_threshold else "WARNING"
        profile = self._honeypot_profile_for_port(port)
        service = profile.get("service", self._honeypot_service_for_port(port))
        banner = profile.get("banner", f"NS-{int(port):04d}")
        lure = profile.get("lure", "Legacy misconfiguration indicators detected.")
        fingerprint = self._honeypot_fingerprint(port, src_ip=src_ip, hit_count=hit_count)
        return {
            "level": level,
            "type": "Honeypot Triggered / Deception Engagement",
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "src_mac": src_mac,
            "hostname": hostname,
            "dst_ip": dst_ip,
            "what": (
                f"Decoy service interaction detected from {src_ip}.\n\n"
                f"  Decoy target : {service} (port {port})\n"
                f"  Presented banner : {banner}\n"
                f"  Bait claim : {lure}\n"
                f"  Interaction window hits : {hit_count} in {self._honeypot_window_sec}s\n"
                f"  Engagement age : {int(engagement_age)}s\n"
                f"  Recon breadth : {int(unique_ports)} decoy ports, {int(total_hits)} total hits\n"
                f"  Deception signal : {fingerprint}\n\n"
                "This source is engaging fake services and likely performing hostile recon/exploitation."
            ),
            "action": [
                "1. Verify source legitimacy; treat unknown source as hostile.",
                "2. Keep deception active to collect telemetry while containing source.",
                "3. Auto-containment may trigger after repeated hits.",
                "4. Export incident report and review packet burst evidence.",
            ],
        }

    def _escalate_honeypot_trap(self, threat):
        src_ip = str(threat.get("src_ip", "")).strip()
        if not self._valid_ip(src_ip):
            return
        if self._is_neutralization_active_or_queued(src_ip):
            return
        ok, _reason = self._preflight_neutralization(threat)
        if not ok:
            return
        # Escalation path: throttle first, then block+kill and isolate.
        self._apply_rate_limit(src_ip, pps_limit=4)
        if self._honeypot_auto_isolate:
            if self._honeypot_force_network_isolation and not self._network_isolation_enabled:
                self._network_isolation_enabled = True
                self._sync_policy_button_texts()
                self._refresh_toggle_button_styles()
                self._append_response_log(
                    "Honeypot trap enabled network isolation for escalation",
                    "warning",
                    kind="auto",
                    status="partial",
                )
            self._queue_neutralization(
                threat,
                self._honeypot_escalation_mode,
                notify=False,
                origin="auto",
            )

    def _log_honeypot_interaction(self, src_ip, port, service_type):
        """Log interaction with honeypot."""
        src_ip = str(src_ip)
        port = int(port)
        now = time.time()
        key = (src_ip, port)
        source_state = self._honeypot_source_session(src_ip, port=port, now=now)
        engagement_age = now - source_state.get("first_seen", now)
        unique_ports = len(source_state.get("ports", set()))
        total_hits = int(source_state.get("total_hits", 1))

        self._honeypot_decoys[port] = self._honeypot_decoys.get(port, 0) + 1
        q = self._honeypot_hits[key]
        q.append(now)
        cutoff = now - self._honeypot_window_sec
        while q and q[0] < cutoff:
            q.popleft()
        hit_count = len(q)

        interaction = {
            "src_ip": src_ip,
            "port": port,
            "service": service_type,
            "timestamp": datetime.now().isoformat(),
            "window_hits": hit_count,
            "engagement_age": int(engagement_age),
            "unique_ports": unique_ports,
            "total_hits": total_hits,
            "fingerprint": self._honeypot_fingerprint(port, src_ip=src_ip, hit_count=hit_count),
        }
        self._honeypot_interactions.append(interaction)

        threat = self._honeypot_threat(
            src_ip=src_ip,
            src_mac=self._detector._mac_for(src_ip) if self._detector else "Unknown",
            hostname=self._detector._resolve(src_ip) if self._detector else "Unresolved",
            dst_ip="",
            port=port,
            hit_count=hit_count,
            engagement_age=engagement_age,
            unique_ports=unique_ports,
            total_hits=total_hits,
        )

        should_publish = False
        if hit_count == 1 or hit_count >= self._honeypot_trap_threshold:
            should_publish = True
        elif hit_count % 3 == 0:
            if (now - self._honeypot_alert_cooldown.get(key, 0)) >= self._honeypot_alert_cooldown_sec:
                should_publish = True

        # Build threat rows only on milestones to avoid overwhelming the operator.
        if should_publish:
            self._queue_threat(threat)

        # Low-noise operator telemetry; avoid popup storms.
        last_alert = self._honeypot_alert_cooldown.get(key, 0)
        if (now - last_alert) >= self._honeypot_alert_cooldown_sec or hit_count >= self._honeypot_trap_threshold:
            self._honeypot_alert_cooldown[key] = now
            severity_tag = "failure" if hit_count >= self._honeypot_trap_threshold else "warning"
            self._append_response_log(
                f"Honeypot hit {src_ip} -> {service_type} ({port}), hits={hit_count}/{self._honeypot_trap_threshold}",
                severity_tag,
                kind="auto",
                status="partial" if hit_count < self._honeypot_trap_threshold else "failure",
                details=interaction.get("fingerprint", ""),
            )
            self._set_status(
                f"● Honeypot engaged {src_ip}:{port} ({hit_count} hits)",
                ORANGE if hit_count < self._honeypot_trap_threshold else RED,
            )

        if self._honeypot_should_escalate(hit_count, engagement_age, unique_ports, total_hits):
            self._escalate_honeypot_trap(threat)
        elif hit_count >= self._honeypot_trap_threshold and hit_count == self._honeypot_trap_threshold:
            self._append_response_log(
                f"Honeypot is holding {src_ip} in deception stage before containment (age={int(engagement_age)}s, ports={unique_ports}, hits={total_hits})",
                "info",
                kind="auto",
                status="info",
            )

    def _handle_honeypot_packet(self, p):
        if not self._honeypot_enabled:
            return
        if str(p.get("proto", "")).upper() not in ("TCP", "UDP"):
            return
        src_ip = str(p.get("src", "")).strip()
        dst_ip = str(p.get("dst", "")).strip()
        dport = p.get("dport")
        if not self._valid_ip(src_ip) or not self._valid_ip(dst_ip):
            return
        # Decoy triggers are only meaningful when attacker targets this host.
        if dst_ip not in self._local_ips:
            return
        try:
            port = int(dport)
        except Exception:
            return
        if port not in HONEYPOT_DECOY_PORTS:
            return
        self._log_honeypot_interaction(src_ip, port, self._honeypot_service_for_port(port))

    # ═══════════════════════════════════════════════════════════════════════════════
    # NETWORK BASELINE / ANOMALY DETECTION
    # ═══════════════════════════════════════════════════════════════════════════════

    def _learn_network_baseline(self, src_ip, dst_ip, protocol):
        """Learn normal network behavior."""
        if not self._baseline_enabled:
            return
        
        src_ip_str = str(src_ip)
        self._baseline_ips.add(src_ip_str)
        self._baseline_protocols[src_ip_str].add(protocol)

    def _detect_anomaly(self, src_ip, activity_type, details):
        """Detect network anomalies."""
        src_ip_str = str(src_ip)
        
        # Check if this is a "new device"
        if src_ip_str not in self._baseline_ips and self._baseline_learned:
            anomaly = {
                "type": "Unknown Device",
                "src_ip": src_ip_str,
                "details": f"New IP detected: {details}",
                "timestamp": datetime.now().isoformat(),
                "severity": "WARNING"
            }
            self._anomalies.append(anomaly)
            return True, anomaly
        
        return False, None

    def _finalize_baseline(self, quiet=False):
        """Mark baseline learning as complete."""
        self._baseline_learned = True
        if quiet:
            self._set_status("● Monitoring (baseline learned)", GREEN)
            return
        messagebox.showinfo("Baseline Complete", f"Network baseline established.\nLearned {len(self._baseline_ips)} IPs.\nAnomaly detection now active.")

    # ═══════════════════════════════════════════════════════════════════════════════
    # AUTOMATED RESPONSE PLAYBOOKS
    # ═══════════════════════════════════════════════════════════════════════════════

    def _execute_playbook(self, playbook_name, src_ip, tx):
        """Execute automated response playbook."""
        if playbook_name not in self._playbooks:
            return
        
        playbook = self._playbooks[playbook_name]
        actions = playbook.get("actions", [])
        
        for action in actions:
            if action == "pcap_burst":
                self._save_forensic_burst({"src_ip": src_ip})
            elif action == "block_local":
                pass  # Already handled
            elif action == "kill_sessions":
                pass  # Already handled
            elif action == "network_isolate":
                if self._network_isolation_enabled and hasattr(self, "_neutralize_network_isolate_ip"):
                    self._neutralize_network_isolate_ip(src_ip, tx)
            elif action == "export_report":
                self._generate_incident_report()
            elif action == "rate_limit":
                self._apply_rate_limit(src_ip)
            elif action == "auto_quarantine_top5":
                pass  # Handled in auto-quarantine
            elif action == "reduce_alert_noise":
                pass  # Handled in UI
            elif action == "enable_honeypot":
                self._enable_honeypot_decoys()

    # ═══════════════════════════════════════════════════════════════════════════════
    # REAL-TIME ALERTS & ONE-CLICK RESPONSE
    # ═══════════════════════════════════════════════════════════════════════════════

    def _show_desktop_alert_with_button(self, src_ip, threat_type, severity):
        """Show desktop alert with one-click action button."""
        msg = f"🚨 {severity}: {threat_type}\nSource: {src_ip}\n\nBlock this threat NOW?"
        if messagebox.askyesno("Threat Detected - One-Click Response", msg):
            # Find the threat in the table and neutralize it
            for item in self._threat_tree.get_children():
                vals = self._threat_tree.item(item, "values")
                if vals and vals[3] == src_ip:  # IP is at index 3
                    t = self._get_threat_from_row(vals)
                    if t:
                        self._neutralize_selected_threat(t, mode="policy")
                    break

    def _load_allowlist(self):
        default_allow = {"ips": [], "macs": [], "hostnames": []}
        if not os.path.exists(self._allowlist_path):
            try:
                with open(self._allowlist_path, "w") as f:
                    json.dump(default_allow, f, indent=2)
            except Exception:
                self._allowlist = default_allow
                return
        try:
            with open(self._allowlist_path, "r") as f:
                data = json.load(f)
            self._allowlist = {
                "ips": [str(x).strip() for x in data.get("ips", []) if str(x).strip()],
                "macs": [str(x).strip().lower() for x in data.get("macs", []) if str(x).strip()],
                "hostnames": [str(x).strip().lower() for x in data.get("hostnames", []) if str(x).strip()],
            }
        except Exception:
            self._allowlist = default_allow

    def _is_allowlisted(self, t):
        src_ip = str(t.get("src_ip", "")).strip()
        src_mac = str(t.get("src_mac", "")).strip().lower()
        hostname = str(t.get("hostname", "")).strip().lower()
        return (
            src_ip in self._allowlist.get("ips", []) or
            src_mac in self._allowlist.get("macs", []) or
            hostname in self._allowlist.get("hostnames", [])
        )

    def _baseline_warming(self):
        if not self._baseline_enabled or self._baseline_learned:
            return False
        if not self._running or not self._baseline_started_at:
            return False
        return (time.time() - self._baseline_started_at) < self._baseline_warmup_sec

    def _should_suppress_threat(self, t):
        if self._is_allowlisted(t):
            return True, "allowlisted"
        level = t.get("level", "INFO")
        ttype = t.get("type", "")
        if self._baseline_warming() and level in ("INFO", "WARNING") and ttype not in ("Capture Error",):
            return True, "baseline_warmup"
        return False, ""

    def _load_neutralization_history(self):
        if not os.path.exists(self._neutralize_store_path):
            return
        last_tx_by_ip = {}
        try:
            with open(self._neutralize_store_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        tx = json.loads(line)
                    except Exception:
                        continue
                    src_ip = tx.get("source_ip")
                    if not src_ip:
                        continue
                    self._neutralize_history[src_ip].append(tx)
                    last_tx_by_ip[src_ip] = tx
        except Exception:
            return

        # Recovery: treat latest successful block as active unless a rollback was the latest state.
        for src_ip, tx in last_tx_by_ip.items():
            mode = tx.get("mode")
            status = tx.get("status")
            rollback = tx.get("rollback", [])
            if mode in ("rollback", "auto-expire-rollback"):
                self._active_blocks.pop(src_ip, None)
                continue
            if mode in (NEUTRALIZE_SELF, NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL) and status in ("confirmed", "partial") and rollback:
                self._active_blocks[src_ip] = {
                    "expires_at": time.time() + self._block_ttl_sec,
                    "rollback": list(rollback),
                    "source_tx": tx.get("ts"),
                }

    def _persist_neutralization_tx(self, tx):
        try:
            with open(self._neutralize_store_path, "a") as f:
                f.write(json.dumps(tx, ensure_ascii=True) + "\n")
        except Exception:
            pass

    def _register_block_ttl(self, tx):
        if tx.get("mode") not in (NEUTRALIZE_SELF, NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL):
            return
        if tx.get("status") not in ("confirmed", "partial"):
            return
        src_ip = tx.get("source_ip")
        if not src_ip:
            return
        rollback = tx.get("rollback", [])
        if not rollback:
            return
        self._active_blocks[src_ip] = {
            "expires_at": time.time() + self._block_ttl_sec,
            "rollback": list(rollback),
            "source_tx": tx.get("ts"),
        }

    def _process_block_expiry(self):
        now = time.time()
        expired = [ip for ip, meta in self._active_blocks.items() if meta.get("expires_at", 0) <= now]
        for ip in expired:
            meta = self._active_blocks.pop(ip, {})
            rollback_cmds = list(meta.get("rollback", []))
            results = []
            for args in reversed(rollback_cmds):
                r = self._run_cmd(args)
                results.append((" ".join(args), r["ok"], r["err"]))
            tx = {
                "ts": datetime.now().isoformat(timespec="seconds"),
                "threat_type": "TTL Auto-Unblock",
                "source_ip": ip,
                "mode": "auto-expire-rollback",
                "status": "confirmed" if all(ok for _, ok, _ in results) else "partial",
                "steps": [{"step": cmd, "ok": ok, "err": err} for cmd, ok, err in results],
                "verify": [],
                "rollback": [],
            }
            self._neutralize_history[ip].append(tx)
            self._log_neutralization(tx)
            self._persist_neutralization_tx(tx)
            self._append_response_log(
                f"TTL expired for {ip}; automatic rollback {tx['status']}",
                "warning" if tx["status"] == "partial" else "info",
                kind="rollback",
                status=tx["status"],
                details="\n".join(f"{cmd}: {err}" for cmd, ok, err in results if not ok),
            )

    def _response_worker_loop(self):
        while True:
            task = self._response_queue.get()
            if task is None:
                self._response_queue.task_done()
                break
            try:
                t = task.get("threat")
                mode = task.get("mode", "policy")
                origin = task.get("origin", "manual")
                src_ip = str((t or {}).get("src_ip", "Unknown"))
                threat_type = str((t or {}).get("type", "Unknown Threat"))
                self.after(0, lambda src_ip=src_ip, threat_type=threat_type, mode=mode, origin=origin:
                           self._append_response_log(
                               f"Executing {self._mode_label(mode)} for {src_ip} ({threat_type})",
                               "running",
                               kind=origin,
                               status="running",
                           ))
                tx = self._execute_neutralization(t, mode)
                tx["origin"] = origin
            except Exception as e:
                tx = {
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "threat_type": "Neutralization Worker Error",
                    "source_ip": str(task.get("threat", {}).get("src_ip", "Unknown")),
                    "mode": "worker-error",
                    "origin": task.get("origin", "manual"),
                    "steps": [{"step": "worker", "ok": False, "err": str(e)}],
                    "verify": [],
                    "rollback": [],
                    "status": "failed",
                    "confidence": 0,
                }
            self.after(0, lambda tx=tx: self._finish_neutralization(tx))
            self._response_queue.task_done()

    def _save_forensic_burst(self, t):
        if not self._raw_pkts:
            return
        if not SCAPY_AVAILABLE:
            return
        try:
            burst = list(self._raw_pkts)[-self.FORENSIC_BURST_PACKETS:]
            if not burst:
                return
            src = str(t.get("src_ip", "unknown")).replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.expanduser(f"~/Documents/sentinel_forensic_{src}_{ts}.pcap")
            wrpcap(path, burst)
        except Exception:
            pass

    # ── Sniff loop ────────────────────────────────────────────────────────────

    def _sniff_loop(self, iface):
        def handler(pkt):
            self._raw_pkts.append(pkt)
            if self._detector:
                self._detector.process(pkt)
        try:
            while self._running:
                sniff(iface=iface, prn=handler, store=False, timeout=1)
        except Exception as e:
            self._queue_threat({
                "level": "INFO", "type": "Capture Error",
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": "N/A", "src_mac": "N/A", "hostname": "N/A",
                "what": f"Packet capture stopped:\n\n  {e}",
                "action": [
                    "1.  Confirm the selected interface is correct.",
                    "2.  Run:  sudo python3 sentinel.py",
                    "3.  Check interface is up:  ip link show",
                ]
            })

    # ── Thread-safe queues ────────────────────────────────────────────────────

    def _queue_packet(self, p):
        with self._lock:
            if len(self._pkt_queue) >= self.MAX_PKT_QUEUE:
                self._dropped_pkt_queue += 1
            self._pkt_queue.append(p)

    def _queue_threat(self, t):
        with self._lock:
            if len(self._threat_queue) >= self.MAX_THREAT_QUEUE:
                self._dropped_threat_queue += 1
            self._threat_queue.append(t)

    # ── Main poll loop (100 ms) ───────────────────────────────────────────────

    def _poll(self):
        with self._lock:
            pkts    = list(self._pkt_queue)
            threats = list(self._threat_queue)
            self._pkt_queue.clear()
            self._threat_queue.clear()
        for p in pkts:
            self._pkt_buffer.append(p)
            self._handle_honeypot_packet(p)
            if not self._paused:
                self._maybe_add_row(p)
        for t in threats:
            self._add_threat(t)
        if self._detector:
            self._sync_hosts()
        self.after(100, self._poll)

    # ── Stats tick (1 s) ─────────────────────────────────────────────────────

    def _tick_stats(self):
        pps, bps = self._stats.tick()
        with self._lock:
            dropped_pkts = self._dropped_pkt_queue
            dropped_threats = self._dropped_threat_queue
        self._sv_pps.set(str(pps))
        self._sv_bps.set(StatsEngine.fmt_bytes(bps))
        self._sv_hosts.set(str(self._detector.host_count() if self._detector else 0))
        self._sv_sess.set(str(len(self._stats.sessions)))
        self._sv_pkts.set(str(self._stats.total_pkts))
        self._sv_drop_pkts.set(str(dropped_pkts))
        self._sv_drop_threats.set(str(dropped_threats))
        if self._baseline_enabled and not self._baseline_learned and self._baseline_started_at:
            if (time.time() - self._baseline_started_at) >= self._baseline_warmup_sec:
                self._finalize_baseline(quiet=True)
        self._graph.refresh()
        self._process_block_expiry()
        self.after(self.GRAPH_MS, self._tick_stats)

    # ── Packet feed ───────────────────────────────────────────────────────────

    def _matches_filter(self, p):
        if not self._filter_str:
            return True
        fs = self._filter_str.lower()
        return (fs in str(p.get("src",   "")).lower() or
                fs in str(p.get("dst",   "")).lower() or
                fs in str(p.get("proto", "")).lower() or
                fs in str(p.get("sport", "")).lower() or
                fs in str(p.get("dport", "")).lower())

    def _maybe_add_row(self, p):
        if not self._matches_filter(p):
            return
        proto = p.get("proto", "IP")
        tag   = proto if proto in ("TCP", "UDP", "ICMP", "ARP") else "TCP"
        vals  = (p["ts"], p["src"], p["dst"], p["proto"],
                 p["sport"], p["dport"], p["flags"], p["length"])
        self._pkt_tree.insert("", 0, values=vals, tags=(tag,))
        self._pkt_count += 1
        children = self._pkt_tree.get_children()
        if len(children) > self.MAX_PACKETS:
            self._pkt_tree.delete(children[-1])

    def _on_filter_change(self, *_):
        self._filter_str = self._filter_var.get().strip()
        self._rerender_packets()

    def _rerender_packets(self):
        self._pkt_tree.delete(*self._pkt_tree.get_children())
        for p in list(self._pkt_buffer):
            if self._matches_filter(p):
                proto = p.get("proto", "IP")
                tag   = proto if proto in ("TCP", "UDP", "ICMP", "ARP") else "TCP"
                vals  = (p["ts"], p["src"], p["dst"], p["proto"],
                         p["sport"], p["dport"], p["flags"], p["length"])
                self._pkt_tree.insert("", 0, values=vals, tags=(tag,))

    # ── Hosts ─────────────────────────────────────────────────────────────────

    def _sync_hosts(self):
        for mac, info in self._detector.host_items_snapshot():
            traffic = StatsEngine.fmt_bytes(self._stats.host_bytes.get(info["ip"], 0))
            vals    = (info["ip"], info["mac"], info["hostname"],
                       traffic, info["last_seen"])
            if mac in self._known_mac_rows:
                self._host_tree.item(self._known_mac_rows[mac], values=vals)
            else:
                iid = self._host_tree.insert("", "end", values=vals)
                self._known_mac_rows[mac] = iid

    # ── Threats ───────────────────────────────────────────────────────────────

    def _add_threat(self, t):
        src_ip = t.get("src_ip", "")
        threat_type = t.get("type", "")
        lvl = t.get("level", "INFO")
        suppress, _reason = self._should_suppress_threat(t)
        if suppress:
            return
        
        # ─── REPUTATION SYSTEM: Record this threat ───────────────────────
        self._record_threat_reputation(src_ip, threat_type, lvl)
        
        # ─── NETWORK BASELINE: Learn normal behavior or detect anomalies ──
        if self._baseline_enabled:
            self._learn_network_baseline(src_ip, t.get("dst_ip", ""), t.get("proto", ""))
            is_anomaly, anomaly_data = self._detect_anomaly(src_ip, threat_type, t.get("what", ""))
            if is_anomaly and anomaly_data:
                messagebox.showwarning("Anomaly Detected", f"{anomaly_data['type']}: {anomaly_data['details']}")
        
        # ─── LATERAL MOVEMENT DETECTION ──────────────────────────────────
        is_lateral, lateral_msg = self._detect_lateral_movement(src_ip, t.get("dst_ip", ""))
        if is_lateral:
            messagebox.showwarning("Lateral Movement", lateral_msg)
            t["lateral_movement"] = True
        
        # ─── AUTO-QUARANTINE: Check if IP should be blocked automatically ─
        should_quarantine, quarantine_reason = self._check_auto_quarantine(src_ip, lvl)
        if should_quarantine and self._quarantine_enabled:
            ok, reason = self._preflight_neutralization(t)
            if ok and not self._is_neutralization_active_or_queued(src_ip):
                resolved_mode = self._action_mode_for_threat(t)
                if resolved_mode != NEUTRALIZE_NONE and self._queue_neutralization(t, resolved_mode, notify=False, origin="auto"):
                    self._set_status(
                        f"● Auto-Q {src_ip}: {self._mode_label(resolved_mode)}",
                        ORANGE,
                    )
                    self._record_threat_reputation(src_ip, threat_type, "QUARANTINED")
            elif not ok:
                self._set_status(f"● Auto-Q skipped for {src_ip}: {reason}", ORANGE)
                self._append_response_log(
                    f"Auto-Q skipped for {src_ip}: {reason}",
                    "warning",
                    kind="auto",
                    status="partial",
                    details=reason,
                )
        
        # ─── RATE LIMITING: Apply if enabled ─────────────────────────────
        if self._rate_limit_enabled and lvl in ("WARNING", "INFO"):
            self._apply_rate_limit(src_ip)
        
        # ─── REAL-TIME ALERT: Desktop notification with one-click response ──
        if lvl == "CRITICAL":
            self._show_desktop_alert_with_button(src_ip, threat_type, "🚨 CRITICAL")
        elif lvl == "WARNING":
            if "Honeypot Triggered" not in str(threat_type):
                self._show_desktop_alert_with_button(src_ip, threat_type, "⚠️  WARNING")
        
        # ─── Store and display threat ────────────────────────────────────
        self._threats.append(t)
        self._tc[lvl] = self._tc.get(lvl, 0) + 1
        self._sv_crit.set(str(self._tc["CRITICAL"]))
        self._sv_warn.set(str(self._tc["WARNING"]))
        self._sv_info.set(str(self._tc["INFO"]))
        
        # Show reputation score in threat details
        rep_score = self._get_threat_reputation_score(src_ip)
        t["reputation_score"] = rep_score
        
        iid = self._threat_tree.insert(
            "", 0, values=(t["ts"], t["level"], t["type"], t["src_ip"]),
            tags=(lvl,))
        self._threat_tree.selection_set(iid)
        self._show_detail(t)
        
        if lvl == "CRITICAL":
            self.bell()
            self._notify_desktop(t)
            self._save_forensic_burst(t)

    def _on_threat_select(self, _):
        sel = self._threat_tree.selection()
        if not sel:
            return
        vals = self._threat_tree.item(sel[0], "values")
        for t in reversed(self._threats):
            if t["ts"] == vals[0] and t["type"] == vals[2]:
                self._show_detail(t)
                break

    def _manual_quarantine_selected(self):
        # Prefer host selection so operators can quarantine proactively.
        host_sel = self._host_tree.selection() if hasattr(self, "_host_tree") else ()
        if host_sel:
            vals = self._host_tree.item(host_sel[0], "values")
            src_ip = str(vals[0]) if len(vals) > 0 else ""
            if not self._valid_ip(src_ip):
                messagebox.showwarning("Quarantine Unavailable", f"Selected host has invalid IP: {src_ip}")
                return
            t = self._host_to_threat(vals)
            self._neutralize_selected_threat(t, mode=NEUTRALIZE_SELF)
            return

        threat_sel = self._threat_tree.selection() if hasattr(self, "_threat_tree") else ()
        if threat_sel:
            vals = self._threat_tree.item(threat_sel[0], "values")
            t = self._get_threat_from_row(vals)
            if not t:
                messagebox.showwarning("Quarantine Unavailable", "Could not resolve selected threat details.")
                return
            self._neutralize_selected_threat(t, mode=NEUTRALIZE_BLOCK)
            return

        messagebox.showwarning(
            "No Target Selected",
            "Select a host in Discovered Hosts or a row in Threat Alerts, then quarantine.",
        )

    def _host_context_menu(self, event):
        row = self._host_tree.identify_row(event.y)
        if not row:
            return
        self._host_tree.selection_set(row)
        vals = self._host_tree.item(row, "values")
        src_ip = str(vals[0]) if len(vals) > 0 else ""
        if not self._valid_ip(src_ip):
            return
        t = self._host_to_threat(vals)
        menu = tk.Menu(self, tearoff=0, bg=BG2, fg=FG,
                       activebackground=BG3, activeforeground=CYAN, font=FONT_UI)
        menu.add_command(label=f"Copy IP ({src_ip})", command=lambda: self._copy(src_ip))
        menu.add_separator()
        menu.add_command(label="Self-Quarantine: This PC Only",
                         command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_SELF))
        menu.add_command(label="Neutralize Threat (Recommended)",
                         command=lambda: self._neutralize_selected_threat(t, mode="policy"))
        menu.add_command(label="Neutralize: Block + Kill (Aggressive)",
                         command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_BLOCKKILL))
        menu.tk_popup(event.x_root, event.y_root)

    def _show_detail(self, t):
        dt = self._detail
        dt.config(state=tk.NORMAL)
        dt.delete("1.0", tk.END)
        lvl = t.get("level", "INFO")
        dt.insert(tk.END, f"[{lvl}]  ", lvl)
        dt.insert(tk.END, t.get("type", "") + "\n", "title")
        dt.insert(tk.END, "─" * 56 + "\n", "divider")
        for label, key in [("Timestamp", "ts"), ("Source IP ", "src_ip"),
                            ("MAC Addr  ", "src_mac"), ("Hostname  ", "hostname")]:
            dt.insert(tk.END, f"  {label} : ", "section")
            dt.insert(tk.END, t.get(key, "?") + "\n", "value")
        
        # ─── NEW: Display Reputation Score ──────────────────────────────
        src_ip = t.get("src_ip", "")
        rep_score = self._get_threat_reputation_score(src_ip)
        dt.insert(tk.END, f"  Reputation: ", "section")
        rep_text = f"{rep_score}/100 - "
        if rep_score >= 70:
            rep_text += "🔴 HIGH RISK (Known Attacker)"
        elif rep_score >= 40:
            rep_text += "🟠 MEDIUM RISK (Previously Attempted)"
        else:
            rep_text += "🟡 LOW RISK (First Time)"
        dt.insert(tk.END, rep_text + "\n", "value")
        
        # ─── NEW: Display Lateral Movement Flag ──────────────────────────
        if t.get("lateral_movement"):
            dt.insert(tk.END, f"  ⚠️  Lateral Movement Detected\n", "action")
        
        # ─── NEW: Show previous attacks from this IP ────────────────────
        if src_ip in self._threat_database:
            db = self._threat_database[src_ip]
            dt.insert(tk.END, f"  Previous Attacks: ", "section")
            dt.insert(tk.END, f"{db.get('attack_count', 0)}\n", "value")
        
        dt.insert(tk.END, "\nWHAT HAPPENED\n", "section")
        dt.insert(tk.END, t.get("what", "") + "\n", "body")
        dt.insert(tk.END, "\nCOURSE OF ACTION\n", "section")
        for step in t.get("action", []):
            dt.insert(tk.END, step + "\n", "action")
        dt.config(state=tk.DISABLED)
        dt.see("1.0")

    def _get_threat_from_row(self, vals):
        return next((x for x in reversed(self._threats)
                     if x.get("ts") == vals[0] and x.get("type") == vals[2]), None)

    def _valid_ip(self, ip):
        try:
            if not ip or ip in ("N/A", "Unknown"):
                return False
            ipaddress.ip_address(str(ip))
            return True
        except Exception:
            return False

    @staticmethod
    def _has_cmd(cmd):
        return shutil.which(cmd) is not None

    def _run_cmd(self, args, timeout=12):
        try:
            p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
            return {
                "ok": p.returncode == 0,
                "code": p.returncode,
                "out": (p.stdout or "").strip(),
                "err": (p.stderr or "").strip(),
                "cmd": " ".join(args),
            }
        except Exception as e:
            return {
                "ok": False,
                "code": -1,
                "out": "",
                "err": str(e),
                "cmd": " ".join(args),
            }

    def _action_mode_for_threat(self, t):
        ttype = t.get("type", "")
        level = t.get("level", "INFO")
        if ttype in THREAT_ACTION_MODE:
            return THREAT_ACTION_MODE[ttype]

        if self._policy_profile == "Home":
            if level == "CRITICAL":
                return NEUTRALIZE_BLOCKKILL
            return NEUTRALIZE_BLOCK

        if self._policy_profile == "Lab":
            if level in ("CRITICAL", "WARNING"):
                return NEUTRALIZE_BLOCKKILL
            return NEUTRALIZE_BLOCK

        if self._policy_profile == "Production":
            if "Scan" in ttype or "DNS Tunneling" in ttype:
                return NEUTRALIZE_BLOCK
            if level == "CRITICAL":
                return NEUTRALIZE_BLOCKKILL
            return NEUTRALIZE_BLOCK

        if "Scan" in ttype or "DNS Tunneling" in ttype:
            return NEUTRALIZE_BLOCK
        if level == "CRITICAL":
            return NEUTRALIZE_BLOCKKILL
        return NEUTRALIZE_BLOCKKILL

    def _verify_block(self, src_ip):
        checks = []
        is_v6 = ":" in str(src_ip)
        if self._has_cmd("ufw"):
            ufw = self._run_cmd(["ufw", "status"])
            checks.append(("ufw", ufw["ok"] and src_ip in (ufw["out"] + "\n" + ufw["err"])))
        ipt_cmd = "ip6tables" if is_v6 else "iptables"
        if self._has_cmd(ipt_cmd):
            in_ok = self._run_cmd([ipt_cmd, "-C", "INPUT", "-s", src_ip, "-j", "DROP"])["ok"]
            out_ok = self._run_cmd([ipt_cmd, "-C", "OUTPUT", "-d", src_ip, "-j", "DROP"])["ok"]
            checks.append((ipt_cmd, in_ok and out_ok))
        if self._has_cmd("nft"):
            nft = self._run_cmd(["nft", "list", "ruleset"])
            nft_txt = nft["out"] + "\n" + nft["err"]
            fam = "ip6" if is_v6 else "ip"
            in_ok = f"{fam} saddr {src_ip} drop" in nft_txt
            out_ok = f"{fam} daddr {src_ip} drop" in nft_txt
            checks.append(("nft", nft["ok"] and (in_ok or out_ok)))
        if self._has_cmd("ip"):
            route = self._run_cmd(["ip", "-6", "route", "show"] if is_v6 else ["ip", "route", "show"])
            checks.append(("blackhole", route["ok"] and f"blackhole {src_ip}" in route["out"]))
        return checks, any(ok for _, ok in checks)

    def _verify_kill(self, src_ip):
        checks = []
        verified = False

        if self._has_cmd("ss"):
            r = self._run_cmd(["ss", "-tnp"])
            ok = r["ok"] and (src_ip not in r["out"])
            checks.append(("ss", ok))
            verified = verified or ok

        if self._has_cmd("conntrack"):
            r = self._run_cmd(["conntrack", "-L"])
            ok = r["ok"] and (src_ip not in r["out"])
            checks.append(("conntrack", ok))
            verified = verified or ok

        if not checks:
            checks.append(("kill verification", False))
        return checks, verified

    @staticmethod
    def _pid_alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    def _kill_local_pids_for_ip(self, src_ip):
        # Fallback path: extract socket-owner PIDs tied to source IP and terminate.
        if not self._has_cmd("ss"):
            return False, {"cmd": "pid fallback", "out": "", "err": "ss not found"}

        pids = set()
        outputs = []
        errors = []
        for args in (["ss", "-H", "-tnp"], ["ss", "-H", "-unp"]):
            r = self._run_cmd(args, timeout=8)
            outputs.append(r["out"])
            if r["err"]:
                errors.append(r["err"])
            if not r["ok"]:
                continue
            for line in r["out"].splitlines():
                if src_ip not in line:
                    continue
                for m in re.findall(r"pid=(\d+)", line):
                    try:
                        pids.add(int(m))
                    except Exception:
                        pass

        if not pids:
            return False, {
                "cmd": "pid fallback",
                "out": "No matching socket-owner PIDs found",
                "err": "\n".join(errors).strip(),
            }

        term_ok = []
        kill_ok = []
        for pid in sorted(pids):
            try:
                os.kill(pid, signal.SIGTERM)
                term_ok.append(pid)
            except Exception as e:
                errors.append(f"SIGTERM pid={pid}: {e}")

        time.sleep(0.35)

        for pid in sorted(pids):
            if not self._pid_alive(pid):
                kill_ok.append(pid)
                continue
            try:
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.05)
                if not self._pid_alive(pid):
                    kill_ok.append(pid)
                else:
                    errors.append(f"SIGKILL pid={pid}: still alive")
            except Exception as e:
                errors.append(f"SIGKILL pid={pid}: {e}")

        ok = len(kill_ok) > 0
        out = (
            f"Matched PIDs: {', '.join(map(str, sorted(pids)))}\n"
            f"Terminated PIDs: {', '.join(map(str, sorted(kill_ok)))}"
        )
        return ok, {"cmd": "pid fallback", "out": out, "err": "\n".join(errors).strip()}

    def _neutralize_block_ip(self, src_ip, tx):
        steps = []
        blocked = False
        is_v6 = ":" in str(src_ip)

        if self._has_cmd("ufw"):
            r = self._run_cmd(["ufw", "deny", "from", src_ip])
            exists_msg = "Skipping adding existing rule"
            ok = r["ok"] or exists_msg in (r["out"] + "\n" + r["err"])
            steps.append(("ufw deny", ok, r))
            if ok:
                tx["rollback"].append(["ufw", "--force", "delete", "deny", "from", src_ip])
                blocked = True
        else:
            steps.append(("ufw deny", False, {"err": "ufw not found", "out": "", "cmd": "ufw"}))

        ipt_cmd = "ip6tables" if is_v6 else "iptables"
        if self._has_cmd(ipt_cmd):
            in_exists = self._run_cmd([ipt_cmd, "-C", "INPUT", "-s", src_ip, "-j", "DROP"])["ok"]
            out_exists = self._run_cmd([ipt_cmd, "-C", "OUTPUT", "-d", src_ip, "-j", "DROP"])["ok"]

            if in_exists:
                r1 = {"ok": True, "out": "Rule already exists", "err": "", "cmd": f"{ipt_cmd} -C INPUT"}
            else:
                r1 = self._run_cmd([ipt_cmd, "-I", "INPUT", "-s", src_ip, "-j", "DROP"])

            if out_exists:
                r2 = {"ok": True, "out": "Rule already exists", "err": "", "cmd": f"{ipt_cmd} -C OUTPUT"}
            else:
                r2 = self._run_cmd([ipt_cmd, "-I", "OUTPUT", "-d", src_ip, "-j", "DROP"])

            ok = r1["ok"] and r2["ok"]
            steps.append((f"{ipt_cmd} drop", ok, {
                "cmd": ipt_cmd,
                "out": (r1["out"] + "\n" + r2["out"]).strip(),
                "err": (r1["err"] + "\n" + r2["err"]).strip(),
            }))
            if ok:
                if not out_exists:
                    tx["rollback"].append([ipt_cmd, "-D", "OUTPUT", "-d", src_ip, "-j", "DROP"])
                if not in_exists:
                    tx["rollback"].append([ipt_cmd, "-D", "INPUT", "-s", src_ip, "-j", "DROP"])
                blocked = True
        else:
            steps.append((f"{ipt_cmd} drop", False, {"err": f"{ipt_cmd} not found", "out": "", "cmd": ipt_cmd}))

        if self._has_cmd("nft"):
            fam = "ip6" if is_v6 else "ip"
            in_handle_before = self._nft_find_rule_handle("input", src_ip, "saddr", fam)
            out_handle_before = self._nft_find_rule_handle("output", src_ip, "daddr", fam)
            r1 = self._run_cmd(["nft", "add", "rule", "inet", "filter", "input", fam, "saddr", src_ip, "drop"])
            r2 = self._run_cmd(["nft", "add", "rule", "inet", "filter", "output", fam, "daddr", src_ip, "drop"])
            e1 = "File exists" in (r1["err"] + "\n" + r1["out"])
            e2 = "File exists" in (r2["err"] + "\n" + r2["out"])
            ok = (r1["ok"] or e1) and (r2["ok"] or e2)
            steps.append(("nft drop", ok, {
                "cmd": "nft",
                "out": (r1["out"] + "\n" + r2["out"]).strip(),
                "err": (r1["err"] + "\n" + r2["err"]).strip(),
            }))
            if ok:
                in_handle_after = self._nft_find_rule_handle("input", src_ip, "saddr", fam)
                out_handle_after = self._nft_find_rule_handle("output", src_ip, "daddr", fam)
                if out_handle_after and out_handle_after != out_handle_before:
                    tx["rollback"].append([
                        "nft", "delete", "rule", "inet", "filter", "output", "handle", out_handle_after
                    ])
                if in_handle_after and in_handle_after != in_handle_before:
                    tx["rollback"].append([
                        "nft", "delete", "rule", "inet", "filter", "input", "handle", in_handle_after
                    ])
                blocked = True
        else:
            steps.append(("nft drop", False, {"err": "nft not found", "out": "", "cmd": "nft"}))

        if self._has_cmd("ip"):
            cidr = f"{src_ip}/128" if is_v6 else f"{src_ip}/32"
            add_cmd = ["ip", "-6", "route", "add", "blackhole", cidr] if is_v6 else ["ip", "route", "add", "blackhole", cidr]
            del_cmd = ["ip", "-6", "route", "del", "blackhole", cidr] if is_v6 else ["ip", "route", "del", "blackhole", cidr]
            r = self._run_cmd(add_cmd)
            ok = r["ok"] or "File exists" in r["err"]
            steps.append(("route blackhole", ok, r))
            if ok:
                tx["rollback"].append(del_cmd)
                blocked = True
        else:
            steps.append(("route blackhole", False, {"err": "ip tool not found", "out": "", "cmd": "ip"}))

        checks, verified = self._verify_block(src_ip)
        return steps, blocked, checks, verified

    def _neutralize_kill_sessions(self, src_ip, tx):
        steps = []
        killed = False

        if self._has_cmd("ss"):
            r1 = self._run_cmd(["ss", "-K", "src", src_ip])
            r2 = self._run_cmd(["ss", "-K", "dst", src_ip])
            ok = r1["ok"] or r2["ok"]
            steps.append(("ss kill", ok, {"cmd": "ss -K", "out": r1["out"] + "\n" + r2["out"], "err": r1["err"] + "\n" + r2["err"]}))
            killed = killed or ok
        else:
            steps.append(("ss kill", False, {"err": "ss not found", "out": "", "cmd": "ss"}))

        if self._has_cmd("conntrack"):
            r1 = self._run_cmd(["conntrack", "-D", "-s", src_ip])
            r2 = self._run_cmd(["conntrack", "-D", "-d", src_ip])
            m1 = "0 flow entries have been deleted" in (r1["out"] + "\n" + r1["err"])
            m2 = "0 flow entries have been deleted" in (r2["out"] + "\n" + r2["err"])
            ok = r1["ok"] or r2["ok"] or m1 or m2
            steps.append(("conntrack delete", ok, {"cmd": "conntrack", "out": r1["out"] + "\n" + r2["out"], "err": r1["err"] + "\n" + r2["err"]}))
            killed = killed or ok
        else:
            steps.append(("conntrack delete", False, {"err": "conntrack not found", "out": "", "cmd": "conntrack"}))

        checks, verified = self._verify_kill(src_ip)
        if not verified:
            ok, detail = self._kill_local_pids_for_ip(src_ip)
            steps.append(("pid fallback kill", ok, detail))
            killed = killed or ok
            checks, verified = self._verify_kill(src_ip)
        return steps, killed, checks, verified

    @staticmethod
    def _mode_label(mode):
        return {
            NEUTRALIZE_SELF: "Self-quarantine attacker from this PC only",
            NEUTRALIZE_BLOCK: "Block source IP",
            NEUTRALIZE_KILL: "Kill active sessions",
            NEUTRALIZE_BLOCKKILL: "Block source IP + kill active sessions",
            NEUTRALIZE_NETWORK: "Network isolate via ARP spoofing",
            NEUTRALIZE_NONE: "No action",
        }.get(mode, str(mode))

    def _confirm_neutralize(self, t, mode):
        src_ip = t.get("src_ip", "Unknown")
        ttype = t.get("type", "Unknown Threat")
        mode_txt = self._mode_label(mode)
        msg = (
            f"Threat: {ttype}\n"
            f"Source IP: {src_ip}\n"
            f"Action: {mode_txt}\n\n"
            "This can disrupt legitimate traffic. Continue?"
        )
        return messagebox.askyesno("Confirm Threat Neutralization", msg)

    def _log_neutralization(self, tx):
        try:
            tx_line = json.dumps(tx, ensure_ascii=True)
            with open(self._neutralize_log_path, "a") as f:
                f.write(tx_line + "\n")
        except Exception:
            pass

    def _neutralize_network_isolate_ip(self, src_ip, tx):
        """
        Isolate threat IP from the network via ARP spoofing.
        Sends gratuitous ARP packets claiming attacker_ip = our_mac,
        causing the network to redirect their traffic to us (which we drop).
        """
        steps = []
        isolated = False

        if not SCAPY_AVAILABLE:
            steps.append(("arp spoof", False, {"err": "scapy not available", "out": "", "cmd": "arp"}))
            return steps, isolated, [], False

        if not self._mac_address:
            steps.append(("arp spoof", False, {"err": "Could not determine local MAC address", "out": "", "cmd": "arp"}))
            return steps, isolated, [], False

        try:
            from scapy.all import ARP, Ether, sendp, get_if_list
            iface = self._get_default_interface()
            if not iface:
                steps.append(("arp spoof", False, {"err": "No default network interface found", "out": "", "cmd": "arp"}))
                return steps, isolated, [], False

            # Create gratuitous ARP packet: "src_ip is at our_mac"
            arp_pkt = ARP(op="is-at", pdst=src_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=self._gateway_ip or "0.0.0.0", hwsrc=self._mac_address)
            ether_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_pkt

            # Send ARP packet (non-blocking)
            try:
                sendp(ether_pkt, iface=iface, verbose=False)
                isolated = True
                steps.append(("arp spoof broadcast", True, {"cmd": "arp", "out": f"Sent ARP spoof: {src_ip} -> {self._mac_address}", "err": ""}))
                
                # Register cleanup: send correct ARP to restore cache
                tx["rollback"].append(("arp_restore", src_ip))
            except Exception as e:
                steps.append(("arp spoof broadcast", False, {"cmd": "arp", "out": "", "err": str(e)[:200]}))

        except Exception as e:
            steps.append(("arp spoof", False, {"err": str(e)[:200], "out": "", "cmd": "arp"}))

        checks = [("arp spoof", isolated)]
        return steps, isolated, checks, isolated

    def _get_default_interface(self):
        """Get the default network interface for sending ARP packets."""
        try:
            if not self._has_cmd("ip"):
                return None
            r = self._run_cmd(["ip", "route", "show", "default"])
            if not r["ok"]:
                return None
            parts = r["out"].split()
            if "dev" in parts:
                i = parts.index("dev")
                if i + 1 < len(parts):
                    return parts[i + 1]
        except Exception:
            pass
        try:
            from scapy.all import get_if_list, get_if_hwaddr
            interfaces = get_if_list()
            for iface in interfaces:
                if iface not in ("lo", "docker0"):
                    try:
                        mac = get_if_hwaddr(iface)
                        if mac and mac != "00:00:00:00:00:00":
                            return iface
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    def _nft_find_rule_handle(self, chain, src_ip, direction="saddr", family="ip"):
        if not self._has_cmd("nft"):
            return None
        r = self._run_cmd(["nft", "-a", "list", "chain", "inet", "filter", chain])
        if not r["ok"]:
            return None
        needle = f"{family} {direction} {src_ip} drop"
        for line in r["out"].splitlines():
            if needle in line and "handle" in line:
                handle = line.split("handle")[-1].strip()
                if handle.isdigit():
                    return handle
        return None

    def _show_neutralize_capabilities(self):
        checks = [
            ("ufw", ["ufw", "status", "verbose"]),
            ("iptables", ["iptables", "--version"]),
            ("ip6tables", ["ip6tables", "--version"]),
            ("nft", ["nft", "--version"]),
            ("ss", ["ss", "-V"]),
            ("conntrack", ["conntrack", "-V"]),
            ("ip", ["ip", "-V"]),
        ]
        lines = ["Threat Neutralization Capability Check", ""]
        for name, probe in checks:
            if not self._has_cmd(name):
                lines.append(f"- MISSING  {name}")
                continue
            r = self._run_cmd(probe, timeout=6)
            status = "OK" if r["ok"] else "WARN"
            lines.append(f"- {status}  {name}")
            if not r["ok"] and r["err"]:
                lines.append(f"    {r['err'][:140]}")
        lines.extend([
            "",
            "Runtime Policy:",
            f"- Dry run: {'ON' if self._dry_run else 'OFF'}",
            f"- Policy profile: {self._policy_profile}",
            f"- Block TTL: {self._block_ttl_sec // 60} minutes",
            f"- Network isolation: {'ON (ARP spoofing enabled)' if self._network_isolation_enabled else 'OFF (local firewall only)'}",
            f"- Local MAC: {self._mac_address or 'unknown'}",
            f"- Gateway IP: {self._gateway_ip or 'not found'}",
            f"- Allowlist entries: {len(self._allowlist.get('ips', []))} IP, {len(self._allowlist.get('macs', []))} MAC, {len(self._allowlist.get('hostnames', []))} host",
            "",
            "Advanced Threat Response:",
            "- Self-quarantine blocks the attacker only on this machine (no network-wide isolation).",
            f"- Auto-quarantine: {'ON' if self._quarantine_enabled else 'OFF'} (CRITICAL: {self._quarantine_critical_threshold}, Scans: {self._quarantine_scan_threshold}, Brute-force: {self._quarantine_bruteforce_threshold})",
            f"- Rate limiting: {'ON' if self._rate_limit_enabled else 'OFF'}",
            f"- Honeypot decoys: {'ON' if self._honeypot_enabled else 'OFF'}",
            f"- Network baseline: {'ON' if self._baseline_enabled else 'OFF'} (learned: {self._baseline_learned})",
            f"- Persistent threats tracked: {len(self._threat_database)}",
            f"- Detected anomalies: {len(self._anomalies)}",
            f"- Honeypot interactions: {len(self._honeypot_interactions)}",
            "",
            "Notes:",
            "- Missing tools are skipped during neutralization; fallback layers still run.",
            "- Best results: keep ufw/iptables or nft, ss, conntrack available.",
            "- Network isolation (ARP spoof) requires scapy and local network access.",
            f"- Action log path: {self._neutralize_log_path}",
            f"- Transaction history path: {self._neutralize_store_path}",
            f"- Threat database path: {self._threat_db_path}",
            f"- Allowlist path: {self._allowlist_path}",
        ])
        messagebox.showinfo("Response Tooling", "\n".join(lines))

    def _preflight_neutralization(self, t):
        src_ip = str(t.get("src_ip", "")).strip()
        if self._is_allowlisted(t):
            return False, "Threat source matched allowlist (IP/MAC/hostname)."
        if src_ip in self._local_ips:
            return False, "Source IP is a local interface address; neutralization blocked."
        if self._gateway_ip and src_ip == self._gateway_ip:
            return False, "Source IP is your default gateway; neutralization blocked."
        return True, "ok"

    def _dry_run_tx(self, t, mode):
        src_ip = t.get("src_ip", "")
        tx = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "threat_type": t.get("type", "Unknown"),
            "source_ip": src_ip,
            "mode": mode,
            "steps": [],
            "verify": [],
            "rollback": [],
            "status": "dry-run",
            "confidence": 0,
        }
        if mode in (NEUTRALIZE_SELF, NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL):
            tx["steps"].append({"step": "ufw deny", "ok": self._has_cmd("ufw"), "err": "(dry-run)"})
            tx["steps"].append({"step": "iptables drop", "ok": self._has_cmd("iptables"), "err": "(dry-run)"})
            tx["steps"].append({"step": "nft drop", "ok": self._has_cmd("nft"), "err": "(dry-run)"})
            tx["steps"].append({"step": "route blackhole", "ok": self._has_cmd("ip"), "err": "(dry-run)"})
        if mode in (NEUTRALIZE_KILL, NEUTRALIZE_BLOCKKILL):
            tx["steps"].append({"step": "ss kill", "ok": self._has_cmd("ss"), "err": "(dry-run)"})
            tx["steps"].append({"step": "conntrack delete", "ok": self._has_cmd("conntrack"), "err": "(dry-run)"})
            tx["steps"].append({"step": "pid fallback kill", "ok": True, "err": "(dry-run)"})
        return tx

    def _execute_neutralization(self, t, mode):
        src_ip = t.get("src_ip", "")
        tx = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "threat_type": t.get("type", "Unknown"),
            "source_ip": src_ip,
            "mode": mode,
            "steps": [],
            "verify": [],
            "rollback": [],
            "status": "failed",
        }

        block_ok = False
        kill_ok = False
        block_verified = False
        kill_verified = False

        if mode in (NEUTRALIZE_SELF, NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL):
            steps, block_ok, checks, block_verified = self._neutralize_block_ip(src_ip, tx)
            tx["steps"].extend([{"step": name, "ok": ok, "err": res.get("err", "")} for name, ok, res in steps])
            tx["verify"].extend([{"check": n, "ok": ok} for n, ok in checks])

        if mode in (NEUTRALIZE_KILL, NEUTRALIZE_BLOCKKILL):
            steps, kill_ok, checks, kill_verified = self._neutralize_kill_sessions(src_ip, tx)
            tx["steps"].extend([{"step": name, "ok": ok, "err": res.get("err", "")} for name, ok, res in steps])
            tx["verify"].extend([{"check": n, "ok": ok} for n, ok in checks])

        network_ok = False
        network_verified = False
        if self._network_isolation_enabled and mode in (NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL):
            steps, network_ok, checks, network_verified = self._neutralize_network_isolate_ip(src_ip, tx)
            tx["steps"].extend([{"step": name, "ok": ok, "err": res.get("err", "")} for name, ok, res in steps])
            tx["verify"].extend([{"check": n, "ok": ok} for n, ok in checks])

        requested = []
        if mode in (NEUTRALIZE_SELF, NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL):
            requested.append(("block", block_ok, block_verified))
        if mode in (NEUTRALIZE_KILL, NEUTRALIZE_BLOCKKILL):
            requested.append(("kill", kill_ok, kill_verified))

        if requested and all(v for _, _, v in requested):
            tx["status"] = "confirmed"
        elif any(ok for _, ok, _ in requested):
            tx["status"] = "partial"
        else:
            tx["status"] = "failed"

        check_total = len(tx.get("verify", []))
        check_ok = sum(1 for v in tx.get("verify", []) if v.get("ok"))
        action_total = len(tx.get("steps", []))
        action_ok = sum(1 for s in tx.get("steps", []) if s.get("ok"))
        confidence = 0
        if check_total:
            confidence += int((check_ok / check_total) * 70)
        if action_total:
            confidence += int((action_ok / action_total) * 30)
        tx["confidence"] = min(100, max(0, confidence))
        return tx

    def _finish_neutralization(self, tx):
        src_ip = tx.get("source_ip", "")
        if src_ip:
            self._queued_neutralizations.discard(src_ip)
        self._neutralize_history[src_ip].append(tx)
        self._log_neutralization(tx)
        self._persist_neutralization_tx(tx)
        self._register_block_ttl(tx)
        if tx.get("mode") in (NEUTRALIZE_SELF, NEUTRALIZE_BLOCK, NEUTRALIZE_BLOCKKILL) and tx.get("status") in ("confirmed", "partial"):
            self._record_successful_block(src_ip)
        self._append_response_log(
            f"{tx.get('status', 'unknown').upper()} {self._mode_label(tx.get('mode'))} for {src_ip} ({tx.get('confidence', 0)}% confidence)",
            self._response_log_tag_for_tx(tx),
            kind=self._response_log_kind_for_tx(tx),
            status=tx.get("status", "info"),
            details=self._tx_failure_details(tx),
        )

        summary = [
            f"Result: {tx['status'].upper()}",
            f"Threat: {tx['threat_type']}",
            f"Source IP: {src_ip}",
            f"Confidence: {tx.get('confidence', 0)}%",
            "",
            "Action Steps:",
        ]
        for s in tx.get("steps", []):
            state = "OK" if s.get("ok") else "FAIL"
            detail = f" ({str(s.get('err', ''))[:100]})" if s.get("err") else ""
            summary.append(f"  - {state}  {s.get('step', 'unknown')}{detail}")
        if tx.get("verify"):
            summary.append("\nVerification:")
            for v in tx["verify"]:
                state = "OK" if v.get("ok") else "FAIL"
                summary.append(f"  - {state}  {v.get('check', 'unknown')}")
        if self._running:
            self._set_status("● Monitoring", GREEN)
        else:
            self._set_status("● Idle", FG2)
        messagebox.showinfo("Threat Neutralization Complete", "\n".join(summary))

    def _neutralize_selected_threat(self, t, mode="policy"):
        if not t:
            messagebox.showwarning("No Threat", "No threat selected.")
            return
        src_ip = t.get("src_ip", "")
        if not self._valid_ip(src_ip):
            messagebox.showwarning("Neutralize Unavailable", f"Invalid source IP: {src_ip}")
            return

        resolved_mode = self._action_mode_for_threat(t) if mode == "policy" else mode
        if resolved_mode == NEUTRALIZE_NONE:
            messagebox.showinfo("No Neutralization", "This threat type is informational and has no automatic neutralization action.")
            return

        ok, reason = self._preflight_neutralization(t)
        if not ok:
            messagebox.showwarning("Neutralize Blocked", reason)
            return

        if not self._confirm_neutralize(t, resolved_mode):
            return

        if self._dry_run:
            self._finish_neutralization(self._dry_run_tx(t, resolved_mode))
            return

        self._queue_neutralization(t, resolved_mode, notify=True, origin="manual")

    def _rollback_neutralization_for_ip(self, src_ip):
        if not self._valid_ip(src_ip):
            messagebox.showwarning("Rollback Unavailable", f"Invalid source IP: {src_ip}")
            return
        history = self._neutralize_history.get(src_ip, [])
        if not history:
            messagebox.showinfo("No Rollback", f"No neutralization history for {src_ip} in this session.")
            return
        tx = history[-1]
        rollback_cmds = tx.get("rollback", [])
        if not rollback_cmds:
            messagebox.showinfo("No Rollback Data", "No rollback commands were recorded for the last neutralization.")
            return
        if not messagebox.askyesno("Confirm Rollback", f"Rollback latest neutralization for {src_ip}?"):
            return

        results = []
        for args in reversed(rollback_cmds):
            r = self._run_cmd(args)
            results.append((" ".join(args), r["ok"], r["err"]))

        rollback_tx = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "threat_type": tx.get("threat_type", "Unknown"),
            "source_ip": src_ip,
            "mode": "rollback",
            "status": "confirmed" if all(ok for _, ok, _ in results) else "partial",
            "steps": [{"step": cmd, "ok": ok, "err": err} for cmd, ok, err in results],
            "verify": [],
            "rollback": [],
        }
        self._neutralize_history[src_ip].append(rollback_tx)
        self._log_neutralization(rollback_tx)
        self._persist_neutralization_tx(rollback_tx)
        self._active_blocks.pop(src_ip, None)
        self._append_response_log(
            f"Manual rollback for {src_ip}: {rollback_tx['status'].upper()}",
            "warning" if rollback_tx["status"] == "partial" else "info",
            kind="rollback",
            status=rollback_tx["status"],
            details="\n".join(f"{cmd}: {err}" for cmd, ok, err in results if not ok),
        )

        lines = [f"Rollback result: {rollback_tx['status'].upper()}", f"Source IP: {src_ip}", ""]
        for cmd, ok, err in results:
            state = "OK" if ok else "FAIL"
            detail = f" ({err[:120]})" if err else ""
            lines.append(f"  - {state}  {cmd}{detail}")
        messagebox.showinfo("Rollback Complete", "\n".join(lines))

    def _threat_context_menu(self, event):
        iid = self._threat_tree.identify_row(event.y)
        if not iid:
            return
        self._threat_tree.selection_set(iid)
        vals = self._threat_tree.item(iid, "values")
        if not vals:
            return
        src_ip = vals[3]
        t      = self._get_threat_from_row(vals)
        src_mac = t["src_mac"] if t else "Unknown"
        menu = tk.Menu(self, tearoff=0, bg=BG2, fg=FG,
                       activebackground=BG3, activeforeground=CYAN, font=FONT_UI)
        menu.add_command(label=f"Copy IP  ({src_ip})",
                         command=lambda: self._copy(src_ip))
        menu.add_command(label=f"Copy MAC ({src_mac})",
                         command=lambda: self._copy(src_mac))
        menu.add_separator()
        menu.add_command(label=f"Copy block command:  sudo ufw deny from {src_ip}",
                         command=lambda: self._copy(f"sudo ufw deny from {src_ip}"))
        menu.add_separator()
        menu.add_command(label="Neutralize Threat (Recommended)",
                         command=lambda: self._neutralize_selected_threat(t, mode="policy"))
        menu.add_command(label="Self-Quarantine: This PC Only",
                 command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_SELF))
        menu.add_command(label="Neutralize: Block + Kill (Aggressive)",
                         command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_BLOCKKILL))
        menu.add_command(label="Neutralize: Block Only",
                         command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_BLOCK))
        menu.add_command(label="Neutralize: Kill Sessions Only",
                         command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_KILL))
        if self._network_isolation_enabled:
            menu.add_command(label="Neutralize: Network Isolate (ARP Spoof)",
                             command=lambda: self._neutralize_selected_threat(t, mode=NEUTRALIZE_NETWORK))
        menu.add_separator()
        menu.add_command(label="Rollback Last Neutralization (Source IP)",
                         command=lambda: self._rollback_neutralization_for_ip(src_ip))
        menu.tk_popup(event.x_root, event.y_root)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _notify_desktop(self, t):
        try:
            subprocess.Popen(
                ["notify-send", "--urgency=critical", "--expire-time=8000",
                 "--icon=/usr/share/icons/HighContrast/48x48/apps/config-firewall.png",
                 f"⚠ Network Sentinel: {t['type']}",
                 f"Source: {t['src_ip']}  ({t['hostname']})\n{t['what'][:120]}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def _clear_threats(self):
        self._threat_tree.delete(*self._threat_tree.get_children())
        self._threats.clear()
        self._tc = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
        self._sv_crit.set("0")
        self._sv_warn.set("0")
        self._sv_info.set("0")
        self._detail.config(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        self._detail.config(state=tk.DISABLED)

    def _export_threats(self):
        if not self._threats:
            messagebox.showinfo("Nothing to Export", "No threats recorded yet.")
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.expanduser(f"~/Documents/sentinel_threats_{ts}.txt")
        with open(path, "w") as f:
            f.write(f"Network Sentinel v2.0 — Threat Report  ({datetime.now()})\n")
            f.write("=" * 70 + "\n\n")
            for t in self._threats:
                f.write(f"[{t['level']}]  {t['type']}\n"
                        f"  Time      : {t['ts']}\n"
                        f"  Source IP : {t['src_ip']}\n"
                        f"  MAC Addr  : {t['src_mac']}\n"
                        f"  Hostname  : {t['hostname']}\n\n"
                        f"WHAT HAPPENED:\n{t['what']}\n\nCOURSE OF ACTION:\n")
                for step in t.get("action", []):
                    f.write(f"  {step}\n")
                f.write("\n" + "-" * 70 + "\n\n")
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("ERROR: scapy not found.  Fix:  pip install scapy")
        print("Then run:  sudo python3 sentinel.py")
        sys.exit(1)
    app = NetworkSentinel()
    app.mainloop()
