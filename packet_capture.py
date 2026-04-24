# ============================================================
#  ThreatPulse AI – packet_capture.py
#  Captures live packets from your Windows network interface
# ============================================================

from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from datetime import datetime
import threading
import queue
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CAPTURE] %(message)s")
logger = logging.getLogger(__name__)

# Shared queue – capture thread puts packets, ML thread reads them
packet_queue = queue.Queue(maxsize=10000)


def list_interfaces():
    """Print all available network interfaces so user can pick the right one."""
    print("\n=== Available Network Interfaces ===")
    for i, iface in enumerate(get_if_list()):
        print(f"  [{i}] {iface}")
    print("=====================================\n")


def parse_packet(pkt):
    """
    Convert a raw Scapy packet into a clean Python dict
    with all the fields we need for ML feature extraction.
    """
    record = {
        "timestamp":    datetime.utcnow().isoformat(),
        "src_ip":       None,
        "dst_ip":       None,
        "src_port":     None,
        "dst_port":     None,
        "protocol":     "OTHER",
        "packet_size":  len(pkt),
        "ttl":          None,
        "tcp_flags":    None,
        "http_method":  None,
        "http_host":    None,
        "http_path":    None,
        "icmp_type":    None,
        "raw_summary":  pkt.summary(),
    }

    # ── IP layer ──────────────────────────────────────────
    if pkt.haslayer(IP):
        record["src_ip"] = pkt[IP].src
        record["dst_ip"] = pkt[IP].dst
        record["ttl"]    = pkt[IP].ttl

    # ── TCP ───────────────────────────────────────────────
    if pkt.haslayer(TCP):
        record["protocol"] = "TCP"
        record["src_port"] = pkt[TCP].sport
        record["dst_port"] = pkt[TCP].dport
        # Convert flags integer to readable string e.g. "SA", "PA", "F"
        flags = pkt[TCP].flags
        flag_str = ""
        if flags & 0x01: flag_str += "F"   # FIN
        if flags & 0x02: flag_str += "S"   # SYN
        if flags & 0x04: flag_str += "R"   # RST
        if flags & 0x08: flag_str += "P"   # PSH
        if flags & 0x10: flag_str += "A"   # ACK
        if flags & 0x20: flag_str += "U"   # URG
        record["tcp_flags"] = flag_str if flag_str else "NONE"

    # ── UDP ───────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        record["protocol"] = "UDP"
        record["src_port"] = pkt[UDP].sport
        record["dst_port"] = pkt[UDP].dport

    # ── ICMP ──────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        record["protocol"]  = "ICMP"
        record["icmp_type"] = pkt[ICMP].type

    # ── HTTP (unencrypted, port 80) ───────────────────────
    if pkt.haslayer(HTTPRequest):
        record["protocol"]    = "HTTP"
        try:
            record["http_method"] = pkt[HTTPRequest].Method.decode()
            record["http_host"]   = pkt[HTTPRequest].Host.decode()
            record["http_path"]   = pkt[HTTPRequest].Path.decode()
        except Exception:
            pass

    return record


def _packet_callback(pkt):
    """Called by Scapy for every captured packet."""
    try:
        record = parse_packet(pkt)
        packet_queue.put_nowait(record)
    except queue.Full:
        pass   # drop oldest if queue is full – keeps system stable
    except Exception as e:
        logger.warning(f"Parse error: {e}")


def start_capture(iface=None, packet_filter="ip", stop_event=None):
    """
    Start live packet capture in the current thread.

    Parameters
    ----------
    iface        : str  – network interface name (None = Scapy auto-picks)
    packet_filter: str  – BPF filter string  e.g. "tcp", "udp", "ip"
    stop_event   : threading.Event – set this to stop capturing gracefully
    """
    logger.info(f"Starting capture on interface: {iface or 'auto'}")
    logger.info(f"Filter: {packet_filter}")
    logger.info("Press Ctrl+C to stop.\n")

    def stop_filter(_):
        return stop_event.is_set() if stop_event else False

    sniff(
        iface=iface,
        filter=packet_filter,
        prn=_packet_callback,
        store=False,           # don't buffer in memory
        stop_filter=stop_filter,
    )


def start_capture_thread(iface=None, packet_filter="ip"):
    """
    Launch capture in a background daemon thread.
    Returns (thread, stop_event) so caller can stop it later.
    """
    stop_event = threading.Event()
    t = threading.Thread(
        target=start_capture,
        args=(iface, packet_filter, stop_event),
        daemon=True,
        name="PacketCaptureThread",
    )
    t.start()
    logger.info("Capture thread started.")
    return t, stop_event


# ── Quick test ────────────────────────────────────────────
if __name__ == "__main__":
    list_interfaces()
    print("Capturing 20 packets as a test...\n")

    stop = threading.Event()
    thread, stop = start_capture_thread(iface=None, packet_filter="ip")

    import time
    time.sleep(10)
    stop.set()

    print(f"\nCaptured {packet_queue.qsize()} packets in queue.")
    while not packet_queue.empty():
        p = packet_queue.get()
        print(f"  {p['timestamp']}  {p['protocol']:6s}  {p['src_ip']} → {p['dst_ip']}  size={p['packet_size']}")
