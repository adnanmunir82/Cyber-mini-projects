from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP, Ether
from datetime import datetime

PROTOCOL_NAMES = {
    "TCP": "TCP",
    "UDP": "UDP",
    "ICMP": "ICMP",
    "ARP": "ARP",
}


def list_interfaces():
    """Returns available network interfaces for the user to choose from."""
    try:
        return get_if_list()
    except Exception:
        return []


def parse_packet(packet):
    """
    Converts a scapy packet into a clean, human-readable summary dict.
    Never raises — unparseable/unusual packets fall back to a generic 'Other' entry.
    """
    info = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src": "-",
        "dst": "-",
        "protocol": "Other",
        "src_port": "-",
        "dst_port": "-",
        "size": len(packet),
        "summary": packet.summary(),
    }

    try:
        if packet.haslayer(ARP):
            arp = packet[ARP]
            info["protocol"] = "ARP"
            info["src"] = arp.psrc
            info["dst"] = arp.pdst
            return info

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            info["src"] = ip_layer.src
            info["dst"] = ip_layer.dst

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info["protocol"] = "TCP"
                info["src_port"] = tcp.sport
                info["dst_port"] = tcp.dport
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info["protocol"] = "UDP"
                info["src_port"] = udp.sport
                info["dst_port"] = udp.dport
            elif packet.haslayer(ICMP):
                info["protocol"] = "ICMP"
            else:
                info["protocol"] = f"IP-proto-{ip_layer.proto}"
        elif packet.haslayer(Ether):
            info["protocol"] = "Ethernet (non-IP)"
    except Exception:
        pass  # keep the safe defaults already set above

    return info


def get_layer_breakdown(packet):
    """Returns a multi-line string showing each protocol layer for the detail inspector."""
    lines = []
    layer = packet
    while layer:
        lines.append(f"--- {layer.name} ---")
        lines.append(layer.show(dump=True).strip())
        layer = layer.payload if hasattr(layer, "payload") and layer.payload else None
        if layer.__class__.__name__ == "NoPayload":
            break
    return "\n".join(lines) if lines else packet.show(dump=True)


def build_bpf_filter(protocol_filter, ip_filter):
    """
    Builds a BPF (Berkeley Packet Filter) string from user-selected options.
    protocol_filter: 'All', 'TCP', 'UDP', 'ICMP', or 'ARP'
    ip_filter: optional IP string to restrict to, or empty for no restriction
    """
    parts = []
    if protocol_filter and protocol_filter.lower() != "all":
        parts.append(protocol_filter.lower())
    if ip_filter:
        parts.append(f"host {ip_filter}")
    return " and ".join(parts) if parts else ""


def capture_packets(interface, count, timeout, bpf_filter, on_packet, on_error=None):
    """
    Blocking call intended to run on a background thread.
    on_packet(raw_packet) is invoked for each captured packet.
    on_error(message) is invoked if capture fails outright (e.g. missing driver,
    insufficient permissions) so the GUI can show a clear message instead of hanging.
    """
    kwargs = {"prn": on_packet, "store": False}
    if interface:
        kwargs["iface"] = interface
    if count and count > 0:
        kwargs["count"] = count
    if timeout and timeout > 0:
        kwargs["timeout"] = timeout
    if bpf_filter:
        kwargs["filter"] = bpf_filter

    try:
        sniff(**kwargs)
    except Exception as e:
        # Retry once without the filter, in case the filter engine itself is the problem
        if bpf_filter and on_error:
            try:
                kwargs.pop("filter", None)
                on_error(f"Filter unavailable ({e}); capturing without filter instead")
                sniff(**kwargs)
                return
            except Exception as e2:
                if on_error:
                    on_error(f"Capture failed: {e2}")
                return
        if on_error:
            on_error(f"Capture failed: {e}")