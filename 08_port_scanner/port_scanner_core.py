import socket
import concurrent.futures
import queue
from datetime import datetime

# A curated set of commonly-scanned ports (mirrors the spirit of Nmap's "top ports" idea,
# scaled down to a reasonable set for a portfolio tool)
TOP_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888, 9000, 9090,
    27017, 6379, 5432, 25565, 1521, 2049, 111, 161, 162, 389, 636, 5000
}

FALLBACK_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP (submission)",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8000: "HTTP-alt", 8888: "HTTP-alt", 9000: "HTTP-alt",
    27017: "MongoDB", 25565: "Minecraft", 1521: "Oracle DB", 2049: "NFS",
}


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return FALLBACK_SERVICE_NAMES.get(port, "Unknown")


def resolve_target(host):
    """Resolves a hostname or validates an IP. Raises ValueError with a clear message on failure."""
    try:
        return socket.gethostbyname(host.strip())
    except socket.gaierror:
        raise ValueError(f"Could not resolve host '{host}' — check the address and try again")


def parse_port_range(text):
    """
    Accepts: 'common' / 'top' for the curated common-port set,
    '1-1024' for a range, '22,80,443' for a list, or a mix: '22,80,1000-1010'
    """
    text = text.strip().lower()
    if text in ("common", "top", "top-ports", ""):
        return sorted(TOP_PORTS)

    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_s, end_s = part.split("-")
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"Invalid range: '{part}'")
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: '{part}' (must be within 1-65535)")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} is out of valid range (1-65535)")
            ports.add(p)

    if not ports:
        raise ValueError("No valid ports specified")
    return sorted(ports)


def grab_banner(ip, port, timeout=1.5):
    """
    Attempts to read a service banner. Some services (FTP, SSH, SMTP) announce
    themselves immediately on connect; web servers need a request sent first.
    Returns a short string, or None if nothing could be read.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in (80, 8080, 8000, 8888, 9000, 9090):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass

            data = sock.recv(256)
            if data:
                text = data.decode(errors="ignore").strip()
                return text.splitlines()[0][:100] if text else None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    return None


def scan_port(ip, port, timeout, grab_banners=False):
    """Returns a dict with the scan result for a single port. Never raises."""
    result = {"port": port, "is_open": False, "service": get_service_name(port), "banner": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((ip, port))
            if code == 0:
                result["is_open"] = True
    except OSError:
        pass

    if result["is_open"] and grab_banners:
        result["banner"] = grab_banner(ip, port, timeout=min(timeout, 1.5))

    return result


def scan_ports_threaded(ip, ports, timeout=1.0, max_workers=100, grab_banners=False,
                          result_queue=None, stop_event=None):
    """
    Scans all given ports concurrently. If result_queue is provided, pushes each
    result onto it as it completes (for live GUI updates). Returns the full list too.
    Respects stop_event for cancellation.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout, grab_banners): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            if stop_event is not None and stop_event.is_set():
                break
            result = future.result()
            results.append(result)
            if result_queue is not None:
                result_queue.put(result)
    return results