import socket
import requests

# ip-api.com free tier: no API key needed, ~45 requests/minute limit, HTTP (not HTTPS on free tier)
GEOLOCATION_API = "http://ip-api.com/json/{query}"
GEOLOCATION_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
PUBLIC_IP_API = "https://api.ipify.org?format=json"

REQUEST_TIMEOUT = 6

COUNTRY_FLAG_OFFSET = 127397  # converts 'A'-'Z' regional indicator to flag emoji pairs


def country_code_to_flag(code):
    if not code or len(code) != 2:
        return ""
    try:
        return "".join(chr(ord(c.upper()) + COUNTRY_FLAG_OFFSET) for c in code)
    except Exception:
        return ""


def get_public_ip():
    """Returns (ip_or_None, error_message_or_None)."""
    try:
        resp = requests.get(PUBLIC_IP_API, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("ip"), None
    except requests.exceptions.Timeout:
        return None, "Request timed out — check your internet connection"
    except requests.exceptions.ConnectionError:
        return None, "Could not connect — check your internet connection"
    except requests.exceptions.RequestException as e:
        return None, f"Request failed: {e}"


def resolve_to_ip(target):
    """Accepts an IP or hostname; returns (ip, error). Pure local resolution, no API call."""
    target = target.strip()
    try:
        socket.inet_aton(target)
        return target, None  # already a valid IPv4
    except OSError:
        pass
    try:
        return socket.gethostbyname(target), None
    except socket.gaierror:
        return None, f"Could not resolve '{target}' — check the address and try again"


def reverse_dns(ip):
    """Best-effort local reverse DNS lookup. Returns hostname or None (never raises)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def lookup_ip(target):
    """
    Full lookup pipeline: resolve hostname if needed, query geolocation API,
    attempt reverse DNS. Returns a result dict, always with an 'error' key
    (None if successful) so the caller never needs to catch exceptions.
    """
    ip, resolve_error = resolve_to_ip(target)
    if resolve_error:
        return {"error": resolve_error}

    url = GEOLOCATION_API.format(query=ip)
    try:
        resp = requests.get(url, params={"fields": GEOLOCATION_FIELDS}, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        return {"error": "Geolocation lookup timed out — check your internet connection"}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to the geolocation service — check your internet connection"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Geolocation lookup failed: {e}"}

    if resp.status_code == 429:
        return {"error": "Rate limit reached (free tier allows ~45 requests/minute) — wait a moment and try again"}
    if resp.status_code != 200:
        return {"error": f"Geolocation service returned an unexpected status ({resp.status_code})"}

    try:
        data = resp.json()
    except ValueError:
        return {"error": "Geolocation service returned an unreadable response"}

    if data.get("status") != "success":
        return {"error": data.get("message", "Lookup failed for this address")}

    hostname = reverse_dns(ip)

    return {
        "error": None,
        "query": data.get("query", ip),
        "original_input": target,
        "country": data.get("country", "Unknown"),
        "country_code": data.get("countryCode", ""),
        "flag": country_code_to_flag(data.get("countryCode", "")),
        "region": data.get("regionName", "Unknown"),
        "city": data.get("city", "Unknown"),
        "zip": data.get("zip", ""),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "org": data.get("org", ""),
        "as_info": data.get("as", ""),
        "hostname": hostname or "(no reverse DNS record)",
    }