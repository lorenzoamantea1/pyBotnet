import socket
import threading
import logging
import uuid
import json
from cryptography.hazmat.primitives.asymmetric import padding
from .crypto import Crypto
from .logger import getLogger

class Controller:
    def __init__(self, nodes, debug=False, socket_timeout=1.5):
        """Initialize controller"""
        self.nodes = self._validate_nodes(nodes)
        self.debug = debug
        self.socket_timeout = socket_timeout
        self.running = False
        self.connections = {}
        self.connections_lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.logger = getLogger("Controller", debug)
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.load_rsa_keys()

    def _validate_nodes(self, nodes):
        """Validate node list format and content."""
        if not nodes or not all(isinstance(node, tuple) and len(node) == 2 and
                               isinstance(node[0], str) and isinstance(node[1], int)
                               for node in nodes):
            raise ValueError("Nodes must be a list of (host, port) tuples")
        return nodes

    def setup_sockets(self):
        self.logger.info("Setting up connections to all nodes")
        self.running = True
        for host, port in self.nodes:
            node_id = self._connect_and_authenticate_node(host, port)
            if node_id:
                threading.Thread(target=self._handle_connection, args=(node_id,), daemon=True).start()

    def _connect_and_authenticate_node(self, host, port):
        """Connect to a node, exchange keys, and authenticate."""
        client_socket = self._create_socket(host, port)
        if not client_socket:
            return None

        try:
            node_pubkey = self._receive_node_public_key(client_socket, host, port)
            if not node_pubkey:
                client_socket.close()
                return None

            if not self._send_controller_public_key(client_socket, host, port):
                client_socket.close()
                return None

            if not self._authenticate_controller(client_socket, host, port):
                client_socket.close()
                return None

            node_id = self._store_connection(client_socket, host, port, node_pubkey)
            self.logger.info(f"Connected to node {host}:{port} with ID {node_id}")
            return node_id

        except (socket.error, ValueError, json.JSONDecodeError) as e:
            self.logger.error(f"Unexpected error connecting to {host}:{port}: {type(e).__name__}: {e}")
            self._close_socket(client_socket, host, port)
            return None

    def _create_socket(self, host, port):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(self.socket_timeout)
            client_socket.connect((host, port))
            return client_socket
        except (socket.timeout, socket.gaierror, ConnectionError) as e:
            self.logger.error(f"Failed to connect to {host}:{port}: {type(e).__name__}: {e}")
            return None

    def _receive_node_public_key(self, client_socket, host, port):
        # Receive key length (2 bytes) followed by public key in PEM format
        key_len_bytes = self.receive_bytes(client_socket, 2)
        if not key_len_bytes:
            self.logger.error(f"Failed to receive public key length from {host}:{port}")
            return None

        key_len = int.from_bytes(key_len_bytes, 'big')
        node_pubkey_pem = self.receive_bytes(client_socket, key_len)
        if not node_pubkey_pem:
            self.logger.error(f"Failed to receive public key from {host}:{port}")
            return None

        return self.crypto.load_public_key(node_pubkey_pem)

    def _send_controller_public_key(self, client_socket, host, port):
        try:
            pubkey_pem = self.crypto.serialize_public_key(self.public_key)
            client_socket.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)
            return True
        except socket.error as e:
            self.logger.error(f"Failed to send public key to {host}:{port}: {type(e).__name__}: {e}")
            return False

    def _authenticate_controller(self, client_socket, host, port):
        # Send JSON payload with role and signature, expect success confirmation
        try:
            auth_msg = json.dumps({"role": "controller"}).encode()
            signature = self.crypto.sign(self.private_key, auth_msg)
            auth_payload = json.dumps({"role": "controller", "signature": signature.hex()}).encode()
            client_socket.send(len(auth_payload).to_bytes(2, 'big') + auth_payload)

            length_bytes = self.receive_bytes(client_socket, 2)
            if not length_bytes:
                self.logger.error(f"Failed to receive confirmation length from {host}:{port}")
                return False

            confirm_len = int.from_bytes(length_bytes, 'big')
            confirm_message = self.receive_bytes(client_socket, confirm_len)
            if not confirm_message:
                self.logger.error(f"Failed to receive confirmation message from {host}:{port}")
                return False

            confirm_data = json.loads(confirm_message.decode())
            if confirm_data.get("status") != "success":
                error_msg = confirm_data.get("message", "No error message provided")
                self.logger.error(f"Node {host}:{port} rejected connection: {error_msg}")
                return False

            return True
        except (json.JSONDecodeError, socket.error) as e:
            self.logger.error(f"Authentication failed for {host}:{port}: {type(e).__name__}: {e}")
            return False

    def _store_connection(self, client_socket, host, port, node_pubkey):
        node_id = str(uuid.uuid4())[:8]
        with self.connections_lock:
            self.connections[node_id] = {
                "socket": client_socket,
                "host": host,
                "port": port,
                "pubkey": node_pubkey,
                "uuid": node_id
            }
        return node_id

    def _close_socket(self, client_socket, host, port):
        if client_socket:
            try:
                client_socket.setblocking(False)
                client_socket.close()
            except socket.error as e:
                self.logger.warning(f"Failed to close socket for {host}:{port}: {type(e).__name__}: {e}")

    def _handle_connection(self, node_id):
        with self.connections_lock:
            if node_id not in self.connections:
                self.logger.error(f"Node {node_id} not found")
                return

        try:
            while self.running and not self.shutdown_event.is_set():
                self.shutdown_event.wait(1)
        except Exception as e:
            self.logger.error(f"Error in connection to node {node_id}: {type(e).__name__}: {e}")
        finally:
            self.disconnect_node(node_id)

    def disconnect_node(self, node_id):
        with self.connections_lock:
            if node_id not in self.connections:
                self.logger.warning(f"Node {node_id} not found for disconnection")
                return
            try:
                self.connections[node_id]["socket"].close()
            except socket.error as e:
                self.logger.warning(f"Failed to close socket for node {node_id}: {type(e).__name__}: {e}")
            del self.connections[node_id]
        self.logger.info(f"Disconnected node {node_id}")

    def shutdown(self):
        self.logger.info("Shutting down all node connections")
        self.running = False
        self.shutdown_event.set()
        with self.connections_lock:
            nodes = list(self.connections.items())
        for node_id, node_data in nodes:
            try:
                node_data["socket"].setblocking(False)
                node_data["socket"].close()
            except socket.error as e:
                self.logger.warning(f"Failed to close socket for node {node_id}: {e}")
            with self.connections_lock:
                if node_id in self.connections:
                    del self.connections[node_id]
        self.logger.info("All connections shut down")

    def send_to(self, node_id, message):
        try:
            with self.connections_lock:
                node_data = self.connections.get(node_id)
                if not node_data:
                    self.logger.error(f"Node {node_id} not connected")
                    return

            client_socket = node_data["socket"]
            message_bytes = message.encode()
            signature = self.crypto.sign(self.private_key, message_bytes)

            client_socket.send(len(message_bytes).to_bytes(2, 'big') + message_bytes)
            client_socket.send(len(signature).to_bytes(2, 'big') + signature)

            self.logger.info(f"Sent message to node {node_id}")
            self.logger.debug(message)

            return self.get_node_response(node_data)

        except socket.error as e:
            self.logger.error(f"Failed to send message to node {node_id}: {type(e).__name__}: {e}")
            return self.disconnect_node(node_id)

    def get_node_response(self, node_data):
        length_bytes = self.receive_bytes(node_data["socket"], 2)
        if not length_bytes:
            self.logger.info("Server closed connection")
            return None

        encrypted_session_key_len = int.from_bytes(length_bytes, 'big')
        if encrypted_session_key_len <= 0 or encrypted_session_key_len > 4096:
            self.logger.warning(f"Invalid session key length: {encrypted_session_key_len}")
            return None

        encrypted_session_key = self.receive_bytes(node_data["socket"], encrypted_session_key_len)
        if not encrypted_session_key:
            self.logger.warning("Failed to receive session key")
            return None

        # Receive encrypted message
        length_bytes = self.receive_bytes(node_data["socket"], 2)
        if not length_bytes:
            self.logger.warning("Failed to receive message length")
            return None

        encrypted_msg_len = int.from_bytes(length_bytes, 'big')
        if encrypted_msg_len <= 0 or encrypted_msg_len > 10 * 1024 * 1024:
            self.logger.warning(f"Invalid message length: {encrypted_msg_len}")
            return None

        encrypted_msg = self.receive_bytes(node_data["socket"], encrypted_msg_len)
        if not encrypted_msg:
            self.logger.warning("Failed to receive message")
            return None

        # Decrypt message
        try:
            session_key = self.crypto.rsa_decrypt(self.private_key, encrypted_session_key)
            message = self.crypto.aes_decrypt(session_key, encrypted_msg).decode()
        except Exception as e:
            self.logger.error(f"Decryption failed: {type(e).__name__}: {e}")
            return None

        self.logger.info(f"Received message from {node_data['uuid']}")
        return message

    def send_to_all(self, message):
        with self.connections_lock:
            nodes = list(self.connections.items())
        if not nodes:
            self.logger.warning("No nodes connected")
            return "No nodes connected", False

        self.logger.info(f"Sending message to {len(nodes)} nodes")

        responses = {}
        for node_id, _ in nodes:
            resp = self.send_to(node_id, message)
            if isinstance(resp, str):
                try:
                    responses[node_id] = json.loads(resp)
                except (json.JSONDecodeError, TypeError):
                    self.logger.warning(f"Invalid JSON response from node {node_id}: {resp}")
                    responses[node_id] = {"status": "error", "message": "invalid JSON response", "raw": str(resp)}
            else:
                responses[node_id] = {"status": "error", "message": "no response from node"}

        return responses, True

    def receive_bytes(self, sock, n, timeout=None):
        if timeout is not None:
            sock.settimeout(timeout)
        data = b''
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    self.logger.warning(f"Connection closed while receiving {n} bytes")
                    return None
                data += chunk
            except socket.timeout:
                return None
        return data

    def get_nodes(self):
        with self.connections_lock:
            return [(node_id, d["host"], d["port"]) for node_id, d in self.connections.items()]