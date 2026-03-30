import os
import logging
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from .logger import getLogger

#  Crypto Class 
class Crypto:
    def __init__(self, debug=False):
        self.backend = default_backend()  # Backend for cryptography operations

        self.logger = getLogger("Crypto",debug)

        self.logger.debug("Crypto module initialized (debug=%s)", debug)

    #  RSA Key Generation 
    def generate_rsa_keys(self, key_size=2048):
        self.logger.debug("Generating RSA key pair with key_size=%d", key_size)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        self.logger.debug("RSA key pair generated successfully")
        return private_key, public_key

    #  Serialize keys 
    def serialize_private_key(self, private_key):
        self.logger.debug("Serializing private key to PEM format")
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_public_key(self, public_key):
        self.logger.debug("Serializing public key to PEM format")
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    #  Load keys from PEM 
    def load_private_key(self, pem_data):
        self.logger.debug("Loading private key from PEM data")
        return serialization.load_pem_private_key(pem_data, password=None)

    def load_public_key(self, pem_data):
        self.logger.debug("Loading public key from PEM data")
        return serialization.load_pem_public_key(pem_data)

    # Load RSA keys from files
    def load_rsa_keys(self):
        keys_path = Path("data/keys")
        keys_path.mkdir(parents=True, exist_ok=True)

        pub_path = keys_path / "pub.key"
        priv_path = keys_path / "priv.key"

        try:
            with pub_path.open("rb") as f:
                pub = self.load_public_key(f.read())
            with priv_path.open("rb") as f:
                priv = self.load_private_key(f.read())
            self.logger.debug("Loaded existing RSA keys")
        except (FileNotFoundError, ValueError, OSError) as e:
            self.logger.warning(f"Failed to load existing keys ({e}), generating new keys")
            priv, pub = self.generate_rsa_keys()
            with pub_path.open("wb") as f:
                f.write(self.serialize_public_key(pub))
            with priv_path.open("wb") as f:
                f.write(self.serialize_private_key(priv))
            try:
                os.chmod(pub_path, 0o600)
                os.chmod(priv_path, 0o600)
            except OSError:
                self.logger.warning("Could not set key file permissions")

        return priv, pub
        
    #  Sign and Verify 
    def sign(self, private_key, message):
        self.logger.debug("Signing message with RSA private key (%d bytes)", len(message))
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    #  RSA Encryption / Decryption 
    def rsa_encrypt(self, public_key, message: bytes) -> bytes:
        self.logger.debug("Encrypting message with RSA public key (%d bytes)", len(message))
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, private_key, ciphertext: bytes) -> bytes:
        self.logger.debug("Decrypting RSA ciphertext (%d bytes)", len(ciphertext))
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    #  AES Symmetric Encryption 
    def generate_aes_key(self, length=32):
        self.logger.debug("Generating AES key (length=%d bytes)", length)
        return os.urandom(length)  # Generate random AES key

    def aes_encrypt(self, key: bytes, plaintext: bytes):
        self.logger.debug("Encrypting plaintext with AES (len=%d bytes)", len(plaintext))
        iv = os.urandom(16)  # Random IV for CBC mode
        padder = sym_padding.PKCS7(128).padder()  # Pad plaintext to block size
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        self.logger.debug("AES encryption completed successfully")
        return iv + ciphertext  # Return IV + ciphertext

    def aes_decrypt(self, key: bytes, data: bytes):
        self.logger.debug("Decrypting AES data (total length=%d bytes)", len(data))
        iv = data[:16]  # Extract IV
        ciphertext = data[16:]  # Extract ciphertext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        self.logger.debug("AES decryption completed successfully")
        return plaintext
