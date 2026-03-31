import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .logger import getLogger

#  Crypto Class 
class Crypto:
    def __init__(self, debug=False):
        self.backend = default_backend()  # Backend for cryptography operations

        self.logger = getLogger("Cryptography", debug)

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
        self.logger.debug("Encrypting plaintext with AES-GCM (len=%d bytes)", len(plaintext))
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        self.logger.debug("AES-GCM encryption completed successfully")
        return nonce + ciphertext + encryptor.tag

    def aes_decrypt(self, key: bytes, data: bytes):
        self.logger.debug("Decrypting AES-GCM data (total length=%d bytes)", len(data))
        if len(data) < 28:
            raise ValueError("Invalid AES-GCM payload length")
        nonce = data[:12]
        tag = data[-16:]
        ciphertext = data[12:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.logger.debug("AES-GCM decryption completed successfully")
        return plaintext
