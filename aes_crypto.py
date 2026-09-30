import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key() -> bytes:
    """Generate a secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a secure 256-bit AES key from a password."""

    if not password:
        raise ValueError("Password cannot be empty.")

    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_message(message: str, key: bytes) -> bytes:
    """Encrypt a text message using AES-256-GCM."""

    if not message:
        raise ValueError("Message cannot be empty.")

    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    aes = AESGCM(key)

    # Generate a new random 12-byte nonce
    nonce = os.urandom(12)

    plaintext = message.encode("utf-8")

    # Encrypt the message
    ciphertext = aes.encrypt(nonce, plaintext, None)

    # Store nonce + ciphertext together
    return nonce + ciphertext


def decrypt_message(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt an AES-256-GCM encrypted message."""

    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    if len(encrypted_data) < 13:
        raise ValueError("Invalid encrypted data.")

    aes = AESGCM(key)

    # Extract nonce
    nonce = encrypted_data[:12]

    # Extract encrypted message
    ciphertext = encrypted_data[12:]

    # Decrypt and verify integrity
    plaintext = aes.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")