import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _validate_key(key: bytes) -> None:
    """Validate that the key is a 256-bit AES key."""
    if not isinstance(key, bytes):
        raise TypeError("AES key must be bytes.")

    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")


def encrypt_file(file_data: bytes, key: bytes) -> bytes:
    """
    Encrypt raw file bytes using AES-256-GCM.

    The returned data format is:

        nonce (12 bytes) + ciphertext + authentication tag

    Args:
        file_data: Original file content as bytes.
        key: 32-byte AES-256 key.

    Returns:
        Encrypted file data as bytes.
    """
    if not isinstance(file_data, bytes):
        raise TypeError("File data must be bytes.")

    if not file_data:
        raise ValueError("File is empty.")

    _validate_key(key)

    # AES-GCM recommends a 12-byte nonce.
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    # AESGCM automatically provides authentication/integrity protection.
    ciphertext = aesgcm.encrypt(
        nonce,
        file_data,
        None
    )

    # Store nonce together with ciphertext.
    # The nonce is not secret.
    return nonce + ciphertext


def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted file data.

    Args:
        encrypted_data: nonce + ciphertext + authentication tag.
        key: 32-byte AES-256 key.

    Returns:
        Original file bytes.
    """
    if not isinstance(encrypted_data, bytes):
        raise TypeError("Encrypted data must be bytes.")

    _validate_key(key)

    # 12-byte nonce + at least 16-byte GCM authentication tag.
    if len(encrypted_data) < 28:
        raise ValueError("Invalid encrypted file data.")

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(key)

    # If the encrypted data was modified or the wrong key is used,
    # AESGCM.decrypt() will raise an exception.
    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )