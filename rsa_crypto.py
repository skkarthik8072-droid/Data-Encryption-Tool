from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_key_pair():
    """Generate an RSA private key and corresponding public key."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    return private_key, public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_message(message: str, public_key) -> bytes:
    """Encrypt a short message using the RSA public key."""

    if not message:
        raise ValueError("Message cannot be empty.")

    plaintext = message.encode("utf-8")

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return ciphertext


def decrypt_message(ciphertext: bytes, private_key) -> str:
    """Decrypt an RSA-encrypted message using the RSA private key."""

    if not ciphertext:
        raise ValueError("Encrypted message cannot be empty.")

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return plaintext.decode("utf-8")