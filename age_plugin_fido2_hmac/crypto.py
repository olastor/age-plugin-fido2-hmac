import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def wrap_file_key(
    file_key: bytes,
    hmac_secret: bytes
):
    cipher = ChaCha20Poly1305(hmac_secret)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(
        nonce=nonce,
        data=file_key,
        associated_data=None
    )

    return ciphertext, nonce


def unwrap_file_key(
    ciphertext: bytes,
    hmac_secret: bytes,
    nonce: bytes
):
    cipher = ChaCha20Poly1305(hmac_secret)
    file_key = cipher.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=None
    )

    return file_key
