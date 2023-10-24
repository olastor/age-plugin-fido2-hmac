import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Tuple


def wrap_file_key(
    file_key: bytes,
    hmac_secret: bytes
) -> Tuple[bytes, bytes]:
    """Wrap a file key.

    Args:
        file_key (bytes): The file key provided by age.
        hmac_secret (bytes): The secret hmac output to be used as a wrapping key.

    Returns:
        Tuple[bytes, bytes]: The ciphertext and nonce.
    """
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
) -> bytes:
    """Unwrap a file key.

    Args:
        ciphertext (bytes): The ciphertext to decrypt.
        hmac_secret (bytes): The secret hmac output to be used as the unwrapping key.
        nonce (bytes): The nonce used for encryption.

    Returns:
        bytes: The plaintext file key.
    """
    cipher = ChaCha20Poly1305(hmac_secret)
    file_key = cipher.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=None
    )

    return file_key
