from struct import pack, unpack
from bech32 import bech32_encode, bech32_decode, convertbits
from typing import Tuple

VERSION = '0.1.0'
PLUGIN_NAME = 'fido2-hmac'
HRP_IDENTITY = 'age-plugin-%s-' % (PLUGIN_NAME)
HRP_RECIPIENT = 'age1%s' % (PLUGIN_NAME)
RECIPIENT_FORMAT_VERSION = 1
IDENTITY_FORMAT_VERSION = 1
FIDO2_RELYING_PARTY = 'age-encryption.org'
WAIT_FOR_DEVICE_TIMEOUT = 120

# => bech32_encode(HRP_IDENTITY, convertbits(PLUGIN_NAME.encode('utf-8'), 8, 5)).upper()
MAGIC_IDENTITY = 'AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76'


def create_identity(credential_id: bytes, require_pin: bool): str:
    """Create an new identity for a specific fido2 credential.

    Args:
        credential_id (bytes): The credential ID of a non-discoverable fido2 credential.
        require_pin (bool): Whether or not to require user verification via pin for encryption/decryption.

    Returns:
        str: A valid Bech32-encoded identity.
    """
    return bech32_encode(
        HRP_IDENTITY,
        convertbits(
            pack('>H', IDENTITY_FORMAT_VERSION) +
            pack('?', require_pin) +
            bytes(credential_id),
            8, 5
        )
    ).upper()


def create_recipient(credential_id: bytes, require_pin: bool) -> str:
    """Create an new recipient for a specific fido2 credential.

    Args:
        credential_id (bytes): The credential ID of a non-discoverable fido2 credential.
        require_pin (bool): Whether or not to require user verification via pin for encryption/decryption.

    Returns:
        str: A valid Bech32-encoded recipient.
    """
    return bech32_encode(
        HRP_RECIPIENT,
        convertbits(
            pack('>H', IDENTITY_FORMAT_VERSION) +
            pack('?', require_pin) +
            bytes(credential_id),
            8, 5
        )
    ).lower()


def parse_recipient_or_identity(bech32: str) -> Tuple[int, bool, bytes]:
    """Parses a recipient or identity.

    Args:
        bech32 (str): A valid recipient or identity string.

    Raises:
        Exception: Version not supported.

    Returns:
        Tuple[int, bool, bytes]: The format version, pin flag and credential ID.
    """
    data = bytes(convertbits(bech32_decode(bech32)[1], 5, 8, pad=False))

    version = unpack('>H', data[0:2])

    if version[0] == 1:
        require_pin = unpack('?', data[2:3])
        cred_id = data[3:]

        return version[0], require_pin[0], cred_id

    raise Exception('Unsupported version!')
