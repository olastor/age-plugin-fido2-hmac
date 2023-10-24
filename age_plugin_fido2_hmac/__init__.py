from struct import pack, unpack
from bech32 import bech32_encode, bech32_decode, convertbits

VERSION = '0.1.0'
PLUGIN_NAME = 'fido2-hmac'
HRP_IDENTITY = 'age-plugin-%s-' % (PLUGIN_NAME)
HRP_RECIPIENT = 'age1%s' % (PLUGIN_NAME)
RECIPIENT_FORMAT_VERSION = 1
IDENTITY_FORMAT_VERSION = 1
STANZA_FORMAT_VERSION = 1
FIDO2_RELYING_PARTY = 'age-encryption.org'
WAIT_FOR_DEVICE_TIMEOUT = 120

# => create_identity(bytes('fido2-hmac', 'utf-8'), False)
MAGIC_IDENTITY = 'AGE-PLUGIN-FIDO2-HMAC-1QYQXV6TYDUEZ66RDV93SQUSDAT'


def create_identity(credential_id: bytes, require_pin: bool):
    return bech32_encode(
        HRP_IDENTITY,
        convertbits(
            pack('>H', IDENTITY_FORMAT_VERSION) +
            pack('?', require_pin) +
            bytes(credential_id),
            8, 5
        )
    ).upper()


def create_recipient(credential_id: bytes, require_pin: bool):
    return bech32_encode(
        HRP_RECIPIENT,
        convertbits(
            pack('>H', IDENTITY_FORMAT_VERSION) +
            pack('?', require_pin) +
            bytes(credential_id),
            8, 5
        )
    ).lower()


def parse_recipient_or_identity(bech32: str):
    data = bytes(convertbits(bech32_decode(bech32)[1], 5, 8, pad=False))

    version = unpack('>H', data[0:2])

    if version[0] == 1:
        require_pin = unpack('?', data[2:3])
        cred_id = data[3:]

        return version[0], require_pin[0], cred_id

    raise Exception('Unsupported version!')
