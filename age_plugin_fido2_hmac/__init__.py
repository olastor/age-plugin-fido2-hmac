from bech32 import bech32_encode, bech32_decode, convertbits

VERSION = '0.1.0'
PLUGIN_NAME = 'fido2-hmac'
HRP_IDENTITY = 'age-plugin-%s-' % (PLUGIN_NAME)
HRP_RECIPIENT = 'age1%s' % (PLUGIN_NAME)
RECIPIENT_FORMAT_VERSION = b'\x01'
IDENTITY_FORMAT_VERSION = b'\x01'
STANZA_FORMAT_VERSION = b'\x01'
FIDO2_RELYING_PARTY = 'age-encryption.org'
WAIT_FOR_DEVICE_TIMEOUT = 120

# => create_identity(bytes('fido2-hmac', 'utf-8'), False)
MAGIC_IDENTITY = 'AGE-PLUGIN-FIDO2-HMAC-1QYQXV6TYDUEZ66RDV93SQUSDAT'


def create_identity(credential_id):
    return bech32_encode(
        HRP_IDENTITY,
        convertbits(
            IDENTITY_FORMAT_VERSION +
            credential_id,
            8, 5
        )
    ).upper()


def create_recipient(credential_id):
    return bech32_encode(
        HRP_RECIPIENT,
        convertbits(
            RECIPIENT_FORMAT_VERSION +
            credential_id,
            8, 5
        )
    ).lower()


def parse_recipient_or_identity(bech32: str):
    data = bytes(convertbits(bech32_decode(bech32)[1], 5, 8, pad=False))
    version = data[0]
    credential_id = bytes(data[1:])
    return version, credential_id
