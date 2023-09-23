from bech32 import bech32_encode, bech32_decode, convertbits
from . import HRP_IDENTITY, IDENTITY_FORMAT_VERSION


def create_identity(credential_id, hidden_identity=False):
    return bech32_encode(
        HRP_IDENTITY,
        convertbits(
            IDENTITY_FORMAT_VERSION +
            (b'\xff' if hidden_identity else b'\x00') +
            credential_id,
            8, 5
        )
    ).upper()


def parse_identity(bech32: str):
    data = bytes(convertbits(bech32_decode(bech32)[1], 5, 8, pad=False))
    version = data[0]
    is_hidden_identity = data[1].to_bytes() == b'\xff'
    credential_id = bytes(data[2:])
    return version, is_hidden_identity, credential_id
