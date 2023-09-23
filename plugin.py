#!/usr/bin/env python3

import sys
import os
import argparse
from time import sleep
from fido2 import cose
from fido2.webauthn import UserVerificationRequirement
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, ClientError, UserInteraction
from getpass import getpass
from bech32 import bech32_decode, bech32_encode, convertbits
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VERSION = '0.1.0'
PLUGIN_NAME = 'fido2-hmac'
HRP_IDENTITY = 'age-plugin-%s-' % (PLUGIN_NAME)
IDENTITY_FORMAT_VERSION = b'\x01'
STANZA_FORMAT_VERSION = b'\x01'
FIDO2_RELYING_PARTY = 'example.com'
WAIT_FOR_DEVICE_TIMEOUT = 120

# => create_identity(bytes('fido2', 'utf-8'), False)
MAGIC_IDENTITY = 'AGE-PLUGIN-FIDO2-HMAC-1QYQXV6TYDUEQWRUADX'









