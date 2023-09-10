#!/usr/bin/env python3

import sys
import os
import argparse
import logging

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, ClientError, UserInteraction
from getpass import getpass
from bech32 import bech32_decode, bech32_encode, convertbits
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PLUGIN_NAME = 'fido2-hmac'
HRP_IDENTITY = 'age-plugin-%s-' % (PLUGIN_NAME)
IDENTITY_FORMAT_VERSION = b'\x01'
STANZA_FORMAT_VERSION = b'\x01'
FIDO2_RELYING_PARTY = 'example.com'


def send_command(command, metadata = [], data: str = ''):
    message = '-> %s%s%s\n' % (
        command,
        ' %s' % (' '.join(metadata)) if len(metadata) > 0 else '',
        '\n' + b64encode_no_padding(data) if data else ''
    )
    open('/home/sebastian/Dokumente/Code/age-plugin-fido2-hmac/log', 'a').write(message)

    sys.stdout.write(message)
    sys.stdout.flush()

    open('/home/sebastian/Dokumente/Code/age-plugin-fido2-hmac/log', 'a').write('hererher')


def handle_incoming_data(handlers):
    current_command = None
    current_metadata = []
    expected_data_lines = None

    open('/home/sebastian/Dokumente/Code/age-plugin-fido2-hmac/lines', 'w').write('')
    for line in sys.stdin:
        open('/home/sebastian/Dokumente/Code/age-plugin-fido2-hmac/lines', 'a').write(line)

        line = line.strip()

        if not line:
            continue

        if line.startswith('->'):
            assert expected_data_lines is None or expected_data_lines <= 0

            splitted = line[3:].split(' ')
            current_command = splitted[0].strip()
            current_metadata = splitted[1:]

        if current_command in handlers:
            if 'data-lines' in handlers[current_command] and handlers[current_command]['data-lines'] > 0:
                if line.startswith('->'):
                    # first time, remember for next lines
                    expected_data_lines = handlers[current_command]['data-lines']
                elif expected_data_lines > 0:
                    # call callback for each line individually
                    handlers[current_command]['callback'](current_metadata, line)
                    expected_data_lines = expected_data_lines - 1
            elif 'callback' in handlers[current_command]:
                handlers[current_command]['callback'](current_metadata, None)

            if expected_data_lines is None or expected_data_lines == 0:
                if 'exit' in handlers[current_command] and handlers[current_command]['exit']:
                    break

                current_command = None
                current_metadata = []
                expected_data_lines = None


def recipient_v1_phase1():
    identities = []
    file_key = ''

    def file_key_callback(metadata, data):
        nonlocal file_key
        file_key = data

    handle_incoming_data({
        'add-identity': {
            'data-lines': 0,
            'callback': lambda metadata, data: identities.append(metadata[0])
        },
        'wrap-file-key': {
            'data-lines': 1,
            'callback': file_key_callback
        },
        'done': {
            'exit': True
        }
    })

    recipient_v1_phase2(identities, file_key)


def get_hmac_plugin(credential_id, salt):
    for dev in list(CtapHidDevice.list_devices()):
        try:
            return fido2_hmac_challenge(dev, credential_id, salt, PluginInteraction())
        except ClientError as e:
            if e.code == ClientError.ERR.DEVICE_INELIGIBLE:
                pass
            else:
                send_command('error', ['identity', str(i)], 'Something went wrong!')
        except:
            send_command('error', ['identity', str(i)], 'Unknown Error!')


def b64encode_no_padding(s):
    return b64encode(s.encode('utf-8') if type(s) == str else s).decode('utf-8').replace('=', '')


def b64decode_no_padding(s: str):
    if len(s) % 4 == 0:
        return b64decode(s)
    else:
        padding_length = ((len(s) // 4) + 1) * 4 - len(s)
        return b64decode(s + ('=' * padding_length))


def recipient_v1_phase2(identities, wrap_file_key: str):
    for i, identity in enumerate(identities):
        try:
            version, is_hidden_identity, credential_id = parse_identity(identity)
        except:
            send_command('error', ['identity', str(i)], 'Failed to parse identity!')

        if version != int.from_bytes(IDENTITY_FORMAT_VERSION):
            send_command('error', ['identity', str(i)], 'Unsupported version number!')

        salt = os.urandom(32)
        hmac_secret = get_hmac_plugin(credential_id, salt)

        cipher = ChaCha20Poly1305(hmac_secret)
        nonce = os.urandom(12)

        encrypted_wrap_key = cipher.encrypt(
            nonce=nonce,
            data=b64decode_no_padding(wrap_file_key),
            associated_data=None
        )

        send_command(
            'recipient-stanza', [
                str(i),
                PLUGIN_NAME,
                b64encode_no_padding(salt),
                b64encode_no_padding(nonce)
            ] + (
                [b64encode_no_padding(credential_id)]
                if not is_hidden_identity else []
            ),
            encrypted_wrap_key
        )
        handle_incoming_data({
            'ok': {
                'exit': True
            }
        })

    send_command('done\n', [], None)


def fido2_hmac_challenge(device, credential_id, salt, user_interaction):
    challenge = b"Q0hBTExFTkdF"  # Use a new challenge for each call.
    allow_list = [{"type": "public-key", "id": credential_id}]

    # Prepare parameters for makeCredential
    rp = { 'id': FIDO2_RELYING_PARTY }
    challenge = b"Y2hhbGxlbmdl"


    # uv = "discouraged"

    # # Set up a FIDO 2 client using the origin https://example.com
    # client = Fido2Client(dev, "https://example.com", user_interaction=CliInteraction())

    # # Prefer UV if supported and configured
    # if client.info.options.get("uv") or client.info.options.get("pinUvAuthToken"):
    #     uv = "preferred"
    #     print("Authenticator supports User Verification")


    client = Fido2Client(device, FIDO2_RELYING_PARTY, user_interaction=user_interaction)

    # Authenticate the credential
    result = client.get_assertion(
        {
            "rpId": rp["id"],
            "challenge": challenge,
            "allowCredentials": allow_list,
            "extensions": {"hmacGetSecret": {"salt1": salt}},
        },
    ).get_response(0)

    return result.extension_results["hmacGetSecret"]["output1"]
    # print(output1)
    # print("Authenticated, secret:", output1.hex())



class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


class PluginInteraction(UserInteraction):
    def prompt_up(self):
        send_command('msg', [], 'Please touch your authenticator now...')
        handle_incoming_data({
            'ok': {
                'exit': True
            }
        })

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

def generate_new_credential(device):
    cli_interaction = CliInteraction()
    FIDO2_RELYING_PARTY = "https://example.com"
    client = Fido2Client(device, FIDO2_RELYING_PARTY, user_interaction=cli_interaction)
    rp = {'id': FIDO2_RELYING_PARTY, 'name': 'age'}
    user = {'id': os.urandom(8), 'name': 'adf'}
    rp = {"id": "example.com", "name": "Example RP"}
    user = {"id": b"user_id", "name": "A. User"}
    challenge = b"Y2hhbGxlbmdl"

    result = client.make_credential(
        {
            "rp": rp,
            "user": user,
            "challenge": os.urandom(12),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        },
    )

    return result.attestation_object.auth_data.credential_data.credential_id


def chose_device_interactively():
    # TODO: WindowsClient
    # TODO: NFC/CtapPcscDevice
    devs = [
        (dev, '%s (path=%s, serial=%s)' % (dev.product_name, dev.descriptor.path, dev.serial_number))
        for dev in CtapHidDevice.list_devices()
    ]

    if len(devs) == 0:
        return None

    if len(devs) == 1:
        return devs[0][0]

    for i, (dev, info) in enumerate(devs):
        print('[%i]: %s' % (i, info))

    input_index = int(input("Enter device: ").strip())

    if input_index < 0 or input_index >= len(devs):
        raise 'Invalid device index'

    if input('You have selected: %s. Confirm? [yY]' % (devs[input_index][1])).lower().strip() != 'y':
        raise 'Failed confirmation'

    return devs[input_index][0]

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='ProgramName',
        description='What the program does',
        epilog='Text at the bottom of help'
    )

    parser.add_argument('--age-plugin')
    parser.add_argument('--serial')
    parser.add_argument('--hidden-identity', action='store_true')
    parser.add_argument('-n', '--new-identity', action='store_true')
    parser.add_argument('-v', '--verbose',
                        action='store_true')  # on/off flag

    args = parser.parse_args()

    if args.age_plugin:
        if args.age_plugin == 'recipient-v1':
            recipient_v1_phase1()
        elif args.age_plugin == 'recipient-v1':
            pass
        else:
            raise 'Not implemented'
    elif args.new_identity:
        device = chose_device_interactively()

        if not device:
            raise 'No device found'

        credential_id = generate_new_credential(device)

        identity = create_identity(credential_id, args.hidden_identity)

        print(identity)
