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


def send_command(
    command: str,
    metadata = [],
    data: str = '',
    wait_for_ok=False
):
    message = '-> %s%s%s\n' % (
        command,
        ' %s' % (' '.join(metadata)) if len(metadata) > 0 else '',
        '\n' + b64encode_no_padding(data) if data else ''
    )

    sys.stdout.write(message)
    sys.stdout.flush()

    if wait_for_ok:
        handle_incoming_data({
            'ok': {
                'exit': True
            }
        })


def handle_incoming_data(handlers):
    current_command = None
    current_metadata = []
    expected_data_lines = None

    for line in sys.stdin:
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


def identity_v1_phase1():
    identities = []
    stanzas = []

    handle_incoming_data({
        'add-identity': {
            'data-lines': 0,
            'callback': lambda metadata, data: identities.append(metadata[0])
        },
        'recipient-stanza': {
            'data-lines': 1,
            'callback': lambda metadata, data: stanzas.append([metadata, data])
        },
        'done': {
            'exit': True
        }
    })

    identity_v1_phase2(identities, stanzas)


def try_unwrap_key(stanza_index, stanza, credential_id, dev):
    hmac_secret = None
    salt = b64decode_no_padding(stanza[0][2])

    try:
        hmac_secret = fido2_hmac_challenge(dev, credential_id, salt, PluginInteraction())
    except ClientError as e:
        if e.code == ClientError.ERR.DEVICE_INELIGIBLE:
            return None
        else:
            send_command(
                'error',
                ['stanza', stanza[0], stanza_index],
                'Unexpected ClientError.',
                True
            )
            return None
    except Exception as e:
        send_command(
            'error',
            ['stanza', stanza[0], stanza_index],
            'Unexpected Error.',
            True
        )
        return None

    try:
        cipher = ChaCha20Poly1305(hmac_secret)
        nonce = b64decode_no_padding(stanza[0][3])

        file_key = cipher.decrypt(
            nonce=nonce,
            data=b64decode_no_padding(stanza[1]),
            associated_data=None
        )

        return file_key
    except Exception as e:
        send_command(
            'error',
            ['stanza', stanza[0], stanza_index],
            'Failed to unwrap key!',
            True
        )


def check_identities_stanzas(identities, stanzas, stanzas_by_file):
    # "plugin MUST return errors and MUST NOT attempt to unwrap
    # any file keys with otherwise-valid identities."
    for i, identity in enumerate(identities):
        if identity == MAGIC_IDENTITY:
            continue

        try:
            version, is_hidden_identity, credential_id = parse_identity(identity)
            if version != int.from_bytes(IDENTITY_FORMAT_VERSION):
                send_command(
                    'error',
                    ['identity', str(i)],
                    'Unsupported version.',
                    True
                )
        except Exception as e:
            send_command(
                'error',
                ['identity', str(i)],
                'Failed to parse identity.',
                True
            )

    # "If any known stanza is structurally invalid, the plugin
    # MUST return an error for that stanza, and MUST NOT unwrap
    # any stanzas with the same FILE_INDEX. The plugin MAY continue
    # to unwrap stanzas from other files."
    for i, stanza in enumerate(stanzas):
        # hidden itentities do not include the credential ids,
        # therefore both length 4 or 5 can be valid.
        if len(stanza[0]) not in [4, 5]:
            send_command(
                'error',
                ['stanza', stanza[0][0], str(i)],
                'Invalid stanza.',
                True
            )

            del stanzas_by_file[stanza[0][0]]


def identity_v1_phase2(identities, stanzas):
    stanzas_by_file = {}
    for i, stanza in enumerate(stanzas):
        file_index = stanza[0][0]
        if file_index not in stanzas_by_file:
            stanzas_by_file[file_index] = []

        stanzas_by_file[file_index].append([i, stanza])

    check_identities_stanzas(identities, stanzas, stanzas_by_file)

    for file_index, stanza_group in stanzas_by_file.items():
        for stanza_index, stanza in stanza_group:
            # plugin MUST ignore unknown stanzas
            if stanza[0][1] != PLUGIN_NAME:
                continue

            file_key = None
            devs = wait_for_devices()
            for dev in devs:
                if len(stanza) == 5:
                    # credential id is public information,
                    # no need to use identities
                    cred_id = b64decode_no_padding(stanza[0][4])
                    file_key = try_unwrap_key(
                        stanza_index,
                        stanza,
                        cred_id,
                        dev
                    )
                else:
                    # credential id can only be derived from identity,
                    # so try them all
                    for i, identity in enumerate(identities):
                        if identity == MAGIC_IDENTITY:
                            continue

                        version, is_hidden_identity, cred_id = parse_identity(identity)

                        file_key = try_unwrap_key(
                            stanza_index,
                            stanza,
                            cred_id,
                            dev
                        )

                        if file_key:
                            break

                if file_key:
                    break

            if file_key:
                send_command(
                    'file-key', [
                        stanza[0][0]
                    ],
                    file_key,
                    True
                )

                # we don't need to try any other stanzas for this file
                break

    send_command('done\n', [], None)


def b64encode_no_padding(s):
    return b64encode(s.encode('utf-8') if type(s) == str else s).decode('utf-8').replace('=', '')


def b64decode_no_padding(s: str):
    if len(s) % 4 == 0:
        return b64decode(s)
    else:
        padding_length = ((len(s) // 4) + 1) * 4 - len(s)
        return b64decode(s + ('=' * padding_length))


def wait_for_devices(ignored_devs = []):
    check_interval = 0.5

    ignored_descriptors = [str(d.descriptor) for d in ignored_devs]
    for i in range(int(WAIT_FOR_DEVICE_TIMEOUT / check_interval)):
        devs = list(CtapHidDevice.list_devices())
        devs = [d for d in devs if not str(d.descriptor) in ignored_descriptors]
        if len(devs) > 0:
            return devs

        if i == 0:
            send_command('msg', [], 'Please insert your fido2 token now...')

        sleep(check_interval)

    send_command('error', ['internal'], 'Timed out waiting for device to be present.')


def recipient_v1_phase2(identities, wrap_file_key: str):
    for i, identity in enumerate(identities):
        try:
            version, is_hidden_identity, credential_id = parse_identity(identity)
        except:
            send_command('error', ['identity', str(i)], 'Failed to parse identity!')

        if version != int.from_bytes(IDENTITY_FORMAT_VERSION):
            send_command('error', ['identity', str(i)], 'Unsupported version number!')

    finished_identities = set()
    ignored_devs = []

    while len(finished_identities) < len(identities):
        devs = wait_for_devices(ignored_devs)

        for dev in devs:
            for i, identity in enumerate([idt for idt in identities if not idt in finished_identities]):
                version, is_hidden_identity, credential_id = parse_identity(identity)
                salt = os.urandom(32)

                hmac_secret = None

                try:
                    hmac_secret = fido2_hmac_challenge(dev, credential_id, salt, PluginInteraction())
                except ClientError as e:
                    if e.code == ClientError.ERR.DEVICE_INELIGIBLE:
                        continue
                    else:
                        send_command('error', ['identity', str(i)], 'Failed to generate HMAC using fido2 token!')
                except:
                    send_command('error', ['identity', str(i)], 'Unknown Error!')

                try:
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
                    finished_identities.add(identity)
                except Exception as e:
                    send_command('error', ['identity', str(i)], 'Failed to wrap key!')

        ignored_devs += devs
        send_command('msg', [], 'wrapped using %i of %i identities.' % (len(finished_identities), len(identities)))

    send_command('done\n', [], None)


def fido2_hmac_challenge(device, credential_id, salt, user_interaction):
    challenge = os.urandom(12)
    allow_list = [{"type": "public-key", "id": credential_id}]

    # Prepare parameters for makeCredential
    rp = {'id': FIDO2_RELYING_PARTY}
    challenge = b"Y2hhbGxlbmdl"

    client = Fido2Client(device, 'https://' + FIDO2_RELYING_PARTY, user_interaction=user_interaction)

    # Authenticate the credential
    result = client.get_assertion(
        {
            "rpId": FIDO2_RELYING_PARTY,
            "challenge": challenge,
            "allowCredentials": allow_list,
            "extensions": {"hmacGetSecret": {"salt1": salt}},
        },
    ).get_response(0)

    return result.extension_results["hmacGetSecret"]["output1"]



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
        pin = ''

        def set_pin(metadata, data):
            nonlocal pin
            pin = data

        send_command('msg', [], 'Please enter your pin:')

        handle_incoming_data({
            'ok': {
                'exit': True,
                'callback': set_pin
            }
        })

        return pin

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def generate_new_credential(
    device,
    uv=UserVerificationRequirement.PREFERRED.value,
    algorithm_choice=None
):
    cli_interaction = CliInteraction()
    client = Fido2Client(
        device,
        'https://' + FIDO2_RELYING_PARTY,
        user_interaction=cli_interaction
    )

    rp = {"id": FIDO2_RELYING_PARTY, "name": "Example RP"}
    user = {"id": b"user_id", "name": "A. User"}

    selected_algorithm = None
    if algorithm_choice:
        try:
            selected_algorithm = getattr(cose, algorithm_choice.upper()).ALGORITHM
        except Exception as e:
            print('Error: The provided algorithm %s is not supported.' % (algorithm_choice))
            sys.exit(1)

    challenge = os.urandom(12)
    algs = [{"type": "public-key", "alg": selected_algorithm}] if selected_algorithm else [
        {"type": "public-key", "alg": cose.ES256.ALGORITHM},
        {"type": "public-key", "alg": cose.ES384.ALGORITHM},
        {"type": "public-key", "alg": cose.ES512.ALGORITHM},
        {"type": "public-key", "alg": cose.RS256.ALGORITHM}
    ]

    result = client.make_credential(
        {
            "rp": rp,
            "user": user,
            "challenge": challenge,
            "pubKeyCredParams": algs,
            "extensions": {"hmacCreateSecret": True},
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "requireResidentKey": False,
                "userVerification": uv
             }
        }
    )

    if not result.extension_results.get("hmacCreateSecret"):
        print("Failed to create credential with HmacSecret")
        sys.exit(1)

    return result.attestation_object.auth_data.credential_data.credential_id


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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='ProgramName',
        description='What the program does',
        epilog='Text at the bottom of help'
    )

    parser.add_argument('--age-plugin')
    parser.add_argument('-n', '--new-identity', action='store_true')
    parser.add_argument('-a', '--algorithm')
    parser.add_argument('-uv', '--user-verification', default=UserVerificationRequirement.PREFERRED.value,
                        choices=[UserVerificationRequirement.REQUIRED.value,UserVerificationRequirement.PREFERRED.value,UserVerificationRequirement.DISCOURAGED.value])
    parser.add_argument('--hidden-identity', action='store_true')
    parser.add_argument('-v', '--version',
                        action='store_true')  # on/off flag

    args = parser.parse_args()

    if args.age_plugin:
        if args.age_plugin == 'recipient-v1':
            recipient_v1_phase1()
        elif args.age_plugin == 'identity-v1':
            identity_v1_phase1()
        else:
            raise 'Not implemented'
    elif args.new_identity:
        device = chose_device_interactively()

        if not device:
            raise 'No device found'

        credential_id = generate_new_credential(device, args.user_verification, args.algorithm)

        identity = create_identity(credential_id, args.hidden_identity)

        print(identity)
