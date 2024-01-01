import os
import sys
from struct import unpack
from collections import defaultdict
from fido2.ctap2 import Ctap2
from typing import List, Mapping

from . import PLUGIN_NAME, MAGIC_IDENTITY, IDENTITY_FORMAT_VERSION, parse_recipient_or_identity
from .ipc import send_command, handle_incoming_data
from .b64 import b64decode_no_padding
from .fido2_utils import is_device_eligble, wait_for_devices_plugin, get_hmac_secret, order_devices
from .crypto import unwrap_file_key

DEBUG = 'AGEDEBUG' in os.environ and os.environ['AGEDEBUG'] == 'plugin'


def chunk(lst: List[any], n: int) -> List[List[any]]:
    """Chunk a list.

    Args:
        lst (List[any]): The list.
        n (int): The length of each chunk.

    Returns:
        List[List[any]]: The chunked list.
    """
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def check_identities_stanzas(identities: List[str], stanzas_by_file: Mapping[str, List[any]]):
    """Check the identities and stanzas received.

    Args:
        identities (List[str]): List of identities.
        stanzas_by_file (Mapping[str, List[any]]): Stanzas by their file index.
    """
    # "plugin MUST return errors and MUST NOT attempt to unwrap
    # any file keys with otherwise-valid identities."
    for i, identity in enumerate(identities):
        if identity == MAGIC_IDENTITY:
            continue

        try:
            version, require_pin, credential_id = parse_recipient_or_identity(
                identity)
            if version != IDENTITY_FORMAT_VERSION:
                send_command(
                    'error',
                    ['identity', str(i)],
                    'Unsupported version.',
                    True
                )
        except Exception as e:
            if DEBUG:
                print(e)

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
    for stanzas in stanzas_by_file.values():
        for i, stanza in stanzas:
            # hidden itentities do not include the credential ids,
            # therefore both length 4 or 5 can be valid.
            if len(stanza[0]) not in [4, 6]:
                send_command(
                    'error',
                    ['stanza', stanza[0][0], str(i)],
                    'Invalid stanza.',
                    True
                )

                del stanzas_by_file[stanza[0][0]]

            if len(b64decode_no_padding(stanza[0][2])) != 32:
                send_command(
                    'error',
                    ['stanza', stanza[0][0], str(i)],
                    'Unexpected length of salt.',
                    True
                )

                del stanzas_by_file[stanza[0][0]]

            if len(b64decode_no_padding(stanza[0][3])) != 12:
                send_command(
                    'error',
                    ['stanza', stanza[0][0], str(i)],
                    'Unexpected length of nonce.',
                    True
                )

                del stanzas_by_file[stanza[0][0]]


def identity_v1_phase1():
    """Handle the first phase of the state machine.
    """
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

    try:
        identity_v1_phase2(identities, stanzas)
    except Exception as e:
        if DEBUG:
            print(e)

        send_command('error', ['internal'], 'Fatal: Unknown Error!', True)

        sys.exit(1)


def try_unwrapping_with_recipient_stanzas(dev, dev_always_uv, recipient_stanzas):
    for stanza_index, stanza in recipient_stanzas:
        salt = b64decode_no_padding(stanza[0][2])
        nonce = b64decode_no_padding(stanza[0][3])
        require_pin = unpack('?', b64decode_no_padding(stanza[0][4]))[0]
        cred_id = b64decode_no_padding(stanza[0][5])
        ciphertext = b64decode_no_padding(stanza[1])

        if not dev_always_uv and not is_device_eligble(dev, cred_id):
            continue

        hmac_secret = get_hmac_secret(
            dev, cred_id, salt, require_pin)['output1']

        if not hmac_secret:
            # the device and recipient do not match
            continue

        file_key = unwrap_file_key(ciphertext, hmac_secret, nonce)
        if file_key:
            send_command(
                'file-key', [
                    stanza[0][0]
                ],
                file_key,
                True
            )
            send_command('done\n', [], None)
            return True

    return False


def try_unwrapping_with_identity_stanzas(dev, dev_always_uv, identity_stanzas, identities):
    for identity in identities:
        if identity == MAGIC_IDENTITY:
            continue

        version, require_pin, cred_id = parse_recipient_or_identity(
            identity)

        if not dev_always_uv and not is_device_eligble(dev, cred_id):
            continue

        # we need to find out which salt/nonce decrypts the file by trial and error...
        # because in one assertion two salts can be passed, we check
        # two stanzas at once to avoid unnecessary user prompts
        for i, stanza_pair in enumerate(chunk(identity_stanzas, 2)):
            if i > 0:
                if i == 1:
                    send_command(
                        'msg', [], 'The file is encrypted for multiple fido2 tokens.')

                send_command(
                    'msg', [], 'Please touch again with your token.')

            stanza1_index, stanza1 = stanza_pair[0]

            salt1 = b64decode_no_padding(stanza1[0][2])
            nonce1 = b64decode_no_padding(stanza1[0][3])
            ciphertext1 = b64decode_no_padding(stanza1[1])

            salt2 = None
            nonce2 = None
            ciphertext2 = None
            if len(stanza_pair) == 2:
                stanza2_index, stanza2 = stanza_pair[1]
                salt2 = b64decode_no_padding(stanza2[0][2])
                nonce2 = b64decode_no_padding(stanza2[0][3])
                ciphertext2 = b64decode_no_padding(stanza2[1])

            hmac_secret_outputs = get_hmac_secret(
                dev, cred_id, salt1, require_pin, True, salt2)

            if not hmac_secret_outputs:
                # the device and identity do not match
                break

            file_key = None
            try:
                file_key = unwrap_file_key(
                    ciphertext1, hmac_secret_outputs['output1'], nonce1)
                send_command(
                    'file-key', [
                        stanza1[0][0]
                    ],
                    file_key,
                    True
                )
                send_command('done\n', [], None)
                return True
            except BaseException as e:
                print(e)

            if 'output2' in hmac_secret_outputs:
                try:
                    file_key = unwrap_file_key(
                        ciphertext2, hmac_secret_outputs['output2'], nonce2)
                    send_command(
                        'file-key', [
                            stanza2[0][0]
                        ],
                        file_key,
                        True
                    )
                    send_command('done\n', [], None)
                    return True
                except BaseException as e:
                    print(e)

    return False


def identity_v1_phase2(identities: List[str], stanzas: List[List[str]]):
    """Handle the second phase of the state machine.
    """
    stanzas_by_file = defaultdict(list)

    # group stanzas by their file, but remember the
    # original index of the order they were received
    for i, stanza in enumerate(stanzas):
        if stanza[0][1] != PLUGIN_NAME:
            continue

        file_index = stanza[0][0]
        stanzas_by_file[file_index].append([i, stanza])

    check_identities_stanzas(identities, stanzas_by_file)

    assert len(set(stanzas_by_file.keys())) <= 1, 'Multiple files not supported!'

    recipient_stanzas = [
        (i, s)
        for i, s in stanzas_by_file['0']
        if s[0][1] == PLUGIN_NAME and len(s[0]) == 6
    ]

    identity_stanzas = [
        (i, s) for i, s in stanzas_by_file['0']
        if s[0][1] == PLUGIN_NAME and len(s[0]) == 4
    ]

    ignored_devs = []
    while True:
        available_devs = wait_for_devices_plugin(ignored_devs)
        next_dev = order_devices(available_devs)[0]
        dev_always_uv = Ctap2(next_dev).info.options.get('alwaysUv')

        # First try to unwrap using recipient stanzas that include the credential ID
        # using available tokens that allow for silently checking whether the cred ID
        # was generated with the token. This is the case that requires the least amount
        # of user interaction.
        if try_unwrapping_with_recipient_stanzas(next_dev, dev_always_uv, recipient_stanzas):
            return

        if try_unwrapping_with_identity_stanzas(next_dev, dev_always_uv, identity_stanzas, identities):
            return

        send_command('msg', [], 'Wrong device.')

        ignored_devs.append(next_dev)

    send_command('done\n', [], None)
