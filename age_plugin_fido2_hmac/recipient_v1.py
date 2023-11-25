import os
import sys
from struct import pack
from fido2.ctap2 import Ctap2
from typing import List

from . import PLUGIN_NAME, RECIPIENT_FORMAT_VERSION, IDENTITY_FORMAT_VERSION, parse_recipient_or_identity
from .ipc import send_command, handle_incoming_data
from .b64 import b64encode_no_padding, b64decode_no_padding
from .crypto import wrap_file_key
from .fido2_utils import is_device_eligble, get_hmac_secret, wait_for_devices_plugin, order_devices

DEBUG = 'AGEDEBUG' in os.environ and os.environ['AGEDEBUG'] == 'plugin'

def wrap_all_file_keys(
    device: any,
    file_keys: List[str],
    require_pin: bool,
    credential_id: bytes,
    is_recipient: bool
) -> bool:
    """Wrap the file keys for a specific device and credential.

    Args:
        device (any): The device.
        file_keys (List[str]): The file keys (only one as of age v1.1).
        require_pin (bool): Whether or not to request PIN verification.
        credential_id (bytes): The credential ID.
        is_recipient (bool): Whether or not the information was inside a recipient.

    Returns:
        bool: Returns True if the wrapping was successful, False if the device was ineligble.
    """
    for file_index, file_key in enumerate(file_keys):
        salt = os.urandom(32)

        hmac_secret = get_hmac_secret(
            device, credential_id, salt, require_pin)

        if not hmac_secret:
            return False

        hmac_secret = hmac_secret['output1']

        ciphertext = None
        nonce = None
        try:
            ciphertext, nonce = wrap_file_key(
                b64decode_no_padding(file_key), hmac_secret)
        except BaseException as e:
            if DEBUG:
                print(e)
            raise e

        send_command(
            'recipient-stanza', [
                str(file_index),
                PLUGIN_NAME,
                b64encode_no_padding(salt),
                b64encode_no_padding(nonce)
            ] + (
                [
                    b64encode_no_padding(pack('?', require_pin)),
                    b64encode_no_padding(credential_id)
                ]
                if is_recipient else []
            ),
            ciphertext,
            True
        )

    return True


def recipient_v1_phase1():
    """Handle the first phase of the state machine.
    """

    identities = []
    recipients = []

    # age currently only accepts a single file key: https://github.com/FiloSottile/age/blob/101cc8676386b0503571a929a88618cae2f0b1cd/plugin/client.go#L113
    # however, the plugin spec allows for multiple
    file_keys = []

    handle_incoming_data({
        'add-identity': {
            'data-lines': 0,
            'callback': lambda metadata, data: identities.append(metadata[0])
        },
        'add-recipient': {
            'data-lines': 0,
            'callback': lambda metadata, data: recipients.append(metadata[0])
        },
        'wrap-file-key': {
            'data-lines': 1,
            'callback': lambda metadata, data: file_keys.append(data)
        },
        'done': {
            'exit': True
        }
    })

    try:
        recipient_v1_phase2(recipients, identities, file_keys)
    except BaseException as e:

        if DEBUG:
            print(e)

        send_command('error', ['internal'], 'Fatal: Unknown Error!', True)

        sys.exit(1)


def check_identities(identities: List[str]):
    """Check a list of identities.

    Args:
        identities (List[str]): The identities.
    """
    for i, identity in enumerate(identities):
        try:
            version, require_pin, credential_id = parse_recipient_or_identity(
                identity)
        except BaseException:
            send_command('error', ['identity', str(i)],
                         'Failed to parse identity!')
            sys.exit(1)
        if version != IDENTITY_FORMAT_VERSION:
            send_command('error', ['identity', str(i)],
                         'Unsupported version number!')
            sys.exit(1)


def check_recipients(recipients: List[str]):
    """Check a list of recipients.

    Args:
        identities (List[str]): The recipients.
    """
    for i, recipient in enumerate(recipients):
        try:
            version, crequire_pin, redential_id = parse_recipient_or_identity(
                recipient)
        except BaseException:
            send_command('error', ['recipient', str(i)],
                         'Failed to parse!')
            sys.exit(1)
        if version != RECIPIENT_FORMAT_VERSION:
            send_command('error', ['recipient', str(i)],
                         'Unsupported version number!')
            sys.exit(1)


def recipient_v1_phase2(recipients, identities, file_keys):
    """Handle the second phase of the state machine.
    """

    check_identities(identities)
    check_recipients(recipients)

    # these recipients/identities have successfully wrapped all file keys
    finished = set()
    ignored_devs = []

    while (len(finished) < len(identities) + len(recipients)):
        available_devs = wait_for_devices_plugin(ignored_devs)
        next_dev = order_devices(available_devs)[0]

        dev_always_uv = Ctap2(next_dev).info.options.get('alwaysUv')
        found = False
        all_items = [(True, r) for r in recipients] + [(False, idx) for idx in identities]
        for is_recipient, rec_or_id in all_items:
            if rec_or_id in finished:
                continue

            version, require_pin, cred_id = parse_recipient_or_identity(
                rec_or_id)

            # take advantage of silent assertion for checking eligibility
            if not dev_always_uv and not is_device_eligble(next_dev, cred_id):
                continue

            success = wrap_all_file_keys(
                next_dev,
                file_keys,
                require_pin,
                cred_id,
                is_recipient
            )

            if success:
                finished.add(rec_or_id)
                found = True
                break

        if not found:
            send_command('msg', [],
                         'Please insert the correct device.', True)

        ignored_devs.append(next_dev)

    send_command('done\n', [], None)
