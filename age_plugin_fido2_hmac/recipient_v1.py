import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from fido2.client import ClientError

from . import PLUGIN_NAME, RECIPIENT_FORMAT_VERSION, IDENTITY_FORMAT_VERSION, parse_recipient_or_identity
from .ipc import send_command, handle_incoming_data
from .b64 import b64encode_no_padding, b64decode_no_padding
from .device import wait_for_devices_plugin, PluginInteraction
from .credential import fido2_hmac_challenge

DEBUG = 'AGEDEBUG' in os.environ and os.environ['AGEDEBUG'] == 'plugin'


def try_wrap_key(file_key, file_index, credential_id, dev, include_credential_id):
    salt = os.urandom(32)
    hmac_secret = None

    try:
        hmac_secret = fido2_hmac_challenge(
            dev, credential_id, salt, PluginInteraction())
    except ClientError as e:
        if e.code == ClientError.ERR.DEVICE_INELIGIBLE:
            return False
        else:
            if DEBUG:
                print(e)

            raise e
    except BaseException as e:
        if DEBUG:
            print(e)

        raise e

    try:
        cipher = ChaCha20Poly1305(hmac_secret)
        nonce = os.urandom(12)

        encrypted_file_key = cipher.encrypt(
            nonce=nonce,
            data=b64decode_no_padding(file_key),
            associated_data=None
        )

        send_command(
            'recipient-stanza', [
                str(file_index),
                PLUGIN_NAME,
                b64encode_no_padding(salt),
                b64encode_no_padding(nonce)
            ] + (
                [b64encode_no_padding(credential_id)]
                if include_credential_id else []
            ),
            encrypted_file_key,
            True
        )

        return True
    except BaseException as e:
        if DEBUG:
            print(e)

        raise e


def recipient_v1_phase1():
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


def check_identities(identities):
    for i, identity in enumerate(identities):
        try:
            version, credential_id = parse_recipient_or_identity(identity)
        except BaseException:
            send_command('error', ['identity', str(i)],
                         'Failed to parse identity!')
            sys.exit(1)
        if version != int.from_bytes(IDENTITY_FORMAT_VERSION):
            send_command('error', ['identity', str(i)],
                         'Unsupported version number!')
            sys.exit(1)


def check_recipients(recipients):
    for i, recipient in enumerate(recipients):
        try:
            version, credential_id = parse_recipient_or_identity(recipient)
        except BaseException:
            send_command('error', ['recipient', str(i)],
                         'Failed to parse!')
            sys.exit(1)
        if version != int.from_bytes(RECIPIENT_FORMAT_VERSION):
            send_command('error', ['recipient', str(i)],
                         'Unsupported version number!')
            sys.exit(1)

def recipient_v1_phase2(recipients, identities, file_keys):
    check_identities(identities)
    check_recipients(recipients)

    # these recipients/identities have successfully wrapped all file keys
    finished_identities = set()
    finished_recipients = set()

    ignored_devs = []

    while (len(finished_identities) < len(identities)) or (len(finished_recipients) < len(recipients)):
        devs = wait_for_devices_plugin(ignored_devs)

        for dev in devs:
            for i, identity in enumerate(identities):
                if identity in finished_identities:
                    continue

                version, credential_id = parse_recipient_or_identity(identity)

                device_eligible = False
                for file_index, file_key in enumerate(file_keys):
                    if try_wrap_key(file_key, file_index, credential_id, dev, False):
                        device_eligible = True
                    elif device_eligible:
                        send_command('error', ['identity', str(i)],
                                     'Could not wrap all file keys!', True)
                        sys.exit(1)

                if device_eligible:
                    finished_identities.add(identity)

            for i, recipient in enumerate(recipients):
                if recipient in finished_recipients:
                    continue

                version, credential_id = parse_recipient_or_identity(recipient)

                device_eligible = False
                for file_index, file_key in enumerate(file_keys):
                    if try_wrap_key(file_key, file_index, credential_id, dev, True):
                        device_eligible = True
                    elif device_eligible:
                        send_command('error', ['recipient', str(i)],
                                     'Could not wrap all file keys!', True)
                        sys.exit(1)

                if device_eligible:
                    finished_recipients.add(recipient)

        ignored_devs += devs

    send_command('done\n', [], None)
