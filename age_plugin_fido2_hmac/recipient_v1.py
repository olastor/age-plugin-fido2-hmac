import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from fido2.client import ClientError

from . import PLUGIN_NAME, IDENTITY_FORMAT_VERSION
from .ipc import send_command, handle_incoming_data
from .identity import parse_identity
from .b64 import b64encode_no_padding, b64decode_no_padding
from .device import wait_for_devices, PluginInteraction
from .credential import fido2_hmac_challenge


def recipient_v1_phase1():
    identities = []
    recipients = []
    file_key = ''

    def file_key_callback(metadata, data):
        nonlocal file_key
        file_key = data

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
            'callback': file_key_callback
        },
        'done': {
            'exit': True
        }
    })

    recipient_v1_phase2(recipients, identities, file_key)


def recipient_v1_phase2(recipients, identities, wrap_file_key: str):
    for i, identity in enumerate(identities):
        try:
            version, is_hidden_identity, credential_id = parse_identity(
                identity)
        except BaseException:
            send_command('error', ['identity', str(i)],
                         'Failed to parse identity!')

        if version != int.from_bytes(IDENTITY_FORMAT_VERSION):
            send_command('error', ['identity', str(i)],
                         'Unsupported version number!')

    finished_identities = set()
    ignored_devs = []

    while len(finished_identities) < len(identities):
        devs = wait_for_devices(ignored_devs)

        for dev in devs:
            for i, identity in enumerate(
                    [idt for idt in identities if idt not in finished_identities]):
                version, is_hidden_identity, credential_id = parse_identity(
                    identity)
                salt = os.urandom(32)

                hmac_secret = None

                try:
                    hmac_secret = fido2_hmac_challenge(
                        dev, credential_id, salt, PluginInteraction())
                except ClientError as e:
                    if e.code == ClientError.ERR.DEVICE_INELIGIBLE:
                        continue
                    else:
                        send_command(
                            'error', [
                                'identity', str(i)], 'Failed to generate HMAC using fido2 token!')
                except BaseException:
                    send_command(
                        'error', [
                            'identity', str(i)], 'Unknown Error!')

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
                    send_command(
                        'error', [
                            'identity', str(i)], 'Failed to wrap key!')

        ignored_devs += devs
        send_command(
            'msg', [], 'wrapped using %i of %i identities.' %
            (len(finished_identities), len(identities)))

    send_command('done\n', [], None)
