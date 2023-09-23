from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .ipc import send_command, handle_incoming_data
from .utils import b64decode_no_padding
from . import PLUGIN_NAME, MAGIC_IDENTITY, IDENTITY_FORMAT_VERSION


def check_identities_stanzas(identities, stanzas, stanzas_by_file):
    # "plugin MUST return errors and MUST NOT attempt to unwrap
    # any file keys with otherwise-valid identities."
    for i, identity in enumerate(identities):
        if identity == MAGIC_IDENTITY:
            continue

        try:
            version, is_hidden_identity, credential_id = parse_identity(
                identity)
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


def try_unwrap_key(stanza_index, stanza, credential_id, dev):
    hmac_secret = None
    salt = b64decode_no_padding(stanza[0][2])

    try:
        hmac_secret = fido2_hmac_challenge(
            dev, credential_id, salt, PluginInteraction())
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

                        version, is_hidden_identity, cred_id = parse_identity(
                            identity)

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
