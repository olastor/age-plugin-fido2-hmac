import sys
import argparse
import click
from os.path import isfile

from . import PLUGIN_NAME, MAGIC_IDENTITY, create_identity, create_recipient
from .recipient_v1 import recipient_v1_phase1
from .identity_v1 import identity_v1_phase1
from .device import wait_for_devices_cli
from .credential import generate_new_credential
from .b64 import b64decode_no_padding


def main():
    parser = argparse.ArgumentParser(
        prog='age-plugin-fido2-hmac',
        description='What the program does',
        epilog='Text at the bottom of help'
    )

    parser.add_argument('--age-plugin')
    parser.add_argument('-n', '--new-credential', action='store_true')
    parser.add_argument('-a', '--algorithm')
    parser.add_argument('-m', '--print-magic-id', action='store_true')
    parser.add_argument('-x', '--extract-identities')
    parser.add_argument('-uv', '--user-verification', default='preferred',
                        choices=['required', 'preferred', 'discouraged'],
                        help='Specify how user verification (e.g., via PIN or fingerprint) should be enforced. By default this is preferred as this protects against unauthorized decryptions using the device. If your device does not support user verification, this should be set to "discouraged".')
    parser.add_argument('--hidden-identity', action='store_true')
    parser.add_argument('-v', '--version',
                        action='store_true')  # on/off flag

    args = parser.parse_args()

    if args.age_plugin:
        if args.age_plugin == 'recipient-v1':
            recipient_v1_phase1()
        elif args.age_plugin == 'identity-v1':
            identity_v1_phase1()
    elif args.new_credential:
        devs = wait_for_devices_cli()

        if len(devs) > 1:
            print('Please only insert one fido2 token')
            sys.exit(1)

        credential_id = generate_new_credential(
            devs[0], args.user_verification, args.algorithm)

        if click.confirm('Do you want to have secret identity?', default=True):
            print(create_identity(credential_id))
        else:
            print(create_recipient(credential_id))
    elif args.print_magic_id:
        print(MAGIC_IDENTITY)
    elif args.extract_identities:
        if not isfile(args.extract_identities):
            print('Error: Not a file.')
            sys.exit(1)

        with open(args.extract_identities, 'rb') as f:
            for line in f.readlines():
                if line.decode('utf-8').startswith('---'):
                    break
                if line.decode('utf-8').startswith('-> %s ' % (PLUGIN_NAME)):
                    parts = line.decode('utf-8').split(' ')
                    if len(parts) == 5:
                        credential_id = b64decode_no_padding(parts[-1].replace('\n', ''))
                        identity = create_identity(credential_id, False)
                        print(identity)
                    elif len(parts) == 4:
                        print('# (omitted one hidden identity)')
                    else:
                        print('# (found one malformed identity)')



