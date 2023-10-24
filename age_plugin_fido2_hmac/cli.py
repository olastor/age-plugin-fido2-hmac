import sys
import argparse
import click
from fido2.ctap2 import Ctap2

from . import PLUGIN_NAME, MAGIC_IDENTITY, create_identity, create_recipient, parse_recipient_or_identity
from .recipient_v1 import recipient_v1_phase1
from .identity_v1 import identity_v1_phase1
from .device import wait_for_devices_cli
from .fido2_utils import create_credential


def issue_new_recipient_or_identity(args):
    devs = wait_for_devices_cli()

    if len(devs) > 1:
        print('Please only insert one fido2 token')
        sys.exit(1)

    credential_id = create_credential(devs[0], args.algorithm)

    require_pin = False

    if Ctap2(devs[0]).info.options.get('clientPin'):
        require_pin = click.confirm(
            'Do you want to require a PIN for encryption/decryption?',
            default=False)

    is_identity = click.confirm(
        'Do you want to create a secret identity?',
        default=False)

    if is_identity:
        identity = create_identity(credential_id, require_pin)
        print(identity)
    else:
        recipient = create_recipient(credential_id, require_pin)
        print(recipient)


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
    parser.add_argument('-v', '--version',
                        action='store_true')  # on/off flag

    args = parser.parse_args()

    if args.age_plugin:
        if args.age_plugin == 'recipient-v1':
            recipient_v1_phase1()
        elif args.age_plugin == 'identity-v1':
            identity_v1_phase1()
    elif args.new_credential:
        issue_new_recipient_or_identity(args)
    elif args.print_magic_id:
        print(MAGIC_IDENTITY)
