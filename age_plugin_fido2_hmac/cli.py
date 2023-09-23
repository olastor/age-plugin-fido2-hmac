import argparse
from age_plugin_fido2_hmac import recipient_v1_phase1, identity_v1_phase1, chose_device_interactively


def main():
    parser = argparse.ArgumentParser(
        prog='ProgramName',
        description='What the program does',
        epilog='Text at the bottom of help'
    )

    parser.add_argument('--age-plugin')
    parser.add_argument('-n', '--new-identity', action='store_true')
    parser.add_argument('-a', '--algorithm')
    parser.add_argument('-uv', '--user-verification', default='preferred',
                        choices=['required', 'preferred', 'discouraged'])
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

        credential_id = generate_new_credential(
            device, args.user_verification, args.algorithm)

        identity = create_identity(credential_id, args.hidden_identity)

        print(identity)
