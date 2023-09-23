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


def wait_for_devices(ignored_devs=[]):
    check_interval = 0.5

    ignored_descriptors = [str(d.descriptor) for d in ignored_devs]
    for i in range(int(WAIT_FOR_DEVICE_TIMEOUT / check_interval)):
        devs = list(CtapHidDevice.list_devices())
        devs = [
            d for d in devs if not str(
                d.descriptor) in ignored_descriptors]
        if len(devs) > 0:
            return devs

        if i == 0:
            send_command('msg', [], 'Please insert your fido2 token now...')

        sleep(check_interval)

    send_command(
        'error',
        ['internal'],
        'Timed out waiting for device to be present.')


def fido2_hmac_challenge(device, credential_id, salt, user_interaction):
    challenge = os.urandom(12)
    allow_list = [{"type": "public-key", "id": credential_id}]

    # Prepare parameters for makeCredential
    rp = {'id': FIDO2_RELYING_PARTY}
    challenge = b"Y2hhbGxlbmdl"

    client = Fido2Client(
        device,
        'https://' +
        FIDO2_RELYING_PARTY,
        user_interaction=user_interaction)

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
            selected_algorithm = getattr(
                cose, algorithm_choice.upper()).ALGORITHM
        except Exception as e:
            print(
                'Error: The provided algorithm %s is not supported.' %
                (algorithm_choice))
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


def chose_device_interactively():
    # TODO: WindowsClient
    # TODO: NFC/CtapPcscDevice
    devs = [
        (dev,
         '%s (path=%s, serial=%s)' %
         (dev.product_name,
          dev.descriptor.path,
          dev.serial_number)) for dev in CtapHidDevice.list_devices()]

    if len(devs) == 0:
        return None

    if len(devs) == 1:
        return devs[0][0]

    for i, (dev, info) in enumerate(devs):
        print('[%i]: %s' % (i, info))

    input_index = int(input("Enter device: ").strip())

    if input_index < 0 or input_index >= len(devs):
        raise 'Invalid device index'

    if input(
        'You have selected: %s. Confirm? [yY]' %
            (devs[input_index][1])).lower().strip() != 'y':
        raise 'Failed confirmation'

    return devs[input_index][0]
