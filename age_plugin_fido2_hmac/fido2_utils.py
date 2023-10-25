import sys
import os
from fido2 import cose
from fido2.ctap2 import Ctap2
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import ClientPin
from fido2.ctap import CtapError, STATUS
from hashlib import sha256
from getpass import getpass
from time import sleep
from fido2.hid import CtapHidDevice
from typing import List, Mapping

from . import FIDO2_RELYING_PARTY, WAIT_FOR_DEVICE_TIMEOUT
from .b64 import b64decode_no_padding
from .ipc import send_command, handle_incoming_data


DEBUG = 'AGEDEBUG' in os.environ and os.environ['AGEDEBUG'] == 'plugin'

DEFAULT_ALGORITHMS = [
    {"type": "public-key", "alg": cose.ES256.ALGORITHM},
    {"type": "public-key", "alg": cose.EdDSA.ALGORITHM},
    {"type": "public-key", "alg": cose.RS256.ALGORITHM}
]

def order_devices(devices: List[any]) -> List[any]:
    """Sort devices by whether or not they always require UV.
    The one's that don't require it always come first.

    Args:
        devices (List[any]): List of devices.

    Returns:
        List[any]: List of devices (sorted).
    """
    return sorted(devices, key=lambda dev: 1 if Ctap2(
        dev).info.options.get('alwaysUv') else 0)


def create_credential(device: any, algorithm:str=None) -> bytes:
    """Create a new non-discoverable credential with enabled "hmac-secret" extension.

    Args:
        device (any): The device.
        algorithm (str, optional): A custom public-key algorithm to use for the credential. Defaults to None.

    Returns:
        bytes: The credential ID.
    """
    selected_algorithm = None
    if algorithm:
        try:
            selected_algorithm = getattr(
                cose, algorithm.upper().replace('EDDSA', 'EdDSA')).ALGORITHM
        except Exception as e:
            print(
                'Error: The chosen algorithm %s is unknown.' %
                (algorithm))
            sys.exit(1)

    ctap = Ctap2(device)
    require_pin = False

    if ctap.info.options.get('clientPin') and (not ctap.info.options.get(
            'makeCredUvNotRqd') or ctap.info.options.get('alwaysUv')):
        require_pin = True

    client_hash = sha256()
    client_hash.update(os.urandom(32))
    client_hash = client_hash.digest()

    pin_auth = None
    pin_protocol = None

    if require_pin:
        client_pin = ClientPin(ctap)
        pin = getpass('Please enter the PIN:')
        pin_token = client_pin.get_pin_token(
            pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, FIDO2_RELYING_PARTY)
        pin_protocol = client_pin.protocol
        pin_auth = client_pin.protocol.authenticate(pin_token, client_hash)

    rp = {'id': FIDO2_RELYING_PARTY}
    user = {'id': os.urandom(12)}
    algorithms = DEFAULT_ALGORITHMS if not selected_algorithm else [{"type": "public-key", "alg": selected_algorithm}]
    extensions = {'hmac-secret': True}
    options = {'rk': False}

    response = ctap.make_credential(
        client_hash,
        rp,
        user,
        algorithms,
        None,
        extensions,
        options,
        pin_auth,
        pin_protocol.VERSION if pin_protocol else None,
        on_keepalive=get_keepalive(device, False)
    )

    return response.auth_data.credential_data.credential_id


def is_device_eligble(device: any, credential_id: bytes, use_plugin_interaction:bool=True) -> bool:
    """Check whether a credential ID was created with this device. Only call this function if it can
    be expected that no user verification or presence is required, so that the check is "silent".

    Args:
        device (any): The device.
        credential_id (bytes): The credential ID.
        use_plugin_interaction (bool, optional): Whether or not to interact via the plugin protocol or not. Defaults to True.

    Returns:
        bool: True if the device is eligble.
    """
    try:
        ctap = Ctap2(device)

        client_hash = sha256()
        client_hash.update(os.urandom(32))
        client_hash = client_hash.digest()

        allow_list = [{"type": "public-key", "id": credential_id}]
        ctap.get_assertion(
            FIDO2_RELYING_PARTY,
            client_hash,
            allow_list,
            None,
            {'up': False},
            on_keepalive=get_keepalive(device, use_plugin_interaction)
        )

        return True
    except CtapError as e:
        if e.code in [
            CtapError.ERR.CREDENTIAL_EXCLUDED,
                CtapError.ERR.NO_CREDENTIALS]:
            return False
        else:
            if DEBUG:
                print(e)

            raise e
    except BaseException as e:
        if DEBUG:
            print(e)

        raise e


def request_pin_cli(client_pin: any) -> str:
    """Request a PIN interactively for the CLI.

    Args:
        client_pin (any): A ClientPin instance.

    Returns:
        str: The entered PIN.
    """
    retries_left, _ = client_pin.get_pin_retries()

    if retries_left == 0:
        print('ERROR: No more PIN retries possible.')
        sys.exit(1)
    elif retries_left == 1:
        print(
            'ERROR: Only 1 PIN retry left for device. Please reset that another way first.')
        sys.exit(1)
    elif retries_left <= 3:
        print('WARN: Only %i PIN retries left!')

    return getpass('Please enter your PIN: ')


def request_pin_plugin(client_pin: any) -> str:
    """Request a PIN interactively via the plugin protocol.

    Args:
        client_pin (any): A ClientPin instance.

    Returns:
        str: The entered PIN.
    """
    retries_left, _ = client_pin.get_pin_retries()

    if retries_left == 0:
        send_command('msg', [], 'ERROR: No more PIN retries possible.')
        sys.exit(1)
    elif retries_left == 1:
        send_command(
            'error',
            ['internal'],
            'ERROR: Only 1 PIN retry left for device. Please reset that another way first.')
        sys.exit(1)
    elif retries_left <= 3:
        send_command('error', ['internal'], 'WARN: Only %i PIN retries left!')

    pin = ''

    def set_pin(metadata, data):
        nonlocal pin
        pin = b64decode_no_padding(data).decode('utf-8')

    send_command('request-secret', [], 'Please enter your pin:')

    handle_incoming_data({
        'fail': {
            'exit': True,
            'callback': lambda metadata, data: sys.exit(1)
        },
        'ok': {
            'exit': True,
            'data-lines': 1,
            'callback': set_pin
        }
    })

    if len(pin) == 0:
        send_command('error', ['internal'], 'ERROR: Failed to get PIN.')
        sys.exit(1)

    return pin


def get_keepalive(device:any, use_plugin_interaction=True):
    """Get a keepalive function for telling when user presence is needed.

    Args:
        device (any): The device.
        use_plugin_interaction (bool, optional): Whether or not to interact via the plugin protocol or not.. Defaults to True.

    Returns:
        any: The keepalive event handler function.
    """

    msg = 'Please touch the device "%s".' % (device.descriptor.product_name)

    if use_plugin_interaction:
        def on_keepalive(status):
            if status == STATUS.UPNEEDED:
                send_command('msg', [], msg)

        return on_keepalive
    else:
        def on_keepalive(status):
            if status == STATUS.UPNEEDED:
                print(msg)

        return on_keepalive


def get_hmac_secret(
    device,
    credential_id: bytes,
    salt: bytes,
    require_pin=False,
    use_plugin_interaction=True,
    salt2:bytes=None
) -> Mapping[str, any]:
    """Get the hmac secret from the authenticator using a certain salt and credential.

    Args:
        device (any): The device.
        credential_id (bytes): The credential ID.
        salt (bytes): The 32 bytes salt to use for the hmac.
        require_pin (bool, optional): Whether or not to prompt for user verification via PIN. Defaults to False.
        use_plugin_interaction (bool, optional): _description_. Defaults to True.
        salt2 (bytes, optional): An optional second salt to use. Defaults to None.

    Returns:
        Mapping[str, any]:  The output of the hmac operation(s), being in the "output1" (and "output2") field.
                            Returns None if the device is not eligble.
    """
    try:
        ctap = Ctap2(device)

        client_hash = sha256()
        client_hash.update(os.urandom(32))
        client_hash = client_hash.digest()

        pin_auth = None
        pin_protocol = None

        options = {'up': True}

        allow_list = [{"type": "public-key", "id": credential_id}]

        if require_pin:
            client_pin = ClientPin(ctap)
            pin = request_pin_plugin(
                client_pin) if use_plugin_interaction else request_pin_cli(client_pin)
            pin_token = client_pin.get_pin_token(
                pin, ClientPin.PERMISSION.GET_ASSERTION, FIDO2_RELYING_PARTY)
            pin_protocol = client_pin.protocol
            pin_auth = client_pin.protocol.authenticate(pin_token, client_hash)

        hmac_secret_input = {'hmacGetSecret': {'salt1': salt}}
        if salt2:
            hmac_secret_input['hmacGetSecret']['salt2'] = salt2

        hmac_ext = HmacSecretExtension(ctap, pin_protocol)
        extensions = {
            'hmac-secret': hmac_ext.process_get_input(hmac_secret_input)}

        response = ctap.get_assertion(
            FIDO2_RELYING_PARTY,
            client_hash,
            allow_list,
            extensions,
            options,
            pin_auth,
            pin_protocol.VERSION if pin_protocol else None,
            on_keepalive=get_keepalive(device, use_plugin_interaction)
        )

        return hmac_ext.process_get_output(response)['hmacGetSecret']
    except CtapError as e:
        if e.code in [
            CtapError.ERR.CREDENTIAL_EXCLUDED,
                CtapError.ERR.NO_CREDENTIALS]:
            return None
        else:
            if DEBUG:
                print(e)

            raise e
    except BaseException as e:
        if DEBUG:
            print(e)

        raise e


def wait_for_devices(
    handle_message: any,
    handle_error: any,
    ignored_devs:List[any]=[],
    check_interval=1
) -> List[any]:
    """Wait for new fido2 tokens to be inserted.

    Args:
        handle_message (str): Function to call for showing a message.
        handle_error (any): Function to call to raise an error with a message.
        ignored_devs (List[any], optional): A list of devices to ignore. Defaults to [].
        check_interval (int, optional): The interval in seconds to check for new devices. Defaults to 1.

    Returns:
        List[any]: A list of new devices that appeared.
    """
    ignored_descriptors = [str(d.descriptor) for d in ignored_devs]
    for i in range(int(WAIT_FOR_DEVICE_TIMEOUT / check_interval)):
        devs = list(CtapHidDevice.list_devices())
        devs = [
            d for d in devs if not str(
                d.descriptor) in ignored_descriptors]
        if len(devs) > 0:
            return devs

        if i == 0:
            handle_message('Please insert your fido2 token now...')

        sleep(check_interval)

    handle_error('Timed out waiting for device to be present.')


def wait_for_devices_cli(ignored_devs:List[any]=[]) -> List[any]:
    """Wait for devices with CLI user interaction.

    Args:
        ignored_devs (List[any], optional): A list of devices to ignore. Defaults to [].

    Returns:
        List[any]: A list of new devices that appeared.
    """
    def handle_error(message):
        sys.stderr.write(message)
        sys.exit(1)

    return wait_for_devices(
        lambda msg: print(msg),
        handle_error,
        ignored_devs
    )


def wait_for_devices_plugin(ignored_devs:List[any]=[]) -> List[any]:
    """Wait for devices with plugin user interaction.

    Args:
        ignored_devs (List[any], optional): A list of devices to ignore. Defaults to [].

    Returns:
        List[any]: A list of new devices that appeared.
    """
    return wait_for_devices(
        lambda msg: send_command('msg', [], msg),
        lambda msg: send_command('error', ['internal'], msg),
        ignored_devs
    )
