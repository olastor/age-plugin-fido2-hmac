import sys
from time import sleep
from fido2.hid import CtapHidDevice
from fido2.client import UserInteraction
from getpass import getpass

from . import WAIT_FOR_DEVICE_TIMEOUT
from .ipc import send_command, handle_incoming_data


def wait_for_devices(
    handle_message,
    handle_error,
    ignored_devs=[],
    check_interval = 1
):
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


def wait_for_devices_cli(ignored_devs=[]):
    def handle_error(message):
        sys.stderr.write(message)
        sys.exit(1)

    return wait_for_devices(
        lambda msg: print(msg),
        handle_error,
        ignored_devs
    )


def wait_for_devices_plugin(ignored_devs=[]):
    return wait_for_devices(
        lambda msg: send_command('msg', [], msg),
        lambda msg: send_command('error', ['internal'], msg),
        ignored_devs
    )


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        # TODO: add note about consequences if it fails
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

        # TODO: add note about consequences if it fails
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
