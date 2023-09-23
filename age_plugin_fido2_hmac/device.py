from time import sleep
from fido2.hid import CtapHidDevice
from fido2.client import UserInteraction
from getpass import getpass

from . import WAIT_FOR_DEVICE_TIMEOUT
from .ipc import send_command, handle_incoming_data


def chose_device_interactively():
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
        raise Exception('Invalid device index')

    if input(
        'You have selected: %s. Confirm? [yY]' %
            (devs[input_index][1])).lower().strip() != 'y':
        raise Exception('Failed confirmation')

    return devs[input_index][0]


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
