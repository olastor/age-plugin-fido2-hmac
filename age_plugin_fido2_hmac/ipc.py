import sys
from .b64 import b64encode_no_padding


def send_command(
    command: str,
    metadata=[],
    data: str = '',
    wait_for_ok=False
):
    """Send a command to age.

    Args:
        command (str): The command.
        metadata (list, optional): Optional metadata to add.. Defaults to [].
        data (str, optional): Optional data to send.. Defaults to ''.
        wait_for_ok (bool, optional): Whether or not to wait for an "ok" response. Defaults to False.
    """

    data_encoded = b64encode_no_padding(data) if data else ''

    # make sure to respect the max column size
    max_size = 64
    add_trailing_newline = len(data_encoded) > 0 and (len(data_encoded) % max_size) == 0
    data_encoded = '\n'.join([
        data_encoded[i:i+max_size]
        for i in range(0, len(data_encoded), max_size)
    ])

    if add_trailing_newline:
        # important: if the body size is exactly the max size, a newline needs to be added
        data_encoded += '\n'

    message = '-> %s%s%s\n' % (
        command,
        ' %s' % (' '.join(metadata)) if len(metadata) > 0 else '',
        '\n' + data_encoded
    )

    sys.stdout.write(message)
    sys.stdout.flush()

    if wait_for_ok:
        handle_incoming_data({
            'ok': {
                'exit': True
            }
        })


def handle_incoming_data(handlers):
    """Create a handler for messages sent from age.

    Args:
        handlers (any): The handlers (TODO: add more docs).
    """
    current_command = None
    current_metadata = []
    expected_data_lines = None

    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        if line.startswith('->'):
            splitted = line[3:].split(' ')
            current_command = splitted[0].strip()
            current_metadata = splitted[1:]

        if current_command in handlers:
            if 'data-lines' in handlers[current_command] and handlers[current_command]['data-lines'] > 0:
                if line.startswith('->'):
                    # first time, remember for next lines
                    expected_data_lines = handlers[current_command]['data-lines']
                elif expected_data_lines > 0:
                    # call callback for each line individually
                    handlers[current_command]['callback'](
                        current_metadata, line)
                    expected_data_lines = expected_data_lines - 1
            elif 'callback' in handlers[current_command]:
                handlers[current_command]['callback'](current_metadata, None)

            if expected_data_lines is None or expected_data_lines == 0:
                if 'exit' in handlers[current_command] and handlers[current_command]['exit']:
                    break

                current_command = None
                current_metadata = []
                expected_data_lines = None
