import sys
from .utils.b64 import b64encode_no_padding


def send_command(
    command: str,
    metadata=[],
    data: str = '',
    wait_for_ok=False
):
    message = '-> %s%s%s\n' % (
        command,
        ' %s' % (' '.join(metadata)) if len(metadata) > 0 else '',
        '\n' + b64encode_no_padding(data) if data else ''
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
    current_command = None
    current_metadata = []
    expected_data_lines = None

    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        if line.startswith('->'):
            assert expected_data_lines is None or expected_data_lines <= 0

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
