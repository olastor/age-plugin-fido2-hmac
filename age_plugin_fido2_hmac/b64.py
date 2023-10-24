from base64 import b64encode, b64decode


def b64encode_no_padding(s: str) -> str:
    """Base64-encode a string or byte sequence without padding.

    Args:
        s (str): A string to encode.

    Returns:
        str: Valid base64 string without padding.
    """

    return b64encode(s.encode('utf-8') if isinstance(s, str)
                     else s).decode('utf-8').replace('=', '')


def b64decode_no_padding(s: str):
    """Base64-decode a string without padding.

    Args:
        s (str): Valid base64 string without padding.

    Returns:
        bytes: The decoded data.
    """

    if len(s) % 4 == 0:
        return b64decode(s)
    else:
        padding_length = ((len(s) // 4) + 1) * 4 - len(s)
        return b64decode(s + ('=' * padding_length))
