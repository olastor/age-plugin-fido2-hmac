import sys
import os
from fido2 import cose
from fido2.client import Fido2Client

from . import FIDO2_RELYING_PARTY
from .device import CliInteraction

def generate_new_credential(
    device,
    uv='preferred',
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
