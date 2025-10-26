# Version 3 (Support for Discoverable Credentials and WebAuthN)

- Version: 3.0.0
- Status: Draft

## Format Changes

**Recipient Format:** X25519

**Identity Format:**

```
+--------------+------------------+----------------+------------------------------------+
| version (2B) | require pin (1B) |  user ID (32B) | relying party ID (variable length) |
+--------------+------------------+----------------+------------------------------------+
```

The identity consists of four parts:

- The fixed version identifier "3" (big-endian unsigned short)
- The require pin flag (1 byte: 0 = no pin required, 1 = pin required)
- The user ID that also is used as salt
- The relying party ID (RP_ID) of the discoverable credential 

**Stanza Format:** X25519

## Other Changes

- The user ID of the credential acts as the salt for the HMAC assertion. It MUST be generated using a CSPRNG.
- The HMAC assertion MUST use the correct context string to be compatible with the WebAuthN PRF extension.
- The option for listing credentials on a fido2 token MUST be provided.
- The option for showing the recipient and/or identity string on a fido2 token MUST be provided.
- Credential names use descriptive format: "age-plugin-fido2-hmac (YY-MM-DDTHH:MM:SS)"

