# Version 3 (Support for Discoverable Credentials and WebAuthN)

- Version: 3.0.0
- Status: Draft

## Format Changes

### Linkable

**Recipient Format:**

```
+--------------+---------------------+----------------+------------------------------------+
| version (2B) | x25519 pubkey (32B) |  user ID (32B) | relying party ID (variable length) |
+--------------+---------------------+----------------+------------------------------------+
```

The recipient consists of four parts:

- The fixed version identifier "3" (big-endian unsigned short)
- The X25519 public key
- The user ID that also is used as salt
- The relying party ID (RP_ID) of the discoverable credential 

TODO: keep pin flag?

**Stanza Format:**

```
-> fido2-hmac <stanza version (2B)> <x25519 ephemeral share (32B)> <user id (32B)> <relying party ID>
<x25519 stanza body>
```

**Identity Format:**

Not needed.

### Unlinkable

**Recipient/Stanza Format:** age X25519
**Identity Format:** see format of linkable recipient

Decryption can also be done without identity, but the user needs to enter/select the RP_ID and user ID.

## Other Changes

- The user ID of the credential acts as the salt for the HMAC assertion. It MUST be generated using a CSPRNG.
- The HMAC assertion MUST use the correct context string to be compatible with the WebAuthN PRF extension.
- The option for listing credentials on a fido2 token MUST be provided.
- The option for showing the recipient and/or identity string on a fido2 token MUST be provided.
- TODO: consider option to modify display name upon creation

