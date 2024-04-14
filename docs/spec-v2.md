# Plugin Specification: age-plugin-fido2-hmac

- Version: 2.0.0
- Status: Draft

# Motivation

This plugin's purpose is to enable encryption and decryption of files with age and FIDO2 tokens (such as YubiKeys, NitroKeys etc.). Unlike `age-plugin-yubikey` [1], which only supports the Yubikeys series 4+, this plugin supports the fido2-only series and any fido2 token in general that implements the `hmac-secret` extension [2]. In comparison to the proof-of-concept plugin `age-plugin-fido` [4], this plugin adds the ability for encryption in absence of the authenticator and protection via PIN.

## Constants

- Plugin Name: `fido2-hmac`
- Binary Name: `age-plugin-fido2-hmac`
- Recipient Prefix: `age1fido2-hmac` (or the native X25519 recipient prefix)
- Identity Prefix: `AGE-PLUGIN-FIDO2-HMAC-`
- Relying Party Name: `age-encryption.org`

In the following, "authenticator" refers to a (physical) fido2 device/token.

## Background: FIDO2's "hmac-secret" extension

```
                          ┌─────────────────────────────┐
                          │ [fido2 token]               │
[CRED_ID], RP_ID, SALT ──►│                             ├──► OUTPUT
                          │ CRED_ID ─► secret           │
                          │ OUTPUT = hmac(SALT, secret) │
                          └─────────────────────────────┘
```

The "hmac-secret" extension enables the generation an hmac using an user-defined salt and a credential-specific secret only "known" to the device (see [here](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetAssertion)). Moreover:

- Non-discoverable credentials are nearly stateless (resetting the token might still invalidate the credential). The key material is not stored on the authenticator, but is wrapped in the `CRED_ID` and can only recovered with the authenticator that generated it. For discoverable credentials, the `CRED_ID` is optional. The credential is stored on the authenticator and can be _discovered_ only using the `RP_ID` (relying party id).
- The hmac-secret extension allows for passing one (or two) 32 byte salt(s). A credential-specific secret is used to generate one (or two) hmac output(s) on the device. Only the output leaves the device, not the secret. The secret is different if a PIN is used.

## Considerations

### Security Goals

#### SG-1: Secure Encryption

The encryption/wrapping of the file key MUST use a secure encryption algorithm. The key material MUST have proper entropy. It MUST NOT be possible to recover the key without physical access to the authenticator and knowledge of the PIN (if set and meant to be required).

#### SG-2: Minimal Exposure of Secret Key

The secret key (the HMAC-output) MUST be kept only in memory temporarily for performing the necessary cryptographic operations to unwrap a file key or generate a new recipient/identity.

#### SG-3: User Presence/Verification for Decryption

The secret key MUST only be generated with user presence (i.e. touching the authenticator). The user MUST be given the choice (during generation of new credentials) to additionally require user verification via PIN for every decryption.

#### SG-4: Unlinkability

It SHOULD NOT be possible to identify two files as being encrypted to the same recipient by only inspecting the public metdata (the stanzas).

### UX Goals

#### UG-1: Intuitive CLI

The plugin MUST be simple and intuitive to use. It MUST only serve the purpose of encrypting files with fido2 tokens. Technicalities SHOULD be hidden or explained on a high level if it's important information to the user.

#### UG-2: User Absence for Encryption

Encryption SHOULD be possible in an asymmetric fashion, where the authenticator is optional for encryption, but mandatory for decryption.

#### UG-3: No Separate Identities

It SHOULD be possible to use the authenticator for decryption without any additional identity file.

### Trade-Offs

Using a new salt for every encryption would mean the authenticator must be present and challenged for a new hmac output. UG-2 cannot be achieved in this case. If encryption is done in absence of the authenticator, reusing the same combination of a salt and credential is therefore implied.

Moreover, SG-4 conflicts with UG-3. In order to not have a separate identity, the salt and the credential ID must be included as public metadata in the stanza, as these provide the necessary information to recover the secret key. Even using discoverable credentials, the (separate) salt must still be treated as public metadata and can be used to link ciphertexts. Only if a fixed salt would be used at all times, both SG-4 and UG-3 would be possible (with discoverable credentials only). However, this might raise further concerns about whether or not the hmac output of a fixed salt can be trusted for cryptography.

Considering the mentioned conflicts of interest, **two user groups** are distinguished in the following:

- **Group 1**: Good UX over privacy. Fulfills SG-1, SG-2, SG-3, UG-1, UG-2, UG-3.
  - Being able to use the plugin without storing a separate identity file is more important than unlikability.
  - The authenticator should never be needed to present for encryption.
- **Group 2**: Security and privacy aspects are most important. Fulfills: SG-1, SG-2, SG-3, SG-4, UG-1, UG-2
  - To achieve unlikability, this group is willing to securely store a separate identity file that is required for decryption.

## Format Specification

### Identity

```
+--------------+----------------+------------+---------------------------------+
| version (2B) |  pin flag (1B) | salt (32B) | credential id (variable length) |
+--------------+----------------+------------+---------------------------------+
```

The identity (only used for _group 2_) consists of:

- the identity format version ("2") which is incremented on every change of the format (big-endian unsigned short)
- a byte representation of either "0" (no PIN) or "1" (use PIN)
- a 32 byte long, randomly generated salt
- the credential id of a non-discoverable fido2 credential with enabled hmac-secret extension

Note that _group 1_ uses a fixed, dummy identity instead.

### Recipient

```
+--------------+---------------------+---------------+------------+---------------------------------+
| version (2B) | x25519 pubkey (32B) | pin flag (1B) | salt (32B) | credential id (variable length) |
+--------------+---------------------+---------------+------------+---------------------------------+
```

The recipient (only used for _group 1_) consists of:

- the recipient format version ("2") which is incremented on every change of the format (big-endian unsigned short)
- 32 bytes of a native age x25519 public key derived from the private key (the hmac secret)
- the rest is identical to the data of a separate identity

Note that _group 2_ uses native x25519 recipients instead of plugin recipients.

### Stanza

For _group 2_, the native X25519 stanza is used.

For _group 1_, the first stanza **argument** (after the plugin name) is the base64-encoded version number of the stanza format ("2"). The second argument is the first X25519 stanza argument (the ephemeral share) after wrapping the file key. The remaining arguments are identitcal to the identity (excluding version number), i.e. three base64-encoded (unpadded) strings containing the data parts of the identity data.

```
-> fido2-hmac <stanza version (2B)> <x25519 ephemeral share (32B)> <pin flag (1 byte)> <hmac salt (32 byte)> <cred id>
<x25519 stanza body>
```

The stanza **body** is for both groups identical to the native X25519 stanza body after wrapping the file key.

Note: Future versions may differentiate identity and stanza versions.

## Protocol Specification

### Generating New Recipients/Identities

1. Ask the user to insert the authenticator
2. If the authenticator is protected via PIN, ask for the PIN (assumed to be required for creating credentials for most authenticators)
3. Generate a new fido2 credential
  - Set "RK" to `false` (non-discoverable)
  - Enable the "hmac-secret" extension
  - Use the plugin's relying party ID
  - Use random values for user id/name
4. Generate a 32 byte salt using a CSPRNG
5. Ask the user whether to require a PIN for decryption
6. Challenge the authenticator for the hmac output
  - Use the desired PIN preference (the internal secret changes dependent on it!)
  - Use the previously generated credential ID and salt
7. Derive an X25519 public key using the 32 byte hmac output as a private key
8. Discard the hmac output
9. Ask the user which _group_ they belong to
10. Encode the appropriate recipient and identity as specified above

Note: The hmac secret MUST NOT be included in the identity (let alone recipient).

### File Key Wrapping

The plugin MUST only use plugin recipients for wrapping.

For _group 2_, encryption happens without any plugin interactions since the recipient is a native age recipient.

For _group 1_, the encryption MUST use the age API to encrypt the file key to the X25519 public key in the plugin recipient. The PIN flag, salt and credential ID are copied into the stanza to enable future unwrapping.

### File Key Unwrapping

The plugin MUST try both plugin and native X25519 stanzas for unwrapping. It MUST only accept plugin identities.

For both _groups_, the hmac secret MUST be obtained by challenging the authenticator using the correct PIN flag, salt and credential ID (either obtained from the stanza or identity).

The hmac output is interpreted as a native age identity of type X25519. The stanza body MUST be unwrapped using the native age API.

# References

[1] https://github.com/str4d/age-plugin-yubikey \
[2] https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension \
[3] https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html \
[4] https://github.com/riastradh/age-plugin-fido \
[5] https://github.com/C2SP/C2SP/blob/main/age-plugin.md \
[6] https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#error-responses \
