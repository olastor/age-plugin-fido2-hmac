# Version 1 (Non-discoverable Credentials for Symmetric Encryption)

- Version: 1.0.0
- Status: Implemented

# Motivation

This plugin's purpose is to enable encryption and decryption of files with age and FIDO2 tokens (such as YubiKeys, NitroKeys etc.). Unlike `age-plugin-yubikey` [1], which stores a key on the token, file keys are wrapped in a _stateless manner_ by utilizing the `hmac-secret` extension [2], similar to how systemd-cryptenroll implements it [3]. Thus, this plugin is inspired by the proof-of-concept plugin `age-plugin-fido` [4] and seeks to

- be compliant with the age plugin specification [5],
- implement the notion of recipients/identities using _non-discoverable credentials_,
- support encryption/decryption with one or more fido2 tokens,
- and provide decent user experience and error handling.

## Constants

- Plugin Name: `fido2-hmac`
- Binary Name: `age-plugin-fido2-hmac`
- Recipient Prefix: `age1fido2-hmac`
- Identity Prefix: `AGE-PLUGIN-FIDO2-HMAC-`

## Recipients & Identities

For wrapping/unwrapping the file key provided by age, both the (physical) **fido2 authenticator** and the **non-discoverable credential** generated with it must be present.

Depending on whether or not the _credential id_ is kept as a separate secret there are two ways of defining recipients and identites. This plugin supports both types.

### Encryption using "recipients"

If the _credential ID_ shall be treated as _public_ information, the plugin includes it both in an age recipient string and the stanza stored in the header of the encrypted file. For decryption, only the fido2 token needs to be presented. However, since age might enforce the presence of an identity, the plugin in this case accepts a static, "magic" identity, which simply is the BECH32-encoded plugin name: `AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76`.

This mode of encryption opts for convenience, but does not protect well against compromise of the (physical) fido2 token. It is therefore recommended to activate "user verification", i.e., via PIN, when creating the recipient.

#### Format

The recipient encodes the following data in Bech32 using the recipient's HRP:

```
+-------------------------------------------------------+
| version (2 bytes) | pin flag (1 byte) | credential id |
+-------------------------------------------------------+
```

- the version which is incremented on every change of the format (big-endian unsigned short)
- a boolean indicating whether user verification via PIN must be used for assertions
- the variable-length credential ID

### Encryption using "identities"

In contrast to the above, the plugin also allows for creating age identities which contain a credential id, treating them as _private_ information. For encryption, the identity is provided instead of a recipient and the credential id is **not** included in the stanza. Thus, decryption requires the exact same identity in addition to the presence of the (physical) fido2 token.

This mode of encryption emphasizes security and anonymity. Without the age identity, it is impossible to decrypt the file or identify the fido2 token used for encryption. The user is responsible for keeping the age identity secret and preventing it from being lossed.

#### Format

The format is identical to the recipient format, but uses identity-HRP.

### Generating Credentials

The plugin MUST create non-discoverable credentials. It supports PIN as a means for user verification, but no other methods such as biometric features.

## Stanza Format

Whenever a _recipient_ is used for encryption, the following stanza is generated:

```
-> fido2-hmac <HMAC salt (32 byte)> <Nonce (12 byte)> <PIN flag (1 byte)> <Credential ID>
<wrapped file key>
```


If instead an _identity_ is used, the stanza has the following shape:

```
-> fido2-hmac <HMAC salt (32 byte)> <Nonce (12 byte)>
<wrapped file key>
```

## File Key Wrapping

### Encryption

1. Generate a random 32 byte `salt`.
2. Retrieve the HMAC `secret` from the fido2 token using the credential id and the `salt`.
3. Generate a random 12-byte `nonce`.
4. Encrypt the file key provided by age with ChaCha20Poly1305, using `secret` as key and the previously generated `nonce`.

The resulting ciphertext is passed to age in the stanza.

### Decryption

1. Get the `nonce` and `salt` from the stanza.
2. Retrieve the `secret` on the fido2 token using the credential id (which is either extracted from the stanza or an identity) and the `salt`.
3. Decrypt the wrapped file key using the `secret` and `nonce`.

# UX Considerations

## Invalid PIN Error Handling

The plugin MUST show appropriate error messages about incorrect PINs. If there is only one retry left, the plugin MUST abort immediately without using up this last try.

## Multiple Tokens

The plugin SHOULD try to minimize the amount of user interaction required.

- The plugin MUST be able to decrypt the file with any of the valid tokens. It MUST NOT require one specific valid token to be presented. The user chooses which one to use.
- The plugin MUST NOT expect the user to insert the same fido2 token multiple times for decryption. All necessary operations with a specific token MUST be done while the token is inserted the first time. For encryption, it is expected that the user does not use multiple recipients/identities that map to the same token.
- The plugin MUST be able to deal with both with multiple tokens being available simultaneously and tokens being presented sequentially by the user.
-  Whenever silent detection of a token that can decrypt the file is possible, the plugin SHOULD not ask the user to choose or insert a different token. All operations that can be done silently SHOULD first be exhausted before requiring user interactions.
- The plugin SHOULD be cautious of making redundant assertions with user verification and retrying assertions. UV often means PIN verification, and tokens have a limited amount of tries after which the token can get locked and needs a reset.
- The timeout for inserting a token SHOULD be long enough for the user to overcome common physical challenges of finding and inserting it.

### Generating New Credentials

When creating a new recipient/identity and there are multiple tokens available, the plugin MUST initiate a selection process. The user selects which token to use by proving user precence (tapping on the security key) for the token that shall be used.

### Encryption

A file may be encrypted with multiple tokens to prevent decryption not being possible if one token gets lost.

At encryption, the file key must be wrapped by possiblly multiple tokens if there are multiple target recipients/identities.

While there are remaining recipients/identities that the file key needs to be wrapped with, do the following:

1. Initialize an empty _ignore list_.
2. If no tokens are available or all available tokens are in the _ignore list_, wait until the user has one at least one new token.
3. Sort all available tokens by their `alwaysUv` property such that the ones with `false` are before the ones with `true`. Then iterate over all tokens:
    1. If `alwaysUv` equals `false`, perform a silent assertion without hmac-extension for each recipient's/identity's credential.
        1. If the assertion succeeds, then send a second assertion using the hmac-assertion and the correct uv flag to obtain the secret for encryption. Remove the recipient/identity from the list of remaining recipients/identities. Add the token to the ignore list. Terminate if none are remaining.
        2. If the assertion fails with `CTAP2_ERR_INVALID_CREDENTIAL`, then proceed to checking the next recipient/identity. If this is the last recipient/identity to check, then show an error to the user that this token does not match, and add the token to the _ignore list_.
        3. If any other error is raised, show an error message and abort.
    2. If `alwaysUv` equals `true`, then pick the first remaining recipient/identity and do an assertion with the hmac-secret extension.
        1. If the assertion succeeds, then use the secret for encryption and remove the recipient/identity from the list of remaining recipients/identities. Add the token to the ignore list. Terminate, if none are remaining.
        2. If the assertion fails with `CTAP2_ERR_INVALID_CREDENTIAL`, then repeat 3.2 using the next remaining recipient/identity.
        3. If any other error is raised, show an error message and abort.
4. If there are still recipients/identities left, then goto 2.

### Decryption

At decryption, the file key must be unwrapped with any one of the valid tokens.

1. Initialize an empty _ignore list_.
2. If no tokens are available or all available tokens are in the _ignore list_, wait until the user has one at least one new token.
3. Sort all available tokens by their `alwaysUv` property such that the ones with `false` are before the ones with `true`. Then iterate over all tokens:
    1. If `alwaysUv` equals `false`, perform a silent assertion without hmac-extension for each recipient's/identity's credential.
        1. If the assertion succeeds, then send a second assertion using the hmac-assertion and the correct `UV` flag to obtain the secret for encryption. Terminate and use the secret for decryption upon success.
        2. If the assertion fails with `CTAP2_ERR_INVALID_CREDENTIAL`, then proceed to checking the next recipient/identity. If this is the last recipient/identity to check, then show an error to the user that this token does not match, and add the token to the _ignore list_.
        3. If any other error is raised, show an error message and abort.
    2. If `alwaysUv` equals `true`, then do trial and error for all recipients/identities.
        1. If the assertion succeeds, then terminate and use the obtained secret for decryption.
        2. If the assertion fails with `CTAP2_ERR_INVALID_CREDENTIAL`, then goto 3.2.
        3. If any other error is raised, show an error message and abort.
    3. Add the token to the _ignore list_.
4. Goto 2

#### Caveats

For identities, there is (purposely) not possible to link a stanza to an identity without performing an HMAC assertion and testing the decryption. In this case the plugin is forced to do perform "trial and error" to find out which salt/nonce was used once a token was recognized to map to an identity. Per assertion at most two HMACs can be calculated, which means if the number of times the user has to tap the token and needs to enter the PIN could be as high as `ceil((number of anonymous stanzas for this plugin) / 2)`. As it seems unlikely that the average user would use more than two identity-based tokens, keeping it this way is better than extending the stanza with addtional information which could decrease the level of anonymity/security.

# References

[1] https://github.com/str4d/age-plugin-yubikey \
[2] https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension \
[3] https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html \
[4] https://github.com/riastradh/age-plugin-fido \
[5] https://github.com/C2SP/C2SP/blob/main/age-plugin.md \
[6] https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#error-responses \
