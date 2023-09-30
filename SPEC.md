# spec

Version: 1.0.0

This plugin implements the C2SP age-plugin specification [[1]](#references)

## Names

- Plugin Name: `fido2-hmac`
- Binary Name: `age-plugin-fido2-hmac`
- Recipient Prefix: `age1fido2-hmac-`
- Identity Prefix: `AGE-PLUGIN-FIDO2-HMAC`

## Recipients & Identities

For wrapping/unwrapping the file key provided by age, both the (physical) **fido2 authenticator** and the **non-discoverable credential** generated with it must be present.

Depending on whether or not the _credential id_ is kept as a separate secret there are two ways of defining recipients and identites. This plugin supports both types.

### Encryption using "recipients"

If the _credential ID_ shall be treated as _public_ information, the plugin includes it both in an age recipient string and the stanza stored in the header of the encrypted file. For decryption, only the fido2 token needs to be presented. However, since age might enforce the presence of an identity, the plugin in this case accepts a static, "magic" identity, which simply is the BECH32 encoded plugin name: `AGE-PLUGIN-FIDO2-HMAC-1QYQXV6TYDUEZ66RDV93SQUSDAT`.

This mode of encryption opts for convenience, but does not protect well against compromise of the (physical) fido2 token. It is therefore recommended to activate "user verification", e.g., via PIN or biometric features, when creating the recipient.

### Encryption using "identities"

In contrast to the above, the plugin also allows for creating age identities which contain a credential id, treating them as _private_ information. For encryption, the identity is provided instead of a recipient and the credential id is **not** included in the stanza. Thus, decryption requires the exact same identity in addition to the presence of the (physical) fido2 token.

This mode of encryption emphasizes security and anonymity. Without the age identity, it is impossible to decrypt the file or identify the fido2 token used for encryption. The user is responsible for keeping the age identity secret and preventing it from being lossed.

### Options


## Stanza Format

When a recipient is used for encryption, the stanza uses the following values (encoded in base64 without padding):

```
-> fido2-hmac <HMAC salt (32 byte)> <Nonce (12 byte)> <Credential ID>
<wrapped file key>
```


If an identity is used, the credential ID is omitted:

```
-> fido2-hmac <HMAC salt (32 byte)> <Nonce (12 byte)>
<wrapped file key>
```


## File Key Wrapping

### Encryption

1. Generate a random 32 byte `salt`.
2. Retrieve the HMAC `hmac-secret` from the fido2 token using the credential id and the `salt`.
3. Generate a random 12 byte `nonce`.
4. Encrypt the file key provided by age with ChaCha20Poly1305, using `hmac-secret` as key and the previously generated `nonce`.

The resulting ciphertext is passed to age together with the salt and nonce.

### Decryption

1. Retrieve the `nonce` and `salt` from age.
2. Generate the `hmac-secret` on the fido2 token using the credential id and the `salt`.
3. Decrypt the wrapped file key using the `hmac-secret` and `nonce`.

# References

[1] https://github.com/C2SP/C2SP/blob/main/age-plugin.md

