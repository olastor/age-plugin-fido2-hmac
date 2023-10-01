# spec

Version: 1.0.0
Status: Draft

This plugin implements the C2SP age-plugin specification [[1]](#references)

# Motivation


## Names

- Plugin Name: `fido2-hmac`
- Binary Name: `age-plugin-fido2-hmac`
- Recipient Prefix: `age1fido2-hmac`
- Identity Prefix: `AGE-PLUGIN-FIDO2-HMAC-`

## Recipients & Identities

For wrapping/unwrapping the file key provided by age, both the (physical) **fido2 authenticator** and the **non-discoverable credential** generated with it must be present.

Depending on whether or not the _credential id_ is kept as a separate secret there are two ways of defining recipients and identites. This plugin supports both types.

### Encryption using "recipients"

If the _credential ID_ shall be treated as _public_ information, the plugin includes it both in an age recipient string and the stanza stored in the header of the encrypted file. For decryption, only the fido2 token needs to be presented. However, since age might enforce the presence of an identity, the plugin in this case accepts a static, "magic" identity, which simply is the BECH32 encoded plugin name: `AGE-PLUGIN-FIDO2-HMAC-1QYQXV6TYDUEZ66RDV93SQUSDAT`.

This mode of encryption opts for convenience, but does not protect well against compromise of the (physical) fido2 token. It is therefore recommended to activate "user verification", i.e., via PIN, when creating the recipient.

#### Format

The recipient encodes the following data in Bech32 using the recipient HRP:

```
<recipient format version (1 byte)><credential id>
```

where the first byte is reserved for a version number starting with 0x00 and is incremented everytime the data in the recipient changes.

### Encryption using "identities"

In contrast to the above, the plugin also allows for creating age identities which contain a credential id, treating them as _private_ information. For encryption, the identity is provided instead of a recipient and the credential id is **not** included in the stanza. Thus, decryption requires the exact same identity in addition to the presence of the (physical) fido2 token.

This mode of encryption emphasizes security and anonymity. Without the age identity, it is impossible to decrypt the file or identify the fido2 token used for encryption. The user is responsible for keeping the age identity secret and preventing it from being lossed.

#### Format

The identity encodes the following data in Bech32 using the identity HRP:

```
<identity format version (1 byte)><credential id>
```

where the first byte is reserved for a version number starting with 0x00 and is incremented everytime the data in the identity changes.

### Credential

- uv
- allowlist


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

The resulting ciphertext is passed to age in the stanza.

### Decryption

1. Retrieve the `nonce` and `salt` from age.
2. Generate the `hmac-secret` on the fido2 token using the credential id and the `salt`.
3. Decrypt the wrapped file key using the `hmac-secret` and `nonce`.

# UX Considerations

## Multiple Keys

### Creating new recipients/identities

When trying to create a new recipient/identity, the plugin MUST fail if there are more than one fido2 tokens inserted.

### File key wrapping/unwrapping

After the list of valid recipients/identities has been assembled or whenever a token is required for performing an HMAC challenge, the plugin MUST prompt the user to insert a matching fido2 token if no token is found. If there already are one ore more tokens inserted, the plugin MUST start trying these in any order.

When trying to create an HMAC challenge using a token and a specific credential ID, the fido2 library might raise an error because the combination is wrong ("device not egligible"). This error MUST be ignored if at least one of the tries with different credential IDs succeed, regardless of any file index.

Once all wrapping/unwrapping tries with a specific token have been done, the plugin MUST NOT try to use the same token again while it is still inserted. If the user removes it and inserts it again, the plugin MAY stop ignoring this token.

After a specific file key has been unwrapped, the plugin MUST NOT try to unwrap any more stanzas for the same file. The unwrapped file key is sent to age immediately.

The plugin MUST NOT expect the user to insert the same fido2 token multiple times. All wrapping/unwrapping operations with a specific token, e.g., for different files, MUST be done the first time the fido2 token is presented. However, multiple wrapping/unwrapping operations might require multiple confirmations or user verification prompts.

If a fido2 token is forcefully removed by the user while it still being used, the plugin MUST raise an error and fail.

# References

[1] https://github.com/C2SP/C2SP/blob/main/age-plugin.md

