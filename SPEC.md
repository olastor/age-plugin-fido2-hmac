# spec

This plugin implements the C2SP age-plugin specification [[1]](#references)

## Identities

Due to the symmetric nature of the cryptographic operations this plugin does not generate or consume any "recipients", but only "identities" starting with the Bech32-HRP `AGE-PLUGIN-FIDO2-HMAC-`.

Conceptually, an identity consists of two parts: the (physical) **fido2 authenticator** and a **non-discoverable credential** generated with it.

To address different use-cases and security demands, this plugin provides two types of identities:

1. Only the authenticator is needed for decryption (default).
2. Both the authenticator **AND** the age identity string must be provided for decryption.

### Type 1: Default Identity

The default identity stores the credential ID as _public_ information in the recipient stanza's metadata. Thus, only the fido2 authenticator is needed for decryption and the Bech32 encoded identity must not be especially secured against unauthorized access.


### Type 2: "Hidden" Identity



## File Key Wrapping


## Stanza Format


# References

[1] https://github.com/C2SP/C2SP/blob/main/age-plugin.md

