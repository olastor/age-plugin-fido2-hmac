# age-plugin-fido2-hmac

Plugin for symmetric file encryption using age and fido2 tokens (that support the _hmac-secret_ extension). Thus, key generation is done in a stateless manner. See [SPEC.md](https://github.com/olastor/age-plugin-fido2-hmac/blob/main/SPEC.md) for more details.

⚠️ **Use at own risk and consider this plugin to be experimental.** ⚠️

## Requirements

- [age](https://github.com/FiloSottile/age) (>= 1.1.0) or [rage](https://github.com/str4d/rage)
  - Prefer `rage` when encrypting to multiple fido2 tokens (because of [#525](https://github.com/FiloSottile/age/issues/526)).

## Installation

```bash
git clone https://github.com/olastor/age-plugin-fido2-hmac.git
cd age-plugin-fido2-hmac
pip install .
```

## Usage

### Generate a new recpient/identity

```
$ age-plugin-fido2-hmac -n
Please insert your fido2 token now...
Please enter the PIN:
Please touch the authenticator.
Do you want to require a PIN for encryption/decryption? [y/N]: y
Do you want to create a secret identity? [y/N]: N
# -> prints either recipient ("age1fido2-hmac1...") or identity ("AGE-PLUGIN-FIDO2-HMAC-...")
```

- Don't loose your fido2 token (obviously)!
- You can only require a PIN if you have one set (obviously)!
- Keep identities secret and don't loose them!
- Keep track of which token matches which identity (if you have multiple fido2 tokens)!
- You cannot encrypt to a recipient without your fido2 token.\*
- To decrypt files encrypted with a recipient use the magic identity (`age-plugin-fido2-hmac -m`).
- To decrypt files encrypted with an identity use the same identity.

\* In contrast to asymmetric key pairs, this plugin uses symmetric encryption, meaning for both encryption and decryption the plugin needs to interact with the fido2 token. The difference between a recipient and an identity is nuanced. Basically identities isolate additional information required for decryption, while recipients treat that as public metadata. See [SPEC.md](https://github.com/olastor/age-plugin-fido2-hmac/blob/main/SPEC.md) for more details.

### Encrypting/Decrypting

**Encryption:**

```bash
cat test.txt | rage -r age1fido2-hmac1... -o test.txt.enc
```

or

```bash
cat test.txt | rage -e -i identity.txt -o test.txt.enc
```

**Decryption:**

```bash
age-plugin-fido2-hmac -m > magic.txt
cat test.txt.enc | age -d -i magic.txt -o test-decrypted.txt
```

or

```bash
cat test.txt.enc | age -d -i identity.txt -o test-decrypted.txt
```

### Choosing a different algorithm

By default, one of the following algorithms is picked (in that order): ES256, EdDSA, RS256. If you want the credential to use a specific algorithm, use the `-a` parameter:

```bash
age-plugin-fido2-hmac -a eddsa -n
```

Note that

- your authenticator **may not support** all algorithms,
- the length of recipient/identity strings **can increase dramatically** by using a different algorithm.

The default (in most cases) is "es256", which should provide the smallest recipient/identity strings.

