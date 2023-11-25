# age-plugin-fido2-hmac

⚠️ **Use at own risk and consider this plugin to be experimental** ⚠️

## Requirements

- [rage](https://github.com/str4d/rage) (preferred because of [#525](https://github.com/FiloSottile/age/issues/526)) or [age](https://github.com/FiloSottile/age) >= 1.1.0

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
```

The above shows an example generation of an recipient string starting with `age1fido2-hmac1` (printed to STDOUT). Please note:

- The PIN prompt and question only appears if your device has a PIN set.
- If you answer "yes" to the identity question, the output has an upper case format (`AGE-PLUGIN-FIDO2-HMAC-1`) and must be kept secret. In contrast, recipient strings are not considered sensitive information. More information below.

**Important:** You are responsible for keeping track of which recipient or identity matches which of your fido2 tokens! If you choose to create an identity and loose the secret identity string, you will no longer be able to decrypt any files previously encrypted with that identity (having the fido2 token is not sufficient in this case)!

### Encrypting/Decrypting a file using a recipient

**Encryption:**

```bash
cat test.txt | rage -r age1fido2-hmac1... -o test.txt.enc
```

Follow the instructions for interacting with your device.

**Decryption:**

When using recipients no additional identity is required as all metadata for unwrapping with the fido2 token is stored in the file header (see spec). However, `age`/`rage` requires an identity parameter for decryption. To address this, this plugin uses a static (magic) identity which is ignored by the plugin and only used to circumvent this requirement:

```bash
age-plugin-fido2-hmac -m > magic.txt
cat test.txt.enc | rage -d -i magic.txt -o test-decrypted.txt
```

Follow the instructions for interacting with your device.

### Encrypting/Decrypting a file using an identity

When you chose to create an identity then you need to provide it for every decryption, as well. Loosing either your identity string or your physical fido2 token will make it impossible to decrypt any file that was encrypted with this combination.

The identity stores a unique non-discoverable fido2 credential which is not stored in the encrypted file. Thus, identities makes it impossible for anyone in possession of the encrypted file and your fido2 token to determine if the file was encrypted with that token or not (let alone decrypting the file). It is a security feature, but the risk of loosing access to the file by either loosing the identity string or token is greater than using recipients (where the fido2 credential is not kept secret).

TLDR; You always need **both** your fido2 authenticator + your identity string.

**Encryption:**

Put your previously generated identity in an identity file and pass it to the `-i` parameter:

```bash
cat test.txt | rage -e -i identity.txt -o test.txt.enc
```

Follow the instructions for interacting with your device.

**Decryption:**

```bash
cat test.txt.enc | rage -d -i identity.txt -o test-decrypted.txt
```

Follow the instructions for interacting with your device.

### Choosing a different algorithm

By default, one of the following algorithms is picked (in that order): ES256, EdDSA, RS256. If you want the credential to use a specific algorithm, use the `-a` parameter:

```bash
age-plugin-fido2-hmac -a eddsa -n
```

Note that your authenticator may not support some algorithms and that the size of recipient/identity strings can increase dramatically by using a different algorithm.


