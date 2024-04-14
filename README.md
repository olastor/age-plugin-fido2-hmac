# age-plugin-fido2-hmac

⚠️ Consider this plugin to be experimental until the version v1.0.0 is published! ⚠️

---

:key: Encrypt files with fido2 keys that support the "hmac-secret" extension.

:hash: Unlimited generation of recipients/identities because generated fido2 credentials are stateless.

:memo: See [the spec](https://github.com/olastor/age-plugin-fido2-hmac/blob/main/docs/spec-v2.md) for more details.

---



## Requirements

- [age](https://github.com/FiloSottile/age) (>= 1.1.0) or [rage](https://github.com/str4d/rage)
  - Prefer `rage` when encrypting to multiple fido2 tokens (because of [#525](https://github.com/FiloSottile/age/issues/526)).

## Installation

Download a the latest binary from the [release page](https://github.com/olastor/age-plugin-fido2-hmac/releases).

## Build from source

```bash
git clone https://github.com/olastor/age-plugin-fido2-hmac
cd age-plugin-fido2-hmac
make build
mv ./age-plugin-fido2-hmac ~/.local/bin/age-plugin-fido2-hmac
```

## Usage

### Generate a new recpient/identity

```
$ age-plugin-fido2-hmac -g
[*] Please insert your token now...
[*] Please touch your token...
[*] Please touch your token...
[*] Are you fine with having a separate identity (better privacy)? [y/n]: y
# created: 2024-04-14T21:49:50+02:00
# public key: age1ss38ngkwaw570ucj778flepkenj7c2p98gtwweptpdfmde045fmshhpsna
AGE-PLUGIN-FIDO2-HMAC-1QQPQQ7W0A8EDJCQ53YKMM0XVP...
```

- Don't loose your fido2 token (obviously)!
- You can only require a PIN if you have one set (obviously)!
- Keep identities secret and don't loose them!
- Keep track of which token matches which identity (if you have multiple fido2 tokens)!
- You cannot encrypt to a recipient without your fido2 token.\*
- To decrypt files without an identity, use the magic identity (`age-plugin-fido2-hmac -m`).

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
age-plugin-fido2-hmac -a eddsa -g
```

Note that

- your authenticator **may not support** all algorithms,
- the length of recipient/identity strings **can increase dramatically** by using a different algorithm.

The default (in most cases) is "es256", which should provide the smallest recipient/identity strings.

## Testing

### Unit Tests

In order to run unit tests, execute:

```bash
make test
```

### E2E Tests

Use the following to setup a virtual test device without pin that always accepts any assertions:

```bash
git clone https://github.com/Nitrokey/nitrokey-3-firmware.git
cd nitrokey-3-firmware
nitrokey-3-firmware/runners/usbip
cargo build
cargo run
make attach # separate shell
```

Then run the tests using:

```bash
make test-e2e
```
