# age-plugin-fido2-hmac

⚠️ Consider this plugin to be experimental until the version v1.0.0 is published! ⚠️

---

:key: Encrypt files with fido2 keys that support the "hmac-secret" extension.

:hash: Unlimited generation of recipients/identities because generated fido2 credentials are stateless.

:memo: See [the spec](https://github.com/olastor/age-plugin-fido2-hmac/blob/main/docs/spec-v2.md) for more details.

---


## Requirements

- [age](https://github.com/FiloSottile/age) (>= 1.1.0) or [rage](https://github.com/str4d/rage)
- [libfido2](https://developers.yubico.com/libfido2/)

**Ubuntu (>= 20.04)**

```bash
sudo apt install libfido2-1 libfido2-dev libfido2-doc fido2-tools
```

**Fedora (>= 34)**

```bash
sudo dnf install libfido2 libfido2-devel fido2-tools
```

**Mac OS**

```bash
brew install libfido2
```

## Installation

Download a the latest binary from the [release page](https://github.com/olastor/age-plugin-fido2-hmac/releases). Copy the binary to your `$PATH` (preferably in `$(which age)`) and make sure it's executable.

You can also use the following script for installation:

- Installs binary to `~/.local/bin/age-plugin-fido2-hmac` (change to your preferred directory)
- Make sure to adjust `OS` and `ARCH` if needed (`OS=darwin ARCH=arm64` for Apple Silicon, `OS=darwin ARCH=amd64` for older Macs)

```bash
cd "$(mktemp -d)"
VERSION=v0.2.4 OS=linux ARCH=amd64; curl -L "https://github.com/olastor/age-plugin-fido2-hmac/releases/download/$VERSION/age-plugin-fido2-hmac-$VERSION-$OS-$ARCH.tar.gz" -o age-plugin-fido2-hmac.tar.gz
tar -xzf age-plugin-fido2-hmac.tar.gz
mv age-plugin-fido2-hmac/age-plugin-fido2-hmac ~/.local/bin
```

Please note that Windows builds are currently not enabled, but if you need them please open a new issue and I'll try to look into it.

## Build from source

```bash
git clone https://github.com/olastor/age-plugin-fido2-hmac.git
cd age-plugin-fido2-hmac
make build
mv ./age-plugin-fido2-hmac ~/.local/bin/age-plugin-fido2-hmac
```

(requires Go 1.22)

## Usage

### Generate a new recpient/identity

Generate new credentials with the following command:

```
$ age-plugin-fido2-hmac -g
[*] Please insert your token now...
Please enter your PIN:
[*] Please touch your token...
[*] Do you want to require a PIN for decryption? [y/n]: y
[*] Please touch your token...
[*] Are you fine with having a separate identity (better privacy)? [y/n]: y
# created: 2024-04-21T16:54:23+02:00
# public key: age1zdy49ek6z60q9r34vf5mmzkx6u43pr9haqdh5lqdg7fh5tpwlfwqea356l
AGE-PLUGIN-FIDO2-HMAC-1QQPQZRFR7ZZ2WCV...
```

You can decide between storing your fido2 credential / salt inside the encrypted file header (benefit: no separate identity / downside: ciphertexts can be linked) or in a separate identity (benefit: native age recipient, unlinkabilty / downside: keep identity stored securely somewhere). To decrypt files without an identity, add `-j fido2-hmac` instead of `-i identity.txt` to your age command (e.g. `age -d -j fido2-hmac -o test.txt test.txt.enc`) or use the output of `age-plugin-fido2-hmac -m` as the identity alternatively.

You are responsible for knowing which token matches your recipient / identity. There is no token identifier stored. If you have multiple tokens and forgot which one you used, there's no other way than trial/error to find out which one it was.

If you require a PIN for decryption, you (obviously) must not forget it. The PIN check is not just an UI guard, but the token changes the secret it uses internal!

### Encrypting/Decrypting

**Encryption:**

```bash
age -r age1... -o test.txt.enc test.txt
```

**Decryption:**

```bash
age -d -j fido2-hmac -o test-decrypted.txt test.txt.enc
```

or

```bash
age -d -i identity.txt -o test-decrypted.txt test.txt.enc
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

End-to-end tests can currently no be run in the CI/CD pipeline because they require a virtual fido2 token to be mounted.

Use the following to setup a virtual test device with pin "1234" that always accepts any assertions:

```bash
go install github.com/rogpeppe/go-internal/cmd/testscript@latest # check PATH includes $HOME/go/bin/
sudo dnf install usbip clang clang-devel
git clone https://github.com/Nitrokey/nitrokey-3-firmware.git
cd nitrokey-3-firmware/runners/usbip
cargo build
cargo run -- --ifs ../../../e2e/test_device.bin
make attach # separate shell
```

Then run the tests using:

```bash
make test-e2e
```
