# age-plugin-fido2-hmac

⚠️ **Use at own risk and consider this plugin to be experimental** ⚠️

## Requirements

- [age](https://github.com/FiloSottile/age) >= 1.1.0

## Installation

```bash
git clone https://github.com/olastor/age-plugin-fido2-hmac.git
cd age-plugin-fido2-hmac
pip install .
```

## Usage

### Examples

**Create a recipient/identity using a specific algorithm**

By default, one of the following algorithms is picked (in that order): ES256, EdDSA, RS256. If you want the credential to use a specific algorithm, use the `-a` parameter:

```bash
age-plugin-fido2-hmac -a eddsa -n
```

Note that your authenticator may not support some algorithms.

