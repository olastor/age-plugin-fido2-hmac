module github.com/olastor/age-plugin-fido2-hmac

go 1.22

toolchain go1.22.1

require (
	filippo.io/age v1.1.2-0.20230920124100-101cc8676386
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/keys-pub/go-libfido2 v1.5.3
	github.com/olastor/age-plugin-sss v0.2.1
	golang.org/x/crypto v0.22.0
	golang.org/x/sys v0.19.0
	golang.org/x/term v0.19.0
)

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/hashicorp/vault v1.15.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
)
