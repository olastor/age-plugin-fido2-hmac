module github.com/olastor/age-plugin-fido2-hmac

go 1.24.0

toolchain go1.24.10

require filippo.io/age v1.3.1

require (
	github.com/olastor/go-libfido2 v0.0.0-20250611191617-da5602ad9fbe
	golang.org/x/crypto v0.45.0
	golang.org/x/sys v0.38.0
	golang.org/x/term v0.37.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
)
