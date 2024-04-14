build:
	go build ./cmd/...

test: build
	go test -v ./...

test-e2e: build
	testscript ./cmd/age-plugin-fido2-hmac/testdata/*.txt

format:
	go fmt ./pkg/... ./cmd/...

clean:
	rm -f age-plugin-fido2-hmac
