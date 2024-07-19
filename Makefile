build:
	go build ./cmd/...

test: build
	go test -v ./...

test-e2e: build
	testscript -v ./cmd/age-plugin-fido2-hmac/testdata/*.txtar

format:
	go fmt ./pkg/... ./cmd/...

clean:
	rm -f age-plugin-fido2-hmac
