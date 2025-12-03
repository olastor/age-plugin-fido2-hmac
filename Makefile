build:
	go build -ldflags "-X main.Version=$$(git describe --tags --always)" ./cmd/...

test: build
	go test -v ./...

test-e2e: build
	testscript ./cmd/age-plugin-fido2-hmac/testdata/*.txtar

format:
	go fmt ./pkg/... ./cmd/...

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

clean:
	rm -f age-plugin-fido2-hmac
