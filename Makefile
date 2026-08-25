BINARY_NAME=cipher
WINDOWS_BINARY=cipher.exe

.PHONY: all build test clean run scan sarif help

all: test build

build:
	go build -o $(BINARY_NAME) ./cmd/cipher

build-windows:
	go build -o $(WINDOWS_BINARY) ./cmd/cipher

test:
	go test -v ./...

scan: build
	./$(BINARY_NAME) scan .

scan-history: build
	./$(BINARY_NAME) scan --history .

sarif: build
	./$(BINARY_NAME) scan --format sarif --output results.sarif .

clean:
	rm -f $(BINARY_NAME) $(WINDOWS_BINARY) results.sarif *.test coverage.html