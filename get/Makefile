.PHONY: build clean install test vet check

BINARY ?= ./get-credential-linux-amd64

build:
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	@echo "Built: $(BINARY)"

test:
	go test ./...

vet:
	go vet ./...

check: vet test
