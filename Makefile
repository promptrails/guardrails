.PHONY: all build test lint fmt vet sec coverage clean

all: fmt vet lint sec test build

build:
	go build ./...

test:
	go test -race -count=1 ./...

coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

sec:
	gosec -quiet ./...

clean:
	rm -f coverage.out coverage.html
