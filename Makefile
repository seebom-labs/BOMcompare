VERSION ?= dev

.PHONY: all build test lint golden dist clean

all: lint test build

## build: build ./bomcompare for the host platform
build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bomcompare ./cmd/bomcompare

## test: run all tests (incl. race detector)
test:
	go test -count=1 -race ./...

## lint: gofmt + go vet
lint:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...

## golden: regenerate report golden files after an intentional output change
golden:
	go test ./pkg/report -run TestGolden -update

## dist: cross-compile release archives + checksums into dist/ (VERSION=X.Y.Z)
dist:
	hack/dist.sh $(VERSION)

clean:
	rm -rf bomcompare dist
