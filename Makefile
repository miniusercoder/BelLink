PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

bee2-lib:
	@echo "Building bee2 static library..."
	@mkdir -p bee2/build
	@cd bee2/build && cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_PIC=ON -DBUILD_CMD=OFF -DBUILD_TESTS=OFF -DBUILD_DOC=OFF ..
	@$(MAKE) -C bee2/build -j4

wireguard-go: bee2-lib $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

test: bee2-lib
	go test ./...

clean:
	rm -f wireguard-go
	rm -rf bee2/build

.PHONY: all clean test install generate-version-and-build
