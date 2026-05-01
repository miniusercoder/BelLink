PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
BEE2_BUILD_DIR := bee2go/bee2/build
BEE2_LIB := $(BEE2_BUILD_DIR)/src/libbee2_static.a
CMAKE_FLAGS := -DBUILD_SHARED_LIBS=OFF -DBUILD_PIC=ON -DBUILD_CMD=OFF \
               -DBUILD_TESTS=OFF -DBUILD_DOC=OFF -DBASH_PLATFORM=BASH_AVX2
export GO111MODULE := on

MAKEFLAGS += --no-print-directory

all: wireguard-go

help:
	@printf 'Usage: make [target]\n\n'
	@printf 'Build targets:\n'
	@printf '  all               Build wireguard-go (default)\n'
	@printf '  wireguard-go      Compile the wireguard-go binary\n'
	@printf '  bee2-lib          Build the bee2 C static library (CGo dependency)\n'
	@printf '\n'
	@printf 'Development targets:\n'
	@printf '  test              Run the full test suite\n'
	@printf '  install           Install wireguard-go to $(DESTDIR)$(BINDIR)\n'
	@printf '  clean             Remove build artifacts\n'
	@printf '  clean-all         Remove build artifacts including bee2 library\n'
	@printf '\n'
	@printf 'Variables:\n'
	@printf '  PREFIX=<path>     Installation prefix (default: /usr)\n'
	@printf '  DESTDIR=<path>    Staging directory for install (default: empty)\n'

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true

$(BEE2_LIB):
	@echo "Building bee2 static library..."
	@git -C bee2go submodule update --init
	@mkdir -p $(BEE2_BUILD_DIR)
	@cd $(BEE2_BUILD_DIR) && cmake $(CMAKE_FLAGS) ..
	@$(MAKE) -C $(BEE2_BUILD_DIR) -j$$(nproc 2>/dev/null || echo 4)

bee2-lib: $(BEE2_LIB)

wireguard-go: generate-version-and-build bee2-lib $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

test: bee2-lib
	go test ./...

clean:
	rm -f wireguard-go

clean-all: clean
	rm -rf $(BEE2_BUILD_DIR)

.PHONY: all help bee2-lib clean clean-all test install generate-version-and-build
