.DEFAULT_GOAL := build

.PHONY: build go_build go_test_unit

# Project-specific variables
#
# Binary name
BINARY:=virgil

#
# General variables
#
# Packages covered with unit tests.
GO_UNIT_TESTED_PACKAGES=$(shell go list ./...)



ifneq ($(shell go env GOOS),darwin)
    GO_BUILD_LDFLAGS+= -linkmode external -extldflags '-static'
endif

ifeq ($(shell go env GOOS),windows)
	BINARY:=$(BINARY).exe
endif

ifeq ($(shell go env GOARCH), 386)
	VIRGIL_PACKAGE_ARCH=i386
endif

ifeq ($(shell go env GOARCH), amd64)
	VIRGIL_PACKAGE_ARCH=x86_64
endif

VERSION=$(shell cat VERSION)
OS=$(shell go env GOOS)



# Go build flags.
GO_BUILD_FLAGS=-v --ldflags "$(GO_BUILD_LDFLAGS)" -a -installsuffix cgo

#
# Build targets
#

build: go_get go_build
tests: go_test_functional

go_build:
	@echo ">>> Building go binary."
	go build $(GO_BUILD_FLAGS) -o $(BINARY)

go_get:
	@echo ">>> Getting dependencies."
	go get ./...

go_test_unit:
	@echo ">>> Running unit tests."
	@go test -cover $(GO_UNIT_TESTED_PACKAGES)

go_test_functional:
	@echo ">>> Running functional tests."
	@go test -v -tags="functional" ./test/functional

pack_artifacts:
	@echo ">>> Archiving artifact"
	mkdir -p artifacts
	if [ "$(OS)" = "windows" ]; then \
  		zip artifacts/Virgil_$(VERSION)_$(OS)_$(VIRGIL_PACKAGE_ARCH).zip $(BINARY); \
  	else \
  		tar cvzf artifacts/Virgil_$(VERSION)_$(OS)_$(VIRGIL_PACKAGE_ARCH).tar.gz $(BINARY); \
  	fi
