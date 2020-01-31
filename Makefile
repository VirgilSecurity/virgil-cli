.DEFAULT_GOAL := build

.PHONY: build go_build go_test_unit

# Project-specific variables
#
# Service name. Used for binary name, docker-compose service name, etc...
BINARY=virgil
# Path to service entry point.
GO_PATH_CLI_MAIN=./

#
# General variables
#
# Packages covered with unit tests.
GO_UNIT_TESTED_PACKAGES=$(shell go list ./...)
# Go modules mode
GO111MODULE=on


ifneq ($(shell go env GOOS),darwin)
    GO_BUILD_LDFLAGS+= -linkmode external -extldflags '-static'
endif

# Go build flags.
GO_BUILD_FLAGS=-v --ldflags "$(GO_BUILD_LDFLAGS)" -a -installsuffix cgo

#
# Build targets
#

build: go_test_unit go_build

go_build:
	@echo '>>> Building go binary.'
	go build $(GO_BUILD_FLAGS) -a -o $(BINARY) $(GO_PATH_CLI_MAIN);

go_test_unit:
	@echo ">>> Running unit tests."
	@go test -cover $(GO_UNIT_TESTED_PACKAGES)