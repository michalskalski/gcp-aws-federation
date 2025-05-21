TOP_LEVEL_DIR := $(shell git rev-parse --show-toplevel)
BIN_DIR := $(TOP_LEVEL_DIR)/bin
BASEIMAGE := gcr.io/distroless/static-debian12:nonroot
# Define variables
KO = $(BIN_DIR)/ko
CONTAINER_IMAGE_REPO ?= ko.local
CONTAINER_IMAGE_PREFIX ?= ""
CONTAINER_IMAGE_TAGS ?= $(shell git rev-parse --short HEAD)
KO_FLAGS := --platform=linux/amd64,linux/arm64

$(KO):
	mkdir -p $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/google/ko@latest

# Build and publish the container image with ko
.PHONY: build
build: $(KO)
	go build -o $(BIN_DIR)/sendmail .

.PHONY: clean
clean:
	-rm -rf $(BIN_DIR)
