DOCKER := docker
SHELL := /bin/bash

REPO_ROOT := $$(git rev-parse --show-toplevel)

DOCKER_PROPERTIES_FILE := $(REPO_ROOT)/docker.properties

DOCKER_DIR=$(REPO_ROOT)/tools/docker

IMAGE_PREFIX := ghcr.io/vietanhduong/go-bpf

DEBUG_IMAGE := $(IMAGE_PREFIX)-debug
DEBUG_IMAGE_TAG := $$(grep DEBUG_IMAGE_TAG $(DOCKER_PROPERTIES_FILE) | cut -d'=' -f2)

BCC_REF := ec49363e2e9daec026ee6cae4c5fc316f8fab0ff

.PHONY: build_debug_image
build_debug_image:
	$(DOCKER) build --build-arg BCC_REF=$(BCC_REF) \
		-t $(DEBUG_IMAGE):$(DEBUG_IMAGE_TAG)  \
		-f $(DOCKER_DIR)/Dockerfile.debug \
		$(REPO_ROOT) 

.PHONY: push_debug_image
push_debug_image: build_debug_image
	$(DOCKER) push $(DEBUG_IMAGE):$(DEBUG_IMAGE_TAG)
