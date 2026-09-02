VERSION        ?= 0.1.0
IMAGE_NAME     ?= ghcr.io/fmurrie/godaddy-webhook
IMAGE_TAG      ?= dev
TEST_ZONE_NAME ?= example.com.

OUT := $(shell pwd)/_out

$(shell mkdir -p "$(OUT)")

clean:
	rm -rf vendor
	rm -Rf $(OUT)
	rm -rf apiserver.local.config

install-tools:
	bash ./scripts/fetch-test-binaries.sh

verify: test

test: ## Run unit tests without external DNS credentials.
	go test ./...

test-conformance: clean install-tools ## Run DNS provider conformance tests with dedicated test credentials.
	@test -n "$(TEST_ZONE_NAME)" || { echo "ERROR: set TEST_ZONE_NAME" >&2; exit 2; }
	@test -n "$(GODADDY_TEST_TOKEN)" || { echo "ERROR: set GODADDY_TEST_TOKEN" >&2; exit 2; }
	TEST_ASSET_ETCD=$(OUT)/kubebuilder/bin/etcd \
	TEST_ASSET_KUBECTL=$(OUT)/kubebuilder/bin/kubectl \
	TEST_ASSET_KUBE_APISERVER=$(OUT)/kubebuilder/bin/kube-apiserver \
	TEST_ZONE_NAME=$(TEST_ZONE_NAME) \
	TEST_DNS_SERVER=$(TEST_DNS_SERVER) GODADDY_TEST_TOKEN=$(GODADDY_TEST_TOKEN) go test -tags=integration .

compile:
	echo "### Go mod vendor ..."
	go mod vendor
	echo "### Compile the webhook ..."
	CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

push:
	docker push "$(IMAGE_NAME):$(IMAGE_TAG)"

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
	    --name godaddy-webhook \
        --set image.repository=$(IMAGE_NAME) \
        --set image.tag=$(IMAGE_TAG) \
        deploy/godaddy-webhook > "$(OUT)/rendered-manifest.yaml"

version:
	@echo $(VERSION)
