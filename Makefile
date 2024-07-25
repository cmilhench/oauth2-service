default: help
.PHONY: default

name    ?= $(notdir $(realpath $(dir $(realpath $(MAKEFILE_LIST)))))
registry = 799148671415.dkr.ecr.eu-west-2.amazonaws.com
revision ?= $(shell ./scripts/version.sh)

help: # This
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
.PHONY: help

deps: ## Install dependencies
	@echo "==> Installing dependencies"
	@go mod tidy
.PHONY: deps

gen: clean ## Run the code generation
	@go generate ./...
.PHONY: gen

lint: gen ## Run the linter
	$(call cyan, "Linting...")
	@go vet ./... 2>&1 || echo ''
.PHONY: lint

quality: ## Run various code quality assurance checks
	$(call cyan, "Scanning...")
	$(call check-dependency,docker)
	@docker run --rm -i hadolint/hadolint < Dockerfile 2>&1  || echo ''
	@docker run --rm -i -v "`pwd`:/app" -v ~/.cache/golangci-lint/v1.59.1:/root/.cache -w /app golangci/golangci-lint:v1.59.1 golangci-lint run 2>&1  || echo ''
.PHONT: quality

image: lint ## Create Docker image
	$(call cyan, "Continerising...")
	$(call check-dependency,docker)
	@docker build --tag $(name):latest --tag $(name):$(revision) .
.PHONY: image

publish: image ## Publish to container registory, assumes image is built
	$(call cyan, "Publishing...")
	$(call check-dependency,docker)
	$(call check-dependency,aws)
	@docker tag $(name):latest $(registry)/$(name):$(revision)
	@aws ecr get-login-password --region eu-west-2 | \
	  docker login --username AWS --password-stdin ${registry}
	@docker push $(registry)/$(name):$(revision)
.PHONY: publish

test: lint ## Run the project tests
	$(call cyan, "Testing...")
	$(call setenv,)
	@go test -short -cover ./...
.PHONY: test

start: test ## Start the server
	$(call cyan, "Running...")
	$(call setenv,)
	@go run -ldflags '-w -s ' ./cmd/
.PHONY: start

watch: ## Run locally and monitor for changes
	$(call check-dependency,entr)
	@find . -type f -not -path './vendor/*' -a -not -path '*/\.*' -a -not -path './docs/*' -a -not -path '.data/*' \
	| entr -rcs 'make start -f ./Makefile'
.PHONY: watch

clean:
	@go clean
	@rm -f .version
	@rm -f $(name)
.PHONY: clean

define check-dependency
	$(if $(shell command -v $(1)),,$(error Make sure $(1) is installed))
endef

define red
  @printf '\033[31m'
	@echo $1
	@printf '\033[39m'
endef

define cyan
  @printf '\033[36m'
	@echo $1
	@printf '\033[39m'
endef

define setenv
    $(eval include $1.env)
    $(eval export)
endef
