BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
SHA1 := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
SHORT_SHA1 := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
ORIGIN := $(shell git remote get-url origin 2>/dev/null || echo unknown)
DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%Sz')
VER := $(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.1)
DOCK_REPO := patrickdk/policyfilter

export DOCKERFILE_PATH=Dockerfile
export DOCKER_REPO=$(DOCK_REPO)
export DOCKER_TAG=latest
export GIT_BRANCH=$(BRANCH)
export GIT_SHA1=$(SHA1)
export GIT_SHORT_SHA1=$(SHORT_SHA1)
export GIT_TAG=$(SHA1)
export GIT_VERSION=$(VER)
export GIT_VERSION_MAJOR=$(shell echo $(VER) | cut -f1 -d. 2>/dev/null)
export GIT_VERSION_MINOR=$(shell echo $(VER) | cut -f2 -d. 2>/dev/null)
export IMAGE_NAME=$(DOCKER_REPO):$(VER)
export SOURCE_BRANCH=$(BRANCH)
export SOURCE_COMMIT=$(SHA1)
export SOURCE_TYPE=git
export SOURCE_REPOSITORY_URL=$(ORIGIN)

all: buildx

buildx:
	docker buildx build --pull --push \
		--platform linux/amd64,linux/arm64 \
		--build-arg BUILD_GOOS=linux \
		--build-arg BUILD_DATE=${DATE} \
		--build-arg BUILD_REF=${GIT_SHORT_SHA1} \
		--build-arg BUILD_VERSION=${GIT_VERSION} \
		--build-arg BUILD_REPO=${BUILD_REPO} \
		--file ${DOCKERFILE_PATH} \
		--tag ${IMAGE_NAME} \
		.
	skopeo copy --all docker://${IMAGE_NAME} docker://${DOCKER_REPO}:${GIT_VERSION_MAJOR}
	skopeo copy --all docker://${IMAGE_NAME} docker://${DOCKER_REPO}:${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}
	skopeo copy --all docker://${IMAGE_NAME} docker://${DOCKER_REPO}:latest

build:
	CGO_ENABLED=0 GOAMD64=v2 go build -mod=vendor -ldflags "-s -w"

update:
	GOPROXY=direct go get -u
	GOPROXY=direct go mod tidy

deps:
	GOPROXY=direct go mod vendor
	$(MAKE) vendor-patch

vendor-patch:
	@for p in patches/*.patch; do \
		echo "Applying $$p ..."; \
		patch -p0 --forward --reject-file=- < $$p || exit 1; \
	done

test:
	@docker run --rm -it -v "${PWD}:/go/src/policyfilter/" \
			-w /go/src/policyfilter/ \
	    golangci/golangci-lint:latest-alpine \
			golangci-lint run --config .golangci.yml || true
	@docker run --rm -it -v "${PWD}:/go/src/policyfilter/" \
			-w /go/src/policyfilter/ \
			golangci/golangci-lint:latest-alpine \
			sh -c "go list ./... | grep -v /vendor/ | xargs go test -p 1 -count=1"
