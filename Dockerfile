# Postfix Policy Filter (Milter)
# docker run -d -p 9998:9998 -e DEBUG=true ... policyfilter

ARG BUILD_FROM_PREFIX

FROM ${BUILD_FROM_PREFIX}golang:alpine AS builder
RUN apk --no-cache add gcc musl-dev git
WORKDIR /go/src/
COPY . /go/src/
ARG BUILD_VERSION
ARG BUILD_DATE
ARG BUILD_REF
ARG BUILD_GOARCH
ARG BUILD_GOOS
RUN export GOPROXY=direct \
 && go mod download \
 && go mod verify \
 && CGO_ENABLED=0 go build \
    -ldflags "-s -w" -o /app

FROM scratch
COPY --from=builder /app /policyfilter
ENTRYPOINT ["/policyfilter"]
EXPOSE 9998

ARG BUILD_VERSION
ARG BUILD_DATE
ARG BUILD_REF
LABEL Description="Postfix Policy Filter (Milter)" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.build-date="${BUILD_DATE}" \
  org.label-schema.name="policyfilter" \
  org.label-schema.description="Postfix Policy Filter (Milter)" \
  org.label-schema.vcs-ref="${BUILD_REF}" \
  org.label-schema.version="${BUILD_VERSION}" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  org.opencontainers.image.title="policyfilter" \
  org.opencontainers.image.description="Postfix Policy Filter (Milter)" \
  org.opencontainers.image.version="${BUILD_VERSION}" \
  org.opencontainers.image.ref.name="policyfilter" \
  version="${BUILD_VERSION}"
