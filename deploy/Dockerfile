# Distroless, nonroot, no shell.
#
# The binary is static because the crypto is Go's own -- no cgo, so nothing to
# link against at runtime. That is what makes `distroless/static` enough, and it
# is one of the reasons ADR-011 keeps the core in Go rather than reaching for a
# C or Rust library (see ADR-011).
#
# This file builds from source. Release images come from goreleaser, which builds
# the binary once and copies it in; see .goreleaser.yaml.

# A supported Go, not the module's floor: the standard library is part of what
# this image ships, and a release the Go team no longer patches ships its holes.
# Both bases are pinned by digest, because a tag can be moved and a digest
# cannot; Dependabot keeps tag and digest current together.
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src

# Dependencies first, so a source-only change does not refetch them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
# CGO off for a static binary; the trimmed paths and -s -w keep the image and the
# build reproducible.
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/blindbucket ./cmd/blindbucket

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/blindbucket /blindbucket

# 65532 is distroless's nonroot user. The keyring must be readable by it and by
# nobody else; mount it read-only.
#
# There is no writable directory in this image. A deployment that enables the
# audit log has to mount one and make it writable by 65532 -- see
# deploy/kubernetes-sidecar.yaml.
USER 65532:65532
EXPOSE 9000 9100

# No shell in the image, so this is an exec-form entrypoint and there is nothing
# to interpolate.
ENTRYPOINT ["/blindbucket"]
CMD ["serve", "--config", "/etc/blindbucket/blindbucket.yaml"]
