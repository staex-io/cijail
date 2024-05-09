#!/bin/sh

cleanup() {
    rm -rf "$workdir"
    docker rmi "$tag"-test:latest 2>/dev/null || true
}

build_docker_image() {
    mkdir "$workdir"/tar
    tar -C "$workdir"/tar -xf "$root"/packages/cijail-glibc-2.31/cijail-glibc-2.31.tar.gz
    cp "$root"/ci/docker.sh "$workdir"
    cat >"$workdir"/Dockerfile <<EOF
FROM debian:bullseye AS builder
COPY tar /usr/local
COPY docker.sh /tmp/docker.sh
RUN /tmp/docker.sh
FROM scratch
COPY --from=builder /usr/local /
LABEL org.opencontainers.image.source=https://github.com/staex-io/cijail
LABEL org.opencontainers.image.description="Cijail image"
LABEL org.opencontainers.image.version=$cijail_version
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.vendor=Staex
EOF
    docker build --tag "$tag":latest --tag "$tag":"$cijail_version" "$workdir"
}

test_docker_image() {
    # deb-based
    for image in debian:bullseye ubuntu:22.04; do
        cat >"$workdir"/Dockerfile <<EOF
FROM $image
RUN apt-get -qq update && apt-get -qq install -y openssl ca-certificates
COPY --from=$tag:latest / /usr/local
EOF
        do_test_docker_image
    done
    # rpm-based
    for image in rockylinux:8 rockylinux:9; do
        cat >"$workdir"/Dockerfile <<EOF
FROM $image
RUN dnf install -y openssl ca-certificates
COPY --from=$tag:latest / /usr/local
EOF
        do_test_docker_image
    done
}

do_test_docker_image() {
    docker build --tag "$tag"-test:latest - <"$workdir"/Dockerfile
    docker run --rm "$tag"-test:latest /usr/local/bin/cijail --version
    timeout --signal=KILL 30s \
        docker run --rm --cap-add CAP_SYS_PTRACE "$tag"-test:latest /usr/local/bin/cijail true
    docker rmi "$tag"-test:latest
}

push_docker_image() {
    if test "$GITHUB_ACTIONS" = "true" && test "$GITHUB_REF_TYPE" = "tag"; then
        set +x
        printf '%s' "$GHCR_TOKEN" | docker login --username token --password-stdin
        set -x
        docker push "$tag":latest
        docker push "$tag":"$cijail_version"
    fi
}

set -ex
trap cleanup EXIT
workdir="$(mktemp -d)"
root="$PWD"
tag=ghcr.io/staex-io/cijail
cijail_version="$(git describe --tags --always)"

build_docker_image
test_docker_image
push_docker_image
