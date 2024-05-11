#!/bin/sh

cleanup() {
    rm -rf "$workdir"
}

build_libseccomp() {
    git clone \
        --depth=1 \
        --branch v$libseccomp_version \
        https://github.com/seccomp/libseccomp \
        "$workdir"/libseccomp
    cd "$workdir"/libseccomp
    # https://git.alpinelinux.org/aports/tree/main/libseccomp?id=bdeb5ac39445d803f7d97bb9b3cf9171d9a35f52
    sed -i '/\#include <sys\/prctl.h>/d' src/system.c
    grep prctl src/system.c || true
    autoreconf -vif
    ./configure \
        --prefix=/opt/libseccomp \
        --disable-shared \
        --enable-static \
        CC=musl-gcc \
        LD=musl-gcc \
        CPPFLAGS=-I/usr/include/alpine
    make -j"$(nproc)"
    make install
}

build_openssl() {
    git clone \
        --depth=1 \
        --branch openssl-$openssl_version \
        https://github.com/openssl/openssl \
        "$workdir"/openssl
    cd "$workdir"/openssl
    openssl_dir=/usr/local/cijail/ssl
    ./Configure \
        --prefix=/opt/openssl \
        --openssldir="$openssl_dir" \
        -static
    make -j"$(nproc)"
    make install_sw install_ssldirs
    cp /etc/ssl/certs/ca-certificates.crt "$openssl_dir"/certs/
}

libseccomp_version=2.5.5
openssl_version=3.3.0
set -ex
trap cleanup EXIT
workdir="$(mktemp -d)"
build_libseccomp
build_openssl
