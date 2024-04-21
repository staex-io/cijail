#!/bin/sh

libseccomp_version=2.5.5

cleanup() {
    rm -rf "$workdir"
}

libseccomp_build() {
    git clone --quiet https://github.com/seccomp/libseccomp "$workdir"
    cd "$workdir"
    git checkout v"$libseccomp_version"
    autoreconf -vif
    ./configure --prefix=/opt/libseccomp --enable-static --disable-shared
    make -j"$(nproc)"
    make install
    cd "$rootdir"
}

set -ex
rootdir="$PWD"
workdir="$(mktemp -d)"
rust_flags="-Ccodegen-units=1 -Cstrip=symbols -Copt-level=3 -Cincremental=false -Clto=yes -Cembed-bitcode=yes"
target=x86_64-unknown-linux-musl
export LIBSECCOMP_LINK_TYPE=static
export LIBSECCOMP_LIB_PATH=/usr/lib/x86_64-linux-gnu
apt-get update -qq
apt-get install clang -y
env RUSTFLAGS="$rust_flags" \
    cargo build \
    --quiet \
    --release \
    --target "$target" \
    --no-default-features
mv target/"$target"/release/cijail cijail
