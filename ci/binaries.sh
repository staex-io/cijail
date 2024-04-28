#!/bin/sh

set -ex
if test "$GITHUB_REF_TYPE" != "tag"; then
    exit 0
fi
rust_flags="-Ccodegen-units=1 -Cstrip=symbols -Copt-level=3 -Cincremental=false -Clto=yes -Cembed-bitcode=yes"
target=x86_64-unknown-linux-gnu
export LIBSECCOMP_LINK_TYPE=static
export LIBSECCOMP_LIB_PATH=/usr/lib/x86_64-linux-gnu
glibc_version="$(getconf GNU_LIBC_VERSION | sed 's/ /-/g')"
env RUSTFLAGS="$rust_flags" \
    cargo build \
    --quiet \
    --release \
    --target "$target" \
    --no-default-features
mv target/"$target"/release/cijail cijail-"$glibc_version"
