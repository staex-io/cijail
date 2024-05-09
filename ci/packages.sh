#!/bin/sh

cleanup() {
    rm -rf "$workdir"
    rm "$tarfiles"
}

set -ex
# TODO
#if test "$GITHUB_ACTIONS" = "true" && test "$GITHUB_REF_TYPE" != "tag"; then
#    exit 0
#fi
trap cleanup EXIT
workdir="$(mktemp -d)"
tarfiles="$(mktemp)"
root="$PWD"
mkdir -p "$root"/packages
for dir in "$root"/binaries/glibc-*; do
    glibc_version="$(basename "$dir")"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    for name in cijail cijail-proxy; do
        install -m755 -D "$dir"/$name "$workdir"/bin/$name
    done
    install -m644 -D "$root"/LICENSE "$workdir"/share/cijail/LICENSE
    cd "$workdir"
    find . -type f -print0 >"$tarfiles"
    tar_filename="$root"/packages/cijail-"$glibc_version"/cijail-"$glibc_version".tar.gz
    mkdir -p "$(dirname "$tar_filename")"
    tar -cz --null --files-from "$tarfiles" -f "$tar_filename"
    cd "$dir"
done

for dir in "$root"/packages/*; do
    cd "$dir"
    for file in *.tar.gz; do
        sha256sum "$file" >"$file"-sha256sum.txt
    done
done
