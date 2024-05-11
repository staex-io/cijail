#!/bin/sh

cleanup() {
    rm -rf "$workdir"
    rm "$tarfiles"
}

set -ex
trap cleanup EXIT
workdir="$(mktemp -d)"
tarfiles="$(mktemp)"
root="$PWD"
mkdir -p "$root"/packages
for name in cijail cijail-proxy; do
    install -m755 -D "$root"/binaries/$name "$workdir"/bin/$name
    for file in openssl.cnf certs/ca-certificates.crt; do
        install -m644 -D /usr/local/cijail/ssl/$file "$workdir"/cijail/ssl/$file
    done
done
install -m644 -D "$root"/LICENSE "$workdir"/share/cijail/LICENSE
cd "$workdir"
find . -type f -print0 >"$tarfiles"
tar_filename="$root"/packages/cijail.tar.gz
mkdir -p "$(dirname "$tar_filename")"
tar -cz --null --files-from "$tarfiles" -f "$tar_filename"
cd "$root"/packages
for file in *.tar.gz; do
    sha256sum "$file" >"$file"-sha256sum.txt
done
