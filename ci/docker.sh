#!/bin/sh

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update
    apt-get -qq install -y ca-certificates patchelf
}

make_chroot() {
    lib=/usr/local/lib/cijail
    mkdir -p "$lib"
    for name in cijail cijail-proxy; do
        ldd /usr/local/bin/$name |
            sed -rne 's/.*=> (.*) \(.*\)$/\1/p' |
            while read -r path; do
                cp -n "$path" "$lib"/ || true
            done
    done
    cp /lib64/ld-linux-x86-64.so.2 "$lib"/
    find "$lib"
    for name in cijail cijail-proxy; do
        patchelf \
            --set-interpreter "$lib"/ld-linux-x86-64.so.2 \
            --set-rpath "$lib" /usr/local/bin/$name
        ldd /usr/local/bin/$name
    done
    cijail --version
    cijail -- cijail --version
    find /usr/local -type d -empty -delete
    find /usr/local
}

set -ex
install_dependencies
make_chroot
