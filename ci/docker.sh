#!/bin/sh

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update
    apt-get -qq install -y \
        ca-certificates \
        patchelf \
        libnss-myhostname
}

copy_libraries() {
    ldd "$1" |
        sed -rne 's/.*=> (.*) \(.*\)$/\1/p' |
        while read -r path; do
            cp -n "$path" "$lib"/ || true
        done
}

make_chroot() {
    lib=/usr/local/lib/cijail
    mkdir -p "$lib"
    for name in cijail cijail-proxy; do
        copy_libraries /usr/local/bin/$name
    done
    # nss modules
    ls -l /lib/x86_64-linux-gnu/libnss*
    for name in files dns myhostname; do
        file=/lib/x86_64-linux-gnu/libnss_$name.so.2
        if ! test -e "$file"; then
            file="/usr$file"
        fi
        copy_libraries "$file"
        cp "$file" "$lib"/
    done
    cp /lib64/ld-linux-x86-64.so.2 "$lib"/
    for name in cijail cijail-proxy; do
        patchelf \
            --set-interpreter "$lib"/ld-linux-x86-64.so.2 \
            --set-rpath "$lib" \
            /usr/local/bin/$name
        ldd /usr/local/bin/$name
    done
    for file in "$lib"/lib*.so*; do
        patchelf --set-rpath "$lib" "$file"
        ldd "$file"
    done
    cijail --version
    find /usr/local -type d -empty -delete
    find /usr/local
}

set -ex
install_dependencies
make_chroot
