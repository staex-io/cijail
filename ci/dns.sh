#!/bin/sh
set -ex
if test -z ${CI+x}; then
    exit 0
fi
printf "nameserver 9.9.9.9\n" >/etc/resolv.conf
