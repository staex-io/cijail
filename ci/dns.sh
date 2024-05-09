#!/bin/sh
set -ex
git config --global --add safe.directory "$PWD"
printf "nameserver 9.9.9.9\n" >/etc/resolv.conf
