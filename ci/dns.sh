#!/bin/sh
set -ex
printf "nameserver 9.9.9.9\n" >/etc/resolv.conf
cat /proc/mounts
mount
