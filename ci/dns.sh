#!/bin/sh
set -ex
printf "nameserver 9.9.9.9\n" >/etc/resolv.conf
column -t </proc/mounts
cat /proc/mounts
