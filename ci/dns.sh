#!/bin/sh
set -ex
printf "nameserver 9.9.9.9\n" >/etc/resolv.conf
chmod +x /usr/local/bin/cijail
