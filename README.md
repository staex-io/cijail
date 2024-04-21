Cijail is a CI/CD pipeline process jail that helps prevent supply chain attacks.
Cijail filters outgoing network traffic in accordance with
- allow list of endpoints (specified by an IP address and a port) and
- allow list of DNS names.

**By default the outgoing traffic for all domain names, IP addresses and ports is blocked.**
Cijail makes it impossible to exfiltrate the data over DNS and makes it difficult to do by other means.
(The future versions will include H TTPS URL filter as well that would give even more granular control.)

Cijail is implemented using [`seccomp`](https://man7.org/linux/man-pages/man2/seccomp.2.html) and
needs [`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html) privilege to read memory of the processes being traced.


# Usage

## Run manually

```bash
env CIJAIL_ALLOWED_ENDPOINTS='one.one.one.one:53 github.com:433' \
    CIJAIL_ALLOWED_DNS_NAMES='github.com' \
    cijail \
    YOUR COMMAND AND ARGS
```

## Run in Github Actions

Add the following lines to your `Dockerfile`.

```dockerfile
RUN glibc_version="$(getconf GNU_LIBC_VERSION | sed 's/ /-/g')" \
    cijail_version=0.1.0 \
    && curl \
    --silent \
    --fail \
    --location \
    --output /usr/local/bin/cijail \
    https://github.com/staex-io/cijail/releases/download/$cijail_version/cijail-$glibc_version
```

If there is no matching glibc version, try to choose the lowest one (currently `glibc-2.31`).

Then in your CI/CD pipeline define a list of allowed domain names.
