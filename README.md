# Introduction

Cijail is a CI/CD pipeline process jail that helps prevent supply chain attacks.
Cijail filters outgoing network traffic in accordance with
- allow list of endpoints (specified by an IP address and a port) and
- allow list of DNS names.

**By default the outgoing traffic for all domain names, IP addresses and ports is blocked.**
Cijail makes it impossible to exfiltrate the data over DNS and makes it difficult to do by other means.
(The future versions will include HTTPS URL filter as well that would give even more granular control.)

Cijail is implemented using [`seccomp`](https://man7.org/linux/man-pages/man2/seccomp.2.html).


# Usage

## Use manually

Cijail will print all IP addresses, ports nad domain names that it blocked
as well as the corresponding system calls.
The output looks like the following.
```
$ env CIJAIL_ENDPOINTS='one.one.one.one:53' \
      cijail \
      dig staex.io @1.1.1.1
[Sun Apr 04 17:28:22 2024] cijail: allow connect 1.1.1.1:53
[Sun Apr 04 17:28:22 2024] cijail: deny sendmmsg staex.io
```

## Use in Github Actions

Add the following lines to your `Dockerfile`.

```dockerfile
RUN glibc_version="$(getconf GNU_LIBC_VERSION | sed 's/ /-/g')" \
    cijail_version=0.2.0 \
    curl \
    --silent \
    --fail \
    --location \
    --output /usr/local/bin/cijail \
    https://github.com/staex-io/cijail/releases/download/$cijail_version/cijail-$glibc_version \
    && chmod +x /usr/local/bin/cijail

ENTRYPOINT ["/usr/local/bin/cijail"]
```

If there is no matching glibc version, try to choose the lowest one (currently `glibc-2.31`).

Then in your CI/CD pipeline define a list of allowed domain names and endpoints.

```yaml
jobs:
  build:
    container:
      image: your-image-with-cijail-installed-as-entrypoint
    env:
      CIJAIL_ENDPOINTS: github.com:443
    steps:
      - name: Lint
        run: cijail ./ci/lint.sh
      - name: Test
        run: cijail ./ci/test.sh
```

⚠️ Github Actions do not respect Docker's `ENTRYPOINT`,
and you have to prepend `cijail` to every command in each step.

See this repository's [Github workflow](.github/workflows/ci.yml) as a real-world example.


## Use in a Gitlab pipeline

Add the following lines to your `.gitlab-ci.yml`.

```yaml
variables:
  CIJAIL_ENDPOINTS: gitlab.com:443
```

✅ Gitlab CI/CD pipelines respect Docker's `ENTRYPOINT`,
and you do not have to prepend `cijail` to every command.
