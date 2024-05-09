# Introduction

Cijail is a CI/CD pipeline process jail that helps prevent supply chain attacks.
Cijail filters outgoing network traffic in accordance with
- allow list of HTTP/HTTPS URLs,
- allow list of endpoints (specified by an IP:PORT, UNIX domain socket path or netlink socket) and
- allow list of DNS names.

**By default the outgoing traffic for all domain names, IP addresses and ports is blocked.**
Cijail makes it impossible to exfiltrate the data over DNS and makes it difficult to do by other means.

Cijail is implemented using [`seccomp`](https://man7.org/linux/man-pages/man2/seccomp.2.html) and
sometimes needs [`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability to read memory of the processes being traced.
Our local Docker installation does not require this privilege,
whereas Github Actions runners require.
The capability is dropped before the command is executed.

URL filtering is implemented using HTTP/HTTPS proxy that runs locally.
We automatically set the usual `http_proxy` and `https_proxy` variables,
and similar variables for `git`, `pip`, `npm` etc.
Please, create an issue if your build tool does not work.

HTTPS proxy creates root CA certificate that is used to sign every response sent to the client.
Currently this CA certificate is automatically installed as trusted into the system store.
Usually this is enough to make most of the applications recognize it as trusted.
Please, create an issue if your build tool does not work.


# Usage


## Use manually

Cijail will print all IP addresses, ports nad domain names that it blocked
as well as the corresponding system calls.
The output looks like the following.
```bash
# DNS request (connection to DNS server is allowed whereas name resolution is not)
🌊 env CIJAIL_ENDPOINTS='one.one.one.one:53' \
    cijail \
    dig staex.io @1.1.1.1
[Sun Apr 04 17:28:22 2024] cijail: allow connect 1.1.1.1:53
[Sun Apr 04 17:28:22 2024] cijail: deny sendmmsg staex.io

# HTTPS request (specific URL is allowed)
🌊 env CIJAIL_ENDPOINTS='https://api.github.com/repos/staex-io/cijail/releases' \
    cijail \
    curl https://api.github.com/repos/staex-io/cijail/releases
[Thu May 09 07:20:45 2024] cijail-proxy: allow 200 https://api.github.com/repos/staex-io/cijail/releases
```

- Use `CIJAIL_ENDPOINTS` to restrict which endpoints are allowed to be sent traffic to.
  These can be DNS names (i.e. allow only name resolution, but not the traffic),
  DNS names plus port, IP address plus port, HTTP/HTTPS URL, UNIX socket paths netlink sockets.
- Use `CIJAIL_DRY_RUN=1` to discover what is blocked by the current rules.
  Specifying `CIJAIL_DRY_RUN=0` is not mandatory.
  Dry run always fails.
- Use `CIJAIL_ALLOW_LOOPBACK=1` to allow sending any traffic to any address and port
  in the loopback network
  (`127.0.0.1/8` and `::1`).

Below are `CIJAIL_ENDPOINTS` examples.
```bash
https://github.com/    # allow HTTPS packets to/from github.com:443 with a URL starting with "https://github.com/"
1.1.1.1:53             # allow TCP/UDP packets to/from 1.1.1.1:53
one.one.one.one        # allow DNS packets that resolve `one.one.one.one` to IP addresses
@/tmp/unix             # allow packets to/from abstract UNIX socket with path "\0/tmp/unix"
/tmp/unix              # allow packets to/from named UNIX socket with path "/tmp/unix"
[netlink]              # allow packets to/from netlink socket
```


## Use in Github Actions

Add the following lines to your `Dockerfile`.

```dockerfile
COPY --from=ghcr.io/staex-io/cijail:latest / /usr/local
ENTRYPOINT ["/usr/local/bin/cijail"]
```

Then in your CI/CD pipeline define a list of allowed domain names and endpoints.

```yaml
jobs:
  build:
    container:
      image: your-image-with-cijail-installed-as-entrypoint
      options: --cap-add CAP_SYS_PTRACE
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

Then you *might* need to add `CAP_SYS_PTRACE` capability to your Gitlab runner configuration.
Currently this is supported only for the runners that you host yourself.
To do that add the following lines to `/etc/gitlab-runner/config.toml`.

```toml
[[runners]]
  [runners.docker]
    cap_add = ["SYS_PTRACE"]
```


# Caveats

- You can not run `cijail` inside another `cijail`. We are investigating the issue.
- Cijail **must be** the first process that you run in the Docker container
  because it controls only its descendants.
  Usually this is not a problem in CI/CD.
