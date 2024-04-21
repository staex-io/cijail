FROM rust:1.76.0

RUN apt-get -qq update \
    && apt-get -qq install --no-install-recommends \
    pre-commit \
    python3-pip \
    lcov \
    libclang-dev \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --quiet --no-cache-dir --no-input --break-system-packages lcov_cobertura==2.0.*

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    RUST_VERSION=1.76.0 \
    PATH=/usr/local/cargo/bin:$PATH

RUN rustup toolchain add nightly --target x86_64-unknown-linux-gnu
RUN rustup toolchain add 1.76.0 \
    --target x86_64-unknown-linux-gnu \
    --component clippy rustfmt llvm-tools-preview
RUN rustup target add --toolchain 1.76.0 \
    x86_64-unknown-linux-musl
RUN rustup default 1.76.0-x86_64-unknown-linux-gnu
RUN cargo install --quiet cargo-llvm-cov
RUN cargo install --quiet cargo-deny
RUN cargo install --quiet cargo-about

RUN curl --location --silent --fail --output /usr/bin/shfmt https://github.com/mvdan/sh/releases/download/v3.8.0/shfmt_v3.8.0_linux_amd64 && \
    chmod +x /usr/bin/shfmt

LABEL org.opencontainers.image.source=https://github.com/staex-io/cijail
LABEL org.opencontainers.image.description="CI image"

CMD ["/bin/bash"]
