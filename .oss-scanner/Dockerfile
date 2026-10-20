# Builds russignol for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner clones this repository, builds this file with the checkout as context, then analyses the image
# with no network, so everything a build or test needs is fetched here.
FROM rust:1-trixie
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    RUST_BACKTRACE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential clang pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Scanner contract: the checkout lives inside the image, at /src.
COPY . /src
WORKDIR /src

# The scanner's clone leaves submodules empty. libs/xmss builds on leanVM's crates; buildroot and rpi-linux
# build only the SD card image, which the scan does not cover.
RUN git submodule update --init vendors/leanVM-b

# Tests that force a write to fail do it by making a directory read-only, which root ignores, so everything
# from here runs unprivileged, as the signer does on the device.
RUN useradd --create-home builder && chown -R builder /src "$CARGO_HOME"
USER builder

RUN cargo fetch --locked
ENV CARGO_NET_OFFLINE=true

# Host debug builds: the signer, its libraries and the host utility all build and test on x86-64, and the
# debug profile keeps debug info and overflow checks.
RUN cargo build --locked --workspace --all-targets

RUN (cargo test --locked --workspace || echo "WARNING: cargo test reported failures")
