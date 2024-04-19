# Used for running integration tests on a simulated MPC network
FROM --platform=arm64 rust:latest AS chef

WORKDIR /build
COPY ./rust-toolchain ./rust-toolchain
RUN rustup install $(cat rust-toolchain)

RUN apt-get update && apt-get install -y \
    libsodium-dev \
    libgmp-dev \
    libboost-all-dev \
    libntl-dev \
    libssl-dev \
    clang 

ENV PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
ENV CXX=clang++

# Install chef and generate a recipe
RUN cargo install cargo-chef

COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./offline-phase ./offline-phase
COPY ./online-phase ./online-phase
COPY ./mp-spdz-rs ./mp-spdz-rs
COPY ./integration/src ./integration/src
COPY ./integration/Cargo.toml ./integration/Cargo.toml
RUN cargo chef prepare --recipe-path recipe.json

# Disable compiler warnings and enable backtraces for panic
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

# Build only the dependencies to cache them in this layer
RUN cargo chef cook --tests --release --recipe-path recipe.json

# Copy back in the full sources and build the tests
WORKDIR /build
COPY . .

WORKDIR /build/integration
RUN cargo build --quiet --all-features --release