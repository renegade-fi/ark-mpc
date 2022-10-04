# Used for running integration tests on a simulated MPC network
FROM rust:1.63-slim-buster AS builder

WORKDIR /build
# Place a set of dummy sources in the path, build the dummy executable
# to cache built dependencies, then bulid the full executable
RUN mkdir src
RUN touch src/dummy-lib.rs
RUN mkdir integration
RUN echo 'fn main() { println!("dummy main!") }' >> integration/dummy-main.rs

COPY Cargo.toml .
COPY Cargo.lock .

# Modify the Cargo.toml to point to our dummy sources
RUN sed -i 's/lib.rs/dummy-lib.rs/g' Cargo.toml
RUN sed -i 's/main.rs/dummy-main.rs/g' Cargo.toml

RUN cargo build --test integration

# Edit the Cargo.toml back to the original, build the full executable
RUN sed -i 's/dummy-lib.rs/lib.rs/g' Cargo.toml
RUN sed -i 's/dummy-main.rs/main.rs/g' Cargo.toml

COPY src ./src
COPY integration ./integration

RUN cargo build --test integration

CMD [ "cargo", "test" ]
