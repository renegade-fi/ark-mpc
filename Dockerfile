# Used for running integration tests on a simulated MPC network
# Builder stage 
FROM rust:1.63-slim-buster AS builder

WORKDIR /build
COPY src ./src
COPY integration ./integration
COPY Cargo.toml .

RUN cargo build

# Executable stage
FROM debian:buster-slim as exec
COPY --from=builder \
	/build/target/debug/integration-tests \
	/usr/local/bin/integration-tests

CMD [ "integration-tests" ]
