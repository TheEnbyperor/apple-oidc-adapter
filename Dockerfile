FROM messense/rust-musl-cross:x86_64-musl AS build
WORKDIR /usr/src

RUN USER=root cargo new apple-oidc-adapter
WORKDIR /usr/src/apple-oidc-adapter
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

COPY src ./src
RUN  touch src/main.rs && cargo install --target x86_64-unknown-linux-musl --path .

FROM quay.io/nitrous/ca-certs-scratch
COPY --from=build /root/.cargo/bin/apple-oidc-adapter .
USER 1000
CMD ["./apple-oidc-adapter"]