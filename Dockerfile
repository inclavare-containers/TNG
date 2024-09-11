FROM rust:bullseye as builder

RUN apt update && apt install -y musl-tools

WORKDIR /root/tng/
COPY ./rust-toolchain.toml .
RUN rustup target add x86_64-unknown-linux-musl

COPY . .

RUN cargo install --path . --target=x86_64-unknown-linux-musl

RUN strip /usr/local/cargo/bin/tng

FROM tng-envoy:latest as release

RUN apt-get update && apt-get install -y curl iptables && rm -rf /var/lib/apt/lists/* && update-alternatives --set iptables /usr/sbin/iptables-nft

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
