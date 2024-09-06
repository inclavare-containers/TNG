FROM rust:bullseye as builder

WORKDIR /root/tng/
COPY . .

RUN cargo install --path .

RUN strip /usr/local/cargo/bin/tng


FROM tng-envoy:latest as release

RUN apt-get update && apt-get install -y curl iptables && rm -rf /var/lib/apt/lists/* && update-alternatives --set iptables /usr/sbin/iptables-nft

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
