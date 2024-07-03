FROM rust:latest as builder

WORKDIR /root/tng/
COPY . .
RUN cargo install --path .


FROM tng-envoy:latest as release

RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
