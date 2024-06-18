FROM rust:latest as builder

WORKDIR /root/tng/
COPY . .
RUN cargo install --path .


FROM envoy:light as release

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
