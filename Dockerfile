FROM registry.openanolis.cn/openanolis/anolisos:8 AS builder

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain none

WORKDIR /code/

COPY rust-toolchain.toml .

# install toolchain and cache it
RUN . "$HOME/.cargo/env" && rustup show

RUN yum install -y git protobuf-devel gcc

COPY . .

RUN . "$HOME/.cargo/env" && env RUSTFLAGS="--cfg tokio_unstable" cargo install --locked --path ./tng/ --root /usr/local/cargo/


FROM registry.openanolis.cn/openanolis/anolisos:8 AS release

RUN yum install -y curl iptables && yum clean all

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
