FROM registry.openanolis.cn/openanolis/anolisos:8 AS builder

RUN yum install -y git cargo protobuf-compiler

WORKDIR /code/

COPY . .

RUN env RUSTFLAGS="--cfg tokio_unstable" cargo install --locked --path ./tng/ --root /usr/local/cargo/


FROM registry.openanolis.cn/openanolis/anolisos:8 AS release

RUN yum install -y curl iptables && yum clean all

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
