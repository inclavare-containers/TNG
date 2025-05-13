#
# A special image to pull all code from git submodule
#
FROM registry.openanolis.cn/openanolis/anolisos:8 as code-pull

RUN yum install -y git

WORKDIR /code/

COPY . /code/

RUN { [ -e ./.git/modules/deps/rats-rs ] || git submodule update --init ./deps/rats-rs ; }


#
# tng
#
FROM registry.openanolis.cn/openanolis/anolisos:8 as tng-builder

RUN yum install -y cargo protobuf-compiler

WORKDIR /root/tng/
COPY --from=code-pull /code/rust-toolchain.toml .

COPY --from=code-pull /code/. .

RUN cargo install --locked --path . --root /usr/local/cargo/


FROM registry.openanolis.cn/openanolis/anolisos:8 as tng-release

RUN yum install -y curl iptables && yum clean all

COPY --from=tng-builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
