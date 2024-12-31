#
# A special image to pull all code from git submodule
#
FROM registry.openanolis.cn/openanolis/anolisos:8 as code-pull

RUN yum install -y git

WORKDIR /code/

COPY . /code/

RUN { [ -e ./.git/modules/deps/rats-rs ] || git submodule update --init ./deps/rats-rs ; } \
    && { [ -e ./.git/modules/deps/tng-envoy ] || git submodule update --init ./deps/tng-envoy ; }

#
# rats-rs
#
FROM registry.openanolis.cn/openanolis/anolisos:8 as rats-rs-builder

# install some necessary packages
RUN yum install -y make git vim gcc \
        pkg-config protobuf-compiler cmake \
        wget net-tools curl file gnupg tree libcurl-devel \
        libseccomp-devel openssl-devel binutils-devel protobuf-devel \
        clang jq cargo rust

# install "just"
RUN cargo install just

ENV PATH="$PATH:/root/.cargo/bin"


FROM rats-rs-builder as rats-rs-builder-c-api-coco-only

WORKDIR /root/rats-rs
COPY --from=code-pull /code/deps/rats-rs/. .

# Some hacks to convert git submodule to standalone git repo
RUN rm -f .git && mkdir .git
COPY --from=code-pull /code/.git/modules/deps/rats-rs/. .git/
RUN sed -i '/worktree/d' .git/config

# build headers and librarys (with CoCo attester and CoCo verifier only)
RUN just install-c-api-coco

#
# tng-envoy
#
FROM envoyproxy/envoy-build-ubuntu:26c6bcc3af3d6ad166c42b550de672d40209bc1c as tng-envoy-builder

# Copy rats-rs products as dependency
COPY --from=rats-rs-builder-c-api-coco-only /usr/local/include/rats-rs /usr/local/include/rats-rs
COPY --from=rats-rs-builder-c-api-coco-only /usr/local/lib/rats-rs/ /usr/local/lib/rats-rs/

# prepare envoy source code
RUN useradd -m -s /bin/bash newuser
WORKDIR /home/newuser/envoy
COPY --from=code-pull /code/deps/tng-envoy/. .
## Some hacks to convert git submodule to standalone git repo
RUN rm -f .git && mkdir .git
COPY --from=code-pull /code/.git/modules/deps/tng-envoy/. .git/
RUN sed -i '/worktree/d' .git/config
RUN chown -R newuser:newuser .
USER newuser

# build envoy
RUN bazel/setup_clang.sh /opt/llvm/
RUN echo "build --config=clang" >> user.bazelrc
RUN bazel build -c opt envoy
RUN chmod 0777 bazel-bin/source/exe/envoy-static && \
    strip bazel-bin/source/exe/envoy-static


FROM registry.openanolis.cn/openanolis/anolisos:8 as tng-envoy-release

RUN yum install -y openssl

# copy envoy-static
COPY --from=tng-envoy-builder /home/newuser/envoy/bazel-bin/source/exe/envoy-static /usr/local/bin/envoy-static

# copy dependencies
COPY --from=rats-rs-builder-c-api-coco-only /usr/local/lib/rats-rs/ /usr/local/lib/rats-rs/

CMD ["envoy-static", "-c", "/etc/envoy.yaml", "-l", "off", "--component-log-level", "upstream:error,connection:debug,rats-rs:debug"]


#
# tng
#
FROM registry.openanolis.cn/openanolis/anolisos:8 as tng-builder

WORKDIR /root/tng/
COPY --from=code-pull /code/rust-toolchain.toml .

COPY --from=code-pull /code/. .

RUN cargo install --path .

RUN strip /usr/local/cargo/bin/tng


FROM tng-envoy-release as tng-release

RUN yum install -y curl iptables && yum clean all

COPY --from=tng-builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
