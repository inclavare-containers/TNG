# Builder Dockerfile
FROM openanolis/anolisos:23@sha256:b0067a96f6f8a02d378304bd27ef7c3081f28d75a0003e2f145bf4412001d37c

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TZ=UTC
ENV SOURCE_DATE_EPOCH=1672531200
ENV RPM_BUILD_NCPUS=1

# 安装基本构建依赖
RUN dnf install -y \
    anolis-epao-release-23-4.an23.noarch \
    rpm-build-4.18.2-4.an23.x86_64 \
    rpmdevtools-9.6-5.an23.noarch \
    dnf-plugins-core-4.3.1-3.an23.noarch \
    gzip-1.12-3.an23.x86_64 \
    tar-2:1.35-1.an23.x86_64 \
    wget-1.24.5-1.an23.x86_64 \
    gcc-12.3.0-13.an23.x86_64 \
    make-4.4.1-2.an23.x86_64 \
    cargo-1.84.1-4.an23.x86_64 \
    rust-1.84.1-4.an23.x86_64 \
    && dnf clean all

# ============================== RPM ==============================
RUN echo '%build_mtime_policy clamp_to_source_date_epoch' > /etc/rpm/macros.buildroot && \
    echo '%clamp_mtime_to_source_date_epoch 1' >> /etc/rpm/macros.buildroot && \
    echo '%use_source_date_epoch_as_buildtime 1' >> /etc/rpm/macros.buildroot && \
    echo '%_buildhost reproducible' >> /etc/rpm/macros.buildroot

# ============================== Rust ==============================
RUN mkdir -p /root/.cargo && echo -e \
'[build]\n\
# 全局 rustflags，先留空，由 per-target 覆盖\n\
rustflags = []\n\
\n\
# 各主流架构的 target 配置\n\
# 1) x86_64 Linux（包括多数 Anolis / RHEL / Debian / Ubuntu x86_64）\n\
[target.x86_64-unknown-linux-gnu]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=x86-64",\n\
]\n\
\n\
[target.x86_64-unknown-linux-musl]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=x86-64",\n\
]\n\
\n\
# 2) AArch64 (arm64) Linux\n\
[target.aarch64-unknown-linux-gnu]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=generic",\n\
]\n\
\n\
[target.aarch64-unknown-linux-musl]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=generic",\n\
]\n\
\n\
# 3) ARMv7 (32-bit arm, hard float)\n\
[target.armv7-unknown-linux-gnueabihf]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=generic",\n\
]\n\
\n\
[target.armv7-unknown-linux-musleabihf]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=generic",\n\
]\n\
\n\
# 4) RISC-V 64\n\
[target.riscv64gc-unknown-linux-gnu]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=generic",\n\
]\n\
\n\
[target.riscv64gc-unknown-linux-musl]\n\
linker = "clang"\n\
rustflags = [\n\
#     "-C", "link-arg=-fuse-ld=lld",\n\
    "-C", "target-cpu=generic",\n\
]\n\
\n\
# Release Profile（面向可重现构建）\n\
[profile.release]\n\
codegen-units = 1\n\
lto = "fat"\n\
debug = 1' \
> /root/.cargo/config.toml

# =================================================================

# 复制构建脚本
COPY build-in-docker.sh /usr/local/bin/build-rpm.sh
RUN chmod +x /usr/local/bin/build-rpm.sh

# 默认工作目录
WORKDIR /input

# 入口：接受 tarball 名称作为参数
ENTRYPOINT ["/usr/local/bin/build-rpm.sh"]
