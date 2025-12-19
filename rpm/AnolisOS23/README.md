# TNG RPM 构建与验证指南

本文档旨在指导用户如何在本地环境中复现 TNG RPM 包的构建过程，并验证构建的可重复性。

## 构建流程概述

TNG RPM 包的构建分为两个主要阶段：
1. **构建材料准备阶段**：创建包含所有源代码和依赖项的构建材料包
2. **RPM 构建阶段**：使用构建材料包在容器化环境中构建 RPM 包

## 本地复现构建步骤

### 1. 准备工作

确保您的系统已安装以下工具：
- Docker
- wget 或 curl

### 2. 下载构建材料

从 GitHub Release 页面下载 `rb-build-materials-*.tar.gz` 文件：

```bash
# 替换 ${RELEASE_VERSION} 为实际的版本标签，例如 v1.7.0
wget https://github.com/inclavare-containers/TNG/releases/download/${RELEASE_VERSION}/rb-build-materials-${RELEASE_VERSION}.tar.gz
```

### 3. 提取构建材料

```bash
tar -xzf rb-build-materials-${RELEASE_VERSION}.tar.gz
```

提取后，您将看到 AnolisOS23 目录，其中包含：
- `Dockerfile`：用于构建 RPM 的容器镜像定义
- `build-in-docker.sh`：容器内的构建脚本
- `build-artifacts-${RELEASE_VERSION}.tar.gz`：包含 SPECS 和 SOURCES 的构建工件包
- `README.md`：构建说明（本文档）

### 4. 构建 RPM 容器镜像

```bash
cd AnolisOS23
docker build --no-cache -t rpm-builder:${RELEASE_VERSION} .
```

### 5. 执行 RPM 构建

```bash
# 确保在 AnolisOS23 目录中
mkdir -p rpm-out
docker run --rm \
  -v "$PWD:/input" \
  -v "$PWD/rpm-out:/output" \
  rpm-builder:${RELEASE_VERSION} \
  build-artifacts-${RELEASE_VERSION}.tar.gz
```

构建完成后，RPM 包将位于 `rpm-out` 目录中。

## 验证构建可重复性

为了验证构建的可重复性，请按照以下步骤操作：

### 1. 获取官方发布的 RPM 包哈希值

从 GitHub Release 页面下载官方发布的 RPM 包，并计算其 SHA256 哈希值：

```bash
# 下载官方 RPM 包（示例）
wget https://github.com/inclavare-containers/TNG/releases/download/${RELEASE_VERSION}/TNG-${RELEASE_VERSION}.al8.x86_64.rpm

# 计算哈希值
sha256sum TNG-${RELEASE_VERSION}.al8.x86_64.rpm
```

### 2. 计算本地构建的 RPM 包哈希值

```bash
# 计算本地构建的 RPM 包哈希值
sha256sum rpm-out/RPMS/x86_64/TNG-${RELEASE_VERSION}.al8.x86_64.rpm
```

### 3. 比较哈希值

如果本地构建的 RPM 包与官方发布的 RPM 包具有相同的 SHA256 哈希值，则表明构建是可重复的。

### 4. 验证所有 RPM 包

对于发布的所有 RPM 包（包括源 RPM 和二进制 RPM），都应执行上述验证步骤：

```bash
# 对于源 RPM
sha256sum rpm-out/SRPMS/TNG-${RELEASE_VERSION}.src.rpm

# 对于二进制 RPM（如果有多个）
sha256sum rpm-out/RPMS/x86_64/*.rpm
```

## 故障排除

### 构建失败

如果构建过程中出现错误，请检查：
1. Docker 是否正常运行
2. 构建材料包是否完整且未损坏
3. 系统是否有足够的磁盘空间和内存

### 哈希值不匹配

如果本地构建的 RPM 包与官方发布的版本哈希值不匹配：
1. 确认使用的 `rb-build-materials-*.tar.gz` 文件版本与官方发布版本一致
2. 确认严格按照本文档步骤执行构建过程
3. 检查构建环境是否与官方构建环境一致

## 附加信息

### 构建材料包内容

`rb-build-materials-*.tar.gz` 文件包含：
- 所有源代码和资源文件
- 预编译的依赖项（如 Rust 依赖）
- RPM 构建所需的 SPEC 文件
- 构建脚本和 Dockerfile
- `build-artifacts-${RELEASE_VERSION}.tar.gz`：实际用于 RPM 构建的工件包

### 构建环境

RPM 包在以下环境中构建：
- 基础镜像：openanolis/anolisos:23
- 构建工具：rpm-build、cargo 等
- 所有依赖项均在容器内安装和配置
