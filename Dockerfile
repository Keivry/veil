# veil 网关镜像：builder 编译 + runtime 运行，多阶段构建。
# runtime 仅含二进制与最小运行库，不含 Rust 工具链与构建依赖。

# ---- builder：编译阶段（含完整 Rust 工具链）----
# 此处用 stable（仅编译，不跑 fmt/clippy，故不需要开发侧的 nightly 工具链，避免构建期
# 额外下载）；下限由 `Cargo.toml` 的 `package.rust-version` 声明，base tag 落后会立即
# 在 cargo 处 fail-fast（不再等到 E0658）。改动 base tag 须重跑 `docker build` 验证。
FROM docker.io/library/rust:1.98.1-slim-bookworm AS builder

WORKDIR /app

# 构建期依赖：reqwest 的 `rustls` feature 经 `aws-lc-rs`（`aws-lc-sys`）编译 C/C++ 源码，
# 需要 C++ 编译器与 cmake；`rust:slim` 只自带 gcc/cc/perl，缺 g++/cmake/make，故显式安装
# （仅 builder 阶段，不影响 runtime 体积）。
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ cmake make \
    && rm -rf /var/lib/apt/lists/*

# 先拷贝清单文件，利用构建缓存加速依赖编译。
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# ---- runtime：运行阶段（无工具链，仅运行必需品）----
FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-log-init --create-home --home-dir /home/veil veil \
    && mkdir -p /data \
    && chown veil:veil /data

COPY --from=builder /app/target/release/veil /usr/local/bin/veil

USER veil
WORKDIR /data
VOLUME ["/data"]

# 容器内服务固定监听 8877（见 src/main.rs），宿主机侧三端口映射见 docker-compose.yml。
EXPOSE 8877

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8877/health | grep -q '"ok"'

ENTRYPOINT ["/usr/local/bin/veil"]
