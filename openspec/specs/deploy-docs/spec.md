# deploy-docs Specification

## Purpose
提供顶层 README 作为部署与行为的唯一文档入口，并以多阶段 Dockerfile 与 docker-compose 交付物声明回环三端口（8877/8878/8879）与卷挂载的容器化部署约定。

## Requirements

### Requirement: 顶层 README 五节齐备

系统 SHALL 在仓库顶层提供 `README.md`，内容 MUST 覆盖部署方式、三因子鉴权、限流规则、阈值表、Go 客户端对接指引五节。

#### Scenario: 新人按 README 部署

- **WHEN** 新人仅按 README 部署章节操作
- **THEN** 可完成本地或容器启动并通过健康检查

#### Scenario: 阈值表与契约一致

- **WHEN** 比对 README 阈值表与 admin 限流契约 spec
- **THEN** 两处数值与语义完全一致无漂移

### Requirement: Dockerfile 多阶段构建

系统 SHALL 提供多阶段 `Dockerfile`，builder 阶段编译、runtime 阶段仅含运行必需品。

#### Scenario: 镜像构建成功

- **WHEN** 执行容器镜像构建
- **THEN** 构建成功且 runtime 镜像不含编译工具链

### Requirement: Compose 回环三端口

系统 SHALL 提供 `docker-compose.yml`，声明 `127.0.0.1:8877`、`127.0.0.1:8878`、`127.0.0.1:8879` 回环绑定与数据卷挂载，且默认 MUST NOT 监听公网地址。

#### Scenario: Compose 启动三端口

- **WHEN** 按 compose 文件启动
- **THEN** 三个回环端口均可访问且公网地址不可达

#### Scenario: 端口可用环境变量覆盖

- **WHEN** 经环境变量覆盖端口映射后启动
- **THEN** 新映射生效且回环绑定语义保持
