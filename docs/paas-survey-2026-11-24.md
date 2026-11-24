# 免费 PaaS 开荒调研清单（2026-11-24）

> 目标：为“零预算全球节点舰队”找出能跑 `fleet-node` Docker 容器的免费 PaaS。
> 调研员：subagent（2026-11-24）。**只做调研，未注册任何账号，未填任何邮箱/密钥。**
> 结论以各平台官网/官方文档为准，核查日期 2026-11-24。

## 0. 容器到底需要什么（对照 `docker/Dockerfile` + `providers/base.py`）

| 需求 | 具体要求 |
|---|---|
| 镜像 | 自建 Docker 镜像（`ghcr.io/xtls/xray-core` + `python:3.12-alpine`，约 124MB），平台须能从 Dockerfile 构建或直接拉取镜像（最好支持 GHCR 预构建镜像直推） |
| 端口 | 容器监听 **1 个 `$PORT`**（默认 8080），平台须把公网域名流量路由到该端口，并提供公网域名 + 自动 HTTPS（域名本身不重要，客户端连的是 `host:443` 的 VLESS） |
| 协议 | 入口是 **VLESS + TCP（裸 TCP，非 HTTP）**，`TRANSPORT=ws` 时走 WebSocket，`TRANSPORT=xhttp` 时走 XHTTP。平台若只放行 HTTP(S) 请求、做 L7 代理/强制 TLS 终止，则裸 TCP 的 VLESS 直连不可用 |
| 环境变量 | 须能注入 `UUID`、`WSPATH`、可选 `TRANSPORT`、`PORT`（entrypoint 强制要求 `UUID`、`WSPATH` 非空） |
| 插件能力 | 供应商插件（`providers/base.py`）需要平台提供 **API 或 CLI**，实现 deploy / status / wake / update_env / destroy |
| 红线 | 绑卡、KYC、AUP 禁代理三者任一触发即停手入黑名单（手册第五章第 3 条） |

---

## 1. 结论速览

| # | 平台 | 档位 | 一句话结论 |
|---|---|---|---|
| 1 | **Render** | ✅ 能直接用 | 首选。无卡、Docker（含 GHCR 直推）、750h/月、AUP 无明文禁代理；唯一代价是 15 分钟休眠（哨兵可唤醒） |
| 2 | **Back4app Containers** | ✅ 能直接用（备选） | 无卡、Docker、1 容器 256MB；但“60 分钟/部署就停”的说法待实测验证，可靠性存疑 |
| 3 | **Northflank** | ⚠️ 需验证 | 规格最好（$20/月、常驻不休眠、API+CLI），但“免卡”说法自相矛盾：定价页说免卡，计费文档说建资源必须绑支付方式。先试注册，索卡即停手入黑名单 |
| 4 | **Fly.io** | ⚠️ 需用户提供（卡） | 免费计划 2026-11-23 回归：无卡只有 $1/7 天；想长期用须绑卡拿 $5/月。ToS 全文无 proxy 字样。另有“超 $5 整月按 PAYG 计费”的悬崖 |
| 5 | **Oracle Cloud Always Free** | ⚠️ 需用户提供（卡+手机） | 不是 PaaS，是裸 VM（自己装 Docker）。4 OCPU/24GB（新号常为 2/12）、10TB 流量、永不休眠；但须实体卡 + 手机短信 + IP/发卡国一致，KYC 极重，且常无容量 |
| 6 | **Railway** | ⛔ 禁用 | **AUP 明文禁代理**（见下）。免费额度再好也不能用 |
| 7 | **Koyeb** | ⛔ 禁用 | 注册即索卡，$29 预授权冻结；注册默认 Pro $29/月并按比例扣费。绑卡墙 |
| 8 | **Zeabur** | ⛔ 禁用 | 共享集群 2026-02-22 已停新项目；免费计划只剩“管理你自己的服务器”，无免费计算层 |
| 9 | **Hugging Face Spaces** | ⛔ 禁用 | Docker SDK 自 2026 年 7 月起须 PRO（$9/月）才能创建；免费档只剩 Gradio/Static，跑不了容器 |
| 10 | **Google Cloud Run** | ⛔ 禁用 | 须 GCP 计费账号 + 绑卡；且只走 HTTP(S) 请求驱动，不支持裸 TCP VLESS 入口，协议不匹配 |
| — | Netrun | ⛔ 禁用（已有） | 政策禁代理，2026-11-12 已入黑名单，不再重复 |

**开荒顺序**：Render（先开 1 个验证休眠/唤醒）→ Northflank（试注册验卡）→ Back4app（实测 60 分钟限制）→ Fly.io / Oracle（等用户提供卡/手机后再说）。

---

## 2. 逐家核查

### 2.1 Render — ✅ 能直接用（首选）

- **官网**：https://render.com ；免费说明：https://render.com/articles/platforms-with-a-real-free-tier-for-developers-in-2026
- **能否跑 Docker**：✅ 能。支持 Dockerfile 构建，也支持**直接拉取已有镜像**（含 GHCR 预构建镜像），另有 `render.yaml` 蓝图与 Deploy Hook。我们的镜像可直接推 GHCR 后让 Render 拉取，构建时间省掉。
- **免费层额度**：免费 Web Service：**512MB RAM、0.1 共享 CPU**；每 workspace 每月 **750 实例小时**（1 个服务 24/7 ≈ 720–744 小时，基本 1 个节点刚好塞满；第 2 个服务会共享这 750 小时，超了整 workspace 免费服务停到下月）。出站流量官网口径 100GB/月（见下风险）。免费 PostgreSQL 30 天后过期（与本项目无关）。
- **休眠**：⚠️ **15 分钟无入站流量即休眠**，下次请求约 1 分钟冷启动。哨兵（`sentinel.py`）可定时请求根路径 `/` 唤醒；注意唤醒走的是 HTTP，`cover.py` 返回 200，符合设计。休眠期间不计实例小时，反而省额度。
- **注册条件**：邮箱即可，**无需信用卡**（Render 官网自己的文章明确写“without … entering credit card information”）。部署可选 GitHub 连接或公开镜像。
- **是否禁代理**：✅ **未见明文禁令**。Render 的 Acceptable Use Policy（2019-06-14 版，见 https://render-web-testing.onrender.com/acceptable-use）14 条禁令为：爬取、自动化超限、垃圾邮件、破坏系统完整性、不合理负载、恶意软件、收集个人信息、商业招揽、冒充/欺诈/隐藏身份、干扰服务、未授权手段访问、**挖矿**、绕过访问限制、违法/不当活动。**无“proxy / VPN / anonymization”字样**。灰色地带：第 9 条“hiding or attempting to hide your identity”与第 5 条“不合理负载”——个人自用、不转售、不对外开放可降低风险；但须注意 Render 文档明言免费实例“Do not use them for production applications”（免费层定位是原型/个人项目）。
- **部署方式**：Dashboard、`render.yaml`、REST API、CLI、Deploy Hook。插件可走 REST API（创建服务/触发部署/查状态/删服务）+ 根路径唤醒。
- **风险**：
  - 750 小时/月是 workspace 级共享，**1 个账号只能养约 1 个常驻节点**；多节点需多账号（多邮箱），属“换号”灰色操作，须谨慎（AUP 未明文禁多账号，但“绕过限制”条款可能被援引）。
  - 出站流量口径冲突：Render 官网文章称 100GB/月，第三方核查（snapdeploy.dev，2026-09）称 2026 年 4 月起免费带宽砍到 5GB/月。**部署时以官网账单页为准核对**。
  - 免费实例明确“非生产”定位，平台可随时调整免费层。

### 2.2 Back4app Containers — ✅ 能直接用（备选，需实测）

- **官网**：https://www.back4app.com ；核查来源：https://snapdeploy.dev/state-of-free-hosting 、https://volksdroid.app/infrastructure/app-platforms/back4app/
- **能否跑 Docker**：✅ 能。从 GitHub 或 Docker Hub 部署自定义 Dockerfile/镜像。
- **免费层额度**：**1 个免费容器，0.25 共享 CPU、256MB RAM、100GB/月流量**，美国区 only，无过期。
- **休眠**：⚠️ **说法冲突，须实测**。Back4app 官方模板备注称“免费容器每次部署运行 60 分钟”；另有资料称“30 天无流量/部署才暂停”或“无强制休眠”。若 60 分钟/部署属实，则无法做常驻节点，只能做一次性测试。256MB 内存对本容器够用（Xray 约 35MB + Python 覆盖页约 20MB）。
- **注册条件**：邮箱即可，**无需信用卡**。
- **是否禁代理**：未查到 Back4app 的 AUP 明文禁代理条款（本次未取得其 AUP 全文）。按“未见禁令”处理，但首次部署后须观察有无 AUP 告警。
- **部署方式**：Dashboard 为主（Containers → New App）；API/CLI 待写插件时核对。注意：有资料称其期望**固定 80 端口**而非注入 `$PORT`——我们的 entrypoint 读 `$PORT` 环境变量，若平台不注入则默认 8080，须在部署时把 `PORT` 显式设为平台要求的值。
- **风险**：60 分钟限制若属实则基本不可用；美国区 only（出口单一）；256MB 较紧。

### 2.3 Northflank — ⚠️ 需验证（规格最好，卡问题存疑）

- **官网**：https://northflank.com ；核查来源：https://xcloud.host/best-free-docker-hosting/ 、https://fshy.ajam.dev/p/northflank/ 、https://outplane.com/blog/docker-hosting
- **能否跑 Docker**：✅ 能。支持外部镜像、Git 构建、自带云（BYOC）；有官方 CLI（`@northflank/cli`）与 REST API，完美契合插件模型。
- **免费层额度**：Sandbox 计划 $0：**每月最多 $20 资源**，2 个服务、2 个任务、1 个数据库；**常驻不休眠（“always on, no sleeping”）**。最便宜的计算档 `nf-compute-50`（0.5 vCPU / 1GB）$12/月，可塞进 $20；更小的 `nf-compute-10`（0.1 vCPU / 256MB）$2.70/月，两个都放得下。出口流量 $0.06/GB，无独立免费额度说法（推断从 $20 里扣）。
- **休眠**：✅ **不休眠**。这是目前唯一确认常驻不休眠的免费档。
- **注册条件**：⚠️ **自相矛盾，必须实测**。定价页打“**No card needed**”；但计费文档称“**all users must add a payment method to start creating resources**”（所有用户建资源前必须加支付方式）。多家第三方核查（fshy、outplane，2026-10/11）均确认这一矛盾。**动作：试注册走到创建服务那一步；一旦索卡立即停手并入黑名单**（手册绑卡墙规则）。
- **是否禁代理**：✅ **未见明文禁令**。ToS（2021-03-01，见 https://northflank.com/legal/terms）未提及 proxy/VPN；主要限制是非法用途与“非人工手段访问（除 Northflank 自家 API 外）”——注意：用 API 做部署是被允许的（条款明文豁免自家 API）。
- **部署方式**：Dashboard、CLI、REST API、Git 部署。
- **风险**：
  - 卡之谜未解，是最大不确定项。
  - **2026 年 10 月 30 日安全事件**：Northflank 通知客户假定环境变量已被解密（第三方核查 2026-11-02 仍显示事件未关闭，而其安全页称从未被攻破）。我们的 `UUID` 走环境变量注入，**若用 Northflank，须把 UUID 视为可能泄露、做好轮换准备**，或改走启动时拉取配置。
  - ToS 自 2021 年未更新，可随时无通知终止账号。

### 2.4 Fly.io — ⚠️ 需用户提供（卡）

- **官网**：https://fly.io ；免费计划：https://docs.fly.io/about/free-plan ；ToS：https://fly.io/legal/terms-of-service
- **能否跑 Docker**：✅ 能。Fly Machines 就是 Firecracker 微型 VM，直接跑 Docker 镜像；`flyctl` CLI + Machines API；17 个区可选；支持裸 TCP 服务（可不经 TLS 终止），协议契合度最好。
- **免费层额度**：⚠️ **免费计划 2026-11-23 刚回归**，规则常变。无卡：一次性 **$1 额度、7 天过期**；绑卡后：每月 **$5 用量**，上限 3 台共享 CPU Machine、3 个 Sprites、每卷 5GB。最小常驻 Machine（shared-cpu-1x / 256MB）约 $1.94–$2.19/月，$5 可养约 2 台。无强制休眠（autostop/autostart 可配，默认按流量启停）。
- **休眠**：无强制休眠；可配自动停/启，哨兵可处理。
- **注册条件**：⚠️ 长期用**必须绑卡**（每张卡只能用于一个组织的免费计划）。无卡只能玩 7 天。
- **是否禁代理**：✅ **ToS 全文无 proxy/VPN 字样**（2026-04-29 版全文检索：无 `proxy`、无 `VPN`、无 `Acceptable Use`）。ToS 主要限制：仅供内部使用、不得转授/为第三方利益使用、不得干扰服务。个人自用不转售在字面上不违规，但“为第三方利益”条款是灰色地带。另注意 Fly.io 社区有大量关于“防代理滥用”的讨论，平台对隧道类用途有主动扫描与封禁实践，风控较严。
- **部署方式**：`flyctl` CLI、Machines API、GraphQL API。
- **风险**：
  - **计费悬崖**：超 $5 即自动转 Pay As You Go，且**整月从 $0 起全额计费**（不是只计超额部分），无硬性上限，须设告警。
  - 免费计划 2026 年内反复改（10 月取消、11 月 23 日恢复），政策不稳定。
  - 风控严，隧道/代理类用途可能被主动扫描。

### 2.5 Oracle Cloud Always Free — ⚠️ 需用户提供（卡+手机；VM 形态）

- **官网**：https://www.oracle.com/cloud/free/ ；核查来源：https://github.com/shivajithmutteal/oracle-vm-always-free 、https://byronfinn.github.io/en/oracle-free-vps-guide/
- **能否跑 Docker**：⚠️ **不是 PaaS，是裸 VM**，需自己装 Docker 再跑容器。插件模型不直接适用（无 PaaS API；要走 OCI API + cloud-init，属另一条线）。更适合做“第二大本营”而非 PaaS 节点。
- **免费层额度**：Always Free（永久，不过期）：Ampere A1 ARM 最多 **4 OCPU / 24GB**（2026 年中起新号常只给 **2 OCPU / 12GB**），另有 2 台 AMD 微型 VM；**出站流量 10TB/月**。永不休眠。
- **休眠**：✅ 无休眠，VM 常驻。
- **注册条件**：⛔ **KYC 极重**：须**实体信用卡**（Visa/Mastercard，拒虚拟/预付卡，约 $1 预授权验证）、**手机号短信验证**、且 IP 属地、发卡国、账单地址三者须一致（开代理注册会直接失败）。一人仅限一个免费账号（按邮箱+手机+卡号去重）。另常遇到“无容量”（out-of-capacity）建不出实例。
- **是否禁代理**：未在本次核查中取得 Oracle AUP 的代理明文；但 Oracle 明确禁止用代理注册（IP 与发卡国不一致即拒）。VM 上跑代理本身未见明文禁令，归入“未见禁令、KYC 墙已挡路”。
- **部署方式**：OCI 控制台 / OCI CLI / API + cloud-init。
- **风险**：注册门槛最高（卡+手机+IP 一致），用户须亲自操作；容量不足是常态；家属/多账号去重严。

### 2.6 Railway — ⛔ 禁用（AUP 明文禁代理）

- **官网**：https://railway.com ；免费计划：https://docs.railway.com/pricing/free-plan ；AUP：https://railway.com/legal/acceptable-use
- **能否跑 Docker**：✅ 技术上能（GitHub / Docker 镜像 / 本地目录）。
- **免费层额度**：免费计划 $0：每月 **$1 用量**（约只够 100MB 内存跑满月，或 0.05 vCPU），1 项目、3 服务，每服务 1 vCPU / 0.5GB；新号另有一次性 **$5 试用（30 天、不休眠）**。免费档服务**闲置 5–10 分钟即休眠**（无出站流量时），有出站流量（WebSocket 保持、轮询）可保持唤醒。
- **注册条件**：邮箱/GitHub 即可，试用与免费均**无需信用卡**。
- **是否禁代理**：⛔ **明文禁止**。Railway 官方 AUP 原文：“…or **operating proxies or anonymization services**…”；其 Fair Use Policy 亦写明“**forbids proxies and VPN exits**”。另有案例佐证：某 VPN 产品因该条款把 Railway 只用作控制面、出口节点改放 Vultr。**按手册规则直接判死，永不换号绕行。**
- **结论**：额度与注册条件本是全场最友好之一，但 AUP 一票否决。已记入黑名单（见第 4 节）。

### 2.7 Koyeb — ⛔ 禁用（绑卡墙 + $29 预授权）

- **官网**：https://www.koyeb.com ；核查来源：https://freetier.wiki/services/koyeb/ 、https://www.srvrlss.io/provider/koyeb/
- **能否跑 Docker**：✅ 技术上能（Git / 容器镜像），1 个免费实例。
- **免费层额度**：每组织 1 个免费实例：**0.1 vCPU / 512MB RAM / 2GB SSD**，法兰克福或华盛顿二选一；**闲置 1 小时后缩容到零**，唤醒 1–5 秒；100GB 出站（FAQ 口径）。
- **注册条件**：⛔ **必须绑卡**，且 2026 年 2 月起注册要过 **$29 预授权冻结**（7–21 天解冻）；注册默认选 Pro $29/月，卡验证后按比例扣费，须手动切到 Starter 才只算超额。无卡连号都开不了。
- **是否禁代理**：未取得 Koyeb AUP 的代理明文；但绑卡墙已先触发手册停手规则，无需再查 AUP。
- **结论**：绑卡墙 + 默认 Pro 扣费陷阱，直接判死。已记入黑名单。

### 2.8 Zeabur — ⛔ 禁用（免费计算层已死）

- **官网**：https://zeabur.com ；下线公告：https://zeabur.com/changelogs/phasing-out-shared-cluster ；核查来源：https://www.thegeeksclub.com/platforms/zeabur/ 、https://inetgeek.com/hosting/zeabur/
- **能否跑 Docker**：技术上支持 GitHub / Dockerfile / 镜像 / 本地上传，但**免费层已无处可跑**。
- **免费层额度**：⛔ **共享集群 2026-02-22 起不再接受新项目**（2026-04-01 起新项目无法建在共享集群）。现免费计划只剩“管理 1 台你自己的服务器”、2C4G 构建、48 小时日志——即**不提供免费计算资源**。要跑服务须 Dev 计划 $5/月起（另 14 天试用）。
- **注册条件**：注册本身可能只需邮箱/手机，但跑服务须付费。
- **是否禁代理**：未取得 AUP 明文；免费计算层已死，无需再查。
- **结论**：无免费计算层，直接判死。已记入黑名单。

### 2.9 Hugging Face Spaces — ⛔ 禁用（Docker 创建须付费）

- **官网**：https://huggingface.co/spaces ；核查来源：https://github.com/oruwe/synthetic.api/blob/HEAD/deploy/huggingface/SETUP.md 、https://github.com/thebeamstack/road_designer/blob/HEAD/DEPLOYMENT.md
- **能否跑 Docker**：⛔ **Docker SDK 自 2026 年 7 月起须付费计划才能创建**。HF 官方文档原话（多处引用）：“Gradio and Docker Spaces run on compute and require a paid plan to create: PRO for personal accounts”。免费的 `CPU Basic` 硬件档（2 vCPU / 16GB / 50GB）本身 $0/小时，但**建 Docker Space 这个动作就被 PRO（$9/月）挡住**。
- **免费层额度**：免费硬件 2 vCPU / 16GB，空间不限个数；免费档 **48 小时无活动即休眠**（不可配），可 ping 保活。
- **注册条件**：账号邮箱即可、无卡；但 Docker 创建须 PRO。
- **是否禁代理**：未取得 AUP 明文；Docker 付费墙已先触发停手规则。
- **结论**：Docker 创建被付费墙挡住，直接判死。已记入黑名单。注：若未来 HF 恢复免费 Docker 创建，可复活重测（黑名单 `retry_allowed` 暂记 false，复活须由用户定）。

### 2.10 Google Cloud Run — ⛔ 禁用（绑卡墙 + 协议不匹配）

- **官网**：https://cloud.google.com/run ；免费说明：https://docs.cloud.google.com/free/docs/free-cloud-features
- **能否跑 Docker**：⚠️ **协议不匹配**。Cloud Run 是**请求驱动的 HTTP(S) 服务**：只接受 HTTP/HTTPS（HTTP/2、WebSocket、gRPC），Google 前端终止 TLS 后转发 HTTP 到容器；**不支持裸 TCP 入口**。我们的 VLESS 入口是裸 TCP，无法直通；`TRANSPORT=xhttp` 走 HTTP/2 理论上可能通，但未经验证且 Cloud Run 按请求计费、实例随请求启停，与长连接代理模型冲突大。
- **免费层额度**：Always Free（永久）：每月 200 万请求、180,000 vCPU-秒、360,000 GB-秒、北美出站 1GB；另有新号 $300/90 天试用。
- **休眠**：无传统休眠，**按请求缩容到零**，冷启动按请求唤醒；但长连接会被实例回收打断。
- **注册条件**：⛔ **必须有 GCP 计费账号 + 绑卡**（官网原话：“A Google Cloud billing account is required”；“During the sign up, you must provide a credit card”）。超额直接按量计费（2026-10-12 起支持预算达量暂停，仍须绑卡）。
- **是否禁代理**：未取得 AUP 明文；绑卡墙 + 协议不匹配已足够判死。
- **结论**：绑卡墙 + 协议不匹配，直接判死。已记入黑名单。

---

## 3. 开荒优先级与执行顺序

| 顺序 | 平台 | 动作 | 预期产出 |
|---|---|---|---|
| 1 | **Render** | 邮箱注册 → 推镜像到 GHCR → Dashboard/API 建免费 Web Service → `verify_node.py` 验收 → 入 `fleet.yaml`（staging） | 第 1 个 PaaS 直连节点；验证 15 分钟休眠 + 哨兵唤醒是否成立 |
| 2 | **Northflank** | 邮箱注册 → 走到创建服务；**索卡立即停手并入黑名单**；不索卡则部署验证 | 若免卡属实，拿下唯一常驻不休眠免费档，可放 1–2 个节点 |
| 3 | **Back4app** | 邮箱注册 → 部署验证“60 分钟/部署”说法是否属实 | 若只是休眠而非 60 分钟硬停，可作备用节点 |
| 4 | **Fly.io** | 需用户提供信用卡后才可长期用；先用 $1/7 天无卡试用验证部署流程亦可 | $5/月 2–3 台、多区；注意计费悬崖 |
| 5 | **Oracle** | 需用户亲自提供实体卡 + 手机 + 关闭代理注册；定位是“第二大本营”而非 PaaS 节点 | 2 OCPU/12GB 常驻 VM，10TB 流量 |

**数量规划**：Render 每账号约 1 个常驻节点（750h 上限）；Northflank 每账号 1–2 个小节点；其余靠 Fly.io（绑卡后）与多账号轮换。切勿在同一平台用多账号绕额度——AUP“绕过限制”条款是通用红线。

---

## 4. 黑名单新增条目（`registry/blacklist.yaml` 格式）

> 已同步写入 `~/fleet-muse/registry/blacklist.yaml`（Netrun 原条目保留）。

```yaml
blacklisted:
  - platform: Netrun
    cause: "Platform policy bans proxy use; service closed (2026-11-12)."
    date: "2026-11-12"
    retry_allowed: false
  - platform: Railway
    cause: "AUP explicitly bans operating proxies/anonymization services (railway.com/legal/acceptable-use; Fair Use Policy forbids proxies and VPN exits)."
    date: "2026-11-24"
    retry_allowed: false
  - platform: Koyeb
    cause: "Billing wall: credit card required at signup with $29 pre-authorisation hold; signup defaults to Pro $29/mo with pro-rated charge (Feb 2026)."
    date: "2026-11-24"
    retry_allowed: false
  - platform: Zeabur
    cause: "No free compute left: shared cluster phased out 2026-02-22, no new projects; Free plan only manages your own server. Dev plan $5/mo."
    date: "2026-11-24"
    retry_allowed: false
  - platform: Hugging Face Spaces
    cause: "Docker SDK requires a paid plan to create (PRO $9/mo) since ~Jul 2026; free tiers left are Gradio/Static only, cannot run the container."
    date: "2026-11-24"
    retry_allowed: false
  - platform: Google Cloud Run
    cause: "Billing wall: GCP billing account + credit card required; plus protocol mismatch (HTTP(S) request-driven only, no raw TCP VLESS ingress)."
    date: "2026-11-24"
    retry_allowed: false
```

---

## 5. 需要用户提供什么

| 事项 | 说明 | 是否阻塞开荒 |
|---|---|---|
| 什么都不用（Render / Back4app / Northflank 试注册） | 邮箱注册即可，Muse 可自行开荒 | 否，第 1–3 步可直接开工 |
| Northflank 注册结果 | 试注册时若索卡，Muse 按规则停手入黑名单并汇报；不索卡则继续 | 否，先试再说 |
| 信用卡（Fly.io 长期用） | Fly.io 无卡只有 $1/7 天；要 $5/月长期额度须绑卡。另注意超 $5 整月 PAYG 计费悬崖 | 是，Fly.io 长期节点的前提 |
| 实体卡 + 手机 + 关闭代理注册（Oracle） | 仅当用户想开第二大本营 VM 时需要；PaaS 开荒不需要 | 否，PaaS 线不依赖 |
| 邮箱（多账号轮换） | Render 每账号约 1 个常驻节点；若要多个 Render 节点，需多个邮箱。是否开多账号由用户定（AUP 灰色地带，不擅自做） | 视节点数量目标而定 |

---

## 6. 风险与注意事项

1. **AUP 是最大死因**：本次最大发现是 Railway 明文禁代理——免费额度再好也不能碰。各平台 AUP 随时可改，**每个节点部署后 48 小时 staging 期内须留意平台告警/封号信号**，一触发即下线入黑名单。
2. **免费层说变就变**：2026 年内已发生 Fly.io 免费计划取消又恢复（11-23）、Zeabur 共享集群下线（02-22）、HF Docker 改付费（07 月）、Koyeb 加 $29 预授权（02 月）、Oracle 免费 ARM 减半（06 月）。清单有效期按月计，部署前须重核官网。
3. **Northflank 环境变量泄露事件**（2026-10-30）：官方通知客户假定环境变量已被解密。`UUID` 走环境变量注入的平台都有此风险；Northflank 若启用，须准备 UUID 轮换。
4. **Railway 2026-10 事故**：Railway 2026-10-21 披露环境变量泄露（约 10 万 workspace 受影响）。与本次无关（Railway 已禁），但说明“密钥进 PaaS 环境变量”本身就是风险面。
5. **休眠≠死亡**：Render（15 分钟）、Back4app（待核实）、HF（48 小时）都会休眠，哨兵的职责就是定时唤醒；只有“额度耗尽停服”（Railway $1 用完、Render 750h 用完）才是硬停。
6. **不要用平台跑挖矿/扫描/垃圾邮件**：各家 AUP 通用禁令，触发即整号封禁，连带节点全灭。

## 7. 证据来源（核查日期 2026-11-24）

- Railway 免费计划：https://docs.railway.com/pricing/free-plan
- Railway AUP：https://railway.com/legal/acceptable-use
- Render 免费层说明：https://render.com/articles/platforms-with-a-real-free-tier-for-developers-in-2026
- Render AUP（2019-06-14 版镜像）：https://render-web-testing.onrender.com/acceptable-use
- Render 免费层生产限制核查：https://convika.com/compare/render-free-tier-production/
- Fly.io 免费计划：https://docs.fly.io/about/free-plan
- Fly.io ToS（2026-04-29，全文检索无 proxy/VPN）：https://fly.io/legal/terms-of-service
- Koyeb 免费层核查：https://freetier.wiki/services/koyeb/ 、https://www.srvrlss.io/provider/koyeb/
- Zeabur 共享集群下线公告：https://zeabur.com/changelogs/phasing-out-shared-cluster
- Zeabur 定价核查：https://www.thegeeksclub.com/platforms/zeabur/ 、https://inetgeek.com/hosting/zeabur/
- Northflank 免费层核查：https://xcloud.host/best-free-docker-hosting/ 、https://fshy.ajam.dev/p/northflank/ 、https://outplane.com/blog/docker-hosting
- Northflank ToS：https://northflank.com/legal/terms
- Hugging Face Docker 付费墙核查：https://github.com/oruwe/synthetic.api/blob/HEAD/deploy/huggingface/SETUP.md 、https://github.com/thebeamstack/road_designer/blob/HEAD/DEPLOYMENT.md
- Google Cloud 免费计划：https://docs.cloud.google.com/free/docs/free-cloud-features
- Oracle 免费层核查：https://github.com/shivajithmutteal/oracle-vm-always-free 、https://byronfinn.github.io/en/oracle-free-vps-guide/
- Back4app 免费层核查：https://snapdeploy.dev/state-of-free-hosting 、https://volksdroid.app/infrastructure/app-platforms/back4app/
- 综合对照：https://xcloud.host/best-free-docker-hosting/ 、https://flaviocopes.com/hosting-free-tiers/
