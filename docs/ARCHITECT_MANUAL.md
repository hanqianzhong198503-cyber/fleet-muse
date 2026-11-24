# 零预算全球节点舰队 · Muse × 内置 Codex 联合工程指导手册（v1.0）

> **适用角色**：Muse（总控编排官 / 资产与台账管理者）调度内置 Codex（基础设施与代码总工程师）。
> **归档路径**：`~/fleet-muse/docs/ARCHITECT_MANUAL.md`
> **核心铁律**：Muse 独占运行态与密钥，Codex 独占代码层与测试态；**严禁向 Codex 透传任何真实密钥、账号密码、UUID 或真实订阅链接**。

---

## 第零章：工作区隔离与安全契约

Muse 启动任何开发前，必须先初始化以下双层隔离目录，明确划清“代码层”与“运行态层”的权限边界：

```text
~/fleet-muse/
├── docs/
│   └── ARCHITECT_MANUAL.md        # 本指导手册（双方共同遵循）
├── docker/                        # 【Codex 维护 · 进 Git】双模容器源码
│   ├── Dockerfile
│   ├── cover.py
│   └── entrypoint.sh
├── providers/                     # 【Codex 维护 · 进 Git】统一 PaaS 部署插件库
│   ├── __init__.py
│   ├── base.py                    # 抽象基类、标准数据模型与异常定义
│   ├── mock_provider.py           # 本地无外网测试用 Mock 插件
│   └── ...                        # 后续按需扩展：komuta.py / breezedeploy.py 等
├── scripts/                       # 【Codex 维护 · 进 Git】核心引擎脚本
│   ├── verify_node.py             # 模块一：验收四件套与国内可达探针
│   ├── run_provider.py            # 模块二：插件统一调度器（负责注入密钥）
│   ├── sync_hub.py                # 模块三：大本营链式落地配置生成与原子重载
│   ├── build_sub.py               # 模块三：订阅聚合（V2Ray/Clash）与二维码生成
│   ├── sentinel.py                # 无人值守巡检、休眠唤醒与续期告警
│   └── audit_secrets.py           # 提交/运行前防泄露与日志脱敏静态扫描
├── tests/                         # 【Codex 维护 · 进 Git】单元测试与集成自测
├── .secrets/                      # 【Muse 独占 · chmod 700 · 禁入 Git】
│   ├── hub.env                    # 大本营 VPS SSH/REALITY 核心密钥
│   ├── providers/                 # 各平台 API Key（如 komuta.env，chmod 600）
│   └── nodes/                     # 各节点独立参数（如 nepal-01.json，chmod 600）
├── registry/                      # 【Muse 独占 · 禁入 Git】三本运维台账
│   ├── fleet.yaml                 # 在役与 Staging（观察期）节点总表
│   ├── blacklist.yaml             # 判死平台与死因记录
│   └── scan_log.md                # 全球扫图与筛选日志
└── output/                        # 【Muse 独占 · 禁入 Git】生成的订阅与纯 ASCII 二维码
```

### 强安全约束（双方强制遵守）

1. **权限锁死**：`.secrets/` 目录权限 `700`，内部所有文件权限 `600`。`.gitignore` 必须显式忽略 `.secrets/`、`registry/`、`output/`、`*.key`、`*.pem`、`*sub*`。
2. **日志静默**：所有容器内 `xray` 日志级别默认设为 `warning`，禁止在生产脚本打印 `os.environ`、请求头、UUID 或完整 `vless://` 链接，防止 PaaS 控制台日志审计触发封号或泄露进 AI 对话上下文。
3. **自建镜像原则**：严禁拉取网络不明第三方代理镜像，统一基于 `ghcr.io/xtls/xray-core` 官方二进制构建多阶段 Alpine 镜像，并内置根路径 `/` 返回 `HTTP 200` 的轻量伪装页（`cover.py`）。

---

## 第一章（模块一）：`scripts/verify_node.py` 验收四件套技术规格书

> **目标**：把“节点是否真正可用”固化为一个零人工介入、强确定性的 CLI 验收引擎。面板显示 Running 或日志正常一律不算通过，必须本脚本返回退出码 `0` 才准许进入台账。

### 1.1 CLI 调用接口规范

```bash
python3 scripts/verify_node.py \
  --node-file /path/to/.secrets/nodes/demo-01.json \
  --allow-cf false \
  --cn-probe true \
  --timeout 15 \
  --json-out /tmp/verify_result.json
```

* `--node-file`：由 Muse 在运行时传入的节点参数文件路径（包含 `node_id`、`host`、`port`、`uuid`、`transport`、`path`、`sni`、`alpn`、`allow_insecure`、`mode` 等）。**严禁通过命令行明文参数传递 UUID**（防止被 `ps aux` 抓到）。
* `--allow-cf`：布尔值，默认 `false`。若为 `false`，当 Google DoH 解析出节点域名指向 Cloudflare Anycast 网段时直接判定违规报错（防止误用 CF 面板域名或默认中转）。
* `--cn-probe`：布尔值，默认 `true`。是否调用 Globalping API 从中国主流运营商探针检测 TCP/TLS 连通性。
* `--json-out`：输出完全脱敏后的结构化 JSON 报告路径（同时在 stdout 输出脱敏摘要）。

### 1.2 五阶段流水线详细逻辑

#### 阶段 1：根路径伪装健康检查（Cover Check）
* 使用 HTTPS（或按节点配置）请求 `https://{host}:{port}/`。
* **通过标准**：状态码为 `200`（或显式允许的 `301/302` 跳转至静态页），且响应头与正文不含 `xray`、`vless`、`bad request` 等异常暴露信息。

#### 阶段 2：Google DoH 真实解析与非 CF 校验
* 调用 `https://dns.google/resolve?name={host}&type=A` 与 `type=AAAA` 获取真实解析 IP。
* 加载本地缓存的 Cloudflare 官方 IPv4/IPv6 CIDR 清单（首次运行从 `https://www.cloudflare.com/ips-v4` 和 `ips-v6` 拉取并缓存至 `scripts/cf_cidrs.json`，7 天过期更新）。
* 使用 Python 标准库 `ipaddress` 校验解析结果：
  * 若存在 IPv4 且 `--allow-cf false`，命中 CF 网段则返回退出码 `20`。
  * 若仅有 AAAA（纯 IPv6）而无 A 记录，自动标记 `ipv6_only: true` 与 `transit_recommended: true`（提示需挂大本营中转）。

#### 阶段 3：真实 Xray 客户端端到端 204 拨测（核心）
1. **动态空闲端口分配**：使用 `socket.bind(("127.0.0.1", 0))` 申请本机临时空闲端口作为本地 SOCKS5 监听端口，防止多任务并发端口冲突。
2. **动态配置渲染**：在 `/tmp/` 下生成权限为 `600` 的临时 `xray` 客户端配置 JSON，精确适配以下传输模式：
   * `ws`：`VLESS + WebSocket + TLS`（带 `sni`、`fp=chrome`、`alpn=["http/1.1"]`、`path`）。
   * `xhttp`：`VLESS + XHTTP (mode: packet-up) + TLS`（强制 `alpn=["http/1.1"]`，用于 WS 被网关干扰时的自动回退）。
   * `reality`：`VLESS + TCP + REALITY`（用于裸机 VPS 或大本营入站）。
3. **子进程生命周期管理**：通过 `subprocess.Popen(["xray", "run", "-c", tmp_cfg])` 拉起客户端，轮询本地 SOCKS5 端口就绪（最长等 3 秒）。**必须在 `try...finally` 块中按精确 `proc.pid` 终止进程并物理删除临时配置文件**，绝不使用 `pkill xray` 误杀其他进程。
4. **三连连通性测试**：通过 `socks5h://127.0.0.1:{local_port}`（必须使用 `socks5h` 确保远端解析 DNS，防止本地 DNS 泄漏）连续 3 次请求 `https://www.gstatic.com/generate_204`。
   * **通过标准**：3 次全部返回精确 `HTTP 204`，记录最小/平均/最大 RTT（毫秒）。
   * **特征诊断**：若检测到 WS 握手返回 `400`、`101` 后立刻 EOF 断开、或 HTTP/2 降级异常，返回特定退出码 `30`，提示 Muse 自动触发 `WS -> XHTTP` 回退。

#### 阶段 4：防网关截断大包测速 + 多库出口定性
1. **防截断测速**：通过同一 SOCKS5 通道拉取 5MB 测试流（如 `https://speed.cloudflare.com/__down?bytes=5242880`），校验实际接收字节数不少于 `5242880` 字节，计算真实下载速率（Mbps）。若固定在 1MB/2MB 处断流，标记 `truncation_detected: true` 并返回退出码 `40`。
2. **三库交叉定性**：通过 SOCKS5 并行或依次请求至少 3 个无密钥接口：
   * 接口 A：`https://ipinfo.io/json`
   * 接口 B：`http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,as,hosting,proxy,query`
   * 接口 C：`https://ipwho.is/`（备用：`https://ifconfig.co/json`）
   * **交叉规则**：若至少 2 个库返回相同的出口 IP 与国家代码，则采信；根据 `hosting`、`org` 与 ASN 关键词客观定性为 `DC`（机房）或 `ISP`，**严禁虚标为住宅/家宽**；同时校验直连 PaaS 的出口 IP 是否与阶段 2 解析出的 A 记录同属同一网段/ASN。

#### 阶段 5：中国大陆可达性抽检（Globalping API）
* 当 `--cn-probe true` 时，向 `https://api.globalping.io/v1/measurements` 发送一次 TCP/TLS 或 HTTP 探测请求，指定国内主流运营商探针组（如 `CN` + 移动 `AS9808` / 电信 `AS4134` / 联通 `AS4837`，每组 1-2 个探针），轮询最多 15 秒获取结果。
* **决策字段输出**：
  * 全球 204 通过 **且** 国内探针可达率大于等于 50%：`recommended_mode = "direct"`。
  * 全球 204 通过 **但** 国内探针全部超时/阻断：`recommended_mode = "transit"`（自动建议接入第三章的大本营链式落地，绝不浪费稀有地区出口）。

### 1.3 标准退出码与脱敏 JSON 报告结构

| 退出码 | 含义 | Muse 下一步动作 |
| :---: | :--- | :--- |
| `0` | 全部验收通过 | 录入 `fleet.yaml`（初始状态为 `staging` 观察 48 小时） |
| `10` | 根路径伪装检查失败 | 检查容器 `cover.py` 或平台端口映射 `$PORT` |
| `20` | DoH 校验命中 CF 违规 | 检查是否填错域名，禁止强套 CF |
| `30` | WS 握手/断流异常 | 自动切换 `TRANSPORT=xhttp` 重部署并复测 |
| `40` | 大包测速发生网关截断 | 在台账备注“限流/截断缺陷”，降级为备用或放弃 |
| `50` | 204 不通或三库校验失败 | 最多排障 2 轮，失败则判死入 `blacklist.yaml` |

**脱敏 JSON 输出规范（绝不含 UUID、WSPATH、API Key）**：

```json
{
  "node_id": "eurobase-fr-01",
  "timestamp": "2026-11-24T05:00:00Z",
  "passed": true,
  "exit_code": 0,
  "transport_tested": "ws",
  "cover_http_status": 200,
  "doh_check": {
    "ipv4": ["51.x.x.x"],
    "ipv6": [],
    "is_cloudflare": false,
    "ipv6_only": false
  },
  "probe_204": {
    "attempts": 3,
    "success": 3,
    "rtt_ms_avg": 214
  },
  "bandwidth_test": {
    "bytes_expected": 5242880,
    "bytes_received": 5242880,
    "speed_mbps": 42.6,
    "truncation_detected": false
  },
  "exit_geo": {
    "ip": "51.x.x.x",
    "country_code": "FR",
    "city": "Strasbourg",
    "asn": "AS16276",
    "org": "OVH SAS",
    "ip_class": "DC",
    "sources_agreed": 3
  },
  "cn_probe": {
    "enabled": true,
    "reachable_ratio": 0.67,
    "recommended_mode": "direct"
  }
}
```

---

## 第二章（模块二）：`providers/` 统一平台部署插件接口规范

> **目标**：把不同免费 PaaS 的 API / CLI / MCP 差异封装在独立插件里。Muse 每发现一个支持 API/CLI 的新平台，只需派 Codex 按本规范写一个 `providers/{name}.py`，即可无缝接入部署、唤醒、轮换与销毁全生命周期。

### 2.1 抽象基类与标准异常（`providers/base.py`）

Codex 必须严格实现以下抽象契约与自定义异常，确保 Muse 能精确区分“临时网络故障”与“平台风控红线”：

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict

# ===== 标准化异常体系（用于驱动 Muse 自动决策）=====
class ProviderError(Exception):
    """通用平台异常"""

class AuthFailedError(ProviderError):
    """API Key 无效或账号未激活"""

class BillingWallError(ProviderError):
    """触发绑卡/扣款/付费墙 -> Muse 必须立即停手并记入黑名单"""

class AUPBlockedError(ProviderError):
    """触发 AUP 封禁/扫描拦截/人工执法 -> Muse 必须立刻下线并永久判死，严禁换号绕行"""

class QuotaExhaustedError(ProviderError):
    """免费额度耗尽或库存缺货 -> Muse 可转入补货哨兵或触发月度轮换"""

# ===== 标准数据模型 =====
@dataclass
class ProviderMeta:
    name: str
    region_hint: str
    billing_model: str          # "forever_free" | "credit_grant" | "monthly_rotate" | "short_renew"
    sleep_after_min: int        # 0 表示 24/7 不休眠，大于 0 表示闲置休眠分钟数
    renewal_days: int           # 0 表示无需手动续期，如 4 / 30 表示续期/轮换周期
    supports_xhttp: bool = True
    ipv6_only: bool = False

@dataclass
class DeployConfig:
    app_name: str
    image: str                  # 必须指向用户自建镜像地址
    port: int = 8080
    env_vars: Dict[str, str] = field(default_factory=dict)  # 运行期注入 PORT/UUID/WSPATH/TRANSPORT

@dataclass
class NodeInstance:
    provider: str
    instance_id: str
    app_name: str
    public_host: str            # 纯主机名，不含协议头与路径
    public_port: int = 443
    status: str = "running"     # "running" | "sleeping" | "stopped" | "error"
    raw_notes: str = ""         # 限额与平台脾气简述（脱敏）

# ===== 插件抽象基类 =====
class BaseProvider(ABC):
    meta: ProviderMeta

    def __init__(self, credentials: Dict[str, str]):
        """credentials 仅由 run_provider.py 从 .secrets/ 注入，插件严禁自行读文件或打印 credentials"""
        self._creds = credentials

    @abstractmethod
    def validate_credentials(self) -> bool:
        """校验凭据可用性，不创建计费资源"""

    @abstractmethod
    def deploy(self, config: DeployConfig) -> NodeInstance:
        """创建或覆盖部署应用，等待公网域名就绪后返回 NodeInstance"""

    @abstractmethod
    def status(self, instance_id: str) -> str:
        """返回 running / sleeping / stopped / error"""

    @abstractmethod
    def wake(self, instance_id: str, public_host: str) -> bool:
        """针对闲置休眠平台执行冷启动唤醒（请求根路径 / 或调平台启动 API）"""

    @abstractmethod
    def update_env(self, instance_id: str, env_patch: Dict[str, str]) -> bool:
        """热更新环境变量并触发重启（主要用于 WS -> XHTTP 一键协议回退）"""

    @abstractmethod
    def destroy(self, instance_id: str) -> bool:
        """清理实例（用于月度轮换旧号清理或 AUP 停损下线）"""
```

### 2.2 统一调度入口与密钥隔离机制（`scripts/run_provider.py`）

Muse 不直接 `import` 插件，而是统一通过 `scripts/run_provider.py` 调度。该调度器承担三项核心职责：

1. **自动生成节点机密**：执行 `deploy` 时，若未指定现有节点文件，调度器自动在本地生成全新 `UUIDv4` 和随机 `WSPATH`（格式 `/api/v2/stream-{8位随机字母数字}`），以 `chmod 600` 写入 `.secrets/nodes/{node_id}.json`。
2. **单向密钥注入**：读取 `.secrets/providers/{provider}.env` 解析为字典传给插件构造函数；捕获所有未处理异常并做正则脱敏（替换掉所有已知 Key/UUID 为 `***REDACTED***`）后再输出到终端。
3. **支持的标准子命令**：

```bash
python3 scripts/run_provider.py deploy --provider komuta --node-id komuta-de-01 --image <user_image> --transport ws
python3 scripts/run_provider.py switch-transport --provider komuta --node-id komuta-de-01 --transport xhttp
python3 scripts/run_provider.py status --provider komuta --node-id komuta-de-01
python3 scripts/run_provider.py wake --provider komuta --node-id komuta-de-01
python3 scripts/run_provider.py destroy --provider komuta --node-id komuta-de-01
```

### 2.3 新平台接入的标准化开发契约（Muse 派给 Codex 的固定规则）

* 每个新插件必须位于 `providers/{platform}.py`，并通过装饰器或注册表自动暴露给 `run_provider.py`。
* 每个插件必须配套 `tests/test_provider_{platform}.py`，使用 HTTP Mock（如 `unittest.mock`）覆盖 4 个必测用例：正常部署、触发 `BillingWallError`、触发 `AUPBlockedError`、日志脱敏断言（断言 stdout/stderr 中绝不出现测试假 Key）。

---

## 第三章（模块三）：大本营 VPS 前置中转与链式落地架构规范

> **目标**：解决三个致命痛点——① 国内直连不通但海外极稳的稀有出口（尼泊尔、南非、印度及部分欧陆小厂）；② 纯 IPv6 免费主机（如 NeoHeberg）；③ 底层免费平台月度轮换时，确保手机端订阅地址与节点名**零感知无感切换**。

### 3.1 推荐拓扑：大本营服务端单端口多路复用（Server-Side Chaining）

相比客户端手动配置双跳链式代理（各 App 兼容性差异大、Shadowrocket 与 Clash 语法不统一），本架构默认采用**大本营 Xray 服务端路由分流落地模式**：

```text
[手机客户端: Shadowrocket / Clash / Sing-box]
        │
        │  单一超稳加密隧道：VLESS + TCP + REALITY（或 XHTTP + TLS）
        │  目标地址：大本营永久免费 VPS（仅暴露 1 个 443 端口）
        │  区分落地的方式：每个稀有出口分配 1 个独立接入 UUID（email 标签）
        ▼
[大本营 VPS · Xray Core 路由中控]
        ├── user == "exit-nepal-01@hub"  ──► outbound: out-nepal-01  (VLESS+WS/XHTTP -> MeroDeploy 尼泊尔)
        ├── user == "exit-za-01@hub"     ──► outbound: out-za-01     (VLESS+WS/XHTTP -> HCode 南非)
        ├── user == "exit-fr-v6@hub"     ──► outbound: out-fr-v6     (Shadowsocks/VLESS -> NeoHeberg 纯 IPv6)
        └── user == "direct-hub@hub"     ──► outbound: direct        (大本营本机美国/新加坡直出)
```

**该架构的四大工程优势**：

1. **客户端极简兼容**：所有中转落地节点在手机端看来都是标准的 `VLESS + REALITY` 节点，Shadowrocket、Clash Meta、v2rayN、Sing-box 全平台通吃，国内三大运营商抗干扰能力拉满。
2. **无痛接管纯 IPv6 节点**：只要大本营 VPS 开启双栈（IPv4+IPv6），手机端在纯 IPv4 蜂窝网络下连大本营 IPv4，由大本营通过 IPv6 出站去连纯 IPv6 节点。
3. **无痛接管自签证书与怪异端口**：像自签证书平台，由大本营出站配置处理，手机客户端无需开启全局不安全证书。
4. **月度轮换前端零感知**：当首月免费平台到期换新号、域名变更时，大本营只需更新对应的 `outbound` 地址并原子重载，手机端刷新自有域名订阅即可无缝续接。

*(补充：对于希望节省大本营流量的 Clash Meta / Mihomo 用户，`build_sub.py` 同时也支持按需生成 `dialer-proxy` 客户端链式配置作为备选。)*

### 3.2 大本营配置同步与零停机原子重载器（`scripts/sync_hub.py`）

Codex 编写 `scripts/sync_hub.py` 时，必须严格落实“防翻车安全重载七步法”（彻底杜绝改坏配置导致整座大本营失联）：

1. **读取数据源**：读取 `registry/fleet.yaml` 中所有 `status in ("active", "staging")` 且 `route_mode == "transit"` 的节点，再从 `.secrets/nodes/{node_id}.json` 加载其出站密钥，以及 `.secrets/hub.env` 中的大本营 REALITY 密钥对与 SSH 配置。
2. **生成大本营完整配置**：
   * 单一 `inbound`（端口 443，协议 `vless`，安全 `reality`），为每个中转节点生成一个独立 `client`（`id` 为大本营侧独立分发 UUID，存入 `.secrets/hub_clients.json`；`email` 为 `{node_id}@hub`）。
   * 为每个中转节点生成对应 `outbound`（`tag: "out-{node_id}"`），支持 `ws`、`xhttp`、`shadowsocks`、`reality` 四种落地协议。
   * 生成 `routing.rules`：按 `"user": ["{node_id}@hub"]` 精确映射至 `"outboundTag": "out-{node_id}"`。
3. **本地语法预检**：若本地有 `xray`，先在本地运行 `xray run -test -c /tmp/hub_next.json`。
4. **上传并远端磁盘与配置双校验**（通过 SSH 密钥连接大本营）：
   * 上传至 `/etc/xray/config.json.next`（权限 `600`）。
   * 若配置引用了任何 TLS 证书路径，脚本必须逐个校验磁盘文件真实存在且未过期（防止进程靠内存旧证书硬撑、重启直接挂掉）。
   * 在大本营执行 `xray run -test -c /etc/xray/config.json.next`，失败则立刻中止并删除 `.next` 文件。
5. **备份与原子替换**：`cp /etc/xray/config.json /etc/xray/config.json.bak` 后 `mv /etc/xray/config.json.next /etc/xray/config.json`。
6. **重启与健康自测**：执行 `systemctl restart xray`，等待 2 秒检查 `systemctl is-active xray`；并用本地 `xray` 通过大本营入口发一次 `generate_204` 冒烟测试。
7. **失败自动回滚**：若重启失败或冒烟测试不通过，立即将 `.bak` 还原并重启 `xray`，同时向 Muse 返回非零退出码与脱敏告警。

### 3.3 统一订阅聚合器与分组策略（`scripts/build_sub.py`）

`build_sub.py` 汇总所有 `fleet.yaml` 节点，结合 `.secrets/` 凭据，在 `output/` 下产出最终交付物：

1. **双形态输出**：
   * `output/sub_v2ray.txt`：标准 Base64 编码的 `vless://` 列表（Shadowrocket 扫码直连）。
   * `output/sub_clash.yaml`：Clash Meta (Mihomo) 完整配置文件，自动划分三个策略组：
     * `🚀 舰队主力（Active）`：跑满 48 小时观察期、最近 24 小时拨测通过率达标的节点。
     * `🧪 观察期（Staging-48h）`：刚部署未满 48 小时的新 PaaS 节点，隔离防止新号触发平台审查影响主力体验。
     * `🛡️ 稀有中转（Hub-Transit）`：所有经大本营链式落地的稀有地区与纯 IPv6 节点。
2. **命名规范（自带情报标签）**：
   * 直连节点：`[国旗] 国家-平台名 [DC·直连]`（例：`🇫🇷 FR-Eurobase [DC·直连]`）
   * 中转节点：`[国旗] 国家-平台名 [DC·中转]`（例：`🇳🇵 NP-MeroDeploy [DC·中转]`）
3. **订阅发布与纯 ASCII 二维码**：
   * 将生成的订阅文件同步发布至大本营 Nginx 受保护的随机高熵路径（`https://{my_sub_domain}/{secret_sub_token}/sub`），**不暴露真实源站 IP**。
   * 生成纯 ASCII 文件名二维码（`output/qr_sub_active.png`），供主人手机扫码一次性导入，后续所有节点增删与月度轮换只需在手机点击“刷新订阅”。

---

## 第四章：Muse 调度内置 Codex 的分阶段落地剧本（M1 – M4）

Muse 收到本手册后，**禁止一次性让 Codex 写完所有文件**。必须严格按以下 4 个里程碑依次推进，每个里程碑跑通自测、做一次 Git 提交并向主人汇报后，再进入下一阶段。

### 里程碑 M1：工作区建厂 + 双模安全镜像 + 静态审计脚本
* **Muse 动作**：亲自创建第零章全部目录、`.gitignore`、`.secrets/`（700）及 `registry/` 三本初始台账（将已知判死黑名单填入 `blacklist.yaml`）。
* **Muse 下发给 Codex 的标准指令**：

```text
【工作目录】~/fleet-muse/（仅允许写入 docker/、scripts/audit_secrets.py、tests/）
【任务目标】编写双模节点容器源码（Dockerfile、cover.py、entrypoint.sh），基于 ghcr.io/xtls/xray-core + python:3.12-alpine，支持环境变量 PORT、UUID、WSPATH、TRANSPORT=ws|xhttp；根路径 / 通过 Xray fallback 转发给 cover.py 返回 HTTP 200；日志级别锁死 warning。同时编写 scripts/audit_secrets.py，扫描代码层确保无硬编码 UUID、API Key、明文私钥或调试打印环境变量语句。
【安全约束】严禁读取 .secrets/；所有测试均使用随机生成的临时假 UUID。
【自测标准】本地成功 docker build，分别在 TRANSPORT=ws 和 TRANSPORT=xhttp 模式下启动容器，实测根路径返回 HTTP 200 且用本机 xray 连本地容器跑通 generate_204=204，最后运行 python3 scripts/audit_secrets.py 返回退出码 0 并清理测试容器。
```

### 里程碑 M2：开发并验证 `scripts/verify_node.py`
* **Muse 下发给 Codex 的标准指令**：

```text
【工作目录】~/fleet-muse/（仅允许写入 scripts/verify_node.py、tests/test_verify_node.py）
【任务目标】严格按照 docs/ARCHITECT_MANUAL.md 第一章规格实现 scripts/verify_node.py，完整包含 Cover 检查、Google DoH 非 CF 校验（自动缓存官方 CIDR）、动态端口 Xray 3 次 generate_204 拨测、5MB 防截断测速、三库 IP/ASN 交叉定性、Globalping 国内探针抽检，以及全套退出码与脱敏 JSON 输出。
【安全约束】严禁读取 .secrets/；进程退出必须按精确 PID 清理临时 xray 与 /tmp 配置文件；stdout 绝不输出明文 UUID/WSPATH。
【自测标准】编写并跑通 pytest tests/test_verify_node.py（涵盖正常通过、CF 违规退出码 20、WS 异常退出码 30、脱敏断言），并针对 M1 本地容器执行一次真实端到端验证。
```

### 里程碑 M3：建立 `providers/` 插件框架与统一调度器
* **Muse 下发给 Codex 的标准指令**：

```text
【工作目录】~/fleet-muse/（仅允许写入 providers/、scripts/run_provider.py、tests/test_providers.py）
【任务目标】按 docs/ARCHITECT_MANUAL.md 第二章规格实现 providers/base.py、providers/mock_provider.py 以及统一调度器 scripts/run_provider.py（支持 deploy、switch-transport、status、wake、destroy 与异常正则脱敏）。
【安全约束】插件构造函数仅接收调度器传入的字典，绝不直接读 .secrets/；模拟凭据仅在 tests/ 临时目录生成与销毁。
【自测标准】跑通 pytest tests/test_providers.py，验证完整生命周期（部署 -> WS 切 XHTTP -> 唤醒 -> 销毁）以及 BillingWallError / AUPBlockedError 正确捕获与密钥脱敏。
```

### 里程碑 M4：大本营链式重载器、订阅聚合器与哨兵系统
* **Muse 下发给 Codex 的标准指令**：

```text
【工作目录】~/fleet-muse/（仅允许写入 scripts/sync_hub.py、scripts/build_sub.py、scripts/sentinel.py、tests/test_hub_and_sub.py）
【任务目标】按 docs/ARCHITECT_MANUAL.md 第三章规格实现：① sync_hub.py（服务端单端口 REALITY 多用户路由分流落地配置生成、磁盘证书与 xray -test 预检、原子替换、冒烟测试与失败自动回滚）；② build_sub.py（聚合直连与中转节点，输出 Base64 订阅、带 Active/Staging/Hub-Transit 三分组的 Clash Meta 配置与纯 ASCII 二维码）；③ sentinel.py（每 6 小时休眠唤醒+拨测、48 小时 Staging 自动晋升 Active、到期前 24 小时续期/轮换告警、异常节点自动踢出活跃订阅）。
【安全约束】严禁读取真实 .secrets/；用 --dry-run 模式和临时夹具完成配置生成校验。
【自测标准】使用模拟多节点台账（含直连节点、纯 IPv6 中转节点、Staging 观察期节点）跑通 sync_hub.py --dry-run（通过 xray run -test 验证生成配置语法 100% 合法）、build_sub.py 输出验证及 audit_secrets.py 全仓静态扫描退出码为 0。
```

---

## 第五章：上线运行态与防翻车验收清单（Muse 自查）

M1 至 M4 全部通过并提交本地 Git 后，Muse 正式接管日常舰队运营，必须遵守以下运行态守则：

1. **首次真机闭环前先跑大本营**：让主人先填入 `.secrets/hub.env`（大本营 VPS 信息），先跑通 1 条大本营直出节点并手机扫码验证，再开始批量开荒免费 PaaS。
2. **新平台 48 小时观察期（Staging）铁律**：任何新注册成功的免费 PaaS 节点，即使通过四件套验收，前 48 小时一律标记 `status: staging`，仅放入订阅的观察分组；连续 48 小时内哨兵巡检零失联且未被平台 AUP 清理，才自动晋升 `status: active` 进入主力组。
3. **防死循环熔断**：同一平台技术排障派给 Codex 最多 2 轮；同一平台注册/部署总计尝试最多 3 轮；触发绑卡/KYC/AUP 拦截立刻止损入黑名单，绝不纠缠。
4. **单次新增平台极速流**：发现新免费 API PaaS → Muse 免卡注册存 Key 至 `.secrets/providers/` → 派 Codex 读公开 API 文档写 `providers/{new}.py` 并跑通 Mock 测试 → Muse 调 `run_provider.py deploy` → 调 `verify_node.py` 四件套验收 → 若 `recommended_mode == "transit"` 则调 `sync_hub.py` → 调 `build_sub.py` 刷新订阅并向主人交付脱敏报告。
5. **一键干净停服**：若主人日后叫停本项目，Muse 必须逐条停用全部 `sentinel.py` 定时任务、列出已停用清单并归档台账，严禁后台空跑巡检消耗 Token 或触发未知费用。

---

## 附录：发送给 Muse 的首次启动指令

将本文件发送给 Muse 或保存至 `~/fleet-muse/docs/ARCHITECT_MANUAL.md` 后，可直接发送以下指令启动全流程：

```text
请完整阅读并记住 ARCHITECT_MANUAL.md，将其归档到 ~/fleet-muse/docs/ARCHITECT_MANUAL.md。
严格遵循其中的密钥隔离与分工红线，现在按第四章的 M1 -> M4 里程碑顺序调度内置 Codex 分阶段落地。
每完成一个里程碑并通过全部自测与 audit_secrets.py 静态扫描后，做一次 Git 提交并向我汇报结果，再进入下一个里程碑。
```