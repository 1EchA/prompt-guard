<p align="center">
  <img src="https://img.shields.io/badge/status-stable-success" alt="stable">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="python">
  <img src="https://img.shields.io/badge/docker-ready-blue" alt="docker">
</p>

<h1 align="center">🛡️ Prompt-Guard</h1>
<p align="center"><i>轻量级 AI 内容安全网关 — 实时拦截 LLM 违规请求</i></p>

---

## ✨ 功能

| 特性 | 说明 |
|---|---|
| **两层审查** | 本地 regex 规则（0ms）+ DeepSeek LLM 语义审查 |
| **热加载** | 改规则后 curl 重载，不重启不断流 |
| **Dashboard** | 实时拦截面板、DeepSeek 成本统计、渠道配置 |
| **Shadow 模式** | 先观察再拦截，零风险上线 |
| **渠道控制** | 精确到 channel / account / token group 的扫描范围 |
| **低延迟** | 平均扫描耗时 <100ms（含 DS 的 <1%） |
| **低成本** | 单台机器即可运行，DeepSeek 按调用计费 |

## 🏗️ 架构

```
User → Nginx/Caddy → Prompt-Guard(:8080) → Upstream LLM API
                         │
                     [Local Regex] → block (0ms)
                         │
                    [DeepSeek API] → block (1-2s, sampled)
                         │
                    [Audit Log + Dashboard]
```

## 🚀 快速开始

```bash
# 1. 克隆
git clone https://github.com/1EchA/prompt-guard.git
cd prompt-guard

# 2. 配置
cp .env.example .env
# 编辑 .env，至少设置 DEEPSEEK_API_KEY 和 DASHBOARD_TOKEN

# 3. 启动
docker compose up -d

# 4. 查看面板
# 浏览器打开 http://localhost:8080/__prompt_guard/dashboard
# 输入你设置的 DASHBOARD_TOKEN
```

## ⚙️ 配置

### 运行模式

| 模式 | 行为 | 适用场景 |
|---|---|---|
| `shadow` | 扫描但不拦截，记录到审计 | **首次部署建议** |
| `block` | 扫描并拦截违规请求 | 生产环境 |
| `off` | 透传不扫描 | 维护/调试 |

> 💡 第一次使用建议先 shadow 24h，观察拦截日志确认无误后切 block。

### 关键环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PROMPT_GUARD_MODE` | `shadow` | 运行模式 |
| `DEEPSEEK_API_KEY` | — | DeepSeek API 密钥（[申请](https://platform.deepseek.com)） |
| `DASHBOARD_TOKEN` | `change_me` | 面板访问令牌 |
| `PROMPT_GUARD_DS_REAL_BLOCK_RISK` | `30` | DS 同步审查风险阈值 |
| `PROMPT_GUARD_DEEPSEEK_SAMPLE_PERCENT` | `50` | DS 采样率（%） |

### DS 采样策略

```
请求进入审查
├─ 本地规则命中 → 直接 block（0ms）
├─ 没命中 + risk ≥ 30 → 同步等 DS 裁决（1-2s）
│    └─ DS block → 拦截
│    └─ DS allow → 放行
└─ 没命中 + risk < 30 → 放行 + 异步 DS 采样
```

## 📊 Dashboard

访问 `http://localhost:8080/__prompt_guard/dashboard`

- **实时拦截面板**：block / shadow 事件实时推送
- **分类统计**：按违规类型聚合
- **DeepSeek 成本**：token 消耗、估算费用
- **渠道配置**：在线调整扫描范围（热加载）

## 🔧 热加载

改规则或配置后无需重启：

```bash
# 改规则
curl -X POST http://localhost:8080/__prompt_guard/reload-rules \
  -H "X-Guard-Token: your_token"

# 改 DS prompt
# 编辑 ds_prompt.txt → 下次 DS 调用自动生效
```

## 🎯 规则分类

| 分类 | 覆盖场景 |
|---|---|
| `sexual_explicit` | 色情内容、露骨描写 |
| `sexual_minor` | 未成年人相关违规 |
| `malware` | 恶意软件生成 |
| `credential_theft` | 凭证窃取、钓鱼 |
| `game_cheat` | 游戏外挂、作弊 |
| `jailbreak` | 越狱 prompt injection |
| `financial_fraud` | 金融诈骗 |
| `graphic_violence` | 暴力内容 |

## 📁 项目结构

```
prompt-guard/
├── prompt_guard.py              # 核心引擎
├── prompt_guard_rules.json      # 规则配置
├── prompt-guard.Dockerfile      # 容器构建
├── ds_prompt.txt                # DS 审查提示词
├── docker-compose.yml           # 一键部署
├── channel_scan_config.json     # 渠道控制（可选）
├── .env.example                 # 环境变量模板
└── README.md
```

## 📄 License

MIT
