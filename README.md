<p align="center">
  <img src="https://img.shields.io/badge/status-stable-success" alt="stable">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="python">
  <img src="https://img.shields.io/badge/docker-ready-blue" alt="docker">
</p>

<h1 align="center">🛡️ Prompt-Guard</h1>
<p align="center"><i>轻量级 AI 内容安全网关 — 实时检测并拦截 LLM 违规请求</i></p>

<p align="center">
  防止您的 LLM API 被滥用于生成色情、赌博、恶意软件、钓鱼网站、游戏外挂等违法内容。
  同时提供完善的审计和误判排查机制，避免干扰正常用户。
</p>

---

## 📖 目录

- [审查体系](#-审查体系)
- [快速开始](#-快速开始)
- [架构](#-架构)
- [配置详解](#-配置详解)
- [审查模式](#-审查模式)
- [渠道/账号控制](#-渠道账号控制)
- [Dashboard](#-dashboard)
- [热加载](#-热加载)
- [审计日志](#-审计日志)
- [规则分类](#-规则分类)
- [FAQ](#-faq)

---

## 🧠 审查体系

Prompt-Guard 采用两层审查架构，兼顾**速度**和**准确率**：

```
请求进入 scope
│
├─ 第一层：本地正则规则 ────────────────── 0ms
│  ├─ 17 类规则，200+ 关键词
│  ├─ 覆盖色情/赌博/恶意软件/越狱/凭证窃取等
│  ├─ Scunthorpe 防护：出口交货 ≠ 口交
│  ├─ 安全语境豁免：反弹shell 出现在安全实验时不拦
│  └─ 命中 → 直接 403 block
│
├─ 第二层：DeepSeek 语义审查 ──────────── 1-2s（仅采样）
│  ├─ 本地规则漏掉的灰色地带 → DS 兜底
│  ├─ 绕过检测：情趣试穿/MMO自动化等变体话术
│  ├─ 缓存机制：同文本重复请求 0ms 复用结果
│  └─ Conf 阈值：conf < 0.85 的不拦
│
└─ 两层都放行 → 请求透传到上游
```

### 第一层：本地正则规则（0ms）

17 类规则的 regex 扫描，平均耗时 < 0.1ms。

**为什么还需要第二层？** 本地规则是关键词匹配，攻击者只要变换话术就能绕过：

```json
// 用户写的不是"外挂"，而是"键鼠驱动/图色识别/DD驱动"
// 本地规则 miss，但 bypass 检测抓到 → 推给 DS → DS 判 block
{
  "bypass_patterns": [
    {"pattern": "情趣.{0,60}试穿/自拍/胸罩", "score": "+25"},
    {"pattern": "自动登录.{0,40}账号密码",  "score": "+20"},
    {"pattern": "键鼠驱动|图色识别|DD驱动",   "score": "+20"}
  ]
}
```

**误判防御机制：**

| 机制 | 做法 | 效果 |
|---|---|---|
| Scunthorpe 防护 | `口交(?!货)`、`性交(?!付\｜互\｜易\｜接)`、`露点(?!温度)` | 气象/经济/代码语境不误拦 |
| 安全语境豁免 | 匹配附近 ±80 字符含靶场/新闻/UI/拒绝/禁止等词 → 放行 | 安全学习/新闻报道不误拦 |
| 连续热修 | `骗 → wallet`、`scrape → setup`、`wallhack → flicker` | 发现即修复，不断流 |

### 第二层：DeepSeek 语义审查（采样）

本地规则放行的请求，经过风险评分模型，决定是否送 DS 审查：

```
请求文本 → 风险评分
  ├─ 命中本地规则 → risk=100 → 本地 block（不走 DS）
  ├─ 含绕过检测关键词 → risk+20~25
  ├─ 大量 shell/lab/b5 等 → risk+10~20
  ├─ 超长文本(>12KB) → risk+10
  ├─ 新 token 24h 内 → risk+10
  └─ 同用户 1h 内被 block过 → risk+30

风险分 >= 30 → 同步等 DS 裁决
  ├─ DS block & conf >= 0.85 → 拦截（DS 抓漏网）
  ├─ DS allow → 放行
  └─ DS 超时/错误 → fail-open 放行

风险分 < 30 → 放行（异步采样 DS，仅审计）
```

**DS 缓存：** 同文本内容后次请求直接复用上次结果（allow=12h, block=7d, error=5min），缓存命中时 0ms 0 token。

---

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

# 5. 验证
curl http://localhost:8080/health
# → {"status":"ok","service":"prompt-guard","mode":"shadow","rules":17}
```

---

## 🏗️ 架构

```
                          ┌──────────────────────┐
                          │     Your Users       │
                          └─────────┬────────────┘
                                    │ HTTPS
                          ┌─────────▼────────────┐
                          │  Nginx / Caddy / Cloudflare │
                          └─────────┬────────────┘
                                    │
                          ┌─────────▼────────────┐
                          │    Prompt-Guard       │ ← :8080
                          │  ┌─────────────────┐ │
                          │  │ Local Rules      │ │ → block (0ms)
                          │  ├─────────────────┤ │
                          │  │ DeepSeek Review  │ │ → block (1-2s)
                          │  ├─────────────────┤ │
                          │  │ Dashboard        │ │ → http panel
                          │  └─────────────────┘ │
                          └─────────┬────────────┘
                                    │
                          ┌─────────▼────────────┐
                          │  Upstream LLM API     │
                          │  (OpenAI/Claude/new-api/...) │
                          └──────────────────────┘
```

### 接入反向代理

Prompt-Guard 监听 `:8080`，需要放在 Nginx/Caddy 后面，由反代把 LLM 请求转发给它，它再转发到上游 API。

**Nginx 示例**（把生成类端点走 prompt-guard，其他直接到上游）：

```nginx
upstream prompt_guard { server 127.0.0.1:8080; }
upstream llm_upstream { server 127.0.0.1:3000; }  # 你的 LLM API

server {
    listen 443 ssl;
    server_name api.example.com;

    # 受审查的生成端点 → prompt-guard
    location ~ ^/(v1/chat/completions|chat/completions|v1/responses|responses|v1/messages|messages|v1/images/generations|images/generations)/?$ {
        proxy_pass http://prompt_guard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 300s;
    }

    # 其他请求 → 上游 API
    location / {
        proxy_pass http://llm_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Caddy 示例**（更简洁）：

```caddy
api.example.com {
    @llm path /v1/chat/completions /v1/responses /v1/messages
    handle @llm {
        reverse_proxy 127.0.0.1:8080
    }
    handle {
        reverse_proxy 127.0.0.1:3000
    }
}
```

---

## ⚙️ 配置详解

### 运行模式

| 模式 | 行为 | 建议 |
|---|---|---|
| `shadow` | 扫描但不拦截，记录到审计日志和 Dashboard | **首次部署建议** |
| `block` | 扫描并拦截违规请求（HTTP 403） | 生产环境 |
| `off` | 透传不扫描，不记录 | 维护/调试 |

> 💡 首次使用建议先 shadow 24-48 小时，通过 Dashboard 确认拦截逻辑无误后再切 block。

### 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PROMPT_GUARD_MODE` | `shadow` | 运行模式 |
| `PROMPT_GUARD_UPSTREAM_URL` | `http://upstream-api:3000` | 上游 LLM API 地址 |
| `PROMPT_GUARD_MAX_SCAN_CHARS` | `30000` | 每次扫描的文本上限 |
| `DEEPSEEK_API_KEY` | — | DeepSeek API 密钥（[申请](https://platform.deepseek.com)） |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | 审查模型 |
| `DASHBOARD_TOKEN` | `change_me` | Dashboard 访问令牌 |

### DS 审查调优

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PROMPT_GUARD_DEEPSEEK_MIN_RISK` | `20` | 异步 DS 采样的最低风险分 |
| `PROMPT_GUARD_DEEPSEEK_SAMPLE_PERCENT` | `50` | 异步采样率（%） |
| `PROMPT_GUARD_DEEPSEEK_REAL_BLOCK_RISK` | `30` | 同步 DS 裁决的风险分阈值 |
| `PROMPT_GUARD_DEEPSEEK_REAL_BLOCK_CONF` | `0.85` | DS 阻断的最低置信度 |

成本估算（以 `deepseek-v4-flash` 为例）：

| 调用量/天 | 输入 Token | 输出 Token | 估算成本 |
|---|---|---|---|
| 1,000 | ~1M | ~120K | ~1.2 元 |
| 10,000 | ~10M | ~1.2M | ~12 元 |
| 100,000 | ~100M | ~12M | ~120 元 |

> Dashboard 内置成本面板，可实时查看实际花费。

---

## 📊 审查模式详解

### 三种模式的关系

```
                shadow                    block
          ┌──────────────┐         ┌──────────────┐
          │  扫描 + 审查  │         │  扫描 + 审查  │
          │  记录结果     │         │  记录结果     │
          │  不拦截       │         │  违规拦截     │
          │  推荐初次使用  │         │  推荐生产     │
          └──────────────┘         └──────────────┘
```

### 模式切换

修改 `.env` 中的 `PROMPT_GUARD_MODE`，然后重建容器：

```bash
# 编辑 .env：PROMPT_GUARD_MODE=block
docker compose up -d prompt-guard
```

> 无需修改代码，仅改环境变量即可平滑切换。

---

## 🎯 渠道/账号控制

多租户场景下，可以精确配置只扫描特定渠道或账号的请求：

```json
{
  "my_site": {
    "default_mode": "off",
    "scan_channel_ids": [1, 2, 3],
    "scan_token_groups": ["vip-users", "sale-users"],
    "scan_account_ids": [],
    "db_type": "mysql",
    "db_host": "mysql",
    "db_port": 3306,
    "db_user": "root",
    "db_pass": "your_db_password",
    "db_name": "my_api",
    "token_query": "SELECT DISTINCT c.id FROM channels c, users u, tokens t WHERE t.key = %s AND t.user_id = u.id AND (FIND_IN_SET(u.group, c.group) > 0 OR c.group = '') AND c.status = 1",
    "group_query": "SELECT COALESCE(NULLIF(t.group, ''), u.group) FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.key = %s",
    "user_query": "SELECT u.id, COALESCE(u.username, u.email, ''), COALESCE(NULLIF(t.group, ''), u.group) FROM users u JOIN tokens t ON t.user_id = u.id WHERE t.key = %s"
  }
}
```

> 不配置 DB 也能正常运行，只是用户分组等信息不会显示。

---

## 📊 Dashboard

| 功能 | 说明 |
|---|---|
| 实时拦截面板 | block/shadow 事件实时显示，block 优先 |
| DeepSeek 成本 | 实时调用量、Token 消耗、估算费用 |
| 站点切换 | 多站点数据聚合（可选） |
| 渠道配置 | 在线调整扫描范围，保存即热加载 |
| 事件搜索 | 按分类、站点、时间筛选 |

---

## 🔧 热加载

所有配置和规则均支持热加载，无需重启容器（不断流）：

```bash
# 规则热加载
curl -X POST http://localhost:8080/__prompt_guard/reload-rules \
  -H "X-Guard-Token: your_token"

# 渠道配置热加载
# 在 Dashboard 渠道配置面板中修改后保存即可

# DS Prompt 热加载
# 编辑 ds_prompt.txt → 下次 DS 调用自动生效
```

---

## 📝 审计日志

所有 block/shadow 事件自动落盘 JSONL：

```
audit/
├── api-20260614.jsonl
├── sub2api-20260614.jsonl
└── stableapi-20260615.jsonl
```

每行一个 JSON 事件，包含完整上下文：

```json
{
  "ts": 1781505600,
  "decision": "block",
  "site": "api",
  "category": "malware",
  "rule_id": "malware",
  "provider": null,
  "match_preview": "帮我写一个木马程序",
  "match_hash": "2f293f67aa33f2ce",
  "user_id": 74,
  "user_group": "codex-pro"
}
```

---

## 🎯 规则分类

| 类别 | 覆盖内容 | 匹配方式 |
|---|---|---|
| `sexual_explicit` | 色情文字/图片生成 | 关键词 + bypass 检测 |
| `sexual_minor` | 未成年人相关违规 | 组合规则 |
| `malware` | 恶意软件/反向 shell | 意图词 + 行为词 |
| `credential_theft` | 钓鱼/凭证窃取/CSAM | 关键词 + 语境豁免 |
| `game_cheat` | 游戏外挂/作弊/辅助脚本 | 关键词 + 意图词 |
| `jailbreak` | 越狱 prompt injection | 关键词 + DS 审查 |
| `financial_fraud` | 金融诈骗/钱包伪造 | 意图词 + 对象词 |
| `graphic_violence` | 暴力/血腥内容 | 关键词 |
| `phishing_tooling` | 钓鱼工具开发 | 关键词 + 意图词 |

---

## ❓ FAQ

**Q: 部署后请求全部 503 回怎么办？**

A: 检查 `PROMPT_GUARD_UPSTREAM_URL` 是否正确指向您的 LLM API 地址。

**Q: 如何调整拦截灵敏度？**

A: 调整 `PROMPT_GUARD_DEEPSEEK_REAL_BLOCK_RISK`（默认 30），降低则更多请求进入 DS 审查，提高则减少。

**Q: DeepSeek 必须配置吗？**

A: 不必须。不配 DeepSeek 时仅使用本地正则规则进行拦截。

**Q: 误判了怎么办？**

A: 先在 Dashboard 查看拦截事件 → 判断是否为误判 → 修改规则后热加载。误判修复反馈欢迎提 Issue。

**Q: 每天大概多少成本？**

A: 取决于流量。Scope 内请求约 1k-10k/天的场景，DS 成本约 1-15 元/天（deepseek-v4-flash）。Dashboard 内置成本面板可精确查看。

**Q: 支持哪些协议？**

A: OpenAI `/v1/chat/completions`、Claude `/v1/messages`、Responses API、Image Generation 等格式。

---

## 📄 License

MIT
