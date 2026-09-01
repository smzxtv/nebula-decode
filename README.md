# Nebula-Decode — Cloudflare 单文件终端

Nebula-Decode 是一个 Cloudflare Pages/Workers 单文件终端项目。
整站只有一个 `public/_worker.js`，包含代理协议实现、Web 管理面板、订阅生成和 API，配置存 KV，改完立即生效、无需重新部署。

> ✦ 作者：**数码解码** · 开源地址：<https://github.com/smzxtv/nebula-decode>

## 功能

- **双协议**：VLESS-WS-TLS / Trojan-WS-TLS，同一入口路径共用，Worker 按首包特征自动识别，可同时启用
- **Web 管理面板**：访问 `https://你的域名/{UUID}` 打开终端风格面板，可视化修改 UUID、自定义路径（支持多级）、ProxyIP、Trojan 密码、协议开关、优选域名
- **KV 配置**：优先级 KV > 环境变量 > 默认值，面板保存后立即生效
- **订阅生成**：`/{UUID}/sub` 返回 base64 订阅；Clash/Stash/Mihomo 的 UA 自动返回 YAML（也可用 `?target=clash` 强制）
- **优选 IP 管理**：面板添加/清空，或走 REST API；订阅自动合并「Worker 域名 + 优选域名 + 优选 IP」生成节点
- **ProxyIP 回落**：直连目标无响应（典型为 CF 自家站点）4 秒后自动改走 ProxyIP 重连
- **UDP**：支持 DNS（53 端口）转发，其余 UDP 不支持
- **伪装**：非入口路径返回 404 nginx 风格页面

## 文件结构

```
nebula-decode/
├── public/
│   └── _worker.js     # 全部逻辑（单文件）
├── test/
│   └── verify.mjs     # 本地单元测试（node test/verify.mjs）
├── wrangler.toml      # Pages 配置 + KV 绑定
└── README.md
```

## 部署方式一：Cloudflare 控制台上传（最简单）

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers 和 Pages** → **创建** → **Pages** → **直接上传**
2. 项目名随意（如 `nebula-decode`），把 `nebula-decode/public` 文件夹压缩成 zip 上传
3. 部署完成后先访问 `https://项目名.pages.dev/{默认UUID}` 确认面板能打开
4. **绑定 KV**：项目 → 设置 → 函数 → KV 命名空间绑定 → 变量名填 `KV`，选择一个命名空间（没有就先在 存储/D1/KV 页面创建）
5. 回到面板修改 UUID / 路径 / 密码并保存（没绑 KV 时保存会报错，面板/订阅仍能用默认值）

> ⚠️ 不绑 KV 也能跑，但配置改不了、优选 IP 存不了，强烈建议绑定。

## 部署方式二：Wrangler CLI

```bash
cd nebula-decode

# 1. 创建 KV 并把输出的 id 填进 wrangler.toml
npx wrangler kv namespace create KV

# 2. 部署（读取 wrangler.toml 的 pages_build_output_dir）
npx wrangler pages deploy

# 本地调试（模拟 KV，无需真实 ID）
npx wrangler pages dev
```

## 环境变量（均可省略，面板可改）

| 变量 | 说明 | 默认值 |
|---|---|---|
| `UUID` | VLESS 凭据，也是面板入口路径 | `24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d`（务必修改） |
| `CUSTOM_PATH` | 自定义路径，支持多级如 `my/nodes`，设置后 UUID 路径失效 | 空（用 UUID 当路径） |
| `PROXYIP` | 回落代理 IP/域名 | 空（不回落） |
| `TROJAN_PASSWORD` | Trojan 密码 | 空（Trojan 不可用） |

## 客户端使用

1. 浏览器打开 `https://你的域名/{UUID}` 进入面板
2. 复制「通用订阅」地址，在 v2rayN / v2rayNG / Shadowrocket / Nekoray 等客户端里添加订阅分组
3. Clash 系客户端用「Clash 订阅」地址，或直接点面板上的「Clash」一键导入
4. 面板上也可复制单个 `vless://` / `trojan://` 分享链接直接导入

## REST API（挂载在入口路径下）

```
GET    /{入口}/api/config          读取配置
POST   /{入口}/api/config          保存配置（JSON）
GET    /{入口}/api/ips             查询优选 IP
POST   /{入口}/api/ips             {"text":"1.2.3.4\ncf.090227.xyz"} 批量添加
DELETE /{入口}/api/ips?ip=1.2.3.4  删除单个；不带 ip 参数则清空
```

## 实现说明与限制

- 仅 TLS 节点（443 端口）；IP 节点的 SNI/Host 自动用 Worker 自身域名
- UDP 仅转发 DNS（53），不支持全 UDP；不支持 MUX、xhttp/gRPC
- 内置公共优选域名（`cf.090227.xyz` 等）是社区服务，可能失效，请自行在面板更换
- Workers 免费版每日 10 万请求；`connect()` 出站受 CF 限制，连接 Cloudflare 自家站点必须靠 ProxyIP 回落
- Trojan 密码校验使用内置纯 JS SHA-224（Workers 的 `crypto.subtle` 不支持 SHA-224），实现已通过 FIPS 标准测试向量验证（见 `test/verify.mjs`）

## 免责声明

仅供学习网络协议与 Cloudflare Workers 开发使用，请遵守所在地区法律法规及 Cloudflare 服务条款。
