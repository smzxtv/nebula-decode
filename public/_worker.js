// ============================================================
//  NEBULA-DECODE —— Cloudflare Pages/Workers 单文件终端
//  · VLESS-WS / Trojan-WS 双协议（同一入口自动识别）
//  · Web 图形化管理面板（挂载在 /{UUID 或自定义路径}）
//  · 配置存 KV，改完立即生效，无需重新部署
//  · 订阅生成 + UA 自动识别（base64 / Clash）
//  · 优选 IP / 域名管理 + REST API
//  · ProxyIP 回落（直连无响应自动走 ProxyIP）
//  作者: 数码解码  ·  https://github.com/smzxtv/nebula-decode
// ============================================================
import { connect } from 'cloudflare:sockets';

const CFG_KEY = 'cf_terminal_cfg';
const IPS_KEY = 'cf_terminal_ips';
const WS_OPEN = 1;

const DEFAULT_UUID = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';

// 内置公共优选域名（可在面板中修改，修改后存 KV）
const BUILTIN_PREFERRED = [
  'cf.090227.xyz',
  'bestcf.top',
  'cloudflare.182682.xyz',
  'cf.zhetengsha.eu.org',
];

// ============================ 基础工具 ============================

function uuidStringify(bytes) {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function isValidUUID(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || '');
}

function bytesToB64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
}
function isIPv6(s) {
  return s.includes(':') && /^[0-9a-f:.]+$/i.test(s);
}
function isIP(s) {
  return isIPv4(s) || isIPv6(s);
}

// SHA-224 纯 JS 实现（Workers 的 crypto.subtle 不支持 SHA-224，Trojan 协议必需）
// 常数表已用高精度计算并校验锚点值（K[0]=0x428a2f98, K[63]=0xc67178f2）
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha224Hex(text) {
  const msg = new TextEncoder().encode(text);
  const bitLen = msg.length * 8;
  const paddedLen = (((msg.length + 8) >> 6) << 6) + 64;
  const data = new Uint8Array(paddedLen);
  data.set(msg);
  data[msg.length] = 0x80;
  const dv = new DataView(data.buffer);
  dv.setUint32(paddedLen - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(paddedLen - 4, bitLen >>> 0);

  let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939,
      h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  const w = new Array(64);

  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6]
    .map((v) => (v >>> 0).toString(16).padStart(8, '0'))
    .join('');
}

// ============================ 配置（KV > 环境变量 > 默认值） ============================

function normalizeBase(p) {
  p = (p || '').trim().replace(/^\/+|\/+$/g, '');
  return p ? '/' + p : '';
}

async function loadConfig(env) {
  let kv = {};
  try {
    const raw = env.KV ? await env.KV.get(CFG_KEY) : null;
    if (raw) kv = JSON.parse(raw) || {};
  } catch (e) { /* KV 数据损坏时按默认处理 */ }

  return {
    uuid: String(kv.uuid || env.UUID || DEFAULT_UUID).trim().toLowerCase(),
    path: normalizeBase(kv.path || env.CUSTOM_PATH || ''),
    proxyIP: String(kv.proxyIP || env.PROXYIP || '').trim(),
    trojanPassword: String(kv.trojanPassword || env.TROJAN_PASSWORD || '').trim(),
    enableVless: kv.enableVless !== undefined ? !!kv.enableVless : true,
    enableTrojan: kv.enableTrojan !== undefined ? !!kv.enableTrojan : false,
    preferredDomains: Array.isArray(kv.preferredDomains) && kv.preferredDomains.length
      ? kv.preferredDomains.map((s) => String(s).trim()).filter(Boolean)
      : [...BUILTIN_PREFERRED],
  };
}

// 管理面板 / 隧道 / 订阅 的统一入口路径：自定义路径优先，否则用 UUID
function accessBase(cfg) {
  return cfg.path || '/' + cfg.uuid;
}

function matchBase(pathname, base) {
  return pathname === base || pathname === base + '/';
}

async function getPreferredIPs(env) {
  try {
    const raw = env.KV ? await env.KV.get(IPS_KEY) : null;
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) return arr;
    }
  } catch (e) { /* ignore */ }
  return [];
}

async function savePreferredIPs(env, ips) {
  if (!env.KV) throw new Error('未绑定 KV 存储');
  await env.KV.put(IPS_KEY, JSON.stringify(ips));
}

function jsonResp(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// ============================ 主路由 ============================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      const cfg = await loadConfig(env);
      const base = accessBase(cfg);
      const pathname = url.pathname;
      const isWS = (request.headers.get('upgrade') || '').toLowerCase() === 'websocket';

      // WebSocket 代理隧道入口（VLESS / Trojan 共用，自动识别）
      if (isWS) {
        if (matchBase(pathname, base)) {
          return handleWSTunnel(request, cfg);
        }
        return camouflage();
      }

      // 面板 / 订阅 / API 均挂在 base 路径下
      const rest = pathname === base ? '' : pathname.startsWith(base + '/') ? pathname.slice(base.length) : null;
      if (rest === null) return camouflage();

      if (rest === '' || rest === '/') return renderPanel(url, request, cfg, env);
      if (rest === '/sub') return handleSub(request, url, env, cfg);
      if (rest === '/api/config') return apiConfig(request, env, cfg);
      if (rest === '/api/ips') return apiIPs(request, env);
      return camouflage();
    } catch (err) {
      return new Response('NEBULA-DECODE Error: ' + (err && err.message), {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }
  },
};

// 未匹配路径时的伪装页
function camouflage() {
  return new Response('<!DOCTYPE html><html><head><meta charset="utf-8"><title>404 Not Found</title></head>' +
    '<body><center><h1>404 Not Found</h1><hr>nginx</center><!-- 数码解码 · NEBULA-DECODE --></body></html>', {
    status: 404,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

// ============================ WebSocket 隧道 ============================

function safeCloseWS(ws) {
  try {
    if (ws.readyState === WS_OPEN) ws.close(1000);
  } catch (e) { /* ignore */ }
}

// 读取 WS 0-RTT 早期数据（path 带 ?ed=2048 时，客户端把首包放在 Sec-WebSocket-Protocol 头里）
function getEarlyData(request) {
  const header = request.headers.get('sec-websocket-protocol') || '';
  if (!header) return null;
  try {
    const b64 = header.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch (e) {
    return null;
  }
}

async function handleWSTunnel(request, cfg) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const log = (...args) => console.log('[NEBULA-DECODE]', ...args);

  let firstPacketDone = false;
  let upstreamWriter = null;      // 远端 TCP / DNS socket 的 writer
  let pendingHeader = null;       // 协议响应头（VLESS 需要且只发一次；Trojan 为空）
  const pendingWrites = [];       // 连接建立期间到达的后续数据

  const sendToClient = (data) => {
    if (server.readyState !== WS_OPEN) return;
    if (pendingHeader && pendingHeader.length) {
      const merged = new Uint8Array(pendingHeader.length + data.byteLength);
      merged.set(pendingHeader);
      merged.set(data instanceof Uint8Array ? data : new Uint8Array(data), pendingHeader.length);
      pendingHeader = null;
      server.send(merged);
    } else {
      server.send(data);
    }
  };

  const setUpstream = (socket) => {
    upstreamWriter = socket.writable.getWriter();
    while (pendingWrites.length) {
      upstreamWriter.write(pendingWrites.shift()).catch(() => {});
    }
    return socket;
  };

  // 远端 → 客户端；返回是否收到过数据（用于 ProxyIP 回落判断）
  const pipeRemoteToWS = (socket) => {
    let hasIncomingData = false;
    return socket.readable.pipeTo(new WritableStream({
      write(data) {
        hasIncomingData = true;
        sendToClient(data);
      },
    })).then(
      () => hasIncomingData,
      (err) => {
        log('upstream read error:', err && err.message);
        return hasIncomingData;
      }
    );
  };

  const processFirst = async (buffer) => {
    const parsed = await parseClientPacket(buffer, cfg);
    pendingHeader = parsed.responseHeader;
    log(`proto=${parsed.proto} ${parsed.address}:${parsed.port}`);

    if (parsed.command === 2) {
      // UDP：仅支持 DNS(53)，通过 TCP DNS 转发（2 字节长度前缀帧格式一致）
      if (parsed.port !== 53) throw new Error('UDP 仅支持 53 端口(DNS)');
      const dnsSocket = connect({ hostname: '8.8.8.8', port: 53 });
      setUpstream(dnsSocket);
      await upstreamWriter.write(parsed.payload);
      pipeRemoteToWS(dnsSocket).finally(() => safeCloseWS(server));
      return;
    }

    await forwardTCP(parsed, setUpstream, pipeRemoteToWS, cfg, log, () => safeCloseWS(server));
  };

  server.addEventListener('message', (event) => {
    try {
      if (!firstPacketDone) {
        firstPacketDone = true;
        processFirst(event.data).catch((err) => {
          log('handshake error:', err && err.message);
          try { server.send('NEBULA-DEBUG: ' + (err && err.message)); } catch (e) {}
          safeCloseWS(server);
        });
        return;
      }
      if (upstreamWriter) {
        upstreamWriter.write(event.data).catch(() => {});
      } else {
        pendingWrites.push(event.data);
      }
    } catch (e) { /* ignore */ }
  });

  server.addEventListener('close', () => {
    try { if (upstreamWriter) upstreamWriter.releaseLock(); } catch (e) {}
    upstreamWriter = null;
  });

  // 首包可能在 WS 升级时已经带来（ed=2048 早期数据）
  const early = getEarlyData(request);
  if (early && early.byteLength > 0) {
    firstPacketDone = true;
    processFirst(early).catch((err) => {
      log('handshake(early-data) error:', err && err.message);
      safeCloseWS(server);
    });
  }

  return new Response(null, { status: 101, webSocket: client });
}

async function forwardTCP(parsed, setUpstream, pipeRemoteToWS, cfg, log, onDead) {
  const connectAndWrite = async (address, port) => {
    const socket = connect({ hostname: address, port });
    const writer = socket.writable.getWriter();
    await writer.write(parsed.payload);
    writer.releaseLock();
    return socket;
  };

  // 第一跳：直连目标地址
  let socket = await connectAndWrite(parsed.address, parsed.port);
  setUpstream(socket);
  const hasData = pipeRemoteToWS(socket);

  // 直连拿到数据前给一个宽限期；超时且配置了 ProxyIP 则回落重连
  let got = false;
  if (cfg.proxyIP) {
    got = await Promise.race([
      hasData,
      new Promise((r) => setTimeout(() => r(false), 4000)),
    ]);
    if (!got) {
      log(`直连 ${parsed.address}:${parsed.port} 无响应，回落 ProxyIP ${cfg.proxyIP}`);
      try { socket.close(); } catch (e) {}
      socket = await connectAndWrite(cfg.proxyIP, parsed.port);
      setUpstream(socket);
      pipeRemoteToWS(socket).finally(onDead);
      return;
    }
  } else {
    got = await hasData;
  }
  if (!got) onDead();
}

// ============================ 协议解析（VLESS / Trojan 自动识别） ============================

// 根据首包特征自动识别协议：
//  · Trojan: 前 56 字节为 hex(sha224(密码))，后跟 \r\n CMD ATYP ...
//  · VLESS:  [版本0][UUID长度16][UUID 16B][指令长度][指令][端口2B][地址类型][地址]负载
async function parseClientPacket(buffer, cfg) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // ---------- Trojan ----------
  if (cfg.enableTrojan && cfg.trojanPassword && bytes.length >= 62) {
    let isHex = true;
    for (let i = 0; i < 56; i++) {
      const c = bytes[i];
      if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) { isHex = false; break; }
    }
    if (isHex && bytes[56] === 13 && bytes[57] === 10) {
      const expect = sha224Hex(cfg.trojanPassword);
      const got = Array.from(bytes.slice(0, 56), (b) => String.fromCharCode(b)).join('');
      if (got !== expect) throw new Error('Trojan 密码认证失败');
      return parseTrojan(bytes, dv);
    }
  }

  // ---------- VLESS ----------
  if (!cfg.enableVless) throw new Error('VLESS 已禁用');
  if (bytes.length < 24) throw new Error('VLESS 首包过短');
  if (bytes[0] !== 0) throw new Error('不支持的 VLESS 版本');

  const userId = uuidStringify(bytes.slice(1, 17));
  if (userId !== cfg.uuid) throw new Error('VLESS UUID 认证失败');

  const optLen = bytes[17];
  const command = bytes[18 + optLen];           // 0x01 TCP / 0x02 UDP / 0x03 MUX
  if (command === 3) throw new Error('暂不支持 MUX');
  const port = dv.getUint16(19 + optLen);
  const addrType = bytes[21 + optLen];

  const addr = parseAddress(bytes, dv, addrType, 22 + optLen);
  return {
    proto: 'vless',
    command,
    address: addr.host,
    port,
    payload: bytes.slice(addr.offset),
    responseHeader: new Uint8Array([bytes[0], 0]),
  };
}

function parseTrojan(bytes, dv) {
  const cmd = bytes[58];                        // 0x01 CONNECT / 0x03 UDP_ASSOCIATE
  const addrType = bytes[59];
  const addr = parseAddress(bytes, dv, addrType, 60);
  let off = addr.offset;
  const port = dv.getUint16(off);
  off += 2;
  if (bytes[off] === 13 && bytes[off + 1] === 10) off += 2;
  return {
    proto: 'trojan',
    command: cmd === 3 ? 2 : 1,
    address: addr.host,
    port,
    payload: bytes.slice(off),
    responseHeader: new Uint8Array(0),          // Trojan 服务端不发响应头
  };
}

function parseAddress(bytes, dv, addrType, start) {
  if (addrType === 1) {                         // IPv4
    return { host: Array.from(bytes.slice(start, start + 4)).join('.'), offset: start + 4 };
  }
  if (addrType === 2) {                         // 域名
    const len = bytes[start];
    const host = new TextDecoder().decode(bytes.slice(start + 1, start + 1 + len));
    return { host, offset: start + 1 + len };
  }
  if (addrType === 3) {                         // IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(dv.getUint16(start + i * 2).toString(16));
    return { host: parts.join(':'), offset: start + 16 };
  }
  throw new Error('不支持的地址类型: ' + addrType);
}

// ============================ 节点 / 订阅生成 ============================

// 汇总节点列表：本 Worker 域名 + 优选域名 + 优选 IP
function buildNodes(url, cfg, ips) {
  const wsPath = accessBase(cfg) + '?ed=2048';
  const hosts = [];
  const push = (h) => {
    h = String(h || '').trim();
    if (h && !hosts.includes(h)) hosts.push(h);
  };
  push(url.hostname);
  cfg.preferredDomains.forEach(push);
  ips.forEach(push);

  const nodes = [];
  hosts.forEach((host) => {
    const ipNode = isIP(host);
    // 关键: SNI/Host 头必须始终用 Worker 自己的域名, Cloudflare 才会把请求路由到本 Worker;
    // 优选域名/IP 只作为连接地址 (server), 决定客户端到 CF 边缘的链路质量
    const sni = url.hostname;
    const name = ipNode ? (isIPv4(host) ? 'IP-' + host : 'IPv6-' + host) : host;
    if (cfg.enableVless) {
      nodes.push({
        proto: 'vless', name, server: host, port: 443,
        uuid: cfg.uuid, sni, host: sni, path: wsPath,
        link: `vless://${cfg.uuid}@${host}:443?encryption=none&security=tls&sni=${sni}&fp=chrome&type=ws&host=${sni}&path=${encodeURIComponent(wsPath)}#${encodeURIComponent(name)}`,
      });
    }
    if (cfg.enableTrojan && cfg.trojanPassword) {
      nodes.push({
        proto: 'trojan', name: name + '-trojan', server: host, port: 443,
        password: cfg.trojanPassword, sni, host: sni, path: wsPath,
        link: `trojan://${encodeURIComponent(cfg.trojanPassword)}@${host}:443?security=tls&sni=${sni}&fp=chrome&type=ws&host=${sni}&path=${encodeURIComponent(wsPath)}#${encodeURIComponent(name + '-trojan')}`,
      });
    }
  });
  return nodes;
}

function yamlQuote(s) {
  return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function buildClashYaml(nodes) {
  const lines = [];
  lines.push('# ═══════ 数码解码 · NEBULA-DECODE Clash 订阅 ═══════');
  lines.push('port: 7890');
  lines.push('socks-port: 7891');
  lines.push('allow-lan: false');
  lines.push('mode: rule');
  lines.push('log-level: info');
  lines.push('proxies:');
  for (const n of nodes) {
    lines.push(`  - name: ${yamlQuote(n.name)}`);
    lines.push(`    type: ${n.proto}`);
    lines.push(`    server: ${n.server}`);
    lines.push('    port: 443');
    lines.push('    udp: true');
    if (n.proto === 'vless') {
      lines.push(`    uuid: ${n.uuid}`);
      lines.push('    flow: ""');
    } else {
      lines.push(`    password: ${yamlQuote(n.password)}`);
    }
    lines.push('    tls: true');
    lines.push(`    servername: ${yamlQuote(n.sni)}`);
    lines.push('    skip-cert-verify: false');
    lines.push('    network: ws');
    lines.push('    ws-opts:');
    lines.push(`      path: ${yamlQuote(n.path)}`);
    lines.push('      headers:');
    lines.push(`        Host: ${yamlQuote(n.host)}`);
  }
  const names = nodes.map((n) => yamlQuote(n.name));
  lines.push('proxy-groups:');
  lines.push('  - name: "NEBULA-DECODE"');
  lines.push('    type: select');
  lines.push(names.length ? `    proxies: [${names.join(', ')}, DIRECT]` : '    proxies: [DIRECT]');
  lines.push('rules:');
  lines.push('  - MATCH,NEBULA-DECODE');
  return lines.join('\n') + '\n';
}

async function handleSub(request, url, env, cfg) {
  const ips = await getPreferredIPs(env);
  const nodes = buildNodes(url, cfg, ips);
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const target = url.searchParams.get('target')
    || (ua.includes('clash') || ua.includes('stash') || ua.includes('mihomo') ? 'clash' : 'base64');

  const headers = { 'content-type': 'text/plain; charset=utf-8', 'x-powered-by': 'shumajiedu | NEBULA-DECODE' };
  if (target === 'clash') {
    headers['content-type'] = 'text/yaml; charset=utf-8';
    headers['content-disposition'] = 'attachment; filename="nebula-decode.yaml"';
    return new Response(buildClashYaml(nodes), { headers });
  }
  const text = nodes.map((n) => n.link).join('\n');
  return new Response(bytesToB64(new TextEncoder().encode(text)), { headers });
}

// ============================ REST API ============================

async function apiConfig(request, env, cfg) {
  if (request.method === 'GET') return jsonResp(cfg);

  if (request.method === 'POST') {
    if (!env.KV) return jsonResp({ ok: false, error: '未绑定 KV 存储，无法保存配置' }, 500);
    let body;
    try { body = await request.json(); } catch (e) { return jsonResp({ ok: false, error: '请求体不是合法 JSON' }, 400); }

    const uuid = String(body.uuid || '').trim().toLowerCase();
    if (!isValidUUID(uuid)) return jsonResp({ ok: false, error: 'UUID 格式不合法' }, 400);

    const path = normalizeBase(body.path || '');
    if (path && (path === '/sub' || path.startsWith('/api'))) {
      return jsonResp({ ok: false, error: '自定义路径与保留路径冲突' }, 400);
    }

    const next = {
      uuid,
      path,
      proxyIP: String(body.proxyIP || '').trim(),
      trojanPassword: String(body.trojanPassword || '').trim(),
      enableVless: !!body.enableVless,
      enableTrojan: !!body.enableTrojan,
      preferredDomains: Array.isArray(body.preferredDomains)
        ? body.preferredDomains.map((s) => String(s).trim()).filter(Boolean)
        : [...BUILTIN_PREFERRED],
    };
    if (!next.enableVless && !(next.enableTrojan && next.trojanPassword)) {
      return jsonResp({ ok: false, error: '至少启用一个协议（Trojan 需设置密码）' }, 400);
    }
    await env.KV.put(CFG_KEY, JSON.stringify(next));
    return jsonResp({ ok: true });
  }
  return jsonResp({ ok: false, error: 'Method Not Allowed' }, 405);
}

async function apiIPs(request, env) {
  if (request.method === 'GET') {
    return jsonResp({ ips: await getPreferredIPs(env) });
  }
  if (request.method === 'POST') {
    if (!env.KV) return jsonResp({ ok: false, error: '未绑定 KV 存储' }, 500);
    let body;
    try { body = await request.json(); } catch (e) { return jsonResp({ ok: false, error: '请求体不是合法 JSON' }, 400); }
    const incoming = Array.isArray(body.ips) ? body.ips : String(body.text || '').split(/\r?\n/);
    const valid = incoming
      .map((s) => String(s).trim())
      .filter((s) => isIP(s) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s));
    if (!valid.length) return jsonResp({ ok: false, error: '没有合法的 IP / 域名' }, 400);
    const current = await getPreferredIPs(env);
    const merged = [...new Set([...current, ...valid])];
    await savePreferredIPs(env, merged);
    return jsonResp({ ok: true, ips: merged });
  }
  if (request.method === 'DELETE') {
    if (!env.KV) return jsonResp({ ok: false, error: '未绑定 KV 存储' }, 500);
    const ip = new URL(request.url).searchParams.get('ip');
    if (ip) {
      const rest = (await getPreferredIPs(env)).filter((s) => s !== ip);
      await savePreferredIPs(env, rest);
      return jsonResp({ ok: true, ips: rest });
    }
    await savePreferredIPs(env, []);
    return jsonResp({ ok: true, ips: [] });
  }
  return jsonResp({ ok: false, error: 'Method Not Allowed' }, 405);
}

// ============================ Web 管理面板 ============================

async function renderPanel(url, request, cfg, env) {
  const ips = await getPreferredIPs(env);
  const colo = (request.cf && request.cf.colo) || 'N/A';
  const base = accessBase(cfg);
  const subURL = url.origin + base + '/sub';
  const clashURL = url.origin + base + '/sub?target=clash';
  const protoBadges =
    (cfg.enableVless ? '<span class="badge ok">VLESS-WS</span>' : '<span class="badge off">VLESS 关</span>') +
    (cfg.enableTrojan && cfg.trojanPassword ? '<span class="badge ok">TROJAN-WS</span>' : '<span class="badge off">TROJAN 关</span>') +
    (cfg.path ? '<span class="badge">自定义路径</span>' : '');

  const html = '<!DOCTYPE html>' +
'<html lang="zh-CN"><head><meta charset="utf-8">' +
'<meta name="viewport" content="width=device-width,initial-scale=1">' +
'<title>NEBULA-DECODE 终端</title><style>' +
'*{box-sizing:border-box;margin:0;padding:0}' +
'body{background:#0a0e14;color:#c9d1d9;font-family:ui-monospace,Consolas,Menlo,monospace;font-size:14px;line-height:1.6;padding:24px}' +
'.wrap{max-width:860px;margin:0 auto}' +
'h1{color:#58e6d9;font-size:20px;letter-spacing:2px;margin-bottom:4px}' +
'h1 .v{color:#4a5568;font-size:12px}' +
'.sub{color:#4a5568;font-size:12px;margin-bottom:20px}' +
'.badge{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:4px;padding:1px 8px;font-size:11px;margin-right:6px;color:#8b949e}' +
'.badge.ok{color:#58e6d9;border-color:#1f6f64}' +
'.badge.off{color:#f85149;border-color:#7d2b28}' +
'.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px 18px;margin-bottom:16px}' +
'.card h2{font-size:13px;color:#58e6d9;letter-spacing:1px;margin-bottom:12px;border-bottom:1px solid #21262d;padding-bottom:8px}' +
'label{display:block;color:#8b949e;font-size:12px;margin:10px 0 4px}' +
'input[type=text],input[type=password],textarea{width:100%;background:#010409;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:8px 10px;font-family:inherit;font-size:13px}' +
'input:focus,textarea:focus{outline:none;border-color:#1f6f64}' +
'textarea{resize:vertical;min-height:70px}' +
'button{background:#1158c7;border:none;color:#fff;border-radius:6px;padding:7px 14px;font-family:inherit;font-size:13px;cursor:pointer;margin:10px 8px 0 0}' +
'button:hover{background:#1a6ae0}' +
'button.ghost{background:#21262d;color:#c9d1d9}' +
'button.ghost:hover{background:#30363d}' +
'button.danger{background:#7d2b28}' +
'code,a.code{display:block;background:#010409;border:1px solid #30363d;border-radius:6px;padding:8px 10px;color:#8dd3a0;font-size:12px;word-break:break-all;margin:6px 0;text-decoration:none}' +
'a.code:hover{border-color:#1f6f64}' +
'.chk{margin:8px 16px 0 0;color:#c9d1d9;font-size:13px;cursor:pointer}' +
'.row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:220px}' +
'.msg{margin-top:8px;font-size:12px;color:#58e6d9;min-height:18px}' +
'.hint{color:#4a5568;font-size:12px;margin-top:10px}' +
'.brand{color:#f0883e;border:1px solid #7d4e1e;border-radius:4px;padding:1px 8px;font-size:12px;margin-left:10px;vertical-align:2px}' +
'.footer{color:#4a5568;font-size:12px;text-align:center;margin:18px 0 4px}' +
'.footer a{color:#58e6d9;text-decoration:none}' +
'</style></head><body><div class="wrap">' +
'<h1>NEBULA-DECODE <span class="v">v1.2</span><span class="brand">数码解码 出品</span></h1>' +
'<div class="sub">Cloudflare Pages 单文件终端 &nbsp;|&nbsp; 节点机房: <b style="color:#58e6d9">' + colo + '</b> &nbsp;|&nbsp; 入口路径: <b style="color:#58e6d9">' + base + '</b> &nbsp;|&nbsp; ' + protoBadges + '</div>';

  const body = html +
'<div class="card"><h2>[ 节点配置 ]</h2>' +
'<div class="row"><div><label>UUID（VLESS 凭据，也是面板入口路径）</label><input type="text" id="uuid"><button class="ghost" style="padding:4px 10px;font-size:12px" onclick="genUuid()">🎲 随机生成 UUID</button></div>' +
'<div><label>自定义路径（可多级，如 my/nodes；留空用 UUID）</label><input type="text" id="path"></div></div>' +
'<div class="row"><div><label>ProxyIP（直连 CF 站点无响应时回落，如 1.1.1.1 或 bestcf.top）</label><input type="text" id="proxyIP"></div>' +
'<div><label>Trojan 密码（启用 Trojan 时必填）</label><input type="text" id="trojanPassword"></div></div>' +
'<label style="margin-top:14px">协议开关</label>' +
'<label class="chk"><input type="checkbox" id="enableVless"> VLESS-WS-TLS</label>' +
'<label class="chk"><input type="checkbox" id="enableTrojan"> Trojan-WS-TLS</label>' +
'<button onclick="saveCfg()">保存配置（立即生效）</button><div class="msg" id="msg1"></div>' +
'<div class="hint">提示：修改 UUID / 自定义路径保存后，面板地址会变为新入口路径。</div></div>' +

'<div class="card"><h2>[ 优选 IP / 域名 ]</h2>' +
'<label>每行一个 IP 或域名（会与下方优选域名合并生成订阅节点）</label>' +
'<textarea id="ips"></textarea>' +
'<button onclick="addIps()">添加</button><button class="danger" onclick="clearIps()">清空</button><div class="msg" id="msg2"></div>' +
'<label>优选域名列表（逗号分隔，内置公共优选域名可自行替换）</label>' +
'<input type="text" id="preferredDomains"></div>' +

'<div class="card"><h2>[ 订阅与导入 ]</h2>' +
'<label>通用订阅（v2rayN / v2rayNG / Shadowrocket / Nekoray 等，base64）</label>' +
'<a class="code" id="subA" href="' + subURL + '">' + subURL + '</a>' +
'<label>Clash / Stash / Mihomo 订阅（YAML）</label>' +
'<a class="code" id="clashA" href="' + clashURL + '">' + clashURL + '</a>' +
'<button class="ghost" onclick="copyTo(\'' + subURL + '\',this)">复制通用订阅</button>' +
'<button class="ghost" onclick="copyTo(\'' + clashURL + '\',this)">复制 Clash 订阅</button>' +
'<a class="code" style="display:none" id="nodeLink"></a>' +
'<label>一键导入</label>' +
'<button class="ghost" onclick="location.href=\'v2rayng://install-sub?url=\' + encodeURIComponent(\'' + subURL + '\')">v2rayNG</button>' +
'<button class="ghost" onclick="location.href=\'shadowrocket://add/sub://\' + encodeURIComponent(\'' + subURL + '\')">Shadowrocket</button>' +
'<button class="ghost" onclick="location.href=\'clash://install-config?url=\' + encodeURIComponent(\'' + clashURL + '\')">Clash</button>' +
'<div class="hint">客户端也可直接把通用订阅地址填入「订阅分组」，更新即用；UA 为 Clash 系时自动返回 YAML。</div></div>' +

'<div class="card"><h2>[ API 管理 ]</h2>' +
'<code>GET    ' + base + '/api/ips          查询优选 IP</code>' +
'<code>POST   ' + base + '/api/ips          {"text":"1.2.3.4\\n5.6.7.8"} 批量添加</code>' +
'<code>DELETE ' + base + '/api/ips?ip=1.2.3.4  删除单个；不带 ip 清空</code>' +
'<code>GET/POST ' + base + '/api/config     读取 / 保存全部配置</code></div>' +

'</div>' +
'<div class="footer">✦ 由 <b style="color:#f0883e">数码解码</b> 出品 · <a href="https://github.com/smzxtv/nebula-decode" target="_blank">GitHub 开源项目</a> ✦</div>' +
'<script>var BASE="' + base + '/";</script>' + PANEL_TAIL;
  return new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8', 'x-powered-by': 'shumajiedu | NEBULA-DECODE' } });
}

const PANEL_TAIL = '<script>' +
'function $(id){return document.getElementById(id)}' +
'function show(id,t){$(id).textContent=t;setTimeout(function(){$(id).textContent=""},4000)}' +
'async function loadCfg(){' +
'  var r=await fetch(BASE+"api/config"),c=await r.json();' +
'  $("uuid").value=c.uuid;$("path").value=(c.path||"").replace(/^\\//,"");$("proxyIP").value=c.proxyIP||"";' +
'  $("trojanPassword").value=c.trojanPassword||"";$("enableVless").checked=!!c.enableVless;' +
'  $("enableTrojan").checked=!!c.enableTrojan;$("preferredDomains").value=(c.preferredDomains||[]).join(",");' +
'  var r2=await fetch(BASE+"api/ips"),c2=await r2.json();$("ips").value=(c2.ips||[]).join("\\n");' +
'}' +
'async function saveCfg(){' +
'  var body={uuid:$("uuid").value.trim(),path:$("path").value.trim(),proxyIP:$("proxyIP").value.trim(),' +
'    trojanPassword:$("trojanPassword").value.trim(),enableVless:$("enableVless").checked,' +
'    enableTrojan:$("enableTrojan").checked,preferredDomains:$("preferredDomains").value.split(",").map(function(s){return s.trim()}).filter(Boolean)};' +
'  var r=await fetch(BASE+"api/config",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});' +
'  var c=await r.json();if(!c.ok){show("msg1","保存失败: "+(c.error||"未知错误"));return}' +
'  show("msg1","已保存，即将跳转到新入口...");' +
'  var base=body.path?"/"+body.path.replace(/^\\/+|\\/+$/g,""):"/"+body.uuid;' +
'  setTimeout(function(){location.href=base+"/"},800);' +
'}' +
'async function addIps(){' +
'  var r=await fetch(BASE+"api/ips",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({text:$("ips").value})});' +
'  var c=await r.json();if(c.ok){$("ips").value=c.ips.join("\\n");show("msg2","已添加 "+c.ips.length+" 条")}else show("msg2","失败: "+c.error);' +
'}' +
'async function clearIps(){' +
'  var r=await fetch(BASE+"api/ips",{method:"DELETE"});var c=await r.json();if(c.ok){$("ips").value="";show("msg2","已清空")}' +
'}' +
'function copyTo(t,btn){navigator.clipboard.writeText(t).then(function(){btn.textContent="已复制";setTimeout(function(){btn.textContent=btn.textContent.replace("已复制","复制")},1500)})}' +
'function genUuid(){if(window.crypto&&crypto.randomUUID){$("uuid").value=crypto.randomUUID()}else{var s="0123456789abcdef",u="";for(var j=0;j<36;j++){u+=(j===8||j===12||j===16||j===20)?"-":(j===14)?"4":s.charAt(Math.floor(Math.random()*16))}$("uuid").value=u}}' +
'loadCfg();' +
'<\/script></body></html>';




