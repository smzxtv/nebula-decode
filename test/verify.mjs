// 验证脚本：mock 掉 cloudflare:sockets 后，在 Node 中直接测试 _worker.js 的纯逻辑
import { readFileSync } from 'node:fs';

let src = readFileSync(new URL('../public/_worker.js', import.meta.url), 'utf8');
src = src.replace(/import\s*{\s*connect\s*}\s*from\s*['"]cloudflare:sockets['"];?/, "const connect = () => { throw new Error('mock: no network in tests'); };");
src = src.replace('export default', 'const _default =');
src += '\nexport { sha224Hex, uuidStringify, isValidUUID, bytesToB64, parseClientPacket, buildNodes, buildClashYaml, normalizeBase, _default };';
const mod = await import('data:text/javascript;base64,' + Buffer.from(src, 'utf8').toString('base64'));

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      got:  ${got}\n      want: ${want}`}`);
};

// ---- SHA-224 标准测试向量 (FIPS 180-4) ----
eq('sha224("abc")', mod.sha224Hex('abc'), '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
eq('sha224("")', mod.sha224Hex(''), 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
eq('sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")',
  mod.sha224Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
  '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525');
// 长文本（多块填充 + 长度字段）——直接与 node:crypto 对比
import crypto from 'node:crypto';
eq('sha224(100万字符a)',
  mod.sha224Hex('a'.repeat(1000000)),
  crypto.createHash('sha224').update('a'.repeat(1000000)).digest('hex'));
eq('sha224(中文文本)',
  mod.sha224Hex('云支付终端测试_PASSWORD-2026!'),
  crypto.createHash('sha224').update('云支付终端测试_PASSWORD-2026!').digest('hex'));

// ---- UUID 工具 ----
eq('uuidStringify', mod.uuidStringify(new Uint8Array([
  0x24, 0xb3, 0xc8, 0xb0, 0x0b, 0x1e, 0x4f, 0x5e, 0x9c, 0x2a, 0x7f, 0x6d, 0x5a, 0x4b, 0x3c, 0x2d,
])), '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d');
eq('isValidUUID ok', mod.isValidUUID('24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d'), true);
eq('isValidUUID bad', mod.isValidUUID('not-a-uuid'), false);

// ---- VLESS 首包解析（域名 + IPv4 + IPv6）----
const uuid = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';
const cfg = { uuid, enableVless: true, enableTrojan: false, trojanPassword: '' };

function vlessPacket(host, port, addrType) {
  const bytes = [0, ...Array.from({ length: 16 }, (_, i) => parseInt(uuid.replace(/-/g, '').slice(i * 2, i * 2 + 2), 16)), 0, 1];
  bytes.push((port >> 8) & 0xff, port & 0xff, addrType);
  if (addrType === 2) {
    const d = Array.from(host, (c) => c.charCodeAt(0));
    bytes.push(d.length, ...d);
  } else if (addrType === 1) {
    bytes.push(...host.split('.').map(Number));
  } else {
    for (const part of host.split(':')) bytes.push(parseInt(part, 16) >> 8, parseInt(part, 16) & 0xff);
  }
  bytes.push(0x16, 0x03, 0x01); // 模拟 TLS ClientHello 负载
  return new Uint8Array(bytes);
}

const p1 = await mod.parseClientPacket(vlessPacket('www.example.com', 443, 2), cfg);
eq('vless domain', `${p1.proto}|${p1.address}|${p1.port}|${p1.command}`, 'vless|www.example.com|443|1');
eq('vless responseHeader', Array.from(p1.responseHeader).join(','), '0,0');
eq('vless payload', Array.from(p1.payload.slice(0, 3)).join(','), '22,3,1');

const p2 = await mod.parseClientPacket(vlessPacket('1.2.3.4', 8080, 1), cfg);
eq('vless ipv4', `${p2.address}:${p2.port}`, '1.2.3.4:8080');

const p3 = await mod.parseClientPacket(vlessPacket('2606:4700:4700:0:0:0:0:1111', 443, 3), cfg);
eq('vless ipv6', p3.address, '2606:4700:4700:0:0:0:0:1111');

// ---- Trojan 首包解析 ----
// 格式: hex(sha224(password)) 56B + CRLF + CMD + ATYP + LEN + 域名 + 端口2B + CRLF + 负载
const pw = 'test-pass';
const t = [...Array.from(mod.sha224Hex(pw)).map((c) => c.charCodeAt(0))];
t.push(13, 10);                                  // CRLF
t.push(1);                                       // CMD = CONNECT
t.push(2);                                       // ATYP = 域名
t.push('example.org'.length);
for (const c of 'example.org') t.push(c.charCodeAt(0));
t.push(0x01, 0xbb);                              // 端口 443
t.push(13, 10);                                  // CRLF
t.push(1, 2, 3);                                 // 负载
const trojanBytes = new Uint8Array(t);
const p4 = await mod.parseClientPacket(trojanBytes, { ...cfg, enableTrojan: true, trojanPassword: pw });
eq('trojan parse', `${p4.proto}|${p4.address}|${p4.port}|${p4.command}`, 'trojan|example.org|443|1');
eq('trojan payload', Array.from(p4.payload).join(','), '1,2,3');
eq('trojan responseHeader empty', p4.responseHeader.length, 0);

// ---- 错误路径 ----
try {
  await mod.parseClientPacket(vlessPacket('www.example.com', 443, 2), { ...cfg, uuid: '11111111-1111-1111-1111-111111111111' });
  eq('vless wrong uuid rejected', 'no-error', 'error');
} catch (e) { eq('vless wrong uuid rejected', /UUID/.test(e.message), true); }

try {
  await mod.parseClientPacket(trojanBytes, { ...cfg, enableTrojan: true, trojanPassword: 'wrong' });
  eq('trojan wrong password rejected', 'no-error', 'error');
} catch (e) { eq('trojan wrong password rejected', /Trojan/.test(e.message), true); }

// ---- 节点 / 订阅生成 ----
const url = new URL('https://demo.example.workers.dev');
const subCfg = { uuid, path: '', enableVless: true, enableTrojan: true, trojanPassword: pw, preferredDomains: ['cf.090227.xyz'] };
const nodes = mod.buildNodes(url, subCfg, ['104.16.1.1']);
eq('node count (3 hosts x vless+trojan)', nodes.length, 6);
eq('ip node sni uses worker domain', nodes.find((n) => n.server === '104.16.1.1').sni, 'demo.example.workers.dev');
eq('vless link format', nodes[0].link,
  `vless://${uuid}@demo.example.workers.dev:443?encryption=none&security=tls&sni=demo.example.workers.dev&fp=chrome&type=ws&host=demo.example.workers.dev&path=%2F${uuid}%3Fed%3D2048#demo.example.workers.dev`);
const yaml = mod.buildClashYaml(nodes);
eq('clash yaml has proxies', /proxies:\n {2}- name:/.test(yaml), true);
eq('clash yaml vless ws-opts', /type: vless[\s\S]*?network: ws/.test(yaml), true);

// ---- base64 编解码（分块大文本）----
const big = new TextEncoder().encode('vless://x\n'.repeat(5000));
eq('bytesToB64 roundtrip', Buffer.from(mod.bytesToB64(big), 'base64').toString(), Buffer.from(big).toString());

// ---- 配置路径归一化 ----
eq('normalizeBase multi-level', mod.normalizeBase('my/nodes/'), '/my/nodes');
eq('normalizeBase empty', mod.normalizeBase(''), '');

// ---- 路由冒烟测试（mock KV + 标准 Request/Response，不依赖 Cloudflare 运行时）----
const memKV = {
  store: new Map(),
  get: async (k) => memKV.store.get(k) ?? null,
  put: async (k, v) => { memKV.store.set(k, v); },
};
const worker = mod._default;
const env = { KV: memKV };
const U0 = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';
const origin = 'https://demo.example.workers.dev';
const req = (method, path, body, headers) =>
  new Request(origin + path, { method, body, headers: body ? { 'content-type': 'application/json', ...headers } : headers });

let r = await worker.fetch(req('GET', '/' + U0), env);
eq('面板可访问', r.status, 200);
eq('面板响应头品牌标识', (r.headers.get('x-powered-by') || '').includes('shumajiedu'), true);
const panelHtml = await r.text();
eq('面板标题', panelHtml.includes('CF-TERMINAL'), true);
eq('面板品牌水印(数码解码)', panelHtml.includes('数码解码 出品'), true);
eq('面板页脚含GitHub链接', panelHtml.includes('github.com/smzxtv/cf-terminal'), true);

r = await worker.fetch(req('GET', '/' + U0 + '/api/config'), env);
eq('GET config 默认 UUID', (await r.json()).uuid, U0);

r = await worker.fetch(req('POST', '/' + U0 + '/api/config', JSON.stringify({
  uuid: U0, path: 'my/nodes', proxyIP: '1.1.1.1', trojanPassword: 'pw123',
  enableVless: true, enableTrojan: true, preferredDomains: ['cf.090227.xyz'],
})), env);
eq('POST config 保存', (await r.json()).ok, true);

r = await worker.fetch(req('GET', '/my/nodes/api/config'), env);
const cfg1 = await r.json();
eq('自定义路径生效', cfg1.path, '/my/nodes');
eq('ProxyIP 已存', cfg1.proxyIP, '1.1.1.1');
eq('旧 UUID 路径失效(404)', (await worker.fetch(req('GET', '/' + U0), env)).status, 404);

r = await worker.fetch(req('POST', '/my/nodes/api/ips', JSON.stringify({ text: '104.16.1.1\nbad_input\n104.16.2.2' })), env);
eq('批量添加 IP 过滤非法项', (await r.json()).ips.join(','), '104.16.1.1,104.16.2.2');

r = await worker.fetch(req('GET', '/my/nodes/sub'), env);
eq('订阅响应头品牌标识', (r.headers.get('x-powered-by') || '').includes('shumajiedu'), true);
const subText = Buffer.from(await r.text(), 'base64').toString();
eq('订阅含 vless 节点', subText.includes('vless://'), true);
eq('订阅含 trojan 节点', subText.includes('trojan://'), true);
// base64 订阅正文不能掺广告词(会破坏客户端解析)
eq('订阅正文无广告词(纯节点)', !subText.includes('数码解码'), true);
// 4 hosts(域名+优选域名+2IP) x 2 协议
eq('订阅节点数', subText.split('\n').filter(Boolean).length, 8);

r = await worker.fetch(req('GET', '/my/nodes/sub?target=clash'), env);
const yamlText = await r.text();
eq('clash 订阅', yamlText.includes('type: trojan'), true);
eq('clash 订阅品牌水印', yamlText.includes('数码解码'), true);

r = await worker.fetch(new Request(origin + '/my/nodes/sub', { headers: { 'user-agent': 'clash-verge/1.0' } }), env);
eq('UA 自动返回 clash', (await r.text()).includes('proxies:'), true);

r = await worker.fetch(req('POST', '/my/nodes/api/config', JSON.stringify({ uuid: 'bad', enableVless: true })), env);
eq('非法 UUID 被拒绝', (await r.json()).ok, false);

eq('随机路径伪装 404', (await worker.fetch(req('GET', '/nothing/here'), env)).status, 404);

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
process.exit(fail ? 1 : 0);