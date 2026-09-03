// 线上真机测试: 模拟 VLESS 客户端通过 WebSocket 连接部署好的 Worker,
// 完整跑一遍 VLESS 握手 + 访问目标网站, 验证隧道是否真的能通
// 用法: node test/live-vless-test.mjs [worker域名] [uuid] [目标域名] [端口]
import crypto from 'node:crypto';

const HOST = process.argv[2] || 'z5ozh98qima545uo-nt24t0mdugfa.pages.dev';
const UUID = process.argv[3] || '92c027d1-f2ad-4dc1-9195-6ea7ce472fb1';
const TARGET = process.argv[4] || 'www.gstatic.com';
const PORT = Number(process.argv[5] || 80);

// ---- 构造 VLESS 请求 (与 Xray 客户端格式一致) ----
function buildVlessRequest() {
  const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');
  const domain = Buffer.from(TARGET);
  const head = Buffer.concat([
    Buffer.from([0x00]),            // version
    uuidBytes,                      // uuid 16B
    Buffer.from([0x00]),            // optLen 0
    Buffer.from([0x01]),            // command TCP
    Buffer.from([(PORT >> 8) & 0xff, PORT & 0xff]),
    Buffer.from([0x02]),            // addrType domain
    Buffer.from([domain.length]), domain,
  ]);
  const payload = Buffer.from(
    `GET /generate_204 HTTP/1.1\r\nHost: ${TARGET}\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n`);
  return Buffer.concat([head, payload]);
}

const req = buildVlessRequest();
const earlyB64 = req.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
console.log(`目标: wss://${HOST}/${UUID}?ed=2048  ->  ${TARGET}:${PORT}`);

const ws = new WebSocket(`wss://${HOST}/${UUID}?ed=2048`, earlyB64);
const timer = setTimeout(() => { console.log('FAIL: 15秒超时, 未收到任何数据'); process.exit(1); }, 15000);
let gotHeader = false, buf = Buffer.alloc(0);

ws.onopen = () => console.log('WS 已连接, 已通过 Sec-WebSocket-Protocol 发送早期数据...');
ws.onerror = (e) => { console.log('FAIL: WS 错误', e.message || e); process.exit(1); };
ws.onclose = (e) => { if (!gotHeader) { console.log(`FAIL: WS 被关闭 code=${e.code}`); process.exit(1); } };
ws.onmessage = (ev) => {
  const chunk = Buffer.from(await0(ev.data));
  buf = Buffer.concat([buf, chunk]);
  if (!gotHeader) {
    if (buf.length < 2) return;
    console.log(`收到 VLESS 响应头: ${[...buf.slice(0, 2)]} (预期 [0,0])`);
    if (buf[0] !== 0 || buf[1] !== 0) { console.log('FAIL: 响应头不合法'); process.exit(1); }
    gotHeader = true;
    buf = buf.slice(2);
  }
  const text = buf.toString('latin1');
  if (text.includes('HTTP/1.1 204') || text.includes('HTTP/1.1 30')) {
    clearTimeout(timer);
    console.log('SUCCESS: 隧道全通! 收到目标站响应 ->', text.split('\r\n')[0]);
    ws.close();
    process.exit(0);
  }
};
function await0(data) { return data instanceof ArrayBuffer ? data : new TextEncoder().encode(String(data)).buffer; }
