// 本地 WS 处理逻辑测试: mock WebSocketPair / connect, 复现「首包走 WS 消息事件」的 plain 模式
import { readFileSync } from 'node:fs';

let src = readFileSync(new URL('../public/_worker.js', import.meta.url), 'utf8');
src = src.replace(/import\s*{\s*connect\s*}\s*from\s*['"]cloudflare:sockets['"];?/, '');
src = src.replace('export default', 'const _default =');

const preamble = `
class MockWebSocket {
  constructor() { this.sent = []; this.readyState = 1; this.listeners = {}; }
  accept() { console.log('[MOCK] server.accept()'); }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, ev) { (this.listeners[type] || []).forEach((f) => f(ev)); }
  send(d) { console.log('[MOCK] server.send', (d && d.length) + 'B'); this.sent.push(d); }
  close() { console.log('[MOCK] server.close() readyState=' + this.readyState); this.readyState = 3; (this.listeners['close'] || []).forEach((f) => f({})); }
}
class MockWebSocketPair {
  constructor() { this[0] = new MockWebSocket(); this[1] = new MockWebSocket(); globalThis.__lastPair = this; }
}
class MockWSResponse {
  constructor(body, init) { this.body = body; this.status = init.status; this.webSocket = init.webSocket; }
}
const __sockets = [];
function mockConnect(opts) {
  __sockets.push(opts);
  let controller;
  const readable = new ReadableStream({ start(c) { controller = c; } });
  const written = [];
  const writable = new WritableStream({ write(d) { written.push(d); console.log('[MOCK] 上游 sink.write', d.length + 'B'); } });
  const socket = {
    readable, writable, __opts: opts, written,
    close() { console.log('[MOCK] socket.close() 被调用'); try { controller.close(); } catch (e) { console.log('[MOCK] close 时 controller 已关:', e.message); } },
    __respond(d) { console.log('[MOCK] __respond 入队', d.length + 'B'); controller.enqueue(d); controller.close(); },
  };
  globalThis.__lastSocket = socket;
  return socket;
}
const connect = mockConnect;
globalThis.WebSocketPair = MockWebSocketPair;
`;
src = preamble + src;
src = src.replace('return new Response(null, { status: 101, webSocket: client });', 'return new MockWSResponse(null, { status: 101, webSocket: client });');
src += '\nexport { _default };';
const mod = await import('data:text/javascript;base64,' + Buffer.from(src, 'utf8').toString('base64'));

const UUID = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';
const pair = { 0: null, 1: null };

// 构造 VLESS 请求 (域名 www.gstatic.com:80 + HTTP payload)
function buildVlessRequest() {
  const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');
  const domain = Buffer.from('www.gstatic.com');
  const head = Buffer.concat([
    Buffer.from([0x00]), uuidBytes, Buffer.from([0x00]), Buffer.from([0x01]),
    Buffer.from([0x00, 0x50]), Buffer.from([0x02]), Buffer.from([domain.length]), domain,
  ]);
  const payload = Buffer.from('GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n');
  return Buffer.concat([head, payload]);
}

const req = new Request('https://x.dev/' + UUID + '?ed=2048', {
  headers: { upgrade: 'websocket', 'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==', 'sec-websocket-version': '13' },
});
const resp = await mod._default.fetch(req, { KV: null });

console.log('resp.status =', resp.status, '| webSocket:', typeof resp.webSocket);
const client = globalThis.__lastPair[0];
const server = globalThis.__lastPair[1];
console.log('client/server mock 就绪');

// 关键: 以「WS 消息事件」方式投递首包 (plain 模式); 模拟运行时传入独立 ArrayBuffer
const vlessReq = buildVlessRequest();
const standalone = vlessReq.buffer.slice(vlessReq.byteOffset, vlessReq.byteOffset + vlessReq.length);
server.dispatch('message', { data: standalone });

await new Promise((r) => setTimeout(r, 50));

console.log('connect 调用:', globalThis.__lastSocket ? JSON.stringify(globalThis.__lastSocket.__opts) : '无');
const sock = globalThis.__lastSocket;

// 轮询观察链路推进
for (let i = 0; i < 8; i++) {
  await new Promise((r) => setTimeout(r, 50));
  const written = sock && sock.written.length ? sock.written[0].length : 0;
  console.log(`t=${(i + 1) * 100}ms  上游已写入: ${written}B  server.sent: ${server.sent.length}  server.readyState: ${server.readyState}`);
  if (server.sent.length) break;
}

// 模拟远端返回: VLESS 响应头 [0,0] + HTTP 204
if (sock) {
  sock.__respond(Buffer.concat([Buffer.from([0x00, 0x00]), Buffer.from('HTTP/1.1 204 No Content\r\n\r\n')]));
}
await new Promise((r) => setTimeout(r, 50));

// 数据会发到 server 端 WS (真实运行时里由 Cloudflare 转交客户端)
if (server.sent.length) {
  const msg = server.sent[server.sent.length - 1];
  console.log('SUCCESS: plain 模式数据已回送, 前 40 字节:', [...msg.slice(0, 40)]);
  process.exit(0);
} else {
  console.log('FAIL: 没有任何数据发回客户端');
  process.exit(1);
}
