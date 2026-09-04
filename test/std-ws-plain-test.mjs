// 标准 WebSocket API 的 plain 模式测试 (与真实客户端行为一致)
// 用法: node test/std-ws-plain-test.mjs [主机] [uuid]
const HOST = process.argv[2] || '111-6jh.pages.dev';
const UUID = process.argv[3] || 'c4f4450f-704a-4c22-afba-5aecffd73289';
const TARGET = 'www.gstatic.com', PORT = 80;

function buildVlessRequest() {
  const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');
  const domain = Buffer.from(TARGET);
  const head = Buffer.concat([
    Buffer.from([0x00]), uuidBytes, Buffer.from([0x00]), Buffer.from([0x01]),
    Buffer.from([(PORT >> 8) & 0xff, PORT & 0xff]), Buffer.from([0x02]),
    Buffer.from([domain.length]), domain,
  ]);
  const payload = Buffer.from(`GET /generate_204 HTTP/1.1\r\nHost: ${TARGET}\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n`);
  return Buffer.concat([head, payload]);
}

const built = buildVlessRequest();
const req = built.buffer.slice(built.byteOffset, built.byteOffset + built.length);
console.log(`标准WS plain测试: wss://${HOST}/${UUID}?ed=2048`);
const ws = new WebSocket(`wss://${HOST}/${UUID}?ed=2048`);
let buf = Buffer.alloc(0), gotHeader = false;
const timer = setTimeout(() => { console.log('FAIL: 15秒超时'); process.exit(1); }, 15000);

ws.onopen = () => {
  console.log('WS 已连接, 发送 VLESS 请求(binary)...');
  ws.send(req); // Node 全局 WebSocket 发送 ArrayBuffer -> binary 帧
};
ws.onerror = (e) => { console.log('FAIL: WS 错误', e.message || e); process.exit(1); };
ws.onclose = () => { if (!gotHeader) { console.log('FAIL: WS 提前关闭, 无 VLESS 响应头'); process.exit(1); } };
ws.onmessage = (ev) => {
  const chunk = Buffer.from(ev.data);
  buf = Buffer.concat([buf, chunk]);
  if (!gotHeader) {
    if (buf.length < 2) return;
    console.log('收到 VLESS 响应头:', [...buf.slice(0, 2)], '| 首包类型:', ev.data && ev.data.constructor ? ev.data.constructor.name : typeof ev.data);
    if (buf[0] !== 0 || buf[1] !== 0) { console.log('FAIL: 响应头不合法'); process.exit(1); }
    gotHeader = true;
    buf = buf.slice(2);
  }
  const text = buf.toString('latin1');
  if (text.includes('HTTP/1.1 204') || text.includes('HTTP/1.1 30')) {
    clearTimeout(timer);
    console.log('SUCCESS: 标准WS plain 模式隧道全通! ->', text.split('\r\n')[0]);
    process.exit(0);
  }
};