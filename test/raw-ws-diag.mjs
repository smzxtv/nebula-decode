// 底层诊断: 原始 TLS + 手写 WebSocket 升级/帧协议, 逐步打印握手与 VLESS 隧道状态
// 用法: node test/raw-ws-diag.mjs [worker域名] [uuid] [模式: plain|early]
import crypto from 'node:crypto';
import tls from 'node:tls';

const HOST = process.argv[2] || 'z5ozh98qima545uo-nt24t0mdugfa.pages.dev';
const UUID = process.argv[3] || '92c027d1-f2ad-4dc1-9195-6ea7ce472fb1';
const MODE = process.argv[4] || 'early';
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

function maskFrame(data) {
  const mask = crypto.randomBytes(4);
  const len = data.length;
  let head;
  if (len < 126) head = Buffer.from([0x82, 0x80 | len]);
  else if (len < 65536) { head = Buffer.from([0x82, 0x80 | 126]); head = Buffer.concat([head, Buffer.from([(len >> 8) & 0xff, len & 0xff])]); }
  else { head = Buffer.from([0x82, 0x80 | 127]); const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(len)); head = Buffer.concat([head, b]); }
  const masked = Buffer.from(data.map((v, i) => v ^ mask[i % 4]));
  return Buffer.concat([head, mask, masked]);
}

function parseFrames(buf) {
  const frames = [];
  let off = 0;
  while (buf.length - off >= 2) {
    const opcode = buf[off] & 0x0f;
    const len0 = buf[off + 1] & 0x7f;
    let len = len0, skip = 2;
    if (len0 === 126) { if (buf.length - off < 4) break; len = buf.readUInt16BE(off + 2); skip = 4; }
    else if (len0 === 127) { if (buf.length - off < 10) break; len = Number(buf.readBigUInt64BE(off + 2)); skip = 10; }
    if (buf.length - off < skip + len) break;
    frames.push({ opcode, data: buf.slice(off + skip, off + skip + len) });
    off += skip + len;
  }
  return { frames, rest: buf.slice(off) };
}

const vlessReq = buildVlessRequest();
const earlyB64 = vlessReq.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const key = crypto.randomBytes(16).toString('base64');
const protoHeader = MODE === 'early' ? `Sec-WebSocket-Protocol: ${earlyB64}\r\n` : '';
const upgrade =
  `GET /${UUID}?ed=2048 HTTP/1.1\r\nHost: ${HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
  `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n${protoHeader}\r\n`;

console.log(`[诊断] 模式=${MODE}  目标: wss://${HOST}/${UUID.slice(0, 8)}...?ed=2048`);
const sock = tls.connect({ host: HOST, port: 443, servername: HOST });
const fail = (msg) => { console.log('FAIL:', msg); process.exit(1); };
const timeout = setTimeout(() => fail('20秒超时'), 20000);

sock.on('error', (e) => fail('TLS/网络错误: ' + e.message));
sock.on('secureConnect', () => {
  console.log('[1] TLS 已建立');
  sock.write(upgrade);
});
let stage = 'handshake', httpBuf = Buffer.alloc(0), wsBuf = Buffer.alloc(0), gotHeader = false;

sock.on('data', (d) => {
  if (stage === 'handshake') {
    httpBuf = Buffer.concat([httpBuf, d]);
    const s = httpBuf.toString('latin1');
    const idx = s.indexOf('\r\n\r\n');
    if (idx === -1) return;
    const statusLine = s.split('\r\n')[0];
    console.log('[2] 升级响应:', statusLine);
    if (!s.startsWith('HTTP/1.1 101')) {
      console.log('--- 完整响应头 ---\n' + s.slice(0, idx));
      fail('WebSocket 升级被拒绝');
    }
    console.log('[3] WebSocket 升级成功, 发送 VLESS 请求帧...');
    stage = 'ws';
    wsBuf = httpBuf.slice(idx + 4);
    if (MODE !== 'early') sock.write(maskFrame(vlessReq));
    // 继续处理可能随 101 一起到达的数据
    handleWs(wsBuf); wsBuf = Buffer.alloc(0);
  } else {
    handleWs(d);
  }
});

function handleWs(d) {
  wsBuf = Buffer.concat([wsBuf, d]);
  const { frames, rest } = parseFrames(wsBuf);
  wsBuf = rest;
  for (const f of frames) {
    if (f.opcode === 8) fail('服务器发送了 WebSocket Close 帧, code=' + (f.data.length >= 2 ? f.data.readUInt16BE(0) : '?'));
    if (f.opcode === 1) { console.log('服务器文本消息: ' + f.data.toString('utf8')); continue; }
    const data = f.data;
    if (!gotHeader) {
      if (data.length < 2) continue;
      console.log(`[4] VLESS 响应头: ${[...data.slice(0, 2)]} (预期 [0,0])`);
      if (data[0] !== 0 || data[1] !== 0) fail('VLESS 响应头不合法');
      gotHeader = true;
      const payload = data.slice(2);
      if (payload.length) checkHttp(payload);
    } else {
      checkHttp(data);
    }
  }
}

function checkHttp(data) {
  const text = data.toString('latin1');
  if (text.includes('HTTP/1.1 204') || text.includes('HTTP/1.1 30')) {
    clearTimeout(timeout);
    console.log('[5] SUCCESS: 隧道全通! ->', text.split('\r\n')[0]);
    process.exit(0);
  }
}
