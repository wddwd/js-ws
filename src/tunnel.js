'use strict';

const net = require('node:net');
const log = require('./log');
const { NodeStream } = require('./stream');
const {
  RequestType, ReplyStatus, buildReply, parsePayload, addrToString
} = require('./protocol');

const CONNECT_TIMEOUT_MS = 10_000;
const HTTP_TIMEOUT_MS = 30_000;
const RELAY_GRACE_MS = 5_000;
const RELAY_CHUNK = 8192;

const METHOD = {
  [RequestType.GET]: 'GET',
  [RequestType.POST]: 'POST',
  [RequestType.PUT]: 'PUT',
  [RequestType.DELETE]: 'DELETE',
  [RequestType.HEAD]: 'HEAD',
  [RequestType.OPTIONS]: 'OPTIONS',
  [RequestType.PATCH]: 'PATCH'
};

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function safeWrite(enc, buf) {
  try {
    await enc.write(buf);
    await enc.flush();
  } catch { /* 对端已断开 */ }
}

/** 拨号目标; timeoutMs 为 0 表示不设超时 (HTTP 代取路径与 C# 一致) */
function dial(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    let settled = false;

    const timer = timeoutMs > 0
      ? setTimeout(() => finish(new Error(`连接 ${host}:${port} 超时`)), timeoutMs)
      : null;

    function finish(err) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (err) {
        sock.destroy();
        reject(err);
      } else {
        resolve(new NodeStream(sock));
      }
    }

    sock.once('connect', () => finish(null));
    sock.once('error', finish);
  });
}

async function pump(src, dst) {
  try {
    for (;;) {
      const chunk = await src.readSome(RELAY_CHUNK);
      if (chunk === null) return;
      await dst.write(chunk);
      await dst.flush();
    }
  } catch { /* 单方向结束属正常 */ }
}

/** 双向中继: 任一方向结束后再等 5 秒收尾 */
async function relayBoth(a, b) {
  const c2t = pump(a, b);
  const t2c = pump(b, a);
  await Promise.race([c2t, t2c]);
  await Promise.race([Promise.allSettled([c2t, t2c]), delay(RELAY_GRACE_MS)]);
  a.destroy();
  b.destroy();
}

async function handleConnect(enc, host, port) {
  let target;
  try {
    target = await dial(host, port, CONNECT_TIMEOUT_MS);
  } catch (e) {
    log.error(`CONNECT失败 ${host}:${port}: ${e.message}`);
    await safeWrite(enc, buildReply(ReplyStatus.REFUSED, e.message));
    return;
  }

  await enc.write(buildReply(ReplyStatus.SUCCESS));
  await enc.flush();
  await relayBoth(enc, target);
}

async function handleHttp(enc, type, host, port, path) {
  let target;
  try {
    target = await dial(host, port, 0);
  } catch (e) {
    log.error(`HTTP请求失败 ${host}:${port}: ${e.message}`);
    await safeWrite(enc, buildReply(ReplyStatus.GENERAL, e.message));
    return;
  }

  await enc.write(buildReply(ReplyStatus.SUCCESS));
  await enc.flush();

  // 与 C# 一致: 只代发最小请求行, 不转发浏览器原始请求头/Cookie/body
  const method = METHOD[type] || 'GET';
  const hostHeader = (port !== 80 && port !== 443) ? `${host}:${port}` : host;
  const head = `${method} ${path || '/'} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`;
  await target.write(Buffer.from(head, 'latin1'));

  const c2t = pump(enc, target);
  const t2c = pump(target, enc);
  const timer = setTimeout(() => { target.destroy(); }, HTTP_TIMEOUT_MS);

  await Promise.race([c2t, t2c]);
  clearTimeout(timer);
  await Promise.race([Promise.allSettled([c2t, t2c]), delay(RELAY_GRACE_MS)]);
  target.destroy();
}

/** 一条 WS 隧道只处理一个请求帧, 之后就是纯字节中继 */
async function handleTunnel(enc) {
  const header = await enc.readExactly(3);
  const type = header[0];
  const dataLen = header.readUInt16BE(1);
  const payload = dataLen > 0 ? await enc.readExactly(dataLen) : Buffer.alloc(0);

  const req = parsePayload(payload);
  const host = addrToString(req.atyp, req.addr);
  log.debug(`请求 ${type} ${host}:${req.port}`);

  if (type === RequestType.CONNECT) await handleConnect(enc, host, req.port);
  else await handleHttp(enc, type, host, req.port, req.path);
}

module.exports = { handleTunnel };
