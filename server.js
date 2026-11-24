'use strict';

const http = require('node:http');
const { WebSocketServer, createWebSocketStream } = require('ws');
const log = require('./src/log');
const { NodeStream } = require('./src/stream');
const { TicketKeyRing, AntiReplay, serverHandshake } = require('./src/crypto');
const { handleTunnel } = require('./src/tunnel');
const { ReplyStatus, buildReply } = require('./src/protocol');

const PORT = Number(process.env.PORT || 5081);
const WS_PATH = '/api/live';

// 与 common/Defaults.cs 同一条内置密钥; 换密钥用环境变量 HTTPP_PSK (base64 32 字节)
const PSK = Buffer.from(
  process.env.HTTPP_PSK || '6/VmJZNcAVN3nXgosCAftWXkyUqNSR0ahwYZnWNlzZw=', 'base64');
if (PSK.length !== 32) {
  console.error('HTTPP_PSK 必须是 base64 编码的 32 字节');
  process.exit(1);
}

const HANDSHAKE_TIMEOUT_MS = 30_000;
const CONNECTION_TIMEOUT_MS = 300_000;

const keyring = new TicketKeyRing();
const antiReplay = new AntiReplay();

// ------------------------------------------------------------------ HTTP

const server = http.createServer((req, res) => {
  const pathname = (req.url || '/').split('?')[0];

  if (pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    res.end('ok');
    return;
  }

  if (pathname === WS_PATH) {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end('{"status":"ok"}');
    return;
  }

  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('ok');
});

// ------------------------------------------------------------------ WebSocket

const wss = new WebSocketServer({
  noServer: true,
  perMessageDeflate: false,
  maxPayload: 1 << 20
});

server.on('upgrade', (req, socket, head) => {
  const pathname = (req.url || '/').split('?')[0];
  if (pathname !== WS_PATH) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

function isQuietClose(err) {
  if (!err) return true;
  if (err.code === 'EOF') return true;
  return /EOF|截断|closed|terminated|aborted|socket hang up/i.test(err.message || '');
}

wss.on('connection', ws => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const duplex = createWebSocketStream(ws);
  const raw = new NodeStream(duplex);

  (async () => {
    let enc = null;
    const handshakeTimer = setTimeout(() => {
      try { ws.terminate(); } catch { /* ignore */ }
    }, HANDSHAKE_TIMEOUT_MS);

    try {
      enc = await serverHandshake(raw, PSK, keyring, antiReplay);
    } catch (e) {
      if (!isQuietClose(e)) log.error(`加密握手异常: ${e.message}`);
    } finally {
      clearTimeout(handshakeTimer);
    }

    if (!enc) {
      log.debug('加密握手失败/被拒');
      try { ws.close(); } catch { /* ignore */ }
      try { duplex.destroy(); } catch { /* ignore */ }
      return;
    }

    const connTimer = setTimeout(() => {
      try { ws.terminate(); } catch { /* ignore */ }
    }, CONNECTION_TIMEOUT_MS);

    try {
      await handleTunnel(enc);
    } catch (e) {
      if (isQuietClose(e)) {
        log.debug('连接在请求前关闭 (预热池释放属正常)');
      } else {
        log.error(`服务端处理-错误: ${e.message}`);
        try {
          await enc.write(buildReply(ReplyStatus.GENERAL, e.message));
          await enc.flush();
        } catch { /* ignore */ }
      }
    } finally {
      clearTimeout(connTimer);
      enc.destroy();
    }
  })();
});

// 30 秒 ping 一次, 与 C# 端 KeepAliveInterval 对齐
const keepAlive = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      try { ws.terminate(); } catch { /* ignore */ }
      continue;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch { /* ignore */ }
  }
}, 30_000);

server.listen(PORT, '0.0.0.0', () => {
  log.info(`httpp-server-node 监听 0.0.0.0:${PORT}, 隧道路径 ${WS_PATH}`);
});

function shutdown() {
  clearInterval(keepAlive);
  try { server.close(); } catch { /* ignore */ }
  setTimeout(() => process.exit(0), 1000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
