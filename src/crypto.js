'use strict';

const crypto = require('node:crypto');
const log = require('./log');

// 加密传输协议常量, 与 common/Encryption.cs 的 EncProtocol 完全一致。
const C = {
  version: 0x01,
  typeColdHello: 0x01,
  typeHot: 0x02,
  typeColdReply: 0x03,
  typeHotAck: 0x04,
  typeReject: 0xFF,

  pubLen: 64,
  nonceLen: 16,
  macLen: 32,
  expiryLen: 8,

  ticketPlainLen: 42,          // 版本(1) + sessionMaster(32) + 到期(8) + flags(1)
  ticketLen: 70,               // nonce(12) + 密文(42) + tag(16)

  coldHelloLen: 82,            // 2 + 64 + 16
  coldReplyLen: 192,           // 2 + 64 + 16 + 32 + 8 + 70
  hotLen: 88,                  // 2 + 70 + 16

  recordHeaderLen: 4,
  maxRecord: 64 * 1024,
  writeBufSize: 8 * 1024,

  ticketTtlSec: 3600,
  replayWindowMs: 300 * 1000
};

const TICKET_AAD = Buffer.from('httpp-ticket-v1');

function hkdf(ikm, salt, info, len) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));
}

function hmac(key, ...parts) {
  const h = crypto.createHmac('sha256', key);
  for (const p of parts) h.update(p);
  return h.digest();
}

function buildNonce(iv, counter) {
  const nonce = Buffer.allocUnsafe(12);
  iv.copy(nonce, 0);
  nonce.writeBigUInt64BE(BigInt(counter), 4);
  return nonce;
}

// ---------------------------------------------------------------- P-256 ECDH

function createKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const pub = ecdh.getPublicKey();          // 65 字节, 0x04 前缀
  return { ecdh, pubRaw: pub.subarray(1) }; // 协议里只传 X||Y
}

function deriveShared(ecdh, peerRaw) {
  if (peerRaw.length !== C.pubLen) throw new Error('公钥长度不正确');
  const raw = ecdh.computeSecret(Buffer.concat([Buffer.from([0x04]), peerRaw]));
  // 关键兼容点: Windows 上 .NET 的 ECDiffieHellmanCng.DeriveKeyMaterial 默认 KDF 是 Hash(SHA256),
  // 返回的是 SHA256(raw shared secret), 不是 raw 本身 (Linux/OpenSSL 才是 raw)。
  // 本服务端对端是 Windows C# 客户端, 所以这里必须再取一次 SHA256, 否则握手能过、首帧解密失败。
  return crypto.createHash('sha256').update(raw).digest();
}

// ------------------------------------------------------------- 票据密钥环

/** 内存随机密钥, 每小时轮换, 保留当前 + 上一代 (与 C# TicketKeyRing 一致) */
class TicketKeyRing {
  constructor() {
    this.current = crypto.randomBytes(32);
    this.previous = crypto.randomBytes(32);
    this.rotatedAt = Date.now();
  }

  _rotateIfNeeded() {
    if (Date.now() - this.rotatedAt >= 60 * 60 * 1000) {
      this.previous = this.current;
      this.current = crypto.randomBytes(32);
      this.rotatedAt = Date.now();
    }
  }

  seal(expiryUnix, sessionMaster) {
    this._rotateIfNeeded();
    const plain = Buffer.alloc(C.ticketPlainLen);
    plain[0] = C.version;
    sessionMaster.copy(plain, 1);
    plain.writeBigInt64BE(BigInt(expiryUnix), 33);
    plain[41] = 0;

    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.current, nonce, { authTagLength: 16 });
    cipher.setAAD(TICKET_AAD);
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
  }

  /** 成功返回 { sessionMaster, expiry }, 失败返回 null */
  unseal(ticket) {
    if (!ticket || ticket.length !== C.ticketLen) return null;
    this._rotateIfNeeded();
    return this._open(ticket, this.current) || this._open(ticket, this.previous);
  }

  _open(ticket, key) {
    try {
      const nonce = ticket.subarray(0, 12);
      const ct = ticket.subarray(12, 12 + C.ticketPlainLen);
      const tag = ticket.subarray(12 + C.ticketPlainLen, 12 + C.ticketPlainLen + 16);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      decipher.setAAD(TICKET_AAD);
      decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
      if (plain[0] !== C.version) return null;
      return {
        sessionMaster: Buffer.from(plain.subarray(1, 33)),
        expiry: Number(plain.readBigInt64BE(33))
      };
    } catch {
      return null;
    }
  }
}

// ---------------------------------------------------------------- 防重放

class AntiReplay {
  constructor() {
    this.seen = new Map();
    this.lastPurge = 0;
  }

  /** 见过返回 true, 否则登记并返回 false */
  check(connSalt) {
    const key = crypto.createHash('sha256').update(connSalt).digest().subarray(0, 8).toString('hex');
    const now = Date.now();
    if (now - this.lastPurge > 30_000) {
      this._purge(now);
      this.lastPurge = now;
    }
    if (this.seen.has(key)) return true;
    this.seen.set(key, now);
    return false;
  }

  _purge(now) {
    const limit = now - C.replayWindowMs;
    for (const [k, v] of this.seen) if (v < limit) this.seen.delete(k);
  }
}

// ------------------------------------------------------- AES-256-GCM 记录层

/** 每帧 LEN(4,BE) | 密文 | TAG(16); nonce = IV(4) | counter(8,BE); AAD = LEN */
class EncStream {
  constructor(raw, sendKey, sendIv, recvKey, recvIv) {
    this.raw = raw;
    this.sendKey = sendKey;
    this.sendIv = sendIv;
    this.recvKey = recvKey;
    this.recvIv = recvIv;
    this.sendCounter = 0;
    this.recvCounter = 0;
    this.plain = Buffer.alloc(0);
    this.pending = Buffer.alloc(0);
  }

  async readSome(max) {
    if (this.plain.length === 0 && !(await this._readRecord())) return null;
    const n = Math.min(max, this.plain.length);
    const out = this.plain.subarray(0, n);
    this.plain = this.plain.subarray(n);
    return out;
  }

  async readExactly(n, allowEmpty = false) {
    const out = Buffer.allocUnsafe(n);
    let off = 0;
    while (off < n) {
      if (this.plain.length === 0 && !(await this._readRecord())) {
        if (off === 0 && allowEmpty) return null;
        const err = new Error('流被截断');
        err.code = 'EOF';
        throw err;
      }
      const take = Math.min(n - off, this.plain.length);
      this.plain.copy(out, off, 0, take);
      this.plain = this.plain.subarray(take);
      off += take;
    }
    return out;
  }

  async _readRecord() {
    const header = await this.raw.readExactly(C.recordHeaderLen, true);
    if (header === null) return false;

    const n = header.readUInt32BE(0);
    if (n === 0 || n > C.maxRecord) throw new Error(`非法记录长度: ${n}`);

    const body = await this.raw.readExactly(n + 16);
    const aad = Buffer.allocUnsafe(4);
    aad.writeUInt32BE(n, 0);

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm', this.recvKey, buildNonce(this.recvIv, this.recvCounter++), { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(body.subarray(n, n + 16));
    this.plain = Buffer.concat([decipher.update(body.subarray(0, n)), decipher.final()]);
    return true;
  }

  async write(chunk) {
    this.pending = this.pending.length === 0 ? chunk : Buffer.concat([this.pending, chunk]);
    while (this.pending.length >= C.writeBufSize) {
      const data = this.pending.subarray(0, C.writeBufSize);
      this.pending = this.pending.subarray(C.writeBufSize);
      await this._writeRecord(data);
    }
  }

  async flush() {
    if (this.pending.length > 0) {
      const data = this.pending;
      this.pending = Buffer.alloc(0);
      await this._writeRecord(data);
    }
  }

  async _writeRecord(data) {
    const lenBuf = Buffer.allocUnsafe(4);
    lenBuf.writeUInt32BE(data.length, 0);

    const cipher = crypto.createCipheriv(
      'aes-256-gcm', this.sendKey, buildNonce(this.sendIv, this.sendCounter++), { authTagLength: 16 });
    cipher.setAAD(lenBuf);
    const ct = Buffer.concat([cipher.update(data), cipher.final()]);
    await this.raw.write(Buffer.concat([lenBuf, ct, cipher.getAuthTag()]));
  }

  destroy() {
    this.raw.destroy();
  }
}

// ---------------------------------------------------------------- 握手

function buildStream(raw, sessionMaster, connSalt) {
  const c2s = hkdf(sessionMaster, connSalt, Buffer.from('httpp-v1 c2s'), 36);
  const s2c = hkdf(sessionMaster, connSalt, Buffer.from('httpp-v1 s2c'), 36);
  return new EncStream(
    raw,
    s2c.subarray(0, 32), s2c.subarray(32, 36),
    c2s.subarray(0, 32), c2s.subarray(32, 36)
  );
}

async function sendReject(raw) {
  try { await raw.write(Buffer.from([C.version, C.typeReject])); } catch { /* ignore */ }
}

async function coldHandshake(raw, psk, keyring) {
  const rest = await raw.readExactly(C.coldHelloLen - 2, true);
  if (rest === null) return null;

  const pubC = rest.subarray(0, C.pubLen);
  const cnonce = rest.subarray(C.pubLen, C.pubLen + C.nonceLen);

  const { ecdh, pubRaw: pubS } = createKeyPair();
  const snonce = crypto.randomBytes(C.nonceLen);
  const dh = deriveShared(ecdh, pubC);

  const transcript = Buffer.concat([
    Buffer.from([C.version, C.typeColdHello]),
    pubC, cnonce, pubS, snonce
  ]);

  const sessionMaster = hkdf(dh, psk, Buffer.concat([Buffer.from('httpp-v1 session'), transcript]), 32);
  const srvMac = hmac(psk, Buffer.from('s2c'), transcript);

  const expiry = Math.floor(Date.now() / 1000) + C.ticketTtlSec;
  const ticket = keyring.seal(expiry, sessionMaster);

  const reply = Buffer.alloc(C.coldReplyLen);
  reply[0] = C.version;
  reply[1] = C.typeColdReply;
  let off = 2;
  pubS.copy(reply, off); off += C.pubLen;
  snonce.copy(reply, off); off += C.nonceLen;
  srvMac.copy(reply, off); off += C.macLen;
  reply.writeBigInt64BE(BigInt(expiry), off); off += C.expiryLen;
  ticket.copy(reply, off);

  await raw.write(reply);

  const connSalt = await raw.readExactly(C.nonceLen, true);
  if (connSalt === null) return null;

  log.debug('[加密] 冷握手完成, 票据已下发');
  return buildStream(raw, sessionMaster, connSalt);
}

async function hotHandshake(raw, keyring, antiReplay) {
  const rest = await raw.readExactly(C.hotLen - 2, true);
  if (rest === null) return null;

  const ticket = rest.subarray(0, C.ticketLen);
  const connSalt = rest.subarray(C.ticketLen, C.ticketLen + C.nonceLen);

  const opened = keyring.unseal(ticket);
  if (!opened || opened.expiry < Math.floor(Date.now() / 1000)) {
    log.debug('[加密] 票据无效或已过期, 已拒绝');
    await sendReject(raw);
    return null;
  }
  if (antiReplay.check(connSalt)) {
    log.error('[加密] 检测到重放, 已拒绝');
    await sendReject(raw);
    return null;
  }

  await raw.write(Buffer.from([C.version, C.typeHotAck]));
  log.debug('[加密] 热连接 (票据复用)');
  return buildStream(raw, opened.sessionMaster, connSalt);
}

/** 服务端握手入口: 成功返回 EncStream, 失败返回 null */
async function serverHandshake(raw, psk, keyring, antiReplay) {
  const head = await raw.readExactly(2, true);
  if (head === null) return null;
  if (head[0] !== C.version) return null;

  if (head[1] === C.typeColdHello) return coldHandshake(raw, psk, keyring);
  if (head[1] === C.typeHot) return hotHandshake(raw, keyring, antiReplay);

  await sendReject(raw);
  return null;
}

module.exports = {
  CONFIG: C,
  EncStream,
  TicketKeyRing,
  AntiReplay,
  serverHandshake
};
