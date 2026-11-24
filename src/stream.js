'use strict';

/**
 * 把任意 Node 双工流 (ws 的 WebSocketStream / net.Socket) 包成协议需要的接口:
 *   readSome(max) / readExactly(n, allowEmpty) / write(buf) / flush() / destroy()
 * 内部保留一块缓冲, 所以握手阶段多读到的字节不会丢, 后续解密记录还能接着用。
 */
class NodeStream {
  constructor(duplex) {
    this.duplex = duplex;
    this.iterator = duplex[Symbol.asyncIterator]();
    this.buf = Buffer.alloc(0);
    this.eof = false;
  }

  async _pull() {
    if (this.eof) return false;
    const { value, done } = await this.iterator.next();
    if (done || !value || value.length === 0) {
      this.eof = true;
      return false;
    }
    this.buf = this.buf.length === 0 ? value : Buffer.concat([this.buf, value]);
    return true;
  }

  /** 读最多 max 字节; 对端关闭返回 null */
  async readSome(max) {
    while (this.buf.length === 0) {
      if (!(await this._pull())) return null;
    }
    const n = Math.min(max, this.buf.length);
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }

  /** 读满 n 字节; 起始就 EOF 且 allowEmpty 时返回 null */
  async readExactly(n, allowEmpty = false) {
    while (this.buf.length < n) {
      if (!(await this._pull())) {
        if (this.buf.length === 0 && allowEmpty) return null;
        const err = new Error('流被截断');
        err.code = 'EOF';
        throw err;
      }
    }
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }

  write(chunk) {
    return new Promise((resolve, reject) => {
      this.duplex.write(chunk, err => (err ? reject(err) : resolve()));
    });
  }

  // 每次 write 已经是一条完整的 WS 消息, 不需要额外刷缓冲
  flush() {
    return Promise.resolve();
  }

  destroy() {
    try { this.duplex.destroy(); } catch { /* ignore */ }
  }
}

module.exports = { NodeStream };
