'use strict';

// 应用层帧: 与 common/Protocol.cs 一一对应。
// 字节布局见 docs/协议规范.md §1, 任何改动都要同步那份文档。

const RequestType = {
  CONNECT: 0x01,
  GET: 0x02,
  POST: 0x03,
  PUT: 0x04,
  DELETE: 0x05,
  HEAD: 0x06,
  OPTIONS: 0x07,
  PATCH: 0x08,
  OTHER: 0xFF
};

const AddressType = {
  IPV4: 0x01,
  DOMAIN: 0x03,
  IPV6: 0x04
};

const ReplyStatus = {
  SUCCESS: 0x00,
  GENERAL: 0x01,
  REFUSED: 0x03,
  TIMEOUT: 0x04,
  HOST_NOT_FOUND: 0x05,
  ATYP_UNSUPPORTED: 0x06,
  MALFORMED: 0xFF
};

/** 构建回复帧: REP(1) | DLEN(2,BE) | 可选 UTF-8 描述 */
function buildReply(rep, description) {
  const desc = description ? Buffer.from(String(description), 'utf8') : Buffer.alloc(0);
  const frame = Buffer.allocUnsafe(3 + desc.length);
  frame[0] = rep;
  frame.writeUInt16BE(desc.length, 1);
  desc.copy(frame, 3);
  return frame;
}

/** 解析载荷: ATYP | DST.ADDR | PORT | PATH_LEN | PATH */
function parsePayload(data) {
  if (data.length < 1) throw new Error('载荷为空');
  const atyp = data[0];
  let addrLen;
  if (atyp === AddressType.IPV4) addrLen = 4;
  else if (atyp === AddressType.IPV6) addrLen = 16;
  else if (atyp === AddressType.DOMAIN) {
    if (data.length < 2) throw new Error('载荷过短');
    addrLen = 1 + data[1];
  } else {
    throw new Error(`不支持的地址类型: ${atyp}`);
  }

  // 1(atyp) + addrLen + 2(port) + 2(pathLen)
  if (data.length < 1 + addrLen + 4) throw new Error('载荷长度不足');
  const addr = data.subarray(1, 1 + addrLen);
  const port = data.readUInt16BE(1 + addrLen);
  const pathLen = data.readUInt16BE(1 + addrLen + 2);
  if (data.length < 1 + addrLen + 4 + pathLen) throw new Error('路径长度越界');
  const path = pathLen > 0
    ? data.subarray(1 + addrLen + 4, 1 + addrLen + 4 + pathLen).toString('utf8')
    : '/';

  return { atyp, addr, port, path };
}

function formatIPv6(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i));

  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart < 0) { curStart = i; curLen = 0; }
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }

  const hex = groups.map(g => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
}

/** 地址字节转字符串 (域名跳过长度前缀) */
function addrToString(atyp, addr) {
  if (atyp === AddressType.IPV4) return Array.from(addr).join('.');
  if (atyp === AddressType.IPV6) return formatIPv6(addr);
  if (atyp === AddressType.DOMAIN) return addr.subarray(1).toString('utf8');
  return addr.toString('hex');
}

module.exports = { RequestType, AddressType, ReplyStatus, buildReply, parsePayload, addrToString };
