'use strict';

// 日志门面: 与 C# 端一致的三档 (调试/消息/错误), 等级由 LOG_LEVEL 控制。
const LEVELS = { '调试': 1, '消息': 2, '错误': 3 };
let current = LEVELS[process.env.LOG_LEVEL] || LEVELS['调试'];

function emit(tag, args) {
  console.log(`[${tag}]`, ...args);
}

module.exports = {
  debug(...args) { if (current <= LEVELS['调试']) emit('调试', args); },
  info(...args) { if (current <= LEVELS['消息']) emit('消息', args); },
  error(...args) { if (current <= LEVELS['错误']) emit('错误', args); },
  setLevel(name) { if (LEVELS[name]) current = LEVELS[name]; }
};
