# js-ws

httpp 协议的 Node.js WebSocket 服务端，字节级兼容 `httpp` 的 C# 客户端（PSK + P-256 ECDH + AES-256-GCM）。

## 本地运行

```bash
npm install
npm start          # 默认监听 $PORT 或 5081
```

- 隧道入口：`/api/live`（WebSocket）
- 健康检查：`/healthz`
- 密钥：环境变量 `HTTPP_PSK`（base64 32 字节），不设则用代码内置默认值
- 日志等级：环境变量 `LOG_LEVEL`（`调试` / `消息` / `错误`）

## Render 部署

仓库根已有 `render.yaml`（免费档、新加坡、`npm start`、健康检查 `/healthz`）。
Render → New → Blueprint → 选本仓库即可。

客户端远程地址填 `wss://<app>.onrender.com/api/live`。

免费实例 15 分钟无入站流量会休眠，冷启动约 1 分钟，建议用外部定时任务每 5–10 分钟访问一次 `/healthz` 保活。

## 客户端

```bash
HttppClient.exe -l 127.0.0.1:18893 -r wss://<app>.onrender.com/api/live
```
