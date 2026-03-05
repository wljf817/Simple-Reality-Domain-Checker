# Simple Reality Domain Checker

一个用于检测目标域名网络能力的 Python 脚本，适合快速排查 Reality/VPN 场景下的域名可用性。

## 功能

- 自动解析输入域名并跟随跳转，使用最终域名检测
- 检查是否支持 `TLS1.3`
- 检查是否支持 `X25519`
- 检查是否支持 `HTTP/2 (h2)`
- 检查证书是否与 SNI 匹配
- 检测是否疑似使用 CDN（告警，不直接失败）
- 输出 TLS 握手时间
- 调用 ITDOG 中国节点 Ping（默认展示 5 个代表节点）
- 若某项失败，立即停止后续步骤（Fail-fast）

## 依赖

- Python 3.8+
- `openssl`（用于 X25519 兼容检测）
- Node.js（用于 ITDOG websocket 采集）
  - 若 Node 环境无全局 `WebSocket`，需安装 `ws`：
  - `npm i ws`

## 使用方式

```bash
python3 domain_checker.py bing.com
```

交互模式：

```bash
python3 domain_checker.py
```

可选参数：

- `--skip-itdog`：跳过 ITDOG Ping
- `--itdog-timeout N`：设置 ITDOG 等待秒数（默认 15）

示例：

```bash
python3 domain_checker.py bing.com --itdog-timeout 12
python3 domain_checker.py bing.com --skip-itdog
```

## 输出说明

- `PASS`：通过
- `WARN`：通过但有告警（例如疑似 CDN）
- `FAIL`：失败并中止后续检查

结论会给出具体失败原因或告警原因。

## 彩色输出

- 终端 TTY 默认启用颜色
- `FORCE_COLOR=1` 强制启用颜色
- `NO_COLOR=1` 禁用颜色

## 备注

- README 由 OpenAI Codex 编写。
