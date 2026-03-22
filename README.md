# 🦞 OpenClaw Agent Monitor

<p align="center">
  <strong>复旦大学 MAS 实验室 | 钱振兴教授 指导 | 李杰雨、张羽仪 开发</strong>
</p>

实时监控OpenClaw Agent活动，追踪会话、工具调用、文件访问，并智能评估安全风险。

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 功能特性

- **📊 实时监控**：追踪所有Agent会话、工具调用、消息数量
- **📂 路径追踪**：记录Agent访问的所有文件路径
- **⏰ 定时任务**：监控Cron任务状态和运行记录
- **🚨 安全报警**：GLM-5智能风险评估，高危操作实时预警
- **🎨 美观界面**：暗色主题，自动刷新，响应式设计

## 快速开始

### 1. 前置要求

- Python 3.9+
- OpenClaw已安装并运行
- 百炼GLM-5 API Key（用于风险评估）

### 2. 安装

```bash
# 克隆仓库
git clone https://github.com/lij113/openclaw-monitor.git
cd openclaw-monitor
```

### 3. 启动

```bash
# 一键启动
python start.py
```

访问http://localhost:8765 查看监控面板。

## 界面预览

```
┌─────────────────────────────────────────────────────────────┐
│  🦞 OpenClaw Monitor                    更新: 12:30:45      │
├─────────────────────────────────────────────────────────────┤
│  会话: 3   定时任务: 2   工具调用: 156   路径: 89             │
├─────────────────────────────────────────────────────────────┤
│  🤖 Agent 会话          │  🔧 工具使用统计                  │
│  ├─ Main (主会话)       │  ├─ exec        ████████ 45       │
│  ├─ 论文监控 (cron)     │  ├─ read        ██████   32       │
│  └─ 天气推送 (cron)     │  └─ web_search  ████     21       │
├─────────────────────────────────────────────────────────────┤
│  🚨 安全报警                                                │
│  ⚠️ 高危: exec - rm -rf /important/data                     │
│     原因: 删除文件操作                                       │
└─────────────────────────────────────────────────────────────┘
```

## 安全风险评估

监控器会自动评估以下高危操作：

| 类型 | 示例 | 风险等级 |
|------|------|----------|
| 文件删除 | `rm -rf`, `trash`, `delete` | 🔴 高危 |
| 系统配置 | `/etc/`, `/System/`, `launchd` | 🔴 高危 |
| 凭证访问 | `.env`, `apiKey`, `password` | 🔴 高危 |
| 网络请求 | `curl POST` 含敏感数据 | 🔴 高危 |
| 读取文件 | `read`, `list_files` | 🟢 正常 |
| 网页搜索 | `web_search`, `web_fetch` | 🟢 正常 |

## 配置说明
### config.json

```json
{
  "server": {
    "port": 8765,
    "host": "0.0.0.0",
    "refresh_interval": 3
  },
  "bailian": {
    "api_key": "your-api-key",
    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"
  },
  "alerts": {
    "max_count": 50,
    "enable_llm_evaluation": true
  },
  "paths": {
    "openclaw_home": "~/.openclaw"
  },
}
```
可按需修改配置文件，并确保配置文件路径正确。

### 环境变量

```bash
# 自定义OpenClaw路径
export OPENCLAW_HOME=~/.openclaw

# 自定义端口
export MONITOR_PORT=8765
```

## API接口

### GET /api/state

获取完整监控状态

```json
{
  "sessions": [...],
  "cron_jobs": [...],
  "tools": { "total": 156, "usage": [...] },
  "paths": [...],
  "alerts": [...],
  "last_updated": "2026-03-21T12:30:45"
}
```

## 项目结构

```
openclaw-monitor/
├── server.py           # 后端服务
├── index.html          # 前端界面
├── start.py            # 启动脚本
├── logger.py           # 日志模块
├── requirements.txt    # Python依赖
├── config.json         # 配置文件
├── README.md           # 说明文档
└── docs/
    └── SECURITY.md     # 安全评估逻辑说明
```

## 常见问题

### Q: 端口被占用怎么办？

```bash
# 查找占用进程，并终止该进程
lsof -i :8765

# 或使用其他端口
export MONITOR_PORT=9000
```

### Q: 不想用GLM-5评估怎么办？

编辑 `config.json`，设置 `ENABLE_LLM_EVALUATION = False`，将只使用关键词匹配。

### Q: 如何监控远程OpenClaw？

修改 `config.json` 中的路径配置，指向远程服务器的OpenClaw目录（需要网络共享或同步）。

## 贡献

欢迎提交Issue和Pull Request！

## License

MIT License - 详见 [LICENSE](LICENSE)

## 致谢

- [OpenClaw](https://github.com/openclaw/openclaw) - AI Agent框架
- [百炼GLM-5](https://dashscope.console.aliyun.com/) - 智能风险评估
