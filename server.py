#!/usr/bin/env python3
"""OpenClaw Agent Monitor v3 - GLM-5 风险评估 + 实时报警

支持监控本地或远程 OpenClaw 实例，可用于安全审计和行为追踪。
"""

import json
import os
import re
import threading
import time
import urllib.request
from collections import Counter, deque
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from logger import get_logger
logger = get_logger("monitor server")
import platform

# ==================== 配置加载 ====================
CONFIG_FILE = Path(__file__).parent / "config.json"
DEFAULT_CONFIG = {
    "server": {"port": 8765, "host": "0.0.0.0", "refresh_interval": 3},
    "bailian": {"api_key": "", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "glm-5"},
    "alerts": {"max_count": 50, "enable_llm_evaluation": True, "enable_keyword_check": True},
    "paths": {
        "openclaw_home": "~/.openclaw",
        "agents_dir": "~/.openclaw/agents/main",
        "sessions_json": "~/.openclaw/agents/main/sessions/sessions.json",
        "cron_file": "~/.openclaw/cron/jobs.json"
    },
    "high_risk_keywords": [
        "rm -rf", "rm -r", "trash", "delete", "rmdir",
        "apiKey", "password", "secret", "token", "credential",
        ".env", "openclaw.json", "/etc/", "/System/",
        "curl -X POST", "curl -d", "wget --post",
        "病毒", "木马", "后门", "exploit", "malware", "virus",
        "trojan", "backdoor", "keylog", "ransomware"
    ]
}

def load_config():
    """加载配置文件，支持环境变量覆盖"""
    config = DEFAULT_CONFIG.copy()
    
    # 尝试加载配置文件
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                # 递归合并配置
                def merge(base, override):
                    for k, v in override.items():
                        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                            merge(base[k], v)
                        else:
                            base[k] = v
                merge(config, user_config)
        except Exception as e:
            logger.error(f"配置文件加载失败，使用默认配置: {e}")
    
    # 尝试从OpenClaw配置读取API Key
    openclaw_cfg_path = Path(os.path.expanduser(config["paths"]["openclaw_home"])) / "openclaw.json"
    if openclaw_cfg_path.exists() and not config["bailian"]["api_key"]:
        try:
            with open(openclaw_cfg_path, "r", encoding="utf-8") as f:
                oc_cfg = json.load(f)
                config["bailian"]["api_key"] = oc_cfg.get("models", {}).get("providers", {}).get("bailian", {}).get("apiKey", "")
                config["bailian"]["base_url"] = oc_cfg.get("models", {}).get("providers", {}).get("bailian", {}).get("baseUrl", config["bailian"]["base_url"])
        except Exception as e:
            logger.error(f"OpenClaw配置文件读取失败: {e}")
    
    # 环境变量覆盖
    if os.environ.get("MONITOR_PORT"):
        config["server"]["port"] = int(os.environ["MONITOR_PORT"])
    if os.environ.get("BAILIAN_API_KEY"):
        config["bailian"]["api_key"] = os.environ["BAILIAN_API_KEY"]
    
    return config

CONFIG = load_config()

# 路径配置
PORT = CONFIG["server"]["port"]
AGENTS_DIR = Path(os.path.expanduser(CONFIG["paths"]["agents_dir"]))
SESSIONS_JSON = Path(os.path.expanduser(CONFIG["paths"]["sessions_json"]))
SESSIONS_DIR = AGENTS_DIR / "sessions"
CRON_FILE = Path(os.path.expanduser(CONFIG["paths"]["cron_file"]))

# 刷新间隔
REFRESH_INTERVAL = CONFIG["server"]["refresh_interval"]

# 百炼GLM-5配置
BAILIAN_KEY = CONFIG["bailian"]["api_key"]
BAILIAN_URL = CONFIG["bailian"]["base_url"]
HIGH_RISK_KEYWORDS = CONFIG["high_risk_keywords"]

PATH_RE = re.compile(r'(?:~(?=/)|(?=/))(?:/[\w.~\u4e00-\u9fff-]+)+')

# 系统信息
SYSTEM_INFO = f"{platform.system()} {platform.machine()}"

# 全局状态
state = {"sessions": [], "cron_jobs": [], "system": {}, "tools": {}, "paths": [], "alerts": [], "last_updated": None, "system_info":SYSTEM_INFO}
# 已评估过的动作（避免重复调用 LLM）
evaluated_actions = set()
# 报警队列（最近50条）
alerts = deque(maxlen=50)
# 上次解析到的位置（增量解析）
last_line_counts = {}


RISK_PROMPT = """你是一个安全监控 AI。判断以下 agent 动作是否是高危动作。

高危动作包括：
- 删除文件（rm, trash, delete）
- 修改系统配置（/etc, /System, launchd）
- 发送敏感数据到外部（curl POST 含密码/token, 邮件发送敏感内容）
- 执行未知脚本或二进制
- 访问密钥/凭证文件（.env, credentials, secrets, apiKey, password）
- 网络请求到可疑域名
- 修改 OpenClaw 核心配置（openclaw.json 的 auth/token 部分）
- 大规模文件操作（rm -rf, 批量删除）

低危/正常动作包括：
- 读取文件、列出目录
- 搜索网页、读取论文
- 写入工作区文件
- 浏览器导航和截图
- 查看系统状态

请只回复 JSON 格式：
{"risk": "high" 或 "low", "reason": "一句话原因"}

动作信息：
工具: {tool_name}
参数: {args}"""

def call_glm5(tool_name, args_summary):
    """调用GLM-5评估风险"""
    if not BAILIAN_KEY or not CONFIG["alerts"]["enable_llm_evaluation"]:
        return None, None
    try:
        prompt = RISK_PROMPT.replace("{tool_name}", tool_name).replace("{args}", args_summary[:500])
        body = json.dumps({
            "model": "glm-5",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 100,
            "temperature": 0.1
        }).encode()
        req = urllib.request.Request(
            BAILIAN_URL + "/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {BAILIAN_KEY}",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read().decode())
            text = resp["choices"][0]["message"]["content"].strip()
            # 解析JSON
            if "{" in text:
                j = json.loads(text[text.index("{"):text.rindex("}")+1])
                return j.get("risk", "low"), j.get("reason", "")
    except Exception as e:
        logger.error(f"调用GLM-5评估风险失败: {e}, 继续使用关键词匹配")
        pass
    return None, None

def quick_risk_check(tool_name, args_summary):
    """快速关键词风险检查（不调LLM，用于预筛选）"""
    text = f"{tool_name} {args_summary}".lower()
    for kw in HIGH_RISK_KEYWORDS:
        if kw.lower() in text:
            return True
    # exec命令一律送LLM评估（除非极短的查询类命令）
    if tool_name == "exec" and len(args_summary) > 20:
        return None  # 需要LLM评估
    return False

def evaluate_action(tool_name, args_summary, timestamp):
    """评估单个动作的风险"""
    action_key = f"{tool_name}:{args_summary[:100]}:{timestamp or ''}"
    if action_key in evaluated_actions:
        return
    evaluated_actions.add(action_key)
    
    # 快速检查
    quick = quick_risk_check(tool_name, args_summary)
    
    if quick is True:
        # 明确高危
        alerts.append({
            "level": "high",
            "tool": tool_name,
            "args": args_summary[:200],
            "reason": "关键词匹配：包含危险操作",
            "timestamp": timestamp or datetime.now().isoformat(),
            "method": "keyword"
        })
    elif quick is None:
        # 需要LLM评估
        risk, reason = call_glm5(tool_name, args_summary)
        if risk == "high":
            alerts.append({
                "level": "high",
                "tool": tool_name,
                "args": args_summary[:200],
                "reason": reason or "GLM-5判定高危",
                "timestamp": timestamp or datetime.now().isoformat(),
                "method": "glm-5"
            })

def parse_session_file(sf_path, session_key):
    """增量解析session文件"""
    messages = []
    tool_calls = []
    paths_dict = {}
    
    if not sf_path or not Path(sf_path).exists():
        logger.debug(f"Session file not found: {sf_path}") ### 
        return messages, tool_calls, paths_dict, 0
    
    msg_count = 0
    start_line = 0  # 始终全量解析以获取完整数据
    new_tools = []
    
    try:
        with open(sf_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                msg_count += 1
                if i < start_line and start_line > 0:
                    # 跳过已解析的行（但仍然计数）
                    continue
                try:
                    entry = json.loads(line.strip())
                    inner = entry.get("message", {})
                    role = inner.get("role", "")
                    ts = entry.get("timestamp")
                    content = inner.get("content", "")
                    
                    if role in ("user", "assistant"):
                        text = ""
                        if isinstance(content, str):
                            text = content[:300]
                        elif isinstance(content, list):
                            for part in content:
                                if isinstance(part, dict) and part.get("type") == "text":
                                    text = part.get("text", "")[:300]
                                    break
                        if text:
                            messages.append({"role": role, "content": text, "timestamp": ts})
                    
                    if isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "toolCall":
                                name = part.get("name", "")
                                args = part.get("arguments", {})
                                summary = _summarize_args(name, args)
                                tc = {"name": name, "args_summary": summary, "timestamp": ts}
                                tool_calls.append(tc)
                                if i >= start_line:
                                    new_tools.append(tc)
                                _extract_paths(args, paths_dict, ts)
                    
                    if role == "toolResult" and isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text":
                                text = part.get("text", "")
                                for m in PATH_RE.finditer(text):
                                    p = m.group()
                                    if any(p.startswith(pre) for pre in ("/Users", "/tmp", "/opt", "/var", "/etc")):
                                        p = p[:120]
                                        if p not in paths_dict or (ts and ts > (paths_dict[p] or "")):
                                            paths_dict[p] = ts
                except Exception as e:
                    logger.error(f"处理消息时发生错误: {e}")
        
        last_line_counts[session_key] = msg_count
        
        # 评估新工具调用的风险（异步，不阻塞）
        for tc in new_tools:
            threading.Thread(
                target=evaluate_action,
                args=(tc["name"], tc["args_summary"], tc["timestamp"]),
                daemon=True
            ).start()
    except Exception as e:
        logger.error(f"session文件读取失败: {e}")
        
    
    return messages[-8:], tool_calls, paths_dict, msg_count

def _summarize_args(name, args):
    if not args: return ""
    if name in ("exec",): return args.get("command", "")[:150]
    if name in ("read", "write", "edit"): return args.get("file_path", args.get("path", ""))[:100]
    if name in ("web_search",): return args.get("query", "")[:80]
    if name in ("web_fetch",): return args.get("url", "")[:80]
    if name in ("browser",): return args.get("action", "") + " " + (args.get("url", "") or args.get("ref", ""))[:60]
    if name in ("message",): return args.get("action", "") + " → " + (args.get("to", "") or "")[:40]
    if name in ("feishu_doc",): return args.get("action", "")
    if name in ("cron",): return args.get("action", "")
    if name in ("gateway",): return args.get("action", "")
    if name in ("pdf",): return (args.get("pdf", "") or "")[:80]
    if name in ("memory_search",): return args.get("query", "")[:60]
    keys = list(args.keys())[:3]
    return ", ".join(f"{k}={str(args[k])[:30]}" for k in keys)

def _extract_paths(args, paths_dict, ts=None):
    for k, v in args.items():
        if isinstance(v, str) and len(v) < 300:
            if v.startswith("/") or v.startswith("~"):
                p = v[:120]
                if p not in paths_dict or (ts and ts > (paths_dict[p] or "")):
                    paths_dict[p] = ts
            if k in ("command",):
                for m in PATH_RE.finditer(v):
                    p = m.group()
                    if any(p.startswith(pre) for pre in ("/Users", "/tmp", "/opt", "/var", "/etc", "~/")):
                        p = p[:120]
                        if p not in paths_dict or (ts and ts > (paths_dict[p] or "")):
                            paths_dict[p] = ts

def read_sessions():
    sessions = []
    all_tools = []
    all_paths = {}
    try:
        if not SESSIONS_JSON.exists(): return sessions, all_tools, all_paths
        with open(SESSIONS_JSON, encoding="utf-8") as f: ### 加了一下encoding
            data = json.load(f)

        # 读取 cron job 名称映射
        cron_names = {}
        try:
            cron_jobs = read_cron()
            for j in (cron_jobs if isinstance(cron_jobs, list) else []):
                jid = j.get("id", "")
                cron_names[jid] = j.get("name", jid[:8])
        except: pass

        # 第一遍：收集 cron job 的最新 run 信息
        cron_groups = {}  # cron_id -> {latest_key, latest_updated, all_keys}
        normal_keys = []
        for key, info in data.items():
            if ":cron:" in key:
                # 提取 cron job id（cron: 后面的 uuid）
                parts = key.split(":cron:")
                if len(parts) >= 2:
                    cron_part = parts[1]  # uuid 或 uuid:run:uuid
                    cron_id = cron_part.split(":")[0]
                    updated_ms = info.get("updatedAt", 0)
                    if cron_id not in cron_groups:
                        cron_groups[cron_id] = {"latest_key": key, "latest_updated": updated_ms, "all_keys": [key]}
                    else:
                        cron_groups[cron_id]["all_keys"].append(key)
                        if updated_ms > cron_groups[cron_id]["latest_updated"]:
                            cron_groups[cron_id]["latest_key"] = key
                            cron_groups[cron_id]["latest_updated"] = updated_ms
            else:
                normal_keys.append(key)

        # 第二遍：处理普通会话
        for key in normal_keys:
            info = data[key]
            if "tui-" in key:
                continue  # TUI 合并到主会话，不单独显示
            sid = info.get("sessionId", "")
            updated_ms = info.get("updatedAt", 0)
            session_file = info.get("sessionFile", "")
            sf = Path(session_file) if session_file else None
            if not sf or not sf.exists():
                sf = SESSIONS_DIR / f"{sid}.jsonl"
            messages, tool_calls, paths, msg_count = parse_session_file(sf, key)
            logger.debug(f"Session {key}: {len(messages)} messages, {len(tool_calls)} tool calls, {len(paths)} paths, {msg_count} msg_count") ### 
            all_tools.extend(tool_calls)
            for p, t in paths.items():
                if p not in all_paths or (t and t > (all_paths[p] or "")):
                    all_paths[p] = t
            sessions.append({
                "sessionKey": key, "sessionId": sid,
                "updatedAt": datetime.fromtimestamp(updated_ms/1000).isoformat() if updated_ms else None,
                "messageCount": msg_count, "toolCallCount": len(tool_calls),
                "messages": messages, "channel": info.get("lastChannel", ""),
                "chatType": info.get("chatType", ""),
                "compactions": info.get("compactionCount", 0),
                "model": "claude-opus-4-6", "sessionType": "主会话"
            })

        # 第三遍：每个 cron job 聚合为一个子 agent 会话
        for cron_id, group in cron_groups.items():
            latest_key = group["latest_key"]
            info = data[latest_key]
            sid = info.get("sessionId", "")
            updated_ms = group["latest_updated"]
            session_file = info.get("sessionFile", "")
            sf = Path(session_file) if session_file else None
            if not sf or not sf.exists():
                sf = SESSIONS_DIR / f"{sid}.jsonl"
            messages, tool_calls, paths, msg_count = parse_session_file(sf, latest_key)
            # 累计所有 run 的工具调用（用于全局统计）
            total_msgs = 0
            total_tools = 0
            for rk in group["all_keys"]:
                ri = data[rk]
                rsid = ri.get("sessionId", "")
                rsf_path = ri.get("sessionFile", "")
                rsf = Path(rsf_path) if rsf_path else SESSIONS_DIR / f"{rsid}.jsonl"
                if rsf.exists():
                    _, rtc, rpaths, rmc = parse_session_file(rsf, rk)
                    all_tools.extend(rtc)
                    total_msgs += rmc
                    total_tools += len(rtc)
                    for p, t in rpaths.items():
                        if p not in all_paths or (t and t > (all_paths[p] or "")):
                            all_paths[p] = t

            job_name = cron_names.get(cron_id, cron_id[:8])
            sessions.append({
                "sessionKey": f"cron:{cron_id}", "sessionId": sid,
                "updatedAt": datetime.fromtimestamp(updated_ms/1000).isoformat() if updated_ms else None,
                "messageCount": total_msgs, "toolCallCount": total_tools,
                "messages": messages, "channel": "",
                "chatType": "cron",
                "compactions": 0,
                "model": "glm-5", "sessionType": f"子Agent: {job_name}"
            })

        sessions.sort(key=lambda x: x.get("updatedAt") or "", reverse=True)
    except Exception as e:
        logger.error(f"Session读取失败: {e}")
    return sessions, all_tools, all_paths

def read_cron():
    try:
        if CRON_FILE.exists():
            with open(CRON_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("jobs", data) if isinstance(data, dict) else data
    except: pass
    return []

def read_system():
    try:
        with open(Path.home() / ".openclaw" / "openclaw.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        providers = cfg.get("models", {}).get("providers", {})
        model_count = sum(len(p.get("models", [])) for p in providers.values())
        channels = [k for k, v in cfg.get("channels", {}).items() if isinstance(v, dict) and v.get("enabled")]
        hb = cfg.get("agents", {}).get("defaults", {}).get("heartbeat", {})
        return {"hostname": "openclaw的Mac mini", "chip": "Apple M4", "memory": "24GB",
                "version": cfg.get("meta", {}).get("lastTouchedVersion", ""),
                "primary_model": "claude-opus-4-6", "model_count": model_count,
                "channels": channels, "heartbeat": hb.get("every", "off")}
    except: return {}

def background_poller():
    while True:
        try:
            sessions, all_tools, all_paths = read_sessions()
            state["sessions"] = sessions
            state["cron_jobs"] = read_cron()
            state["system"] = read_system()
            tool_counter = Counter(t["name"] for t in all_tools)
            all_tools_sorted = sorted(all_tools, key=lambda x: x.get("timestamp") or "", reverse=True)
            state["tools"] = {
                "total": len(all_tools),
                "usage": [{"name": n, "count": c} for n, c in tool_counter.most_common(20)],
                "recent": all_tools_sorted[:30]
            }
            clean_paths = []
            for p, t in all_paths.items():
                if any(c in p for c in ('{', '}', '|', '(', ')', '`', '$', "'", '"', '\\', ';')): continue
                if len(p) > 100: continue
                if not p.startswith('/') and not p.startswith('~'): continue
                clean_paths.append({"path": p, "timestamp": t})
            clean_paths.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
            state["paths"] = clean_paths
            state["alerts"] = list(alerts)
            state["last_updated"] = datetime.now().isoformat()
        except Exception as e:
            print(f"后台轮询更新失败: {e}")
        time.sleep(REFRESH_INTERVAL)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent), **kwargs)
    def do_GET(self):
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(state, default=str).encode())
        else:
            if self.path in ("/", ""): self.path = "/index.html"
            super().do_GET()
    def log_message(self, *a): pass

if __name__ == "__main__":
    t = threading.Thread(target=background_poller, daemon=True)
    t.start()
    
    host = CONFIG["server"]["host"]
    print(f"🦞 OpenClaw Agent Monitor v3")
    print(f"   监控地址: http://{host}:{PORT}")
    print(f"   OpenClaw: {CONFIG['paths']['openclaw_home']}")
    print(f"   GLM-5: {'已配置' if BAILIAN_KEY else '未配置（仅关键词检测）'}")
    print(f"   按 Ctrl+C 停止服务")
    
    import socket
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()
    ReusableHTTPServer((host, PORT), Handler).serve_forever()
