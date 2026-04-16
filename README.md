# Hcollector 性能分析平台 — 部署文档

## 项目结构

```
perf-analyzer/
├── app.py              # FastAPI 后端（解析器 + API）
├── static/
│   └── index.html      # 前端单页应用
└── DEPLOY.md           # 本文档
```

## 环境要求

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Python | 3.9+ | 标准库已包含 zipfile / tarfile |
| fastapi | 0.100+ | Web 框架 |
| uvicorn | 0.20+ | ASGI 服务器 |
| python-multipart | 0.0.6+ | 文件上传支持 |

> 已在 Python 3.14.3 + FastAPI 0.135.1 + uvicorn 0.41.0 环境下验证。

---

## 快速启动

### 1. 安装依赖

```bash
pip install fastapi uvicorn python-multipart
```

> 若系统 Python 被保护（PEP 668），加 `--break-system-packages` 或使用虚拟环境：
> ```bash
> python3 -m venv .venv && source .venv/bin/activate
> pip install fastapi uvicorn python-multipart
> ```

### 2. 启动服务

```bash
cd perf-analyzer
python3 -m uvicorn app:app --host 0.0.0.0 --port 8766
```

### 3. 访问

打开浏览器访问：`http://localhost:8766`

---

## 生产部署

### 方式一：多进程（推荐）

```bash
python3 -m uvicorn app:app \
  --host 0.0.0.0 \
  --port 8766 \
  --workers 4 \
  --access-log
```

> `--workers` 建议设为 CPU 核心数，每个 worker 独立处理一个上传请求。

### 方式二：守护进程（nohup）

```bash
nohup python3 -m uvicorn app:app \
  --host 0.0.0.0 --port 8766 --workers 64 \
  > /var/log/perf-analyzer.log 2>&1 &

echo $! > /var/run/perf-analyzer.pid
```

停止服务：
```bash
kill $(cat /var/run/perf-analyzer.pid)
```

### 方式三：systemd 服务（Linux）

创建服务文件 `/etc/systemd/system/perf-analyzer.service`：

```ini
[Unit]
Description=Hcollector 性能分析平台
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/perf-analyzer
ExecStart=/usr/bin/python3 -m uvicorn app:app --host 0.0.0.0 --port 8766 --workers 4
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

启用并启动：
```bash
sudo systemctl daemon-reload
sudo systemctl enable perf-analyzer
sudo systemctl start perf-analyzer
sudo systemctl status perf-analyzer
```

### 方式四：Nginx 反向代理

`/etc/nginx/conf.d/perf-analyzer.conf`：

```nginx
server {
    listen 80;
    server_name perf.example.com;

    # 上传文件大小限制（runlog 包通常 5~50 MB）
    client_max_body_size 200m;

    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # 大文件上传超时设置
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

重载 Nginx：
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## 支持的压缩格式

上传文件时，后端按以下顺序自动检测格式，**无需用户指定**：

| 扩展名 | 格式 | 备注 |
|--------|------|------|
| `.zip` | ZIP | 优先尝试 |
| `.tar.gz` / `.tgz` | gzip 压缩 tar | |
| `.tar.bz2` | bzip2 压缩 tar | |
| `.tar.xz` | xz 压缩 tar | |
| `.tar` | 无压缩 tar | |

---

## 解析的日志文件

服务从压缩包中按文件名查找以下文件（不依赖目录结构）：

| 文件名 | 内容 | 对应 Tab |
|--------|------|---------|
| `hpt-uarch.log` | IPC、频率、L1/L2/L3缓存缺失率、TopDown | CPU / 缓存 |
| `hpt-topdown.log` | TopDown 详细分解 | CPU |
| `hpt-cm.log` | 各 Die/Socket 内存带宽 | 缓存 & 带宽 |
| `hpt-hotspot.log` | perf 热点函数（多事件） | 热点函数 |
| `hpt-mem.log` | 进程远程/本地内存访问比 | NUMA |
| `hpt-sched.log` | 进程调度、CPU/Die 迁移 | 调度 |
| `mpstat.log` | CPU 利用率时序 | CPU |
| `version.log` | 采集工具版本号 | 顶栏显示 |
| `hpt-hotspot-flame*.svg` | CPU 火焰图 | 火焰图 |

> 文件缺失时对应模块显示"无数据"，不影响其他模块。

---

## 性能参考

基于 `runlog-system-20260310-094235.tar`（7.3 MB）测试：

| 指标 | 数值 |
|------|------|
| 文件读取 + 解压 | ~10 ms |
| 全部解析器运行 | ~60 ms |
| 总响应时间 | **~71 ms** |
| 响应体大小 | ~530 KB |

单机单进程可支撑并发分析，多 worker 可线性扩展。

---

## 常见问题

**Q: 上传后页面无反应**
检查浏览器 Console（F12）是否有 JS 错误；确认服务端口未被防火墙拦截。

**Q: 火焰图显示空白**
压缩包中需包含 `*.svg` 文件（如 `hpt-hotspot-flame.svg`）。

**Q: 部分指标显示 N/A**
对应日志文件在压缩包中缺失，属正常情况，不影响其他项。

**Q: 端口 8766 被占用**
```bash
lsof -ti :8766 | xargs kill
# 或换端口
python3 -m uvicorn app:app --port 9000
```

**Q: pip 安装报 PEP 668 错误**
```bash
pip install fastapi uvicorn python-multipart --break-system-packages
# 或使用虚拟环境（推荐）
python3 -m venv .venv && source .venv/bin/activate && pip install fastapi uvicorn python-multipart
```
