# perf-analyzer

基于 Web 的 性能日志分析工具。上传 hcollector 采集的 runlog 压缩包，自动解析并可视化 CPU、内存、IO、网络、调度等多维度性能数据，并根据可配置规则输出优化建议。

## 功能

### 分析模块

| 模块 | 来源文件 | 内容 |
|------|---------|------|
| 基础信息 | `base*.log` | CPU 型号、核数、NUMA 拓扑、内核版本、内存 |
| CPU 微架构 | `hpt-uarch.log` | IPC、频率、L1/L2/L3 缺失率、分支预测 |
| TopDown | `hpt-topdown.log` | Frontend/Backend Bound、Bad Speculation 详细分解 |
| 缓存 & 带宽 | `hpt-cm.log` | 各 Die/Socket 内存带宽 |
| 热点函数 | `hpt-hotspot.log` | perf 多事件热点函数排名 |
| 火焰图 | `hpt-hotspot-flame*.svg` | CPU 火焰图（交互式 SVG） |
| NUMA | `hpt-mem.log` | 进程远程/本地内存访问比 |
| 调度 | `hpt-sched.log` | CPU/Die 迁移次数、调度延迟 |
| CPU 利用率 | `mpstat.log` | 时序 CPU 利用率（usr/sys/iowait） |
| 磁盘 IO | `iostat.log` / `di*.log` | IOPS、吞吐量、await 时序 |
| IO 内存 | `iom*.log` | IO 内存使用 |
| 网络 | `sar_net*.log` / `nethogs*.log` / `eths*.log` | 网络吞吐、进程级流量 |
| 进程 Top | `top*.log` | 系统进程资源快照 |
| Turbostat | `turbostat*.log` | 频率、C-State、功耗 |
| NUMA 绑定 | `numactl*.log` | 进程 NUMA 策略 |
| 硬件信息 | `lspci*.log` | PCIe 设备列表 |
| IPMI | `ipmi*.log` | 温度、风扇、电源传感器 |
| 容器 | `container*.log` | Docker/Podman 容器信息 |
| 虚拟化 | `virt*.log` / `qemu*.log` | QEMU/KVM 虚拟机配置 |
| 线程调度 | `process_sched*.log` | 线程级调度统计 |
| CPU 亲和性 | `proc_affinity*.log` | 进程 CPU 绑定情况 |
| 线程运行时 | `thread_runtime*.log` | 线程运行时间分布 |
| 符号表 | `kallsyms` | 内核符号解析 |

### 规则引擎

内置可配置的性能诊断规则，分析完成后自动生成 **高 / 中 / 低** 三级优化建议。规则支持多条件组合（AND/OR），可通过 Web UI 增删改查，并支持多规则集管理（密码保护）。

## 快速开始

### 安装依赖

```bash
pip install fastapi uvicorn python-multipart
```

> 若系统 Python 受 PEP 668 保护，改用虚拟环境：
> ```bash
> python3 -m venv .venv && source .venv/bin/activate
> pip install fastapi uvicorn python-multipart
> ```

### 启动服务

```bash
python3 -m uvicorn app:app --host 0.0.0.0 --port 8766
```

打开浏览器访问 `http://localhost:8766`，上传 runlog 压缩包即可。

### 支持的压缩格式

`.zip` · `.tar.gz` / `.tgz` · `.tar.bz2` · `.tar.xz` · `.tar`

文件缺失时对应模块显示"无数据"，不影响其他模块。

## 生产部署

### 多进程

```bash
python3 -m uvicorn app:app --host 0.0.0.0 --port 8766 --workers 4
```

### 守护进程

```bash
nohup python3 -m uvicorn app:app \
  --host 0.0.0.0 --port 8766 --workers 4 \
  > /var/log/perf-analyzer.log 2>&1 &
echo $! > /var/run/perf-analyzer.pid
```

### systemd

创建 `/etc/systemd/system/perf-analyzer.service`：

```ini
[Unit]
Description=perf-analyzer
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/perf-analyzer
ExecStart=/usr/bin/python3 -m uvicorn app:app --host 0.0.0.0 --port 8766 --workers 4
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now perf-analyzer
```

### Nginx 反向代理

```nginx
server {
    listen 80;
    server_name perf.example.com;
    client_max_body_size 200m;

    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/analyze` | 上传压缩包，返回全量解析结果（JSON） |
| `GET` | `/api/rules` | 获取当前规则列表 |
| `POST` | `/api/rules` | 保存规则列表 |
| `POST` | `/api/rules/reset` | 恢复默认规则 |
| `GET` | `/api/rulesets` | 获取所有规则集 |
| `POST` | `/api/rulesets` | 创建规则集 |
| `DELETE` | `/api/rulesets/{name}` | 删除规则集 |
| `POST` | `/api/recommendations` | 对已解析结果单独执行规则推断 |

## 项目结构

```
perf-analyzer/
├── app.py              # FastAPI 后端（解析器 + API）
├── rules.json          # 当前活跃规则
├── rules/              # 多规则集目录
├── static/
│   ├── index.html      # 前端单页应用
│   └── rules.html      # 规则编辑页
└── README.md
```

## 环境要求

| 依赖 | 版本 |
|------|------|
| Python | 3.9+ |
| fastapi | 0.100+ |
| uvicorn | 0.20+ |
| python-multipart | 0.0.6+ |

已在 Python 3.14 + FastAPI 0.135 + uvicorn 0.41 下验证。

## 性能参考

测试文件：`runlog-system-20260310-094235.tar`（7.3 MB）

| 指标 | 数值 |
|------|------|
| 文件读取 + 解压 | ~10 ms |
| 全部解析器 | ~60 ms |
| 总响应时间 | ~71 ms |
| 响应体大小 | ~530 KB |
