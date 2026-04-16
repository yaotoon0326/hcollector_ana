#!/usr/bin/env python3
"""HPC 性能日志分析工具 - 后端服务"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import zipfile, tarfile, io, re, os, json
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

app = FastAPI(title="Hcollector 性能分析工具")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

STATIC_DIR = Path(__file__).parent / "static"
RULES_FILE = Path(__file__).parent / "rules.json"
DEFAULT_RULES_FILE = Path(__file__).parent / "default_rules.json"
RULES_DIR = Path(__file__).parent / "rules"
RULES_DIR.mkdir(exist_ok=True)


# ── 工具函数 ────────────────────────────────────────────────────────────────

def build_file_map(archive):
    """构建 {文件名: 压缩包内路径} 映射"""
    file_map = {}
    if isinstance(archive, zipfile.ZipFile):
        for name in archive.namelist():
            if not name.endswith('/'):
                basename = Path(name).name
                if basename not in file_map:
                    file_map[basename] = name
    elif isinstance(archive, tarfile.TarFile):
        for member in archive.getmembers():
            if member.isfile():
                basename = Path(member.name).name
                if basename not in file_map:
                    file_map[basename] = member.name
    return file_map


def read_file_by_path(archive, path_substr: str) -> Optional[str]:
    """按路径子串搜索并读取压缩包内文件（用于同名但不同目录的文件）"""
    try:
        if isinstance(archive, zipfile.ZipFile):
            for name in archive.namelist():
                if path_substr in name and not name.endswith('/'):
                    with archive.open(name) as f:
                        return f.read().decode('utf-8', errors='replace')
        else:
            for member in archive.getmembers():
                if path_substr in member.name and member.isfile():
                    f = archive.extractfile(member.name)
                    if f:
                        return f.read().decode('utf-8', errors='replace')
    except Exception:
        pass
    return None


def read_file(archive, file_map, filename) -> Optional[str]:
    """从压缩包中读取指定文件内容"""
    if filename not in file_map:
        return None
    try:
        if isinstance(archive, zipfile.ZipFile):
            with archive.open(file_map[filename]) as f:
                return f.read().decode('utf-8', errors='replace')
        else:
            member = archive.extractfile(file_map[filename])
            if member:
                return member.read().decode('utf-8', errors='replace')
    except Exception:
        return None


def get_col_bounds(sep_line: str):
    """从分隔符行提取列边界 [(start, end), ...]"""
    cols = []
    in_dash = False
    start = 0
    for i, c in enumerate(sep_line + ' '):
        if c == '-' and not in_dash:
            start = i
            in_dash = True
        elif c != '-' and in_dash:
            cols.append((start, i))
            in_dash = False
    return cols


def parse_size_val(s: str) -> Optional[float]:
    """解析带单位的数值，如 '120 M'、'22 GB/s'、'1.49'"""
    s = str(s).strip()
    if not s or s in ('N/A', 'n/a', '-'):
        return None
    m = re.match(r'^([\d.]+)\s*([KMGT]?)(?:B/s|B)?$', s)
    if m:
        val = float(m.group(1))
        mult = {'K': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12, '': 1}.get(m.group(2), 1)
        return val * mult
    try:
        return float(re.sub(r'[^\d.]', '', s))
    except Exception:
        return None


def avg(lst):
    lst = [v for v in lst if v is not None]
    return round(sum(lst) / len(lst), 3) if lst else None


# ── 各日志解析器 ────────────────────────────────────────────────────────────

def parse_uarch(archive, file_map) -> Optional[dict]:
    """解析 hpt-uarch.log：缓存命中率、IPC、微架构指标"""
    content = read_file(archive, file_map, 'hpt-uarch.log')
    if not content:
        return None

    lines = content.splitlines()
    collected = {}   # section_type -> list of {col_name: raw_str}
    i = 0

    while i < len(lines):
        line = lines[i]
        if 'Time(s)' in line and 'Level' in line:
            header_line = line
            # 下一行是分隔符
            if i + 1 >= len(lines):
                i += 1
                continue
            sep_line = lines[i + 1]
            col_bounds = get_col_bounds(sep_line)
            if not col_bounds:
                i += 1
                continue

            # 列名（从 header 行按分隔符位置切片）
            col_names = []
            for s, e in col_bounds:
                name = header_line[s:min(e, len(header_line))].strip()
                col_names.append(name)
            hstr = ' '.join(col_names)

            # 判断区块类型
            if 'l3-cache-miss-ratio' in hstr:
                stype = 'l3'
            elif 'cpu-freq' in hstr and 'IPC' in hstr:
                stype = 'ipc'
            elif 'SSE-ratio' in hstr:
                stype = 'simd'
            elif 'l1-dcache-miss-ratio' in hstr:
                stype = 'l1'
            elif 'l2-dcache-miss-ratio' in hstr:
                stype = 'l2'
            elif 'l1-dtlb' in hstr or 'l1-itlb' in hstr:
                stype = 'tlb'
            elif 'backend-bound' in hstr:
                stype = 'topdown'
            else:
                stype = None

            if stype:
                if stype not in collected:
                    collected[stype] = []
                j = i + 2
                while j < len(lines):
                    dl = lines[j]
                    if not dl.strip() or 'Time(s)' in dl:
                        break
                    if re.match(r'^\s*\d', dl):
                        row = {}
                        for k, (s, e) in enumerate(col_bounds):
                            v = dl[s:min(e, len(dl))].strip()
                            if k < len(col_names):
                                row[col_names[k]] = v
                        collected[stype].append(row)
                    j += 1
                i = j
                continue
        i += 1

    def col_avg(stype, col):
        rows = collected.get(stype, [])
        vals = [parse_size_val(r.get(col, '')) for r in rows]
        return avg(vals)

    def col_max(stype, col):
        rows = collected.get(stype, [])
        vals = [v for r in rows if (v := parse_size_val(r.get(col, ''))) is not None]
        return round(max(vals), 4) if vals else None

    def col_min(stype, col):
        rows = collected.get(stype, [])
        vals = [v for r in rows if (v := parse_size_val(r.get(col, ''))) is not None]
        return round(min(vals), 4) if vals else None

    result = {}
    result['avg_ipc'] = col_avg('ipc', 'IPC')
    result['max_ipc'] = col_max('ipc', 'IPC')
    result['min_ipc'] = col_min('ipc', 'IPC')
    result['avg_freq_ghz'] = col_avg('ipc', 'cpu-freq(GHz)')
    result['max_freq_ghz'] = col_max('ipc', 'cpu-freq(GHz)')
    result['min_freq_ghz'] = col_min('ipc', 'cpu-freq(GHz)')
    result['avg_branch_miss'] = col_avg('ipc', 'branch-miss-ratio(%)')
    result['avg_l3_miss'] = col_avg('l3', 'l3-cache-miss-ratio(%)')
    result['max_l3_miss'] = col_max('l3', 'l3-cache-miss-ratio(%)')
    result['avg_sse_ratio'] = col_avg('simd', 'SSE-ratio(%)')
    result['avg_l1d_miss'] = col_avg('l1', 'l1-dcache-miss-ratio(%)')
    result['max_l1d_miss'] = col_max('l1', 'l1-dcache-miss-ratio(%)')
    result['avg_l2d_miss'] = col_avg('l2', 'l2-dcache-miss-ratio(%)')
    result['max_l2d_miss'] = col_max('l2', 'l2-dcache-miss-ratio(%)')
    result['avg_l2_pf_miss'] = col_avg('l2', 'l2-prefetch-miss-ratio(%)')
    result['max_l2_pf_miss'] = col_max('l2', 'l2-prefetch-miss-ratio(%)')
    result['avg_backend_bound'] = col_avg('topdown', 'backend-bound(%)')
    result['avg_frontend_bound'] = col_avg('topdown', 'frontend-bound(%)')
    result['avg_retire'] = col_avg('topdown', 'retired(%)')
    result['avg_bad_spec'] = col_avg('topdown', 'bad-speculation(%)')

    # 缓存缺失率时序（按 DIE 分组，用于折线图）
    def col_ts_by_level(stype, col):
        rows = collected.get(stype, [])
        level_order, seen_levels = [], set()
        time_order,  seen_times  = [], set()
        level_vals = {}
        for r in rows:
            t     = r.get('Time(s)', '')
            level = r.get('Level', '')
            val   = parse_size_val(r.get(col, ''))
            if val is None or not level:
                continue
            if level not in seen_levels:
                level_order.append(level)
                seen_levels.add(level)
                level_vals[level] = []
            if t not in seen_times:
                time_order.append(t)
                seen_times.add(t)
            level_vals[level].append(round(val, 2))
        return {'labels': level_order, 'times': time_order, 'series': level_vals}

    result['cache_miss_ts'] = {
        'l1d':  col_ts_by_level('l1', 'l1-dcache-miss-ratio(%)'),
        'l2d':  col_ts_by_level('l2', 'l2-dcache-miss-ratio(%)'),
        'l3':   col_ts_by_level('l3', 'l3-cache-miss-ratio(%)'),
        'l2pf': col_ts_by_level('l2', 'l2-prefetch-miss-ratio(%)'),
    }

    # 时序数据（前 30 个采样点，用于图表）
    topdown_ts = []
    for r in collected.get('topdown', [])[:60]:
        if r.get('Time(s)') and r.get('Level', '').startswith('die-S0'):
            topdown_ts.append({
                't': r.get('Time(s)', ''),
                'backend': parse_size_val(r.get('backend-bound(%)', '')),
                'frontend': parse_size_val(r.get('frontend-bound(%)', '')),
                'retire': parse_size_val(r.get('retired(%)', '')),
                'bad_spec': parse_size_val(r.get('bad-speculation(%)', '')),
            })
    result['topdown_ts'] = topdown_ts[:30]

    return result


def parse_topdown(archive, file_map) -> Optional[dict]:
    """解析 hpt-topdown.log：详细 TopDown 层次分析"""
    content = read_file(archive, file_map, 'hpt-topdown.log')
    if not content:
        return None

    result = {}
    for line in content.splitlines():
        # 匹配 "指标名  ...  数值%" 格式
        m = re.match(r'^(\s*)([\w\s/()\-\.]+?)\s{3,}([-\d.]+)%?\s*$', line)
        if not m:
            continue
        indent = len(m.group(1))
        key = m.group(2).strip()
        try:
            val = float(m.group(3))
        except ValueError:
            continue
        # 只收集顶层（缩进<=4）和一级子项（缩进<=8）
        if indent <= 4:
            result[key] = val
        elif indent <= 8 and key in ('Microcode', 'FP', 'Non-Microcode'):
            result[key] = val

    return result if result else None


def parse_cm(archive, file_map) -> Optional[dict]:
    """解析 hpt-cm.log：CORE-MEM 带宽，支持 KB/s MB/s GB/s，多快照取均值"""
    content = read_file(archive, file_map, 'hpt-cm.log')
    if not content:
        return None

    def to_kbps(val_str: str, unit: str) -> float:
        v = float(val_str)
        return v * {'K': 1, 'M': 1024, 'G': 1024 * 1024}.get(unit, 1)

    samples = []   # list of {node: total_kbps}
    current = {}

    for line in content.splitlines():
        if 'CORE-MEM:' in line:
            if current:
                samples.append(current)
            current = {}
            continue

        # 匹配 DIE0..DIE7 / SKT0 SKT1 / SYS 行，提取末尾 TOTAL_BW 列
        # 格式：   DIE0   41 K   40 K   41 K   2619   2681   2622   8455 KB/s
        #          DIE7   48 K   46 K   47 K   35 K   35 K   35 K   15 MB/s
        m = re.match(r'\s+(DIE\d+|SKT\d+|SYS)\s+.+?\s+([\d.]+)\s+([KMG])B/s\s*$', line)
        if m:
            node = m.group(1)
            kbps = to_kbps(m.group(2), m.group(3))
            current[node] = kbps

    if current:
        samples.append(current)

    if not samples:
        return None

    # 各节点采样期间最大值（KB/s）
    node_acc: dict = {}
    for s in samples:
        for node, kbps in s.items():
            node_acc.setdefault(node, []).append(kbps)
    max_bw_kbps = {n: max(v) for n, v in node_acc.items()}

    def fmt_bw(kbps):
        if kbps >= 1024 * 1024:
            return f'{kbps/1024/1024:.1f} GB/s'
        if kbps >= 1024:
            return f'{kbps/1024:.1f} MB/s'
        return f'{int(kbps)} KB/s'

    # 区分 DIE / SKT / SYS
    die_rows = {k: v for k, v in max_bw_kbps.items() if k.startswith('DIE')}
    skt_rows = {k: v for k, v in max_bw_kbps.items() if k.startswith('SKT')}
    sys_bw   = max_bw_kbps.get('SYS')

    # SYS 带宽时序（GB/s）
    sys_ts_kbps = [s.get('SYS') for s in samples if 'SYS' in s]
    sys_ts_gb   = [round(v / 1024 / 1024, 2) for v in sys_ts_kbps]

    # 每个 DIE 的带宽时序（GB/s，最多 120 个采样点）
    die_ts = {}
    for node, vals in node_acc.items():
        if node.startswith('DIE'):
            die_ts[node] = [round(v / 1024 / 1024, 3) for v in vals[:120]]

    # 各 DIE 最大带宽（GB/s），用于规则引擎指标
    die_max_bw_gb = {}
    for k, v in die_rows.items():
        m = re.match(r'DIE(\d+)', k)
        if m:
            die_max_bw_gb[f'die{m.group(1)}_max_bw_gb'] = round(v / 1024 / 1024, 2)

    return {
        'avg_bw': {k: round(v / 1024 / 1024, 2) for k, v in max_bw_kbps.items()},  # GB/s，兼容旧前端
        'avg_bw_kbps': max_bw_kbps,
        'die_rows': {k: {'kbps': v, 'fmt': fmt_bw(v)} for k, v in sorted(die_rows.items())},
        'skt_rows': {k: {'kbps': v, 'fmt': fmt_bw(v)} for k, v in sorted(skt_rows.items())},
        'sys_bw':   {'kbps': sys_bw, 'fmt': fmt_bw(sys_bw)} if sys_bw else None,
        'sys_ts':      sys_ts_gb[:60],
        'max_sys_bw':  round(max(sys_ts_gb), 2) if sys_ts_gb else None,
        'snapshots':   len(samples),
        'die_ts':      die_ts,
        **die_max_bw_gb,
    }


def parse_perf(archive, file_map) -> Optional[dict]:
    """解析所有 perf-top*.log 文件"""
    perf_files = sorted(k for k in file_map if re.match(r'perf-top.*\.log$', k))
    if not perf_files:
        return None

    result = {}
    for fname in perf_files:
        content = read_file(archive, file_map, fname)
        if not content:
            continue

        info = {'filename': fname, 'samples': None, 'event': None, 'event_count': None, 'entries': [], 'has_callgraph': False}
        entries = []
        for line in content.splitlines():
            # 元信息
            m = re.search(r'Samples:\s*([\d.]+\w*)\s+of event\s+\'([^\']+)\'', line)
            if m:
                info['samples'] = m.group(1)
                info['event'] = m.group(2)
            m = re.search(r'Event count \(approx\.\):\s*(\d+)', line)
            if m:
                info['event_count'] = int(m.group(1))
            if line.startswith('#'):
                continue
            # perf-top-g：children%  self%  command  object  [type] symbol
            m = re.match(r'^\s*([\d.]+)%\s+([\d.]+)%\s+(\S+)\s+(\S+)\s+\[.\]\s+(.+)$', line)
            if m:
                info['has_callgraph'] = True
                entries.append({
                    'children': float(m.group(1)),
                    'overhead': float(m.group(2)),
                    'command': m.group(3),
                    'object': m.group(4),
                    'symbol': m.group(5).strip(),
                })
                continue
            # perf-top：overhead%  command  object  [type] symbol
            m = re.match(r'^\s*([\d.]+)%\s+(\S+)\s+(\S+)\s+\[.\]\s+(.+)$', line)
            if m:
                entries.append({
                    'overhead': float(m.group(1)),
                    'command': m.group(2),
                    'object': m.group(3),
                    'symbol': m.group(4).strip(),
                })

        info['entries'] = entries[:40]
        result[fname] = info

    return result if result else None


def parse_hotspot(archive, file_map) -> Optional[dict]:
    """解析 hpt-hotspot.log：函数级 CPU 热点"""
    content = read_file(archive, file_map, 'hpt-hotspot.log')
    if not content:
        return None

    result = {}
    current_event = None
    entries = []

    for line in content.splitlines():
        m = re.match(r'Show samples.*?event:\s+(\S+)', line)
        if m:
            if current_event and entries:
                result[current_event] = entries[:20]
            current_event = m.group(1)
            entries = []
            continue

        # 数据行：15.61%  eclipse_ilmpi.e  eclipse_ilmpi.exe  [.] lxpen3_
        m = re.match(r'\s*([\d.]+)%\s+(\S+)\s+(\S+)\s+\[.\]\s+(\S+)', line)
        if m and current_event:
            entries.append({
                'overhead': float(m.group(1)),
                'command': m.group(2),
                'object': m.group(3),
                'symbol': m.group(4),
            })

    if current_event and entries:
        result[current_event] = entries[:20]

    return result if result else None


def parse_mem(archive, file_map) -> Optional[dict]:
    """解析 hpt-mem.log：远程/本地内存访问比（仅取首个无 DIE 列的区块）"""
    content = read_file(archive, file_map, 'hpt-mem.log')
    if not content:
        return None

    procs = {}
    in_simple_section = False   # 只处理 PID/CMD/RMA/LMA/Ratio 的区块
    for line in content.splitlines():
        # 区块标题行
        if 'RMA(K)' in line and 'LMA(K)' in line:
            in_simple_section = ('DIE' not in line)
            continue
        if not in_simple_section:
            continue
        # 数据行：PID  COMMAND  RMA  LMA  ratio
        m = re.match(r'\s*(\d{4,})\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$', line)
        if m:
            pid = m.group(1)
            ratio = float(m.group(5))
            if ratio <= 1.0 and pid not in procs:   # ratio 是小数，做合法性校验
                procs[pid] = {
                    'pid': pid,
                    'command': m.group(2),
                    'rma': float(m.group(3)),
                    'lma': float(m.group(4)),
                    'ratio': ratio,
                }
    if not procs:
        return None

    proc_list = sorted(procs.values(), key=lambda x: -x['ratio'])
    ratios = [p['ratio'] for p in proc_list]
    avg_ratio = avg(ratios)
    max_ratio = round(max(ratios), 4) if ratios else None
    return {'processes': proc_list[:20], 'avg_rma_ratio': avg_ratio, 'max_rma_ratio': max_ratio}


def parse_iostat(archive, file_map) -> Optional[dict]:
    """解析 iostat.log：CPU iowait 和磁盘设备性能时序"""
    content = read_file(archive, file_map, 'iostat.log')
    if not content:
        return None

    # 按时间戳行切分快照
    snapshot_pattern = re.compile(r'^\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', re.MULTILINE)
    split_positions = [m.start() for m in snapshot_pattern.finditer(content)]
    if not split_positions:
        return None

    snapshots = []
    for i, pos in enumerate(split_positions):
        end = split_positions[i + 1] if i + 1 < len(split_positions) else len(content)
        snapshots.append(content[pos:end])

    timestamps = []
    iowait_ts = []
    devices_data = {}  # name -> lists

    for snap in snapshots:
        lines = snap.splitlines()
        if not lines:
            continue

        # 提取时间（HH:MM:SS）
        m = re.match(r'\d{2}/\d{2}/\d{4}\s+(\d{2}:\d{2}:\d{2})', lines[0])
        if not m:
            continue
        ts = m.group(1)

        # 找 avg-cpu 行，提取 %iowait（第4列，0-indexed）
        iowait_val = 0.0
        for idx, line in enumerate(lines):
            if line.strip().startswith('avg-cpu:'):
                # 下一行是数值
                if idx + 1 < len(lines):
                    parts = lines[idx + 1].split()
                    if len(parts) >= 4:
                        try:
                            iowait_val = float(parts[3])
                        except ValueError:
                            pass
                break

        # 找 Device header 行，按列名解析设备数据
        dev_header_idx = None
        col_map = {}
        for idx, line in enumerate(lines):
            if re.match(r'\s*Device\b', line):
                dev_header_idx = idx
                headers = line.split()
                for ci, h in enumerate(headers):
                    col_map[h] = ci
                break

        snap_devices = {}
        if dev_header_idx is not None:
            for line in lines[dev_header_idx + 1:]:
                parts = line.split()
                if not parts or parts[0].startswith('avg-cpu') or re.match(r'\d{2}/\d{2}/\d{4}', parts[0]):
                    break
                if len(parts) < 2:
                    continue
                dev_name = parts[0]

                def gcol(name, default=0.0):
                    ci = col_map.get(name)
                    if ci is None or ci >= len(parts):
                        return default
                    try:
                        return float(parts[ci])
                    except ValueError:
                        return default

                snap_devices[dev_name] = {
                    'r_s':    gcol('r/s'),
                    'w_s':    gcol('w/s'),
                    'rMB_s':  gcol('rMB/s'),
                    'wMB_s':  gcol('wMB/s'),
                    'r_await': gcol('r_await'),
                    'w_await': gcol('w_await'),
                    'util':   gcol('%util'),
                }

        timestamps.append(ts)
        iowait_ts.append(iowait_val)

        # 合并设备数据
        for dev_name, vals in snap_devices.items():
            if dev_name not in devices_data:
                devices_data[dev_name] = {k: [] for k in vals}
            for k, v in vals.items():
                devices_data[dev_name][k].append(v)

        # 对本快照未出现的设备补 0
        for dev_name, arr in devices_data.items():
            for k in arr:
                if len(arr[k]) < len(timestamps):
                    arr[k].append(0.0)

    # 构建 device_summary，跳过全为 0 的设备
    device_summary = []
    for dev_name, arr in devices_data.items():
        max_r = max(arr['r_s']) if arr['r_s'] else 0
        max_w = max(arr['w_s']) if arr['w_s'] else 0
        if max_r + max_w == 0:
            continue
        n = len(arr['r_s']) or 1

        def davg(k):
            return sum(arr[k]) / n if arr[k] else 0.0

        device_summary.append({
            'name':        dev_name,
            'avg_r_s':     davg('r_s'),
            'avg_w_s':     davg('w_s'),
            'avg_rMB':     davg('rMB_s'),
            'avg_wMB':     davg('wMB_s'),
            'avg_r_await': davg('r_await'),
            'avg_w_await': davg('w_await'),
            'max_util':    max(arr['util']) if arr['util'] else 0.0,
        })

    device_summary.sort(key=lambda x: -x['max_util'])

    return {
        'timestamps':     timestamps,
        'iowait_ts':      iowait_ts,
        'devices':        devices_data,
        'device_summary': device_summary,
    }


def parse_iom(archive, file_map) -> Optional[dict]:
    """解析 hpt-iom.log：Non-CACHE-MEM IO 内存带宽"""
    content = read_file(archive, file_map, 'hpt-iom.log')
    if not content:
        return None

    sys_bw_ts = []
    # 找所有 SYS 行，提取 TOTAL_BW_MIN（倒数第2列）
    # 格式：SYS   ... TOTAL_BW_MIN  TOTAL_BW_MAX
    header_found = False
    bw_min_col = None
    for line in content.splitlines():
        stripped = line.strip()
        # 找 header 行
        if 'TOTAL_BW_MIN' in stripped and 'TOTAL_BW_MAX' in stripped:
            parts = stripped.split()
            if 'TOTAL_BW_MIN' in parts:
                bw_min_col = parts.index('TOTAL_BW_MIN')
            header_found = True
            continue
        if not header_found:
            continue
        # SYS 数据行
        if not stripped.startswith('SYS'):
            continue
        # 拆分时保留 "123 KB/s" 这种带空格的单位——先把 "数字 单位" 当成两个 token
        # 重新把行按 token 拆分
        parts = stripped.split()
        # parts[0] = 'SYS'，后续每个数值+单位占2个 token
        # 列索引（header 里）对应的数据位置：第 i 列（0-indexed, 包含 SYS 开头）
        # TOTAL_BW_MIN 在 header 中的位置（含 NON-CACHE-MEM-> 开头），
        # 但实际 SYS 行用 "SYS" 替代第一列，后续数据每列2个 token
        # 用简单策略：从后往前找最后2个数值+单位的倒数第4个token开始
        # 格式：SYS  v1 u1  v2 u2  ... vN-1 uN-1  vN uN
        # TOTAL_BW_MIN 是倒数第2对，TOTAL_BW_MAX 是最后一对
        # 即 parts[-4] = BW_MIN 数值，parts[-3] = 单位，parts[-2] = BW_MAX 数值，parts[-1] = 单位
        try:
            val_str = parts[-4]
            unit_str = parts[-3]
            val = float(val_str)
            unit_lower = unit_str.lower()
            if 'mb' in unit_lower:
                val *= 1024
            elif 'b' in unit_lower and 'kb' not in unit_lower:
                val /= 1024
            # else KB/s 保持不变
            sys_bw_ts.append(val)
        except (ValueError, IndexError):
            continue

    return {'sys_bw_ts': sys_bw_ts}


def parse_sar_net(archive, file_map) -> Optional[dict]:
    """解析 sar.log：网络接口性能时序"""
    content = read_file(archive, file_map, 'sar.log')
    if not content:
        return None

    devices_data = {}   # iface -> {rxkB:[], txkB:[], rxpck:[], txpck:[], ifutil:[]}
    timestamps = []
    cur_ts = None

    for line in content.splitlines():
        line = line.rstrip()
        if not line:
            continue
        # 跳过 Linux 信息行
        if line.startswith('Linux'):
            continue
        # header 行（含 IFACE 列名）
        if re.search(r'\bIFACE\b', line):
            m = re.match(r'^(\d+:\d+:\d+)\s+(AM|PM)', line)
            if m:
                cur_ts = m.group(1)
                if not timestamps or timestamps[-1] != cur_ts:
                    timestamps.append(cur_ts)
            continue
        # 数据行
        m = re.match(r'^(\d+:\d+:\d+)\s+(?:AM|PM)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+([\d.]+)', line)
        if not m:
            continue
        ts, iface = m.group(1), m.group(2)
        rxpck, txpck = float(m.group(3)), float(m.group(4))
        rxkB, txkB   = float(m.group(5)), float(m.group(6))
        ifutil        = float(m.group(7))

        if iface not in devices_data:
            devices_data[iface] = {'rxkB': [], 'txkB': [], 'rxpck': [], 'txpck': [], 'ifutil': []}
        d = devices_data[iface]
        d['rxkB'].append(rxkB);  d['txkB'].append(txkB)
        d['rxpck'].append(rxpck); d['txpck'].append(txpck)
        d['ifutil'].append(ifutil)

    if not timestamps:
        return None

    # 过滤活跃接口（max rxkB + txkB > 0）
    active = {k: v for k, v in devices_data.items()
              if max(v['rxkB'], default=0) + max(v['txkB'], default=0) > 0}

    summary = []
    for iface, d in active.items():
        n = len(d['rxkB']) or 1
        summary.append({
            'iface':       iface,
            'avg_rxkB':    sum(d['rxkB']) / n,
            'avg_txkB':    sum(d['txkB']) / n,
            'max_rxkB':    max(d['rxkB']),
            'max_txkB':    max(d['txkB']),
            'avg_rxpck':   sum(d['rxpck']) / n,
            'avg_txpck':   sum(d['txpck']) / n,
            'max_ifutil':  max(d['ifutil']),
        })
    summary.sort(key=lambda x: -(x['max_rxkB'] + x['max_txkB']))

    return {
        'timestamps': timestamps,
        'devices': active,
        'summary': summary,
    }


def parse_nethogs(archive, file_map) -> Optional[dict]:
    """解析 nethogs.log：进程级网络流量"""
    content = read_file(archive, file_map, 'nethogs.log')
    if not content:
        return None

    procs = {}   # name -> {sent_total, recv_total, count}
    in_refresh = False

    for line in content.splitlines():
        if line.strip() == 'Refreshing:':
            in_refresh = True
            continue
        if not in_refresh:
            continue
        parts = line.strip().split('\t')
        if len(parts) < 3:
            continue
        proc_raw = parts[0]
        # 跳过 Unknown connection 行和空行
        if proc_raw.startswith('Unknown') or proc_raw.startswith('unknown'):
            continue
        try:
            sent = float(parts[1])
            recv = float(parts[2])
        except ValueError:
            continue
        # 提取进程名（去掉 /pid/uid 后缀）
        name = re.sub(r'/\d+/\d+$', '', proc_raw).strip()
        if name not in procs:
            procs[name] = {'sent': 0.0, 'recv': 0.0, 'count': 0}
        procs[name]['sent'] += sent
        procs[name]['recv'] += recv
        procs[name]['count'] += 1

    if not procs:
        return None

    result = sorted([
        {'name': k, 'avg_sent': v['sent'] / v['count'],
         'avg_recv': v['recv'] / v['count'],
         'total': v['sent'] + v['recv']}
        for k, v in procs.items() if v['count'] > 0
    ], key=lambda x: -x['total'])

    return result[:20]


def parse_eths(archive, file_map) -> Optional[dict]:
    """解析 ethS-*.log：ethtool 接口统计（delta 值汇总）"""
    eths_files = [k for k in file_map if re.match(r'ethS-.+\.log$', k)]
    if not eths_files:
        return None

    result = []
    for fname in sorted(eths_files):
        content = read_file(archive, file_map, fname)
        if not content or 'Cannot access ethtool' in content:
            continue
        # 提取接口名
        m = re.search(r'Starting ethtool monitor for interface:\s*(\S+)', content)
        if not m:
            m = re.match(r'ethS-(.+)\.log$', fname)
            iface = m.group(1) if m else fname
        else:
            iface = m.group(1)

        # 汇总所有 delta（括号里是正数的行）
        totals = {}
        for line in content.splitlines():
            dm = re.match(r'\s+(\S+):\s+[\d,]+\s+\(\+(\d+)\)', line)
            if dm:
                key = dm.group(1)
                val = int(dm.group(2))
                totals[key] = totals.get(key, 0) + val

        if not totals:
            continue
        result.append({
            'iface':      iface,
            'rx_bytes':   totals.get('rx_bytes', 0),
            'tx_bytes':   totals.get('tx_bytes', 0),
            'rx_packets': totals.get('rx_packets', 0),
            'tx_packets': totals.get('tx_packets', 0),
            'rx_errors':  totals.get('rx_errors', 0),
            'tx_errors':  totals.get('tx_errors', 0),
            'rx_drops':   totals.get('rx_dropped', totals.get('rx_drop', 0)),
            'tx_drops':   totals.get('tx_dropped', totals.get('tx_drop', 0)),
        })

    return result if result else None


def parse_numactl(archive, file_map) -> Optional[dict]:
    """解析 numactl-H.log：各 NUMA 节点内存使用情况（取最后一个快照）"""
    content = read_file(archive, file_map, 'numactl-H.log')
    if not content:
        return None

    # 按 "available:" 行切分快照，取最后一个
    snapshots = re.split(r'(?=^available:)', content, flags=re.MULTILINE)
    snapshots = [s for s in snapshots if s.strip().startswith('available:')]
    if not snapshots:
        return None
    last = snapshots[-1]

    nodes = {}
    for line in last.splitlines():
        m = re.match(r'^node\s+(\d+)\s+size:\s*(\d+)\s*MB', line)
        if m:
            nid = int(m.group(1))
            nodes.setdefault(nid, {})['size_mb'] = int(m.group(2))
        m = re.match(r'^node\s+(\d+)\s+free:\s*(\d+)\s*MB', line)
        if m:
            nid = int(m.group(1))
            nodes.setdefault(nid, {})['free_mb'] = int(m.group(2))
        m = re.match(r'^node\s+(\d+)\s+cpus:\s*([\d ]+)', line)
        if m:
            nid = int(m.group(1))
            nodes.setdefault(nid, {})['cpus'] = m.group(2).strip()

    result = []
    for nid in sorted(nodes):
        n = nodes[nid]
        size = n.get('size_mb', 0)
        free = n.get('free_mb', 0)
        used = size - free
        result.append({
            'node': nid,
            'size_mb': size,
            'free_mb': free,
            'used_mb': used,
            'used_pct': round(used / size * 100, 1) if size else 0,
            'cpus': n.get('cpus', ''),
        })

    return result if result else None


def parse_sched(archive, file_map) -> Optional[dict]:
    """解析 hpt-sched.log：进程调度信息"""
    content = read_file(archive, file_map, 'hpt-sched.log')
    if not content:
        return None

    processes = []
    in_proc_section = False

    for line in content.splitlines():
        if 'Process Schedule Report:' in line:
            in_proc_section = True
            continue
        if 'Thread Schedule Report:' in line:
            in_proc_section = False
            continue
        if not in_proc_section:
            continue

        # 数据行：idx pid command runtime sleep wait iowait block avg-lat max-lat switch cpu-mig die-mig
        m = re.match(r'\s*(\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)', line)
        if m:
            processes.append({
                'idx': int(m.group(1)),
                'pid': int(m.group(2)),
                'command': m.group(3),
                'runtime': float(m.group(4)),
                'sleep': float(m.group(5)),
                'wait': float(m.group(6)),
                'iowait': float(m.group(7)),
                'switches': int(m.group(11)),
                'cpu_mig': int(m.group(12)),
                'die_mig': int(m.group(13)),
            })

    if not processes:
        return None

    total_die_mig = sum(p['die_mig'] for p in processes)
    total_cpu_mig = sum(p['cpu_mig'] for p in processes)
    return {
        'processes': processes[:30],
        'total_die_mig': total_die_mig,
        'total_cpu_mig': total_cpu_mig,
        'process_count': len(processes),
    }


def parse_mpstat(archive, file_map) -> Optional[dict]:
    """解析 mpstat.log：CPU 利用率时序 + 各核心均值"""
    content = read_file(archive, file_map, 'mpstat.log')
    if not content:
        return None

    ts = []
    cpu_acc: dict = {}   # {cpu_id: {field: [values]}}
    # 列顺序：%usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle
    CPU_RE = re.compile(
        r'\d+:\d+:\d+\s+[AP]M\s+(\d+)\s+'
        r'([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+[\d.]+\s+'   # usr nice sys iowait
        r'([\d.]+)\s+[\d.]+\s+[\d.]+\s+'                # irq soft steal
        r'([\d.]+)\s+[\d.]+\s+([\d.]+)'                 # guest gnice idle
    )
    ALL_RE = re.compile(
        r'(\d+:\d+:\d+\s+[AP]M)\s+all\s+([\d.]+)\s+[\d.]+\s+([\d.]+)\s+([\d.]+)\s+[\d.]+\s+([\d.]+)'
    )

    for line in content.splitlines():
        m = ALL_RE.match(line)
        if m:
            usr = float(m.group(2))
            sys_ = float(m.group(3))
            iowait = float(m.group(4))
            soft = float(m.group(5))
            ts.append({'time': m.group(1).strip(), 'usr': usr, 'sys': sys_,
                       'iowait': iowait, 'soft': soft,
                       'active': round(usr + sys_ + soft, 2)})
            continue
        m = CPU_RE.match(line)
        if m:
            cid = int(m.group(1))
            acc = cpu_acc.setdefault(cid, {'usr': [], 'nice': [], 'sys': [],
                                           'irq': [], 'guest': [], 'idle': []})
            acc['usr'].append(float(m.group(2)))
            acc['nice'].append(float(m.group(3)))
            acc['sys'].append(float(m.group(4)))
            acc['irq'].append(float(m.group(5)))
            acc['guest'].append(float(m.group(6)))
            acc['idle'].append(float(m.group(7)))

    if not ts:
        return None

    # 降采样到 60 点
    step = max(1, len(ts) // 60)
    sampled = ts[::step][:60]
    active_vals = [t['active'] for t in ts]
    avg_active = avg(active_vals)
    max_active = round(max(active_vals), 2) if active_vals else None
    avg_usr    = avg([t['usr']    for t in ts])
    avg_sys    = avg([t['sys']    for t in ts])

    # 各核心繁忙度时序（与 sampled 对齐，busy = 100 - idle）
    indices = list(range(0, len(ts), step))[:60]
    cpu_ts = {}
    cpu_avg = {}   # cpu_id -> 全程平均繁忙度
    for cid, fields in sorted(cpu_acc.items()):
        idle_vals = fields['idle']
        cpu_ts[cid] = [round(100 - idle_vals[i], 1)
                       for i in indices if i < len(idle_vals)]
        window = idle_vals[4:10]
        if window:
            cpu_avg[cid] = round(100 - sum(window) / len(window), 1)
    ts_labels = [t['time'] for t in sampled]

    return {'timeseries': sampled, 'avg_active_pct': avg_active,
            'max_active_pct': max_active,
            'avg_usr_pct': avg_usr, 'avg_sys_pct': avg_sys,
            'cpu_ts': cpu_ts, 'cpu_avg': cpu_avg, 'ts_labels': ts_labels}


def parse_version(archive, file_map) -> Optional[str]:
    content = read_file(archive, file_map, 'version.log')
    if not content:
        return None
    for line in content.splitlines():
        if line.strip():
            return line.strip()
    return None


def _parse_bw_val(s: str) -> Optional[float]:
    """解析带宽字符串，统一转换为 KB/s。如 '342 KB/s' -> 342.0，'10 MB/s' -> 10240.0"""
    s = s.strip()
    if s in ('N/A', 'n/a', '-', ''):
        return None
    m = re.match(r'^([\d.]+)\s*(KB|MB|GB)/s$', s)
    if not m:
        return None
    val = float(m.group(1))
    unit = m.group(2)
    return val * {'KB': 1, 'MB': 1024, 'GB': 1024 * 1024}[unit]


def parse_di(archive, file_map) -> Optional[dict]:
    """解析 hpt-di.log：Die-to-Die 互联带宽（多快照取均值）"""
    content = read_file(archive, file_map, 'hpt-di.log')
    if not content:
        return None

    # 每个快照结构：DIEIN (Socket0 4×4 矩阵 + Socket1 4×4 矩阵) + SocketIn
    # 用列表累积各快照的矩阵，最后取均值
    # socket_matrices[sock_id] = list of 4×4 float matrix (None=N/A)
    socket_acc = {}     # {sock_id: [list of row_values_flat]}
    socket_in_acc = {}  # {sock_id: [list of float KB/s]}

    cur_sock = None
    cur_matrix = []     # 当前正在读取的矩阵行
    expected_dies = None

    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # Socket 开始行
        m = re.match(r'^\s+Socket(\d+)\s*$', line)
        if m:
            cur_sock = int(m.group(1))
            cur_matrix = []
            i += 1
            continue

        # DIEIN->  列头行（确定 DIE 数量）
        m = re.match(r'\s+DIEIN->\s+(DIE\d+\s*)+', line)
        if m:
            die_cols = re.findall(r'DIE\d+', line)
            expected_dies = len(die_cols)
            i += 1
            continue

        # 分隔线
        if re.match(r'^-{10,}', line.strip()):
            i += 1
            continue

        # 矩阵数据行：DIE0   N/A   342 KB/s   608 KB/s   ...
        m = re.match(r'^\s+(DIE\d+)\s+(.*)', line)
        if m and cur_sock is not None and expected_dies:
            cells = re.findall(r'N/A|[\d.]+ (?:KB|MB|GB)/s', m.group(2))
            row = [_parse_bw_val(c) for c in cells]
            cur_matrix.append(row)
            # 矩阵收集完毕
            if len(cur_matrix) == expected_dies:
                if cur_sock not in socket_acc:
                    socket_acc[cur_sock] = []
                socket_acc[cur_sock].append(cur_matrix)
                cur_matrix = []
            i += 1
            continue

        # SocketIn 数据行：Socket0   6841 KB/s
        m = re.match(r'^\s+Socket(\d+)\s+([\d.]+ (?:KB|MB|GB)/s)', line)
        if m:
            sid = int(m.group(1))
            val = _parse_bw_val(m.group(2))
            if val is not None:
                if sid not in socket_in_acc:
                    socket_in_acc[sid] = []
                socket_in_acc[sid].append(val)
            i += 1
            continue

        i += 1

    if not socket_acc:
        return None

    # 对各快照取最大值
    def avg_matrices(mat_list):
        if not mat_list:
            return []
        n_rows = len(mat_list[0])
        n_cols = len(mat_list[0][0]) if n_rows else 0
        result = []
        for r in range(n_rows):
            row = []
            for c in range(n_cols):
                vals = [m[r][c] for m in mat_list if m[r][c] is not None]
                row.append(max(vals) if vals else None)
            result.append(row)
        return result

    def fmt_bw(kb):
        if kb is None:
            return 'N/A'
        if kb >= 1024:
            return f'{kb/1024:.1f} MB/s'
        return f'{int(kb)} KB/s'

    die_count = expected_dies or 4
    die_labels = [f'DIE{i}' for i in range(die_count)]

    sockets_result = {}
    for sid, mat_list in sorted(socket_acc.items()):
        avg_mat = avg_matrices(mat_list)
        sockets_result[f'Socket{sid}'] = {
            'matrix': avg_mat,
            'labels': die_labels,
            'formatted': [[fmt_bw(v) for v in row] for row in avg_mat],
            'snapshots': len(mat_list),
        }

    socket_in_result = {}
    for sid, vals in sorted(socket_in_acc.items()):
        socket_in_result[f'Socket{sid}'] = fmt_bw(max(vals))

    # 各 Socket Die-to-Die 最大带宽（MB/s），用于规则引擎
    di_max_metrics = {}
    all_di_vals = []
    for sid, mat_list in sorted(socket_acc.items()):
        avg_mat = avg_matrices(mat_list)
        flat = [v for row in avg_mat for v in row if v is not None]
        if flat:
            mx = max(flat)
            di_max_metrics[f'skt{sid}_max_di_bw_mbps'] = round(mx / 1024, 1)
            all_di_vals.append(mx)
    if all_di_vals:
        di_max_metrics['max_di_bw_mbps'] = round(max(all_di_vals) / 1024, 1)

    return {'sockets': sockets_result, 'socket_in': socket_in_result, **di_max_metrics}


def parse_kallsyms(archive, file_map) -> Optional[dict]:
    """解析 proc-kallsyms.log：提取 hygon / m4h 相关内核符号"""
    content = read_file(archive, file_map, 'proc-kallsyms.log')
    if not content:
        return None
    symbols = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if 'hygon' not in low and 'm4h' not in low:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        module = parts[3].strip('[]') if len(parts) > 3 else ''
        symbols.append({'type': parts[1], 'name': parts[2], 'module': module})
    if not symbols:
        return None
    return {'symbols': symbols}


def parse_base(archive, file_map) -> Optional[dict]:
    """解析 base.log：机器基本信息"""
    content = read_file(archive, file_map, 'base.log')
    if not content:
        return None

    # 剥除 ANSI 转义码
    clean = re.sub(r'\x1b\[[0-9;]*m|\x1b\[\d*[A-Za-z]', '', content)
    lines = clean.splitlines()

    result = {}

    # ── 按 ===节名=== 切分各段 ──────────────────────────────────────────────
    sections = {}
    cur_sec = None
    cur_lines = []
    for line in lines:
        m = re.match(r'^={3,}\s*(.+?)\s*={3,}\s*$', line.strip())
        if m:
            if cur_sec:
                sections[cur_sec] = cur_lines
            cur_sec = m.group(1).strip()
            cur_lines = []
        else:
            if cur_sec:
                cur_lines.append(line)
    if cur_sec:
        sections[cur_sec] = cur_lines

    # ── CPU 摘要 ────────────────────────────────────────────────────────────
    cpu_sec = sections.get('CPU', [])
    result['cpu_summary'] = ' | '.join(l.strip() for l in cpu_sec if l.strip())[:200]

    # ── 内存摘要 ────────────────────────────────────────────────────────────
    mem_sec = sections.get('Memory', [])
    result['mem_summary'] = ' | '.join(l.strip() for l in mem_sec[:3] if l.strip())[:300]

    # ── 网络 ────────────────────────────────────────────────────────────────
    net_sec = sections.get('Network', [])
    nics = []
    for line in net_sec:
        # 实体网卡行：iface node driver fw
        m = re.match(r'^(\S+)\s+(node\S*)\s+(\S+)?\s+driver:\s+(\S+)\s+\S+\s+FW:\s*(.*)', line)
        if m:
            nics.append({'iface': m.group(1), 'node': m.group(2),
                         'driver': m.group(4), 'fw': m.group(5).strip()})

    # 从 nic_info.log 读取各网卡标称最大带宽（ethtool Supported link modes 中最高速率）
    nic_info = read_file(archive, file_map, 'nic_info.log')
    if nic_info:
        nic_max_bw: dict[str, str] = {}
        cur_iface = None
        in_supported = False
        max_mbps = 0
        for line in nic_info.splitlines():
            # ethtool <iface> 段起始（排除 ethtool -x 选项行）
            m_eth = re.match(r'^ethtool\s+([a-zA-Z][^\s-]\S*)\s*$', line)
            if m_eth:
                if cur_iface and max_mbps > 0:
                    gbps = max_mbps / 1000
                    nic_max_bw[cur_iface] = f'{gbps:.0f}G' if gbps == int(gbps) else f'{gbps:.1f}G'
                cur_iface = m_eth.group(1)
                in_supported = False
                max_mbps = 0
                continue
            if cur_iface:
                if 'Supported link modes:' in line:
                    in_supported = True
                elif in_supported and re.match(r'^\s+\S+base\S+', line):
                    for speed_m in re.finditer(r'(\d+)base', line):
                        max_mbps = max(max_mbps, int(speed_m.group(1)))
                elif in_supported and line.strip() and not re.match(r'^\s+\d+base', line) \
                        and 'Supported' not in line:
                    in_supported = False
        # 保存最后一个接口
        if cur_iface and max_mbps > 0:
            gbps = max_mbps / 1000
            nic_max_bw[cur_iface] = f'{gbps:.0f}G' if gbps == int(gbps) else f'{gbps:.1f}G'
        # 将带宽信息注入到 nics 列表
        for nic in nics:
            nic['max_bw'] = nic_max_bw.get(nic['iface'], '')

    # 从 base.log 的 ip addr show 输出解析 iface → IP 映射
    SKIP_IP_IFACE = {'lo', 'virbr', 'docker', 'br-', 'veth', 'tunl', 'dummy'}
    iface_ip: dict[str, str] = {}
    for line in lines:
        m = re.match(r'^\s+inet\s+([\d.]+)/\d+.*\s(\S+)\s*$', line)
        if m:
            ip, iface = m.group(1), m.group(2)
            if not any(iface.startswith(p) for p in SKIP_IP_IFACE):
                iface_ip.setdefault(iface, ip)
    for nic in nics:
        ip = iface_ip.get(nic['iface'])
        if ip:
            nic['ip'] = ip

    result['network'] = nics

    # ── 磁盘摘要 ────────────────────────────────────────────────────────────
    disk_sec = sections.get('DISKS', [])
    result['disk_summary'] = [l.strip() for l in disk_sec if l.strip()]

    # ── 磁盘设备列表（含容量）────────────────────────────────────────────────
    disk_devices: list[dict] = []
    seen_devs: set = set()

    # 1. NVMe compact 格式: node N /dev/nvmeXnY SERIAL MODEL ... USED UNIT / TOTAL UNIT
    for line in lines:
        m = re.match(
            r'^node\s+\d+\s+(/dev/nvme\S+)\s+\S+\s+(.+?)\s+\d+\s+'
            r'([\d.]+)\s+([TGM]B)\s*/\s*([\d.]+)\s+([TGM]B)',
            line.strip()
        )
        if m:
            dev = m.group(1)
            if dev in seen_devs:
                continue
            seen_devs.add(dev)
            disk_devices.append({
                'name': dev.replace('/dev/', ''),
                'dev': dev,
                'model': m.group(2).strip(),
                'size': f'{m.group(5)} {m.group(6)}',
                'used': f'{m.group(3)} {m.group(4)}',
                'type': 'nvme',
            })

    # 2. DISKS section → model → size 映射（用于 SCSI 设备容量查找）
    disks_model_size: dict[str, str] = {}
    for line in disk_sec:
        m = re.match(r'^\d+\s*\*\s*(.+?)\s+([\d.]+\s*[TGM][B]?)\s*(?:FW:.*)?$', line.strip())
        if m:
            mod = m.group(1).strip()
            sz = m.group(2).strip()
            disks_model_size[mod] = sz
            last_word = mod.split()[-1]
            disks_model_size.setdefault(last_word, sz)

    # 3. lsscsi 格式: [H:C:T:L]  disk  VENDOR MODEL  REV  /dev/xxx
    for line in lines:
        m = re.match(r'^\[[\d:]+\]\s+disk\s+(.+?)\s+[\d.]+\s+(/dev/\S+)\s*$', line.strip())
        if m:
            model_raw = m.group(1).strip()
            dev = m.group(2)
            if dev in seen_devs:
                continue
            seen_devs.add(dev)
            size_str = ''
            for mod_key, sz in disks_model_size.items():
                if mod_key in model_raw:
                    size_str = sz
                    break
            disk_devices.append({
                'name': dev.replace('/dev/', ''),
                'dev': dev,
                'model': model_raw,
                'size': size_str,
                'used': '',
                'type': 'scsi',
            })

    result['disk_devices'] = disk_devices

    # ── CPU 频率直方图 ───────────────────────────────────────────────────────
    freq_sec = sections.get('CPU Freq', [])
    freq_hist = []
    for line in freq_sec:
        m = re.match(r'^(\d+)MHz:\s*(\+*)\s*(\d+)?', line.strip())
        if m:
            freq_hist.append({'freq_mhz': int(m.group(1)),
                              'count': int(m.group(3)) if m.group(3) else len(m.group(2))})
    result['cpu_freq'] = freq_hist

    # ── Baseinfo 详细字段 ────────────────────────────────────────────────────
    bi_sec = sections.get('Baseinfo', [])
    bi = {}
    kv_map = {
        'Name': 'name', 'BIOS': 'bios', 'BMC': 'bmc', 'Board': 'board',
        'Serial Number': 'serial', 'Clock Source': 'clock_source',
        'Kernel': 'kernel', 'glibc': 'glibc', 'compiler': 'compiler',
    }
    for line in bi_sec:
        for key, field in kv_map.items():
            m = re.match(rf'^{re.escape(key)}:\s*(.+)', line.strip())
            if m:
                bi[field] = m.group(1).strip()
                break
        # OS 行（含 IP）
        m = re.match(r'^OS:\s*(.+)', line.strip())
        if m:
            bi['os'] = m.group(1).split('(')[0].strip()

    # 从 dmidecode.log 读取 System Information 段，覆盖机器名称和序列号
    dmidecode = read_file(archive, file_map, 'dmidecode.log')
    if dmidecode:
        in_sys_info = False
        for line in dmidecode.splitlines():
            if line.strip() == 'System Information':
                in_sys_info = True
                continue
            if in_sys_info:
                m = re.match(r'^\s+Product Name:\s*(.+)', line)
                if m:
                    bi['name'] = m.group(1).strip()
                m = re.match(r'^\s+Serial Number:\s*(.+)', line)
                if m:
                    bi['serial'] = m.group(1).strip()
                # 遇到下一个非缩进行（新 Handle 段）则退出
                if line.strip() and not line.startswith('\t') and not line.startswith('  '):
                    in_sys_info = False

    result['baseinfo'] = bi

    # ── lscpu 关键字段 ────────────────────────────────────────────────────────
    lscpu = {}
    lscpu_fields = {
        'CPU(s)': 'cpus', 'Thread(s) per core': 'threads_per_core',
        'Core(s) per socket': 'cores_per_socket', 'Socket(s)': 'sockets',
        'NUMA node(s)': 'numa_nodes', 'Model name': 'model_name',
        'CPU MHz': 'cpu_mhz', 'L1d cache': 'l1d', 'L1i cache': 'l1i',
        'L2 cache': 'l2', 'L3 cache': 'l3', 'Vendor ID': 'vendor',
        'Virtualization': 'virt',
    }
    for line in lines:
        for key, field in lscpu_fields.items():
            m = re.match(rf'^{re.escape(key)}\s*:\s*(.+)', line)
            if m and field not in lscpu:
                lscpu[field] = m.group(1).strip()
    result['lscpu'] = lscpu

    # ── DIMM 槽位（dmidecode Memory Device）──────────────────────────────────
    dimm_slots: list[dict] = []
    dmem_blocks = re.split(r'(?m)^Memory Device\s*$', content)
    for block in dmem_blocks[1:]:
        blines = block.split('\n')
        first = blines[0].strip() if blines else ''
        if 'Mapped Address' in first:          # 跳过 Mapped Address 伴生块
            continue
        info: dict = {}
        for bl in blines:
            bl = bl.strip()
            if not bl:
                continue
            if bl.startswith('Handle') or bl.startswith('DMI type'):
                break                          # 遇到下一个 Handle 段结束解析
            if ':' not in bl:
                continue
            key, val = bl.split(':', 1)
            key = key.strip(); val = val.strip()
            if key == 'Locator' and 'locator' not in info:
                info['locator'] = val
            elif key == 'Bank Locator' and 'bank' not in info:
                info['bank'] = val
            elif key == 'Size' and 'size' not in info:
                info['size'] = val
                info['populated'] = val not in (
                    'No Module Installed', 'Unknown', '0 MB', '', 'Not Provided')
            elif key == 'Speed' and 'speed' not in info:
                info['speed'] = val
            elif key == 'Configured Memory Speed' and 'configured_speed' not in info:
                info['configured_speed'] = val
            elif key == 'Part Number' and 'part' not in info:
                info['part'] = val
            elif key == 'Manufacturer' and 'manufacturer' not in info:
                info['manufacturer'] = val
        if info.get('locator'):
            dimm_slots.append(info)
    result['dimm_slots'] = dimm_slots

    # ── NUMA 拓扑（numactl --hardware）────────────────────────────────────────
    numa_nodes = []
    for line in lines:
        m = re.match(r'^node\s+(\d+)\s+size:\s*(\d+)\s*MB', line)
        if m:
            numa_nodes.append({'id': int(m.group(1)), 'size_mb': int(m.group(2))})
        m2 = re.match(r'^node\s+(\d+)\s+free:\s*(\d+)\s*MB', line)
        if m2:
            nid = int(m2.group(1))
            for n in numa_nodes:
                if n['id'] == nid:
                    n['free_mb'] = int(m2.group(2))
        m3 = re.match(r'^node\s+(\d+)\s+cpus:\s*([\d ]+)', line)
        if m3:
            nid = int(m3.group(1))
            for n in numa_nodes:
                if n['id'] == nid:
                    n['cpus'] = m3.group(2).strip()

    # NUMA 距离矩阵
    dist_matrix = []
    in_dist = False
    for line in lines:
        if re.match(r'^node distances:', line):
            in_dist = True
            continue
        if in_dist:
            m = re.match(r'^\s*(\d+):\s+([\d\s]+)', line)
            if m:
                dist_matrix.append([int(x) for x in m.group(2).split()])
            elif dist_matrix:
                break
    result['numa'] = {'nodes': numa_nodes, 'distances': dist_matrix}

    return result


def get_flame_svgs(archive, file_map) -> dict:
    """读取火焰图 SVG 文件"""
    svgs = {}
    for filename in file_map:
        if filename.endswith('.svg') and 'flame' in filename:
            content = read_file(archive, file_map, filename)
            if content:
                # 去掉 XML 声明，只保留 SVG 标签
                content = re.sub(r'<\?xml[^>]+\?>', '', content).strip()
                svgs[filename] = content
    return svgs


def parse_turbostat(archive, file_map) -> Optional[dict]:
    """解析 turbostat.log：提取 Bzy_MHz 时序及每 CPU 分布"""
    content = read_file(archive, file_map, 'turbostat.log')
    if not content:
        return None

    lines = content.splitlines()
    snapshots_bzy = []   # 每个快照的 system Bzy_MHz（- 行）
    cpu_bzy_all   = []   # 所有快照所有 CPU 的 Bzy_MHz（用于分布）

    header_cols = None
    for line in lines:
        # header 行
        if line.startswith('Package\t') or line.startswith('Package '):
            cols = line.split()
            header_cols = cols
            continue
        if header_cols is None:
            continue
        parts = line.split()
        if len(parts) < len(header_cols):
            continue
        try:
            bzy_idx = header_cols.index('Bzy_MHz')
        except ValueError:
            continue
        if parts[0] == '-':
            # system summary 行
            try:
                snapshots_bzy.append(int(parts[bzy_idx]))
            except (ValueError, IndexError):
                pass
        else:
            # 单 CPU 行（Package 列为数字）
            try:
                int(parts[0])  # 确认是数字行
                cpu_bzy_all.append(int(parts[bzy_idx]))
            except (ValueError, IndexError):
                pass

    if not snapshots_bzy:
        return None

    avg_bzy = round(sum(snapshots_bzy) / len(snapshots_bzy))
    return {
        'snapshots_bzy': snapshots_bzy,
        'avg_bzy_mhz': avg_bzy,
        'max_bzy_mhz': max(snapshots_bzy),
        'cpu_bzy_all': cpu_bzy_all,
    }


def parse_top(archive, file_map) -> Optional[dict]:
    """解析 top.log：多快照系统摘要 + CPU/内存时序"""
    content = read_file(archive, file_map, 'top.log')
    if not content:
        return None

    snapshots = []
    cur = {}
    lines = content.splitlines()

    for line in lines:
        # 快照开头：top - HH:MM:SS ...
        m = re.match(r'^top - (\d+:\d+:\d+).+load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)', line)
        if m:
            if cur:
                snapshots.append(cur)
            cur = {
                'time': m.group(1),
                'load_1m': float(m.group(2)),
                'load_5m': float(m.group(3)),
                'load_15m': float(m.group(4)),
                'procs': [],
            }
            continue

        if not cur:
            continue

        # Tasks 行
        m = re.match(r'^Tasks:\s*(\d+)\s+total,\s*(\d+)\s+running,\s*(\d+)\s+sleeping,\s*(\d+)\s+stopped,\s*(\d+)\s+zombie', line)
        if m:
            cur['tasks_total']   = int(m.group(1))
            cur['tasks_running'] = int(m.group(2))
            cur['tasks_sleep']   = int(m.group(3))
            cur['tasks_zombie']  = int(m.group(5))
            continue

        # %Cpu 行
        m = re.match(r'^%Cpu\(s\):\s*([\d.]+)\s+us,\s*([\d.]+)\s+sy,\s*([\d.]+)\s+ni,\s*([\d.]+)\s+id,\s*([\d.]+)\s+wa', line)
        if m:
            cur['cpu_us'] = float(m.group(1))
            cur['cpu_sy'] = float(m.group(2))
            cur['cpu_ni'] = float(m.group(3))
            cur['cpu_id'] = float(m.group(4))
            cur['cpu_wa'] = float(m.group(5))
            continue

        # MiB Mem 行
        m = re.match(r'^MiB Mem\s*:\s*([\d.]+)\S*\s*total,\s*([\d.]+)\S*\s*free,\s*([\d.]+)\S*\s*used', line)
        if m:
            cur['mem_total_mib'] = float(m.group(1))
            cur['mem_free_mib']  = float(m.group(2))
            cur['mem_used_mib']  = float(m.group(3))
            continue

        # 进程行：PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
        m = re.match(r'^\s*(\d+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+([\d.]+)\s+([\d.]+)\s+(\S+)\s+(.*)', line)
        if m and 'cpu_us' in cur:
            cur['procs'].append({
                'pid':     int(m.group(1)),
                'user':    m.group(2),
                'res':     m.group(3),
                'cpu_pct': float(m.group(4)),
                'mem_pct': float(m.group(5)),
                'time':    m.group(6),
                'cmd':     m.group(7).strip(),
            })

    if cur:
        snapshots.append(cur)

    if not snapshots:
        return None

    # 时序（降采样到 60 点）
    step = max(1, len(snapshots) // 60)
    ts = [{'time': s['time'], 'us': s.get('cpu_us', 0), 'sy': s.get('cpu_sy', 0),
            'id': s.get('cpu_id', 0), 'wa': s.get('cpu_wa', 0),
            'load': s.get('load_1m', 0)}
          for s in snapshots[::step][:60]]

    first = snapshots[0]
    # 第一个快照的进程，按 CPU 降序，最多 300 条
    top_procs = sorted(first.get('procs', []), key=lambda p: p['cpu_pct'], reverse=True)[:300]

    # 为前 20 个进程补充各快照的 CPU/MEM 时序（降采样到 60 点）
    top_pids = {p['pid'] for p in top_procs[:20]}
    snap_step = max(1, len(snapshots) // 60)
    sampled = snapshots[::snap_step][:60]
    proc_ts: dict = {pid: [] for pid in top_pids}
    for snap in sampled:
        pid_map = {p['pid']: p for p in snap.get('procs', [])}
        for pid in top_pids:
            p = pid_map.get(pid)
            proc_ts[pid].append({
                't': snap['time'],
                'c': p['cpu_pct'] if p else 0,
                'm': p['mem_pct'] if p else 0,
                'r': p['res']     if p else '',
                'x': p['time']    if p else '',
            })
    for p in top_procs:
        if p['pid'] in proc_ts:
            p['snap_ts'] = proc_ts[p['pid']]

    return {
        'timeseries': ts,
        'summary': {
            'load_1m':       first.get('load_1m'),
            'load_5m':       first.get('load_5m'),
            'load_15m':      first.get('load_15m'),
            'tasks_total':   first.get('tasks_total'),
            'tasks_running': first.get('tasks_running'),
            'tasks_zombie':  first.get('tasks_zombie'),
            'cpu_us':        first.get('cpu_us'),
            'cpu_sy':        first.get('cpu_sy'),
            'cpu_id':        first.get('cpu_id'),
            'cpu_wa':        first.get('cpu_wa'),
            'mem_total_mib': first.get('mem_total_mib'),
            'mem_used_mib':  first.get('mem_used_mib'),
        },
        'top_procs': top_procs,
        'snapshot_count': len(snapshots),
    }


def _parse_ps_table(content: str) -> list:
    """解析 ps 格式表格：USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND"""
    rows = []
    for line in content.splitlines():
        m = re.match(r'^(\S+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.*)', line)
        if m:
            rows.append({
                'user':    m.group(1),
                'pid':     int(m.group(2)),
                'cpu_pct': float(m.group(3)),
                'mem_pct': float(m.group(4)),
                'rss_kb':  int(m.group(5)),
                'time':    m.group(6),
                'cmd':     m.group(7).strip(),
            })
    return rows


def parse_top_procs(archive, file_map) -> Optional[dict]:
    """解析 top-cpu-processes.log 和 top-mem-processes.log"""
    cpu_content = read_file(archive, file_map, 'top-cpu-processes.log')
    mem_content = read_file(archive, file_map, 'top-mem-processes.log')
    if not cpu_content and not mem_content:
        return None
    return {
        'by_cpu': _parse_ps_table(cpu_content)[:20] if cpu_content else [],
        'by_mem': _parse_ps_table(mem_content)[:20] if mem_content else [],
    }


# ── 推荐引擎 ────────────────────────────────────────────────────────────────

# ── 规则引擎 ────────────────────────────────────────────────────────────────

def load_default_rules() -> list:
    try:
        return json.loads(DEFAULT_RULES_FILE.read_text(encoding='utf-8'))
    except Exception:
        return []


def load_rules() -> list:
    """加载当前活跃规则（rules.json 优先，兼容数组和对象两种格式）"""
    if RULES_FILE.exists():
        try:
            data = json.loads(RULES_FILE.read_text(encoding='utf-8'))
            if isinstance(data, list):
                return data
            return data.get('rules', [])
        except Exception:
            pass
    return load_default_rules()


def save_rules_to_file(rules: list):
    """保存规则到 rules.json，保留已有密码"""
    pwd = ''
    if RULES_FILE.exists():
        try:
            data = json.loads(RULES_FILE.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                pwd = data.get('password', '')
        except Exception:
            pass
    content = {'password': pwd, 'rules': rules} if pwd else rules
    RULES_FILE.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding='utf-8')


def load_ruleset_raw(name: str) -> dict:
    """返回 {"password": "...", "rules": [...]}"""
    if name == '默认':
        if RULES_FILE.exists():
            try:
                data = json.loads(RULES_FILE.read_text(encoding='utf-8'))
                if isinstance(data, list):
                    return {"password": "", "rules": data}
                return data
            except Exception:
                pass
        return {"password": "", "rules": load_default_rules()}
    path = RULES_DIR / f"{name}.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(data, list):          # 旧格式兼容
                return {"password": "", "rules": data}
            return data
        except Exception:
            pass
    return {"password": "", "rules": []}


def list_rulesets() -> list:
    """返回 [{name, has_password}, ...]，默认在首位"""
    default_raw = load_ruleset_raw('默认')
    result = [{"name": "默认", "has_password": bool(default_raw.get("password"))}]
    for f in sorted(RULES_DIR.glob('*.json')):
        raw = load_ruleset_raw(f.stem)
        result.append({"name": f.stem, "has_password": bool(raw.get("password"))})
    return result


def load_ruleset(name: str) -> list:
    return load_ruleset_raw(name)["rules"]


def save_ruleset(name: str, rules: list):
    """保存规则，保留已有密码不变"""
    if name == '默认':
        save_rules_to_file(rules)
        return
    raw = load_ruleset_raw(name)
    (RULES_DIR / f"{name}.json").write_text(
        json.dumps({"password": raw.get("password", ""), "rules": rules},
                   ensure_ascii=False, indent=2), encoding='utf-8')


def create_ruleset(name: str, password: str):
    """创建空规则集（含密码）"""
    (RULES_DIR / f"{name}.json").write_text(
        json.dumps({"password": password, "rules": []},
                   ensure_ascii=False, indent=2), encoding='utf-8')


def delete_ruleset(name: str):
    if name == '默认':
        return
    path = RULES_DIR / f"{name}.json"
    if path.exists():
        path.unlink()


# 从 results 中取指标值
_METRIC_PATHS = {
    'avg_backend_bound':  ('uarch', 'avg_backend_bound'),
    'avg_frontend_bound': ('uarch', 'avg_frontend_bound'),
    'avg_retire':         ('uarch', 'avg_retire'),
    'avg_bad_spec':       ('uarch', 'avg_bad_spec'),
    'avg_l3_miss':        ('uarch', 'avg_l3_miss'),
    'max_l3_miss':        ('uarch', 'max_l3_miss'),
    'avg_l2_pf_miss':     ('uarch', 'avg_l2_pf_miss'),
    'max_l2_pf_miss':     ('uarch', 'max_l2_pf_miss'),
    'avg_l1d_miss':       ('uarch', 'avg_l1d_miss'),
    'max_l1d_miss':       ('uarch', 'max_l1d_miss'),
    'avg_l2d_miss':       ('uarch', 'avg_l2d_miss'),
    'max_l2d_miss':       ('uarch', 'max_l2d_miss'),
    'avg_ipc':            ('uarch', 'avg_ipc'),
    'max_ipc':            ('uarch', 'max_ipc'),
    'min_ipc':            ('uarch', 'min_ipc'),
    'avg_freq_ghz':       ('uarch', 'avg_freq_ghz'),
    'max_freq_ghz':       ('uarch', 'max_freq_ghz'),
    'min_freq_ghz':       ('uarch', 'min_freq_ghz'),
    'avg_bzy_mhz':        ('turbostat', 'avg_bzy_mhz'),
    'max_bzy_mhz':        ('turbostat', 'max_bzy_mhz'),
    'avg_sse_ratio':      ('uarch', 'avg_sse_ratio'),
    'avg_branch_miss':    ('uarch', 'avg_branch_miss'),
    'avg_rma_ratio':      ('mem',   'avg_rma_ratio'),
    'max_rma_ratio':      ('mem',   'max_rma_ratio'),
    'total_die_mig':      ('sched', 'total_die_mig'),
    'total_cpu_mig':      ('sched', 'total_cpu_mig'),
    'avg_active_pct':     ('mpstat','avg_active_pct'),
    'max_active_pct':     ('mpstat','max_active_pct'),
    'avg_usr_pct':        ('mpstat','avg_usr_pct'),
    'avg_sys_pct':        ('mpstat','avg_sys_pct'),
    'max_sys_bw':         ('cm',    'max_sys_bw'),
    'die0_max_bw':        ('cm',    'die0_max_bw_gb'),
    'die1_max_bw':        ('cm',    'die1_max_bw_gb'),
    'die2_max_bw':        ('cm',    'die2_max_bw_gb'),
    'die3_max_bw':        ('cm',    'die3_max_bw_gb'),
    'die4_max_bw':        ('cm',    'die4_max_bw_gb'),
    'die5_max_bw':        ('cm',    'die5_max_bw_gb'),
    'die6_max_bw':        ('cm',    'die6_max_bw_gb'),
    'die7_max_bw':        ('cm',    'die7_max_bw_gb'),
    'skt0_max_di_bw':     ('di',    'skt0_max_di_bw_mbps'),
    'skt1_max_di_bw':     ('di',    'skt1_max_di_bw_mbps'),
    'max_di_bw':          ('di',    'max_di_bw_mbps'),
}


def _get_metric(results: dict, metric: str):
    path = _METRIC_PATHS.get(metric)
    if not path:
        return None
    return (results.get(path[0]) or {}).get(path[1])


def _eval_condition(cond: dict, results: dict):
    """返回 (matched: bool, display_value: str)"""
    ctype = cond.get('type', 'always')
    if ctype == 'always':
        return True, ''

    if ctype in ('file_present', 'file_absent'):
        fname = cond.get('filename', '')
        present = fname in (results.get('file_list') or [])
        matched = present if ctype == 'file_present' else not present
        return matched, fname

    if ctype == 'metric':
        val = _get_metric(results, cond.get('metric', ''))
        if val is None:
            return False, ''
        op = cond.get('operator', '>')
        threshold = float(cond.get('value', 0))
        hit = {'>': val > threshold, '<': val < threshold,
               '>=': val >= threshold, '<=': val <= threshold,
               '==': abs(val - threshold) < 1e-9}.get(op, False)
        # 格式化显示值
        fmt_hint = cond.get('value_format', '')
        if fmt_hint == 'pct':
            disp = f'{val:.1%}'
        elif val == int(val):
            disp = str(int(val))
        elif abs(val) < 10:
            disp = f'{val:.2f}'
        else:
            disp = f'{val:.1f}'
        return hit, disp

    return False, ''


def parse_lspci(archive, file_map) -> Optional[dict]:
    """解析 lspci.log：按 NUMA 节点分类关键 PCIe 设备"""
    content = read_file(archive, file_map, 'lspci.log')
    if not content:
        return None

    CLASS_CAT = {
        '0200': '网络', '0207': '网络',
        '0108': 'NVMe',
        '0104': 'RAID',
        '0106': '存储', '0107': '存储', '0101': '存储',
        '0300': 'VGA', '0302': '显卡', '0380': '显卡',
        '0c03': 'USB',
        '0c04': 'FC',
    }
    SKIP = {'0600', '0604', '0605', '0806', '0c05', '0601',
            '1300', '1080', '0801', '0802', '0880', '0500'}

    devices = []
    current = None
    all_numa_nodes: set[int] = set()   # 记录所有出现过的 NUMA 节点（含无关设备）
    pending_numa = None                 # 跳过设备时也需追踪 NUMA node

    for line in content.splitlines():
        # 设备首行：BB:DD.F class [XXXX]: description
        m = re.match(r'^([0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])\s+(.+?)\s+\[([0-9a-f]{4})\]:\s*(.+)', line)
        if m:
            if current:
                devices.append(current)
            bdf, cls_name, cls_code, desc = m.group(1), m.group(2), m.group(3), m.group(4)
            cat = CLASS_CAT.get(cls_code)
            if cls_code in SKIP or cat is None:
                current = None
                pending_numa = True   # 仍要捕获后续 NUMA node 行
                continue
            pending_numa = None
            # 去除末尾 [vendor:device] 及之后的内容（保留方括号内的产品名如 [ConnectX-6 Lx]）
            name = re.sub(r'\s*\[[0-9a-f]{4}:[0-9a-f]{4}\].*$', '', desc, flags=re.IGNORECASE).strip()
            current = {'bdf': bdf, 'class_name': cls_name, 'cls_code': cls_code,
                       'name': name, 'numa': -1, 'category': cat,
                       'lnk_cap': None, 'lnk_sta': None, 'iommu_group': None}
        elif current or pending_numa:
            if 'NUMA node:' in line:
                m2 = re.search(r'NUMA node:\s*(-?\d+)', line)
                if m2:
                    n = int(m2.group(1))
                    if n >= 0:
                        all_numa_nodes.add(n)
                    if current:
                        current['numa'] = n
                    pending_numa = None
            elif 'IOMMU group:' in line:
                m2 = re.search(r'IOMMU group:\s*(\d+)', line)
                if m2:
                    current['iommu_group'] = int(m2.group(1))
            elif re.search(r'LnkCap:', line) and 'LnkCap2' not in line:
                sp = re.search(r'Speed\s+([\w./]+)', line)
                wd = re.search(r'Width\s+(x\d+)', line)
                if sp or wd:
                    current['lnk_cap'] = {'speed': sp.group(1) if sp else '?',
                                          'width': wd.group(1) if wd else '?'}
            elif re.search(r'LnkSta:', line) and 'LnkSta2' not in line:
                sp = re.search(r'Speed\s+([\w./]+)', line)
                wd = re.search(r'Width\s+(x\d+)', line)
                if sp or wd:
                    current['lnk_sta'] = {'speed': sp.group(1) if sp else '?',
                                          'width': wd.group(1) if wd else '?'}

    if current:
        devices.append(current)

    # ── 构建 BDF → 系统标识符 映射 ──────────────────────────────────────────────
    bdf_to_id: dict[str, str] = {}

    # 网卡：从 nic_info.log 的 ethtool -i 段解析 bus-info → iface
    nic_info = read_file(archive, file_map, 'nic_info.log')
    if nic_info:
        cur_iface_ei = None
        for line in nic_info.splitlines():
            m_ei = re.match(r'^ethtool\s+-i\s+(\S+)', line)
            if m_ei:
                cur_iface_ei = m_ei.group(1)
            elif cur_iface_ei:
                m_bus = re.match(r'^bus-info:\s+(?:[\da-f]{4}:)?([0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])', line)
                if m_bus:
                    bdf_to_id[m_bus.group(1)] = cur_iface_ei
                    cur_iface_ei = None

    # NVMe：按 BDF 排序后顺序赋 nvme0、nvme1…（与 Linux 枚举顺序一致）
    nvme_devs = sorted([d for d in devices if d['category'] == 'NVMe'], key=lambda d: d['bdf'])
    for idx, dev in enumerate(nvme_devs):
        bdf_to_id[dev['bdf']] = f'nvme{idx}'

    # 按 NUMA 分组（预填所有已知节点，保证空节点也出现）
    SKIP_VENDORS = ('chengdu haiguang', 'haiguang ic design')
    by_numa: dict[str, dict[str, list]] = {str(n): {} for n in sorted(all_numa_nodes)}
    for dev in devices:
        # 过滤芯片组集成外设（Haiguang 芯片组 USB/存储等）
        if any(v in dev['name'].lower() for v in SKIP_VENDORS):
            continue
        node = str(max(0, dev['numa']))
        all_numa_nodes.add(max(0, dev['numa']))
        by_numa.setdefault(node, {}).setdefault(dev['category'], []).append({
            'bdf': dev['bdf'], 'name': dev['name'], 'class_name': dev['class_name'],
            'lnk_cap': dev['lnk_cap'], 'lnk_sta': dev['lnk_sta'],
            'iommu_group': dev['iommu_group'],
            'dev_id': bdf_to_id.get(dev['bdf']),   # 系统标识符（iface / nvmeN）
        })

    return {
        'by_numa': by_numa,
        'numa_nodes': sorted(by_numa.keys(), key=int),
    }


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s)


def parse_cpu_mem_procs(archive, file_map) -> Optional[dict]:
    """解析 cpu_mem_numa.log：所有完整快照的 Top5 CPU / Top5 MEM 进程"""
    content = read_file(archive, file_map, 'cpu_mem_numa.log')
    if not content:
        return None

    lines = content.splitlines()

    _DAY_RE   = re.compile(r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+')
    _PID_RE   = re.compile(r'^PID:\s+(\d+)')
    _CMD_RE   = re.compile(r'^Command:\s+(.+)')
    _THR_RE   = re.compile(r'Total\s+(\d+)\s+threads')
    _NODE_RE  = re.compile(r'^node\s+(\d+):\s+([\d.]+)%')
    _TOTAL_RE = re.compile(r'^Total\s+([\d\s]+)$')
    _MEM_RE   = re.compile(r'Per-node process memory usage')

    snap_starts = [i for i, l in enumerate(lines) if _DAY_RE.match(l)]
    if not snap_starts:
        snap_starts = [0]

    def _snap_lines(idx):
        nxt = next((snap_starts[k + 1] for k, s in enumerate(snap_starts)
                    if s == idx and k + 1 < len(snap_starts)), len(lines))
        return lines[idx:nxt]

    def _find_section(section_lines, keyword):
        start = None
        for i, l in enumerate(section_lines):
            if keyword in l and '===' in l:
                start = i + 1; break
        if start is None:
            return []
        end = len(section_lines)
        for i in range(start, end):
            if '===' in section_lines[i] and keyword not in section_lines[i]:
                end = i; break
        return section_lines[start:end]

    def _proc_metrics(raw_text: str):
        """从 raw 文本提取 per-NUMA-node CPU%、内存 MB、线程数、所在核心"""
        node_cpu: dict[int, float] = {}
        node_mem: dict[int, float] = {}
        mem_nodes: list[int] = []
        total_cpu: float = 0.0
        total_mem_mb: float = 0.0
        threads: Optional[int] = None
        cpu_cores: list[int] = []
        for line in raw_text.splitlines():
            clean = line.strip()
            # 线程数：Total X threads Running on CPU:
            mt = re.match(r'^Total\s+(\d+)\s+threads', clean)
            if mt:
                threads = int(mt.group(1))
                continue
            # 每节点 CPU% 及所在核心：node N: ++X%: CORE(pct)
            m = re.match(r'^node\s+(\d+):\s+\+*([0-9.]+)%', clean)
            if m:
                pct = float(m.group(2))
                node_cpu[int(m.group(1))] = pct
                if pct > 0:
                    mc = re.search(r':\s+(\d+)\(', clean)
                    if mc:
                        cpu_cores.append(int(mc.group(1)))
            elif 'Node 0' in line and 'Total' in line:
                mem_nodes = [int(x) for x in re.findall(r'Node\s+(\d+)', line)]
            elif clean.startswith('Total') and mem_nodes:
                nums = re.findall(r'\d+', clean[5:])
                for i, nid in enumerate(mem_nodes):
                    if i < len(nums):
                        node_mem[nid] = float(nums[i])
                if nums:
                    total_mem_mb = float(nums[-1])
        total_cpu = sum(node_cpu.values())
        return node_cpu, node_mem, total_cpu, total_mem_mb, threads, cpu_cores

    def _short_cmd(cmd: str) -> str:
        """提取可执行名（取第一个词再去路径，限 18 字符）"""
        name = cmd.split()[0].split('/')[-1] if cmd else ''
        return name[:18]

    def _parse_procs(section_lines):
        """提取 Processes details 各进程原文块，并解析 per-node CPU/MEM 指标"""
        detail_start = None
        for i, l in enumerate(section_lines):
            if 'Processes details:' in _strip_ansi(l):
                detail_start = i + 1; break
        if detail_start is None:
            return []

        procs = []
        cur_lines: list = []
        cur_pid = None

        def _flush():
            if cur_pid is None or not cur_lines:
                return
            trimmed = []
            for ln in cur_lines:
                if 'Libraries and mappings' in ln:
                    break
                trimmed.append(ln)
            while trimmed and not trimmed[-1].strip():
                trimmed.pop()
            raw = '\n'.join(trimmed).strip()
            cmd = ''
            for ln in trimmed:
                m = _CMD_RE.match(ln.strip())
                if m: cmd = m.group(1).strip(); break
            node_cpu, node_mem, total_cpu, total_mem_mb, threads, cpu_cores = _proc_metrics(raw)
            procs.append({'pid': cur_pid, 'command': cmd, 'raw': raw,
                          'node_cpu': node_cpu, 'node_mem': node_mem,
                          'total_cpu': total_cpu, 'total_mem_mb': total_mem_mb,
                          'threads': threads, 'cpu_cores': cpu_cores})

        for line in section_lines[detail_start:]:
            clean = _strip_ansi(line).rstrip()
            pm = _PID_RE.match(clean.strip())
            if pm and not clean.strip().startswith('Per-node'):
                _flush()
                cur_pid = int(pm.group(1))
                cur_lines = [clean]
            elif cur_pid is not None:
                cur_lines.append(clean)
        _flush()
        return procs

    snapshots = []
    for idx in snap_starts:
        sl = _snap_lines(idx)
        has_cpu = any('sort by CPU usage' in l for l in sl)
        has_mem = any('sort by MEM usage' in l for l in sl)
        if not (has_cpu or has_mem):
            continue
        ts = _strip_ansi(sl[0]).strip()
        cpu_procs = _parse_procs(_find_section(sl, 'sort by CPU usage')) if has_cpu else []
        mem_procs = _parse_procs(_find_section(sl, 'sort by MEM usage')) if has_mem else []
        if cpu_procs or mem_procs:
            snapshots.append({'timestamp': ts, 'cpu_procs': cpu_procs, 'mem_procs': mem_procs})

    if not snapshots:
        return None

    # 取最后一个快照构建 by_node：每个 NUMA 节点的 Top CPU / Top MEM 进程
    last = snapshots[-1]
    by_node: dict[str, dict] = {}
    for p in last.get('cpu_procs', []):
        for nid, pct in p.get('node_cpu', {}).items():
            if pct <= 0:
                continue
            entry = by_node.setdefault(str(nid), {})
            if pct > entry.get('_top_cpu_pct', 0):
                entry['top_cpu'] = {'cmd': _short_cmd(p['command']), 'pct': round(pct, 1)}
                entry['_top_cpu_pct'] = pct
    for p in last.get('mem_procs', []):
        for nid, mb in p.get('node_mem', {}).items():
            if mb <= 0:
                continue
            entry = by_node.setdefault(str(nid), {})
            if mb > entry.get('_top_mem_mb', 0):
                entry['top_mem'] = {'cmd': _short_cmd(p['command']), 'mb': int(mb)}
                entry['_top_mem_mb'] = mb
    for entry in by_node.values():
        entry.pop('_top_cpu_pct', None)
        entry.pop('_top_mem_mb', None)

    # 系统级 Top 5：按 total_cpu / total_mem_mb 排序（来自最后快照）
    cpu_sorted = sorted(last.get('cpu_procs', []),
                        key=lambda p: p.get('total_cpu', 0), reverse=True)
    mem_sorted = sorted(last.get('mem_procs', []),
                        key=lambda p: p.get('total_mem_mb', 0), reverse=True)
    top_cpu_procs = [{'cmd': _short_cmd(p['command']), 'pct': round(p['total_cpu'], 1)}
                     for p in cpu_sorted[:5] if p.get('total_cpu', 0) > 0]
    top_mem_procs = [{'cmd': _short_cmd(p['command']), 'mb': int(p['total_mem_mb'])}
                     for p in mem_sorted[:5] if p.get('total_mem_mb', 0) > 0]

    # by_pid：PID → 线程数 + 所在核心（供进程表关联展示）
    by_pid: dict[int, dict] = {}
    for snap in snapshots:
        for p in snap.get('cpu_procs', []) + snap.get('mem_procs', []):
            pid = p['pid']
            if pid not in by_pid:
                by_pid[pid] = {
                    'threads':   p.get('threads'),
                    'cpu_cores': p.get('cpu_cores', []),
                }

    return {'snapshots': snapshots, 'by_node': by_node,
            'top_cpu_procs': top_cpu_procs, 'top_mem_procs': top_mem_procs,
            'by_pid': by_pid}


def parse_ipmi(archive, file_map) -> Optional[dict]:
    """解析 ipmi_sensor.csv：硬件传感器时序（电压/温度/风扇/功耗）"""
    content = read_file(archive, file_map, 'ipmi_sensor.csv')
    if not content:
        return None

    timestamps = []
    sensor_data: dict = {}  # name -> {unit, values}

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 4:
            continue
        timestamps.append(parts[0])
        i = 1
        while i + 2 < len(parts):
            name, val_str, unit = parts[i], parts[i + 1], parts[i + 2]
            try:
                val = float(val_str)
            except ValueError:
                i += 3
                continue
            if name not in sensor_data:
                sensor_data[name] = {'unit': unit, 'values': []}
            sensor_data[name]['values'].append(val)
            i += 3

    if not timestamps:
        return None

    sensors = {}
    for name, data in sensor_data.items():
        vals = data['values']
        if not vals:
            continue
        sensors[name] = {
            'unit': data['unit'],
            'last': round(vals[-1], 3),
            'min':  round(min(vals), 3),
            'max':  round(max(vals), 3),
            'avg':  round(sum(vals) / len(vals), 3),
        }

    return {'timestamps': timestamps, 'sensors': sensors}


def _parse_size_mb(s: str) -> float:
    """将容器大小字符串（如 963.4MiB、1.472TiB、80.3kB、0B）转换为 MB"""
    m = re.match(r'([\d.]+)\s*([KMGTPE]i?B?|B)', s.strip(), re.I)
    if not m:
        return 0.0
    val, unit = float(m.group(1)), m.group(2).upper().replace('IB', 'B').replace('KIB', 'KB')
    mul = {'B': 1/1048576, 'KB': 1/1024, 'MB': 1, 'GB': 1024, 'TB': 1048576}
    return val * mul.get(unit.replace('I', ''), 1.0)


def parse_container(archive, file_map) -> Optional[dict]:
    """解析容器相关日志：资源占用、限制配置、进程亲和、调优基线"""
    result: dict = {}

    # ── 1. 容器 stats（docker_stats.log / containerd_stats.log / containerd_statsp.log）
    _STATS_LINE = re.compile(
        r'(\d[\d:/ -]{15,})\s+'       # timestamp prefix
        r'([0-9a-f]{12})\s+'           # container id
        r'(\S+)\s+'                    # name
        r'([\d.]+)%\s+'                # cpu%
        r'([\d.]+\S*)\s*/\s*([\d.]+\S*)\s+'  # mem usage / limit
        r'([\d.]+)%\s+'                # mem%
        r'([\d.]+\S*)\s*/\s*([\d.]+\S*)\s+'  # net rx / tx
        r'([\d.]+\S*)\s*/\s*([\d.]+\S*)\s+'  # block rx / tx
        r'(\d+)'                       # pids
    )
    # Also support pod-level stats (containerd_statsp.log): no container_id field
    _STATSP_LINE = re.compile(
        r'(\d[\d:/ -]{15,})\s+'
        r'(\S+)\s+'                    # pod name (no hex ID)
        r'(\S+/\S+)\s+'                # namespace/name
        r'([\d.]+)%\s+'
        r'([\d.]+\S*)'
    )

    container_acc: dict = {}  # name -> {cpu_vals, mem_usage_vals, mem_limit_mb, net_rx_vals, ...}

    for fname in ['docker_stats.log', 'containerd_stats.log', 'containerd_statsp.log']:
        content = read_file(archive, file_map, fname)
        if not content:
            continue
        result['stats_source'] = result.get('stats_source', fname)
        for line in content.splitlines():
            m = _STATS_LINE.match(line.strip())
            if not m:
                continue
            name = m.group(3)
            cpu = float(m.group(4))
            mem_mb = _parse_size_mb(m.group(5))
            mem_lim_mb = _parse_size_mb(m.group(6))
            net_rx = _parse_size_mb(m.group(8))
            net_tx = _parse_size_mb(m.group(9))
            blk_rx = _parse_size_mb(m.group(10))
            blk_tx = _parse_size_mb(m.group(11))
            pids = int(m.group(12))
            if name not in container_acc:
                container_acc[name] = {
                    'id': m.group(2),
                    'cpu_vals': [], 'mem_mb_vals': [],
                    'mem_lim_mb': mem_lim_mb,
                    'net_rx': net_rx, 'net_tx': net_tx,
                    'blk_rx': blk_rx, 'blk_tx': blk_tx,
                    'pids': pids,
                }
            acc = container_acc[name]
            acc['cpu_vals'].append(cpu)
            acc['mem_mb_vals'].append(mem_mb)
            # Update with latest net/block totals
            if net_rx > acc['net_rx']:
                acc['net_rx'] = net_rx
            if blk_rx > acc['blk_rx']:
                acc['blk_rx'] = blk_rx
            acc['mem_lim_mb'] = max(acc['mem_lim_mb'], mem_lim_mb)

    if container_acc:
        containers = []
        for name, acc in container_acc.items():
            cpu_vals = acc['cpu_vals']
            mem_vals = acc['mem_mb_vals']
            containers.append({
                'id': acc['id'],
                'name': name,
                'avg_cpu_pct': round(sum(cpu_vals) / len(cpu_vals), 2),
                'max_cpu_pct': round(max(cpu_vals), 2),
                'avg_mem_mb': round(sum(mem_vals) / len(mem_vals), 1),
                'last_mem_mb': round(mem_vals[-1], 1) if mem_vals else 0,
                'mem_lim_mb': round(acc['mem_lim_mb'], 1),
                'net_rx_mb': round(acc['net_rx'], 1),
                'net_tx_mb': round(acc['net_tx'], 1),
                'blk_rx_mb': round(acc['blk_rx'], 1),
                'pids': acc['pids'],
                'samples': len(cpu_vals),
            })
        containers.sort(key=lambda c: c['avg_cpu_pct'], reverse=True)
        result['containers'] = containers

    # ── 2. docker_ps.log — 容器列表与状态
    ps_content = read_file(archive, file_map, 'docker_ps.log')
    if ps_content:
        ps_list = []
        header_seen = False
        for line in ps_content.splitlines():
            if 'CONTAINER ID' in line:
                header_seen = True
                continue
            if not header_seen or not line.strip():
                continue
            # Format: id  image  command  created  status  ports  names
            # Status column contains "Up N weeks" or "Exited (N)"
            m = re.match(r'([0-9a-f]{12})\s+(\S+)\s+".+?"\s+(.+?)\s+(Up .+?|Exited.+?)\s{2,}(.*?)\s{2,}(\S+)\s*$', line)
            if m:
                ps_list.append({
                    'id': m.group(1),
                    'image': m.group(2).split('/')[-1],  # last part of image path
                    'status': m.group(4).strip(),
                    'ports': m.group(5).strip(),
                    'name': m.group(6).strip(),
                })
        result['ps_list'] = ps_list

    # ── 3. docker_inspect_all.log — 资源 limit
    inspect = read_file(archive, file_map, 'docker_inspect_all.log')
    if inspect:
        limits: dict = {}
        cur_name = None
        for line in inspect.splitlines():
            # Container name (comes before HostConfig)
            m = re.search(r'"Name":\s*"/([^"]+)"', line)
            if m:
                cur_name = m.group(1)
            if cur_name:
                for field in ['Memory', 'NanoCpus', 'CpuQuota', 'CpuPeriod', 'CpusetCpus', 'CpuShares']:
                    m2 = re.search(rf'"{field}":\s*([0-9"]+)', line)
                    if m2:
                        if cur_name not in limits:
                            limits[cur_name] = {}
                        raw = m2.group(1).strip('"')
                        try:
                            limits[cur_name][field] = int(raw)
                        except ValueError:
                            limits[cur_name][field] = raw
        result['inspect_limits'] = limits

    # ── 4. tuned cpu-partitioning profile（用路径搜索，避免同名冲突）
    tuned = read_file_by_path(archive, 'cpu-partitioning/tuned.conf')
    tuned_cp: dict = {}
    if tuned:
        # ps_blacklist
        m = re.search(r'ps_blacklist\s*=\s*(.+)', tuned)
        if m:
            tuned_cp['ps_blacklist'] = m.group(1).strip()
        # bootloader cmdline additions
        m = re.search(r'cmdline_cpu_part\s*=\s*(.+)', tuned)
        if m:
            tuned_cp['cmdline_additions'] = m.group(1).strip()
        m = re.search(r'banned_cpus\s*=\s*(.+)', tuned)
        if m:
            tuned_cp['banned_cpus'] = m.group(1).strip()
        m = re.search(r'include\s*=\s*(.+)', tuned)
        if m:
            tuned_cp['include'] = m.group(1).strip()
    result['tuned_cp'] = tuned_cp if tuned_cp else None

    return result if result else None


def _parse_qemu_cmdline(cmdline: str) -> dict:
    """从 QEMU 命令行提取关键优化参数"""
    p: dict = {}
    m = re.search(r'-machine\s+(\S+)', cmdline)
    if m:
        mstr = m.group(1)
        parts = mstr.split(',')
        p['machine_type'] = parts[0]
        for flag in ['kernel_irqchip', 'vmport', 'hpet', 'acpi']:
            fm = re.search(rf'{flag}=(\w+)', mstr)
            if fm:
                p[flag] = fm.group(1)
    m = re.search(r'-cpu\s+(\S+)', cmdline)
    if m:
        cpu_parts = m.group(1).split(',')
        p['cpu_model'] = cpu_parts[0]
        notable = [f for f in cpu_parts[1:] if f not in ('migratable=on',) and '=' in f]
        if notable:
            p['cpu_flags'] = notable
    m = re.search(r'-smp\s+(\S+)', cmdline)
    if m:
        p['smp'] = m.group(1)
    m = re.search(r'-overcommit\s+mem-lock=(\w+)', cmdline)
    if m:
        p['mem_lock'] = m.group(1)
    m = re.search(r'-m\s+size=(\d+)k', cmdline)
    if m:
        p['mem_gb'] = round(int(m.group(1)) / 1024 / 1024, 1)
    m = re.search(r'"host-nodes":\s*(\[[^\]]+\])', cmdline)
    if m:
        p['mem_host_nodes'] = m.group(1)
    m = re.search(r'"policy":\s*"(\w+)"', cmdline)
    if m:
        p['mem_policy'] = m.group(1)
    p['iothread_count'] = len(re.findall(r'"qom-type":"iothread"', cmdline))
    p['vhost'] = bool(re.search(r'"vhost":true', cmdline))
    p['intel_iommu'] = bool(re.search(r'"driver":"intel-iommu"', cmdline))
    if p['intel_iommu']:
        im = re.search(r'"driver":"intel-iommu".*?"intremap":"(\w+)"', cmdline)
        if im:
            p['iommu_intremap'] = im.group(1)
        em = re.search(r'"driver":"intel-iommu".*?"eim":"(\w+)"', cmdline)
        if em:
            p['iommu_eim'] = em.group(1)
    return p


def parse_procs_on_cpu(archive, file_map) -> Optional[dict]:
    """解析 procs_on_cpu.log：每个核心上的进程，反转为 pid -> [cpu, ...]"""
    content = read_file(archive, file_map, 'procs_on_cpu.log')
    if not content:
        return None

    cur_cpu: Optional[int] = None
    in_header = False
    by_pid: dict[str, list] = {}   # pid -> [{cpu, cpu_pct}]

    for line in content.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        # 段头：### CPU N ###
        m = re.match(r'^###\s+CPU\s+(\d+)\s+###', line_s)
        if m:
            cur_cpu = int(m.group(1))
            in_header = True
            continue
        # 列标题行
        if in_header and line_s.startswith('PID'):
            in_header = False
            continue
        if cur_cpu is None or in_header:
            continue
        # 数据行：PID COMMAND CPU %CPU CPU_TIME MEM(KB) %MEM
        parts = line_s.split()
        if len(parts) < 4:
            continue
        try:
            pid = str(int(parts[0]))
            cpu_pct = float(parts[3])
        except (ValueError, IndexError):
            continue
        entry = by_pid.setdefault(pid, [])
        # 同一 pid 在同一核心只保留一条（取最高 %CPU）
        existing = next((e for e in entry if e['cpu'] == cur_cpu), None)
        if existing:
            if cpu_pct > existing['cpu_pct']:
                existing['cpu_pct'] = cpu_pct
        else:
            entry.append({'cpu': cur_cpu, 'cpu_pct': cpu_pct})

    if not by_pid:
        return None
    return {'by_pid': by_pid}


def parse_process_sched(archive, file_map) -> Optional[dict]:
    """解析 process_sched_report.txt：每个进程的调度质量指标"""
    content = read_file(archive, file_map, 'process_sched_report.txt')
    if not content:
        return None

    # 表头：idx pid command runtime sleep wait iowait block avg-lat max-lat switch cpu-mig die-mig
    headers = []
    by_pid: dict[str, dict] = {}

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('-'):
            continue
        if line.startswith('idx'):
            headers = line.split()
            continue
        if not headers:
            continue
        parts = line.split()
        if len(parts) < len(headers):
            continue
        try:
            int(parts[0])  # idx
            pid = str(int(parts[1]))
        except (ValueError, IndexError):
            continue
        row: dict = {}
        for i, h in enumerate(headers[2:], 2):  # 跳过 idx/pid
            try:
                row[h] = float(parts[i]) if '.' in parts[i] else int(parts[i])
            except (ValueError, IndexError):
                row[h] = None
        by_pid[pid] = row

    return {'by_pid': by_pid} if by_pid else None


def parse_proc_affinity(archive, file_map) -> Optional[dict]:
    """解析 hgvmctl-processes-affinity.log：进程 CPU 拓扑归属"""
    content = read_file(archive, file_map, 'hgvmctl-processes-affinity.log')
    if not content:
        return None

    headers = []
    by_pid: dict[str, dict] = {}

    for line in content.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        if line_s.startswith('PID'):
            headers = line_s.split()
            continue
        if not headers:
            continue
        parts = line_s.split()
        if len(parts) < len(headers):
            continue
        try:
            pid = str(int(parts[0]))
            tid = str(int(parts[1]))
        except (ValueError, IndexError):
            continue
        # 只保留主进程（pid == tid）
        if pid != tid:
            continue
        row: dict = {}
        for i, h in enumerate(headers[2:], 2):
            try:
                v = parts[i]
                row[h] = int(v) if v.lstrip('-').isdigit() else v
            except IndexError:
                row[h] = None
        by_pid[pid] = row

    return {'by_pid': by_pid} if by_pid else None


def parse_thread_runtime(archive, file_map) -> Optional[dict]:
    """解析 thread_runtime_report.txt：每个线程在各 DIE 上的运行时间"""
    content = read_file(archive, file_map, 'thread_runtime_report.txt')
    if not content:
        return None

    die_count = 0
    by_pid: dict[int, dict] = {}   # pid -> {total, dies: [float, ...]}

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('-'):
            continue
        # 解析表头，确认 die 列数
        if line.startswith('idx'):
            die_count = line.count('die ')
            continue
        parts = line.split()
        # 最少需要：idx tid/pid command total-runtime + die列
        if len(parts) < 4 + die_count:
            continue
        try:
            int(parts[0])  # idx 必须是数字
        except ValueError:
            continue
        tid_pid = parts[1]
        pid_str = tid_pid.split('/')[-1]
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        try:
            total = float(parts[3])
            dies = [float(parts[4 + i]) for i in range(die_count)]
        except (ValueError, IndexError):
            continue
        # 同一 pid 多个线程，累加各 die 运行时间
        if pid in by_pid:
            by_pid[pid]['total'] += total
            for i in range(die_count):
                by_pid[pid]['dies'][i] += dies[i]
        else:
            by_pid[pid] = {'total': total, 'dies': dies[:]}

    if not by_pid:
        return None
    return {'by_pid': by_pid, 'die_count': die_count}


def parse_virt(archive, file_map) -> Optional[dict]:
    """解析虚拟化相关日志（5 个关注维度）"""
    result: dict = {}

    # ── 1. virtualization_info.log ─────────────────────────────────────────
    virt_info = read_file(archive, file_map, 'virtualization_info.log')
    if virt_info:
        m = re.search(r'Virtualization:\s+(.+)', virt_info)
        result['virt_type'] = m.group(1).strip() if m else None

        result['kvm_modules'] = list(set(re.findall(r'^(kvm(?:_amd|_intel)?)\s+\d+', virt_info, re.MULTILINE)))
        result['dev_kvm'] = '/dev/kvm does not exist' not in virt_info

        m = re.search(r'Compiled against library:\s+libvirt (.+)', virt_info)
        result['libvirt_version'] = m.group(1).strip() if m else None
        m = re.search(r'Running hypervisor:\s+QEMU (.+)', virt_info)
        result['qemu_version'] = m.group(1).strip() if m else None

        validate_items = []
        for m in re.finditer(r'QEMU:\s+Checking (.+?)\s+:\s+(PASS|FAIL|WARN)\s*(?:\(([^)]*)\))?', virt_info):
            validate_items.append({'check': m.group(1).strip(), 'status': m.group(2),
                                   'note': m.group(3).strip() if m.group(3) else ''})
        result['virt_validate'] = validate_items

        # AVIC: 可能是 Y/N/0/1/enabled/disabled/not found
        avic_m = re.search(r'check AVIC support[^\n]*\n([^\n#]+)', virt_info, re.IGNORECASE)
        if avic_m:
            avic_val = avic_m.group(1).strip()
            if avic_val in ('Y', '1', 'enabled') or 'enabled' in avic_val.lower():
                result['avic'] = 'enabled'
            elif avic_val in ('N', '0', 'disabled'):
                result['avic'] = 'disabled'
            elif 'not found' in avic_val.lower():
                result['avic'] = 'N/A'
            else:
                result['avic'] = avic_val or None
        else:
            result['avic'] = None

        # 解析 VM 列表和每 VM 的线程亲和 / QEMU 命令行
        vm_list: list = []
        vm_map: dict = {}
        in_simple_list = False   # "Name  PID  vCPU  Memory" 简表
        in_thread_table = False  # "Name  PID  TID  Allowed_CPUs" 详表
        cur_vm_name: Optional[str] = None

        for line in virt_info.splitlines():
            stripped = line.strip()
            if stripped.startswith('===') or stripped.startswith('##################'):
                in_simple_list = False
                in_thread_table = False
                continue

            # 简表头：Name  PID  vCPU  Memory（不含 TID）
            if re.match(r'Name\s+PID\s+vCPU\s+Memory', stripped):
                in_simple_list = True
                in_thread_table = False
                continue

            # 线程表头：Name  PID  TID  Allowed_CPUs
            if re.match(r'Name\s+PID\s+TID\s+Allowed_CPUs', stripped):
                in_simple_list = False
                in_thread_table = True
                cur_vm_name = None
                continue

            if in_simple_list and stripped:
                parts = stripped.split()
                if len(parts) >= 3:
                    vm: dict = {'name': parts[0], 'pid': parts[1], 'vcpu': parts[2],
                                'memory_gb': parts[3] if len(parts) > 3 else '',
                                'source_file': parts[4] if len(parts) > 4 else '',
                                'threads': [], 'cmdline_params': {}}
                    vm_list.append(vm)
                    vm_map[parts[0]] = vm
                continue

            if in_thread_table and stripped:
                # 列：Name PID TID Allowed_CPUs Allowed_Mems Last_CPU Socket NUMA CCX Core Command
                parts = stripped.split(None, 10)
                if len(parts) < 10:
                    continue
                vm_name, pid, tid = parts[0], parts[1], parts[2]
                allowed_cpus, allowed_mems = parts[3], parts[4]
                socket, numa = parts[6], parts[7]
                command = parts[10] if len(parts) > 10 else ''

                if vm_name in vm_map:
                    cur_vm_name = vm_name

                # 主进程行（TID == PID）：解析 QEMU cmdline
                if tid == pid and '/qemu-kvm' in command and cur_vm_name in vm_map:
                    vm_map[cur_vm_name]['cmdline_params'] = _parse_qemu_cmdline(command)
                    display_cmd = 'qemu-kvm (主进程)'
                else:
                    # 截断过长的 command
                    display_cmd = command[:60] + '…' if len(command) > 60 else command

                if cur_vm_name and cur_vm_name in vm_map:
                    vm_map[cur_vm_name]['threads'].append({
                        'tid': tid, 'allowed_cpus': allowed_cpus, 'allowed_mems': allowed_mems,
                        'socket': socket, 'numa': numa, 'command': display_cmd,
                    })

        result['vm_list'] = vm_list

    # ── 2. kvm_ko.log ─────────────────────────────────────────────────────
    kvm_ko = read_file(archive, file_map, 'kvm_ko.log')
    if kvm_ko:
        m = re.search(r'vermagic:\s+(.+)', kvm_ko)
        result['kvm_vermagic'] = m.group(1).strip() if m else None
        result['kvm_params'] = [[a, b.strip()] for a, b in re.findall(r'^parm:\s+(\w+):(.+)', kvm_ko, re.MULTILINE)]

    # ── 3. domcapabilities.log ────────────────────────────────────────────
    domcap = read_file(archive, file_map, 'domcapabilities.log')
    if domcap:
        dc: dict = {}
        for pat, key in [
            (r'<domain>(\w+)</domain>', 'domain'),
            (r'<machine>([^<]+)</machine>', 'machine'),
            (r'<arch>([^<]+)</arch>', 'arch'),
            (r"<vcpu max='(\d+)'", 'vcpu_max'),
            (r"<iothreads supported='(\w+)'", 'iothreads'),
            (r"<mode name='host-passthrough' supported='(\w+)'", 'host_passthrough'),
            (r"<mode name='host-model' supported='(\w+)'", 'host_model'),
        ]:
            m2 = re.search(pat, domcap)
            if m2:
                dc[key] = m2.group(1)
        m2 = re.search(r"<mode name='host-model'.*?<model[^>]*>([^<]+)</model>", domcap, re.DOTALL)
        if m2:
            dc['host_model_name'] = m2.group(1)
        m2 = re.search(r"<vendor>([^<]+)</vendor>", domcap)
        if m2:
            dc['vendor'] = m2.group(1)
        m2 = re.search(r"name='pciBackend'>(.*?)</enum>", domcap, re.DOTALL)
        if m2:
            dc['pci_backends'] = re.findall(r'<value>([^<]+)</value>', m2.group(1))
        result['domcap'] = dc

    # ── 4. hgvmctl-processes-affinity.log（补充无 vm_list 时的线程数据）────
    affinity = read_file(archive, file_map, 'hgvmctl-processes-affinity.log')
    qemu_threads = []
    if affinity:
        for line in affinity.splitlines():
            lower = line.lower()
            if any(k in lower for k in ['qemu-kvm', 'vhost-', '/kvm', 'iothread', 'kvm-irqfd']):
                parts = line.split()
                if len(parts) >= 9:
                    cmd_raw = ' '.join(parts[9:]) if len(parts) > 9 else parts[8]
                    if '/qemu-kvm' in cmd_raw:
                        display = 'qemu-kvm (主进程)'
                    else:
                        display = cmd_raw[:60] + '…' if len(cmd_raw) > 60 else cmd_raw
                    qemu_threads.append({
                        'pid': parts[0], 'tid': parts[1],
                        'allowed_cpus': parts[2], 'allowed_mems': parts[3],
                        'socket': parts[5], 'numa': parts[6],
                        'command': display,
                    })
    result['qemu_threads'] = qemu_threads

    # ── 5. dmesg.log ─────────────────────────────────────────────────────
    dmesg = read_file(archive, file_map, 'dmesg.log')
    if dmesg:
        m3 = re.search(r'Kernel command line:\s+(.+)', dmesg)
        result['kernel_cmdline'] = m3.group(1).strip() if m3 else None
        iommu_msgs = []
        for line in dmesg.splitlines():
            if re.search(r'iommu.*Default domain|AMD-Vi:|Intel-IOMMU:|Virtual APIC|X2APIC enabled|TLB invalidation', line, re.I):
                m4 = re.search(r'\]\s+(.+)', line)
                if m4:
                    iommu_msgs.append(m4.group(1).strip())
        result['iommu_msgs'] = iommu_msgs[:15]

    # ── 6. kernel-sysctl.log ─────────────────────────────────────────────
    sysctl = read_file(archive, file_map, 'kernel-sysctl.log')
    if sysctl:
        sysctl_vals: dict = {}
        for key in ['kernel.numa_balancing', 'vm.nr_hugepages', 'vm.nr_overcommit_hugepages']:
            m5 = re.search(rf'^{re.escape(key)}\s*=\s*(\S+)', sysctl, re.MULTILINE)
            if m5:
                sysctl_vals[key] = m5.group(1)
        result['sysctl'] = sysctl_vals

    # ── 7. kernel-config.log ─────────────────────────────────────────────
    kconfig = read_file(archive, file_map, 'kernel-config.log')
    if kconfig:
        cfg_targets = [
            'CONFIG_KVM', 'CONFIG_KVM_AMD', 'CONFIG_KVM_INTEL', 'CONFIG_KVM_VFIO',
            'CONFIG_VFIO', 'CONFIG_VFIO_PCI', 'CONFIG_AMD_IOMMU', 'CONFIG_INTEL_IOMMU',
            'CONFIG_VHOST_NET', 'CONFIG_NUMA_BALANCING', 'CONFIG_TRANSPARENT_HUGEPAGE',
            'CONFIG_IOMMU_DEFAULT_PASSTHROUGH', 'CONFIG_KVM_AMD_SEV',
        ]
        configs: dict = {}
        for line in kconfig.splitlines():
            for ck in cfg_targets:
                if ck not in configs:
                    m6 = re.match(rf'^(# )?({re.escape(ck)}\w*)\s*(=\S+|is not set)', line)
                    if m6:
                        val = 'n' if m6.group(1) else m6.group(3).lstrip('=').strip()
                        configs[m6.group(2)] = val
        result['kernel_configs'] = configs

    # ── 8. lspci.log SR-IOV 摘要 ──────────────────────────────────────────
    lspci_content = read_file(archive, file_map, 'lspci.log')
    if lspci_content:
        sriov_devs: list = []
        iommu_groups: set = set()
        cur_bdf = cur_desc = cur_iommu = cur_numa = None
        for line in lspci_content.splitlines():
            m7 = re.match(r'^([0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])\s+.+?\[[0-9a-f]{4}\]:\s*(.+)', line)
            if m7:
                cur_bdf = m7.group(1)
                cur_desc = re.sub(r'\s*\[[0-9a-f]{4}:[0-9a-f]{4}\].*$', '', m7.group(2), flags=re.I).strip()
                cur_iommu = cur_numa = None
            elif cur_bdf:
                m8 = re.search(r'IOMMU group:\s*(\d+)', line)
                if m8:
                    cur_iommu = m8.group(1)
                    iommu_groups.add(m8.group(1))
                m8 = re.search(r'NUMA node:\s*(\d+)', line)
                if m8:
                    cur_numa = m8.group(1)
                if 'Single Root I/O Virtualization' in line:
                    if not any(d['bdf'] == cur_bdf for d in sriov_devs):
                        sriov_devs.append({'bdf': cur_bdf, 'name': cur_desc,
                                           'iommu_group': cur_iommu, 'numa_node': cur_numa})
        result['sriov_devices'] = sriov_devs
        result['iommu_group_count'] = len(iommu_groups)

    # ── 9. interrupts.log ─────────────────────────────────────────────────
    interrupts = read_file(archive, file_map, 'interrupts.log')
    if interrupts:
        result['iommu_msi_count'] = sum(1 for ln in interrupts.splitlines() if 'IOMMU-MSI' in ln)

    # ── 10. systemd-units.log ──────────────────────────────────────────────
    systemd_units = read_file(archive, file_map, 'systemd-units.log')
    if systemd_units:
        svc_targets = {
            'irqbalance.service': 'irqbalance',
            'libvirtd.service': 'libvirtd',
            'tuned.service': 'tuned',
            'virtlogd.service': 'virtlogd',
            'dev-hugepages.mount': 'hugepages',
        }
        services: dict = {}
        for line in systemd_units.splitlines():
            for svc, key in svc_targets.items():
                if svc in line:
                    # 格式: "  svc.service  loaded  active  running  description"
                    m9 = re.search(rf'{re.escape(svc)}\s+\S+\s+(\S+)\s+(\S+)', line)
                    if m9:
                        services[key] = {'active': m9.group(1), 'sub': m9.group(2)}
        result['systemd_services'] = services

    return result if result else None


def generate_recommendations(results: dict, rules: list = None) -> list:
    if rules is None:
        rules = load_rules()
    recs = []
    for rule in rules:
        if not rule.get('enabled', True):
            continue
        matched, disp = _eval_condition(rule.get('condition', {}), results)
        if not matched:
            continue
        title = rule.get('title', '').replace('{value}', disp)
        recs.append({
            'severity':    rule.get('severity', 'low'),
            'category':    rule.get('category', ''),
            'title':       title,
            'description': rule.get('description', ''),
            'suggestions': rule.get('suggestions', []),
        })
    order = {'high': 0, 'medium': 1, 'low': 2}
    recs.sort(key=lambda r: order.get(r['severity'], 3))
    return recs


# ── API 路由 ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return (STATIC_DIR / "index.html").read_text(encoding='utf-8')


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    filename = file.filename or ''
    print(f"[analyze] 收到文件: {filename!r}, 大小: {len(content)/1024:.1f} KB")

    try:
        archive = None
        # 1. 先尝试 zip
        if not filename.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
            try:
                archive = zipfile.ZipFile(io.BytesIO(content))
                print(f"[analyze] 识别为 ZIP 格式")
            except zipfile.BadZipFile:
                pass

        # 2. 再尝试 tar（自动检测压缩方式）
        if archive is None:
            try:
                archive = tarfile.open(fileobj=io.BytesIO(content), mode='r:*')
                print(f"[analyze] 识别为 TAR 格式")
            except tarfile.TarError:
                pass

        if archive is None:
            raise HTTPException(status_code=400, detail=f"无法识别压缩格式（文件名: {filename}），请上传 .zip / .tar.gz / .tar 格式文件")

        file_map = build_file_map(archive)
        results = {
            'version': parse_version(archive, file_map),
            'base': parse_base(archive, file_map),
            'uarch': parse_uarch(archive, file_map),
            'topdown': parse_topdown(archive, file_map),
            'cm': parse_cm(archive, file_map),
            'perf': parse_perf(archive, file_map),
            'hotspot': parse_hotspot(archive, file_map),
            'mem': parse_mem(archive, file_map),
            'di': parse_di(archive, file_map),
            'sched': parse_sched(archive, file_map),
            'sched_report_html': read_file(archive, file_map, 'sched_report.html'),
            'numactl': parse_numactl(archive, file_map),
            'iostat': parse_iostat(archive, file_map),
            'iom': parse_iom(archive, file_map),
            'sar_net': parse_sar_net(archive, file_map),
            'nethogs': parse_nethogs(archive, file_map),
            'eths': parse_eths(archive, file_map),
            'mpstat': parse_mpstat(archive, file_map),
            'turbostat': parse_turbostat(archive, file_map),
            'top': parse_top(archive, file_map),
            'top_procs': parse_top_procs(archive, file_map),
            'flame_svgs': get_flame_svgs(archive, file_map),
            'lspci': parse_lspci(archive, file_map),
            'kallsyms': parse_kallsyms(archive, file_map),
            'ipmi': parse_ipmi(archive, file_map),
            'cpu_mem_procs': parse_cpu_mem_procs(archive, file_map),
            'thread_runtime': parse_thread_runtime(archive, file_map),
            'process_sched': parse_process_sched(archive, file_map),
            'proc_affinity': parse_proc_affinity(archive, file_map),
            'procs_on_cpu': parse_procs_on_cpu(archive, file_map),
            'virt': parse_virt(archive, file_map),
            'container': parse_container(archive, file_map),
            'file_list': sorted(file_map.keys()),
        }
        results['recommendations'] = generate_recommendations(results)

        # 移除超大的 SVG 内容（如果总响应过大，可考虑单独请求）
        total_svg_size = sum(len(v) for v in results['flame_svgs'].values())
        if total_svg_size > 2 * 1024 * 1024:  # 超过 2MB SVG
            results['flame_svgs'] = {k: v for k, v in results['flame_svgs'].items()
                                     if len(v) < 500 * 1024}

        return JSONResponse(content=results)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")


@app.get("/rules", response_class=HTMLResponse)
async def rules_page():
    return (STATIC_DIR / "rules.html").read_text(encoding='utf-8')


@app.get("/api/rulesets")
async def api_list_rulesets():
    return JSONResponse(content=list_rulesets())


class CreateRulesetRequest(BaseModel):
    name: str
    password: str = ''


@app.post("/api/rulesets")
async def api_create_ruleset(req: CreateRulesetRequest):
    name = req.name.strip()
    if not name or name == '默认':
        raise HTTPException(status_code=400, detail='名称无效')
    path = RULES_DIR / f"{name}.json"
    if path.exists():
        raise HTTPException(status_code=409, detail=f'规则集「{name}」已存在')
    create_ruleset(name, req.password)
    return {"ok": True}


class VerifyPasswordRequest(BaseModel):
    password: str


@app.post("/api/rulesets/{name}/verify")
async def api_verify_password(name: str, req: VerifyPasswordRequest):
    raw = load_ruleset_raw(name)
    if raw.get("password") and raw["password"] != req.password:
        raise HTTPException(status_code=403, detail='密码错误')
    return {"ok": True}


@app.get("/api/rules")
async def api_get_rules(name: str = '默认'):
    return JSONResponse(content=load_ruleset(name))


class SaveRulesRequest(BaseModel):
    rules: list
    password: str = ''


@app.post("/api/rules")
async def api_save_rules(name: str = '默认', req: SaveRulesRequest = Body(...)):
    raw = load_ruleset_raw(name)
    if raw.get("password") and raw["password"] != req.password:
        raise HTTPException(status_code=403, detail='密码错误')
    save_ruleset(name, req.rules)
    return {"ok": True, "count": len(req.rules)}


@app.delete("/api/rulesets/{name}")
async def api_delete_ruleset(name: str, password: str = ''):
    if name == '默认':
        raise HTTPException(status_code=400, detail='不能删除默认规则集')
    raw = load_ruleset_raw(name)
    if raw.get("password") and raw["password"] != password:
        raise HTTPException(status_code=403, detail='密码错误')
    delete_ruleset(name)
    return {"ok": True}


@app.post("/api/rules/reset")
async def api_reset_rules():
    defaults = load_default_rules()
    save_rules_to_file(defaults)
    return {"ok": True, "count": len(defaults)}


class RecsRequest(BaseModel):
    results: dict
    rule_set: str = '默认'


@app.post("/api/recommendations")
async def api_recommendations(req: RecsRequest):
    rules = load_ruleset(req.rule_set)
    recs = generate_recommendations(req.results, rules)
    return JSONResponse(content=recs)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8766)
