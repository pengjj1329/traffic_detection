import time
import os
import re
import json
import argparse
from scapy.all import *
from threading import Thread, Lock
import sys
import psutil
import ctypes
from ctypes import wintypes
import subprocess

# 全局数据结构
streams = {}
lock = Lock()
writers = {}  # 文件写入器缓存
packet_count = 0  # 数据包计数器
pid_cache = {}  # 进程信息缓存（带时间戳）
ui_process_cache = {}  # UI进程缓存（带时间戳）

# 核心修复：使用持久化的流文件映射
# 即使流被清理，再次出现相同的四元组时仍然写入同一个文件
flow_file_mapping = {}  # flow_key -> (filepath, start_timestamp, ui_flag, pid)

# 缓存配置
CACHE_TIMEOUT = 30  # 缓存超时时间（秒）
MAX_CACHE_SIZE = 1000  # 最大缓存大小

# Windows API函数声明
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# 定义Windows API结构体和函数
WNDENUMPROC = ctypes. WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes. DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", wintypes.ULONG),
                ("th32ModuleID", wintypes. DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes. DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260)]

def load_config(config_path):
    """加载配置文件并验证"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        required_keys = ["TIMEOUT", "CHECK_INTERVAL", "SAVE_PATH",
                        "SAFE_FILENAME_PATTERN", "IFACE"]
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")
        
        # 编译正则表达式
        config["SAFE_FILENAME_PATTERN"] = re.compile(config["SAFE_FILENAME_PATTERN"])
        return config
    except Exception as e: 
        print(f"配置加载失败: {str(e)}")
        sys.exit(1)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="TCP流量捕获工具")
    parser.add_argument('--config', 
                      default='config.json',
                      help="配置文件路径 (默认: config.json)")
    parser.add_argument('--debug', action='store_true',
                      help="启用调试模式")
    return parser.parse_args()

def sanitize_filename(text, config):
    return config["SAFE_FILENAME_PATTERN"].sub('_', text)

def get_cached_pid_info(port):
    """获取缓存的进程信息（带过期检查）"""
    if port in pid_cache:
        info, timestamp = pid_cache[port]
        if time.time() - timestamp < CACHE_TIMEOUT: 
            return info
        else:
            del pid_cache[port]
    return None

def cache_pid_info(port, process_info):
    """缓存进程信息"""
    if len(pid_cache) >= MAX_CACHE_SIZE:
        oldest_port = min(pid_cache.keys(), key=lambda k: pid_cache[k][1])
        del pid_cache[oldest_port]
    pid_cache[port] = (process_info, time.time())

def get_cached_ui_info(pid):
    """获取缓存的UI信息（带过期检查）"""
    if pid in ui_process_cache:
        info, timestamp = ui_process_cache[pid]
        if time.time() - timestamp < CACHE_TIMEOUT: 
            return info
        else: 
            del ui_process_cache[pid]
    return None

def cache_ui_info(pid, has_ui):
    """缓存UI信息"""
    if len(ui_process_cache) >= MAX_CACHE_SIZE: 
        oldest_pid = min(ui_process_cache.keys(), key=lambda k: ui_process_cache[k][1])
        del ui_process_cache[oldest_pid]
    ui_process_cache[pid] = (has_ui, time.time())

def check_admin_privileges():
    """详细的管理员权限检查"""
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        else:
            print("[-] 当前没有管理员权限，无法获取所有进程信息")
            return False
    except Exception as e:
        print(f"[-] 权限检查失败: {e}")
        return False

def get_process_info_by_port(port, max_retries=3, retry_delay=0.2):
    """改进的进程信息获取函数"""
    cached_info = get_cached_pid_info(port)
    if cached_info:
        return cached_info
    
    for attempt in range(max_retries):
        try:
            for conn in psutil.net_connections(kind='tcp'):
                if (hasattr(conn. laddr, 'port') and conn.laddr.port == port):
                    if conn.pid and conn.pid > 0:
                        return create_process_info(conn.pid, port)
            
            for conn in psutil.net_connections(kind='udp'):
                if (hasattr(conn.laddr, 'port') and conn.laddr.port == port):
                    if conn.pid and conn.pid > 0:
                        return create_process_info(conn.pid, port)
            
            try:
                result = subprocess.run(
                    f'netstat -ano | findstr ":{port}"', 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    for line in result. stdout.split('\n'):
                        if f':{port}' in line and 'TCP' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                pid = int(parts[-1])
                                if pid > 0:
                                    return create_process_info(pid, port)
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                pass
                
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            continue
    
    return None

def create_process_info(pid, port):
    """创建进程信息字典"""
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            process_info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'create_time': process.create_time(),
                'status': process.status()
            }
        cache_pid_info(port, process_info)
        return process_info
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[-] 无法访问进程 {pid} 的详细信息: {e}")
        basic_info = {
            'pid': pid,
            'name':  'Unknown',
            'exe':  'Access Denied',
            'cmdline':  [],
            'create_time': time.time(),
            'status':  'Unknown'
        }
        cache_pid_info(port, basic_info)
        return basic_info
    except Exception as e:
        print(f"[-] 创建进程信息异常 (PID {pid}): {e}")
        basic_info = {
            'pid': pid,
            'name': 'Error',
            'exe': 'Error',
            'cmdline': [],
            'create_time': time.time(),
            'status':  'Error'
        }
        cache_pid_info(port, basic_info)
        return basic_info

def has_ui_window_enhanced(pid):
    """增强的UI窗口检测"""
    if pid == 0 or pid is None:
        return False
        
    cached_ui = get_cached_ui_info(pid)
    if cached_ui is not None:
        return cached_ui
    
    has_ui = False
    
    try:
        def enum_windows_proc(hwnd, lParam):
            nonlocal has_ui
            try:
                process_id = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
                
                if process_id.value == pid:
                    if user32.IsWindowVisible(hwnd):
                        title_length = user32.GetWindowTextLengthW(hwnd)
                        if title_length > 0 or user32.GetWindow(hwnd, 5):
                            has_ui = True
                            return False
            except:
                pass
            return True
        
        enum_proc = WNDENUMPROC(enum_windows_proc)
        user32.EnumWindows(enum_proc, 0)
        
        if not has_ui:
            try:
                process = psutil.Process(pid)
                exe_path = process.exe().lower() if process.exe() else ""
                process_name = process.name().lower()
                
                gui_path_indicators = [
                    'program files', 'windows\\system32\\', 'explorer.exe',
                    'chrome.exe', 'firefox.exe', 'notepad.exe', 'winword.exe',
                    'excel.exe', 'outlook.exe', 'code.exe', 'devenv.exe'
                ]
                
                service_indicators = [
                    'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
                    'csrss.exe', 'smss.exe', 'system', 'registry'
                ]
                
                if any(indicator in exe_path for indicator in gui_path_indicators):
                    if not any(indicator in process_name for indicator in service_indicators):
                        has_ui = True
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        cache_ui_info(pid, has_ui)
        return has_ui
        
    except Exception as e: 
        cache_ui_info(pid, False)
        return False

def get_process_ui_flag_and_pid(src_port, dst_port, debug=False):
    """增强的进程信息获取"""
    dst_process = get_process_info_by_port(dst_port)
    if dst_process and dst_process['pid'] > 0:
        ui_flag = 1 if has_ui_window_enhanced(dst_process['pid']) else 0
        if debug:
            print(f"[+] 目的端口 {dst_port} -> PID:  {dst_process['pid']}, 进程:  {dst_process['name']}, UI:  {ui_flag}")
        return ui_flag, dst_process['pid']
    
    src_process = get_process_info_by_port(src_port)
    if src_process and src_process['pid'] > 0:
        ui_flag = 1 if has_ui_window_enhanced(src_process['pid']) else 0
        if debug:
            print(f"[+] 源端口 {src_port} -> PID: {src_process['pid']}, 进程: {src_process['name']}, UI: {ui_flag}")
        return ui_flag, src_process['pid']
    
    return 0, 0

def generate_flow_key(ip_pkt, tcp_pkt):
    """
    生成标准化的流标识符
    关键修复：只使用IP和端口的固定排序，不包含会话相关的动态信息
    """
    endpoint1 = (ip_pkt.src, tcp_pkt.sport)
    endpoint2 = (ip_pkt.dst, tcp_pkt.dport)
    
    if endpoint1 <= endpoint2:
        return (ip_pkt.src, ip_pkt.dst, tcp_pkt.sport, tcp_pkt.dport)
    else:
        return (ip_pkt.dst, ip_pkt.src, tcp_pkt. dport, tcp_pkt. sport)

def get_or_create_writer(flow_key, config, ui_flag, pid):
    """
    核心修复：获取或创建写入器
    使用 flow_file_mapping 确保同一个四元组始终写入同一个文件
    """
    global flow_file_mapping
    
    # 检查是否已有该流的文件映射
    if flow_key in flow_file_mapping: 
        filepath, start_timestamp, saved_ui_flag, saved_pid = flow_file_mapping[flow_key]
        
        # 如果写入器不存在或已关闭，重新打开同一个文件
        if flow_key not in writers:
            try:
                # 使用 append=True 追加到现有文件
                writers[flow_key] = PcapWriter(filepath, append=True, sync=True)
                if args.debug:
                    print(f"[+] 重新打开现有文件: {os.path.basename(filepath)}")
            except Exception as e: 
                print(f"[-] 重新打开文件失败:  {e}")
                # 如果打开失败，创建新文件
                del flow_file_mapping[flow_key]
                return get_or_create_writer(flow_key, config, ui_flag, pid)
        
        return writers[flow_key]
    
    # 新的流，创建新文件
    src_ip, dst_ip = flow_key[: 2]
    src_port, dst_port = flow_key[2:]
    start_timestamp = int(time.time())
    
    safe_src = sanitize_filename(f"{src_ip}_{src_port}", config)
    safe_dst = sanitize_filename(f"{dst_ip}_{dst_port}", config)
    filename = f"TCP_{safe_src}_to_{safe_dst}_{start_timestamp}_{ui_flag}_{pid}.pcap"
    filepath = os.path.join(config["SAVE_PATH"], filename)
    
    os.makedirs(config["SAVE_PATH"], exist_ok=True)
    
    try:
        writers[flow_key] = PcapWriter(filepath, append=True, sync=True)
        # 保存文件映射，确保后续使用同一个文件
        flow_file_mapping[flow_key] = (filepath, start_timestamp, ui_flag, pid)
        if args.debug:
            print(f"[+] 创建新的捕获文件: {filename}")
    except Exception as e: 
        print(f"[-] 创建文件写入器失败: {e}")
        temp_filename = f"temp_{start_timestamp}_{src_port}_{dst_port}.pcap"
        temp_filepath = os.path.join(config["SAVE_PATH"], temp_filename)
        writers[flow_key] = PcapWriter(temp_filepath, append=True, sync=True)
        flow_file_mapping[flow_key] = (temp_filepath, start_timestamp, ui_flag, pid)
    
    return writers[flow_key]

def is_tcp_syn(tcp_pkt):
    """检测是否是纯SYN包（新连接开始）"""
    flags = tcp_pkt.flags
    # SYN=1, ACK=0
    return bool(flags & 0x02) and not bool(flags & 0x10)

def is_tcp_fin(tcp_pkt):
    """检测FIN包"""
    return bool(tcp_pkt.flags & 0x01)

def is_tcp_rst(tcp_pkt):
    """检测RST包"""
    return bool(tcp_pkt.flags & 0x04)

def handle_packet(packet, config):
    global packet_count
    
    if IP in packet and TCP in packet:
        ip_pkt = packet[IP]
        tcp_pkt = packet[TCP]

        packet_count += 1
        if args.debug and packet_count % 1000 == 0:
            print(f"[*] 已处理数据包: {packet_count}")

        flow_key = generate_flow_key(ip_pkt, tcp_pkt)
        
        with lock:
            is_syn = is_tcp_syn(tcp_pkt)
            is_fin = is_tcp_fin(tcp_pkt)
            is_rst = is_tcp_rst(tcp_pkt)
            
            # 只有在收到新的SYN包时，才考虑是否需要创建新会话
            # 关键逻辑：检查是否是真正的新连接
            if is_syn and flow_key in flow_file_mapping:
                # 检查旧会话是否已经完全结束（收到过FIN或RST）
                if flow_key in streams:
                    old_stream = streams[flow_key]
                    if old_stream.get('session_closed', False):
                        # 旧会话已结束，这是新连接，需要新文件
                        if args.debug:
                            print(f"[+] 检测到新SYN包，旧会话已关闭，创建新文件:  {flow_key}")
                        # 关闭旧写入器
                        if flow_key in writers:
                            try:
                                writers[flow_key].close()
                            except:
                                pass
                            del writers[flow_key]
                        # 删除旧的文件映射，让它创建新文件
                        del flow_file_mapping[flow_key]
                        del streams[flow_key]
            
            # 获取或创建写入器
            if flow_key not in streams:
                # 新建流信息
                ui_flag, pid = get_process_ui_flag_and_pid(tcp_pkt.sport, tcp_pkt.dport, args.debug)
                
                if args.debug:
                    print(f"[+] 新建/恢复流:  {ip_pkt.src}:{tcp_pkt.sport} -> {ip_pkt.dst}:{tcp_pkt.dport}")
                    if flow_key in flow_file_mapping:
                        print(f"    | 使用现有文件: {os.path.basename(flow_file_mapping[flow_key][0])}")
                    else:
                        print(f"    | 创建新文件")
                
                streams[flow_key] = {
                    'start_time': time.time(),
                    'last_active': time.time(),
                    'ui_flag': ui_flag,
                    'pid': pid,
                    'packet_count': 0,
                    'fin_count': 0,
                    'rst_seen': False,
                    'session_closed': False  # 标记会话是否真正结束
                }
                
                get_or_create_writer(flow_key, config, ui_flag, pid)
            
            # 更新流状态
            stream_info = streams[flow_key]
            stream_info['last_active'] = time.time()
            stream_info['packet_count'] += 1
            
            # 跟踪TCP状态
            if is_fin:
                stream_info['fin_count'] += 1
                if args.debug:
                    print(f"[*] FIN包:  {flow_key}, 计数: {stream_info['fin_count']}")
            if is_rst:
                stream_info['rst_seen'] = True
                stream_info['session_closed'] = True  # RST表示会话立即结束
                if args. debug:
                    print(f"[*] RST包:  {flow_key}")
            
            # 双向FIN表示正常关闭
            if stream_info['fin_count'] >= 2:
                stream_info['session_closed'] = True
            
            # 写入数据包
            try:
                if flow_key in writers:
                    writers[flow_key].write(packet)
                else:
                    # 重新获取写入器
                    writer = get_or_create_writer(flow_key, config, 
                                                   stream_info['ui_flag'], 
                                                   stream_info['pid'])
                    writer.write(packet)
            except Exception as e:
                print(f"[-] 写入数据包失败: {str(e)[:100]}")
                if args.debug:
                    import traceback
                    traceback. print_exc()

def cleanup_streams(config):
    """
    清理内存中的流状态，但不删除文件映射
    这样即使流被清理，后续数据包仍能写入同一个文件
    """
    while True:
        time.sleep(config["CHECK_INTERVAL"])
        current_time = time.time()
        
        with lock:
            # 清理过期的PID缓存
            expired_ports = [port for port, (info, timestamp) in pid_cache.items() 
                           if current_time - timestamp > CACHE_TIMEOUT]
            for port in expired_ports:
                del pid_cache[port]
            
            # 清理过期的UI缓存
            expired_pids = [pid for pid, (info, timestamp) in ui_process_cache.items() 
                          if current_time - timestamp > CACHE_TIMEOUT]
            for pid in expired_pids: 
                del ui_process_cache[pid]
            
            # 清理超时的流状态（释放内存）
            # 注意：只清理 streams 和关闭 writers，但保留 flow_file_mapping
            streams_to_cleanup = []
            
            for flow_key, stream_info in streams.items():
                idle_time = current_time - stream_info['last_active']
                
                # 只有超时很久的才清理（释放内存）
                # 使用更长的超时时间，或者只在会话明确结束时清理
                should_cleanup = False
                cleanup_reason = ""
                
                # 条件1: 会话已结束（FIN或RST）且超过5秒
                if stream_info['session_closed'] and idle_time > 5:
                    should_cleanup = True
                    cleanup_reason = "会话已结束"
                
                # 条件2: 超时很久（是配置超时的3倍）
                elif idle_time > config["TIMEOUT"] * 3:
                    should_cleanup = True
                    cleanup_reason = f"超时 {idle_time:.0f}秒"
                
                if should_cleanup:
                    streams_to_cleanup.append((flow_key, cleanup_reason, stream_info))
            
            for flow_key, reason, stream_info in streams_to_cleanup:
                # 关闭写入器（释放文件句柄）
                if flow_key in writers:
                    try:
                        writers[flow_key].close()
                        if args.debug:
                            print(f"[+] 关闭写入器 ({reason}): {flow_key}, "
                                  f"包数: {stream_info['packet_count']}")
                    except Exception as e:
                        print(f"[-] 关闭写入器失败: {e}")
                    del writers[flow_key]
                
                # 清理流状态
                del streams[flow_key]
                
                # 关键：如果会话已明确结束，也清理文件映射
                # 这样新的连接会创建新文件
                if stream_info['session_closed']: 
                    if flow_key in flow_file_mapping:
                        if args.debug:
                            print(f"[+] 清理文件映射（会话已结束）: {flow_key}")
                        del flow_file_mapping[flow_key]

def test_psutil_functionality():
    """测试psutil功能"""
    try:
        tcp_conns = list(psutil.net_connections(kind='tcp'))
        udp_conns = list(psutil.net_connections(kind='udp'))
        
        print(f"psutil测试结果:")
        print(f"  TCP连接数: {len(tcp_conns)}")
        print(f"  UDP连接数: {len(udp_conns)}")
        
        sample_tcp = [conn for conn in tcp_conns if hasattr(conn. laddr, 'port')][:3]
        for i, conn in enumerate(sample_tcp):
            print(f"  样本TCP {i+1}: 端口 {conn.laddr.port} -> PID: {conn.pid}")
            
        return True
    except Exception as e: 
        print(f"psutil功能测试失败: {e}")
        return False

def print_statistics():
    """打印当前统计信息"""
    with lock:
        print(f"\n{'='*60}")
        print(f"当前统计信息:")
        print(f"  活跃流数量: {len(streams)}")
        print(f"  写入器数量: {len(writers)}")
        print(f"  文件映射数量: {len(flow_file_mapping)}")
        print(f"  总数据包数: {packet_count}")
        print(f"  PID缓存大小: {len(pid_cache)}")
        print(f"  UI缓存大小: {len(ui_process_cache)}")
        
        if flow_file_mapping:
            print(f"\n  文件映射列表:")
            for flow_key, (filepath, ts, ui, pid) in list(flow_file_mapping.items())[:10]:
                filename = os.path.basename(filepath)
                status = "活跃" if flow_key in writers else "已关闭"
                pkt_count = streams. get(flow_key, {}).get('packet_count', '? ')
                print(f"    {flow_key}")
                print(f"      -> {filename} [{status}] 包数:{pkt_count}")
            if len(flow_file_mapping) > 10:
                print(f"    ...  还有 {len(flow_file_mapping) - 10} 个映射")
        
        print(f"{'='*60}\n")

def statistics_thread(interval=30):
    """定期打印统计信息的线程"""
    while True: 
        time.sleep(interval)
        if args.debug:
            print_statistics()

if __name__ == "__main__": 
    if os.name != 'nt':
        print("错误：此功能仅支持Windows系统")
        sys.exit(1)
    
    args = parse_args()
    config = load_config(args.config)
    
    print("=" * 60)
    print("TCP流量捕获工具 - 持久会话版")
    print("=" * 60)
    print("系统信息:")
    print(f"  操作系统:  Windows")
    print(f"  Python版本: {sys.version. split()[0]}")
    print(f"  psutil版本: {psutil.__version__}")
    print(f"  Scapy版本: {scapy.__version__}")
    
    is_admin = check_admin_privileges()
    print(f"  管理员权限: {'是' if is_admin else '否'}")
    
    if not is_admin:
        print("\n警告：建议以管理员身份运行以获得完整进程信息！")
    
    psutil_ok = test_psutil_functionality()
    if not psutil_ok:
        print("psutil功能异常，请尝试:  pip install --upgrade psutil")
    
    print("=" * 60)
    print("核心修复说明:")
    print("  1. 使用 flow_file_mapping 持久化存储流与文件的映射关系")
    print("  2. 即使流因超时被清理，后续数据包仍写入同一文件")
    print("  3. 只有检测到新的SYN包且旧会话已结束时才创建新文件")
    print("  4. 支持长连接场景（如Sliver C2）的流量捕获")
    print("=" * 60)
    
    # 启动清理线程
    cleaner = Thread(target=cleanup_streams, args=(config,), name="CleanupThread")
    cleaner.daemon = True
    cleaner.start()
    
    # 启动统计线程
    if args.debug:
        stats_thread = Thread(target=statistics_thread, args=(30,), name="StatsThread")
        stats_thread.daemon = True
        stats_thread.start()
    
    os.makedirs(config['SAVE_PATH'], exist_ok=True)
    print(f"\n捕获配置:")
    print(f"  接口: {config['IFACE']}")
    print(f"  保存路径: {config['SAVE_PATH']}")
    print(f"  超时时间: {config['TIMEOUT']}秒 (实际清理:  {config['TIMEOUT']*3}秒)")
    print(f"  检查间隔: {config['CHECK_INTERVAL']}秒")
    print(f"  调试模式: {'启用' if args.debug else '禁用'}")
    print("\n按 Ctrl+C 停止捕获...")
    print("=" * 60 + "\n")
    
    try:
        sniff(
            prn=lambda pkt: handle_packet(pkt, config),
            store=False,
            filter="tcp",
            iface=config["IFACE"]
        )
    except KeyboardInterrupt:
        print("\n正在停止捕获并保存剩余会话...")
        print_statistics()
        
        with lock:
            for flow_key, writer in list(writers.items()):
                try:
                    writer.close()
                    stream_info = streams. get(flow_key, {})
                    if args.debug:
                        print(f"[+] 关闭:  {flow_key}, 包数: {stream_info.get('packet_count', '?')}")
                except Exception as e:
                    print(f"[-] 关闭写入器失败: {e}")
            
            print(f"\n捕获完成:")
            print(f"  总数据包:  {packet_count}")
            print(f"  生成文件数: {len(flow_file_mapping)}")
            
            writers. clear()
            streams.clear()
        
        sys.exit(0)
    except Exception as e:
        print(f"捕获过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)