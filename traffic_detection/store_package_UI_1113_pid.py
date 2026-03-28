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

# 缓存配置
CACHE_TIMEOUT = 30  # 缓存超时时间（秒）
MAX_CACHE_SIZE = 1000  # 最大缓存大小

# Windows API函数声明
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# 定义Windows API结构体和函数
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", wintypes.ULONG),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
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
            # 缓存过期，删除
            del pid_cache[port]
    return None

def cache_pid_info(port, process_info):
    """缓存进程信息"""
    # 清理过大的缓存
    if len(pid_cache) >= MAX_CACHE_SIZE:
        # 删除最旧的缓存项
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
            # 缓存过期，删除
            del ui_process_cache[pid]
    return None

def cache_ui_info(pid, has_ui):
    """缓存UI信息"""
    # 清理过大的缓存
    if len(ui_process_cache) >= MAX_CACHE_SIZE:
        # 删除最旧的缓存项
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
    # 先检查缓存
    cached_info = get_cached_pid_info(port)
    if cached_info:
        return cached_info
    
    for attempt in range(max_retries):
        try:
            # 方法1: 检查所有TCP连接
            for conn in psutil.net_connections(kind='tcp'):
                if (hasattr(conn.laddr, 'port') and conn.laddr.port == port):
                    if conn.pid and conn.pid > 0:
                        return create_process_info(conn.pid, port)
            
            # 方法2: 检查所有UDP连接
            for conn in psutil.net_connections(kind='udp'):
                if (hasattr(conn.laddr, 'port') and conn.laddr.port == port):
                    if conn.pid and conn.pid > 0:
                        return create_process_info(conn.pid, port)
            
            # 方法3: 使用netstat命令作为备选（Windows）
            try:
                result = subprocess.run(
                    f'netstat -ano | findstr ":{port}"', 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if f':{port}' in line and 'TCP' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                pid = int(parts[-1])
                                if pid > 0:
                                    return create_process_info(pid, port)
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError) as e:
                # netstat失败，继续使用其他方法
                pass
                
            # 重试前等待
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            continue
    
    # 如果所有方法都失败，记录日志
    return None

def create_process_info(pid, port):
    """创建进程信息字典"""
    try:
        process = psutil.Process(pid)
        with process.oneshot():  # 优化性能，一次性获取所有信息
            process_info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'create_time': process.create_time(),
                'status': process.status()
            }
        # 缓存结果
        cache_pid_info(port, process_info)
        return process_info
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[-] 无法访问进程 {pid} 的详细信息: {e}")
        # 即使无法获取详细信息，也返回基本PID信息
        basic_info = {
            'pid': pid,
            'name': 'Unknown',
            'exe': 'Access Denied',
            'cmdline': [],
            'create_time': time.time(),
            'status': 'Unknown'
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
            'status': 'Error'
        }
        cache_pid_info(port, basic_info)
        return basic_info

def has_ui_window_enhanced(pid):
    """增强的UI窗口检测"""
    if pid == 0 or pid is None:
        return False
        
    # 检查缓存
    cached_ui = get_cached_ui_info(pid)
    if cached_ui is not None:
        return cached_ui
    
    has_ui = False
    
    try:
        # 方法1: 检查进程是否有可见窗口
        def enum_windows_proc(hwnd, lParam):
            nonlocal has_ui
            try:
                process_id = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
                
                if process_id.value == pid:
                    if user32.IsWindowVisible(hwnd):
                        # 检查窗口标题长度或子窗口
                        title_length = user32.GetWindowTextLengthW(hwnd)
                        if title_length > 0 or user32.GetWindow(hwnd, 5):  # GW_CHILD
                            has_ui = True
                            return False
            except:
                pass
            return True
        
        enum_proc = WNDENUMPROC(enum_windows_proc)
        user32.EnumWindows(enum_proc, 0)
        
        # 方法2: 检查进程名和可执行文件路径
        if not has_ui:
            try:
                process = psutil.Process(pid)
                exe_path = process.exe().lower() if process.exe() else ""
                process_name = process.name().lower()
                
                # 常见GUI进程的可执行文件路径特征
                gui_path_indicators = [
                    'program files', 'windows\\system32\\', 'explorer.exe',
                    'chrome.exe', 'firefox.exe', 'notepad.exe', 'winword.exe',
                    'excel.exe', 'outlook.exe', 'code.exe', 'devenv.exe'
                ]
                
                # 常见系统服务进程（通常无UI）
                service_indicators = [
                    'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
                    'csrss.exe', 'smss.exe', 'system', 'registry'
                ]
                
                # 如果路径包含GUI特征且不是系统服务，则认为有UI
                if any(indicator in exe_path for indicator in gui_path_indicators):
                    if not any(indicator in process_name for indicator in service_indicators):
                        has_ui = True
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # 缓存结果
        cache_ui_info(pid, has_ui)
        return has_ui
        
    except Exception as e:
        cache_ui_info(pid, False)
        return False

def get_process_ui_flag_and_pid(src_port, dst_port, debug=False):
    """增强的进程信息获取，包含详细调试"""
    # 优先检查目的端口
    dst_process = get_process_info_by_port(dst_port)
    if dst_process and dst_process['pid'] > 0:
        ui_flag = 1 if has_ui_window_enhanced(dst_process['pid']) else 0
        if debug:
            print(f"[+] 目的端口 {dst_port} -> PID: {dst_process['pid']}, 进程: {dst_process['name']}, UI: {ui_flag}")
        return ui_flag, dst_process['pid']
    
    # 检查源端口
    src_process = get_process_info_by_port(src_port)
    if src_process and src_process['pid'] > 0:
        ui_flag = 1 if has_ui_window_enhanced(src_process['pid']) else 0
        if debug:
            print(f"[+] 源端口 {src_port} -> PID: {src_process['pid']}, 进程: {src_process['name']}, UI: {ui_flag}")
        return ui_flag, src_process['pid']
    
    # 调试信息
    if debug:
        print(f"[-] 无法找到端口对应的进程: 源端口 {src_port}, 目的端口 {dst_port}")
        # 尝试列出当前所有连接进行调试
        try:
            print("当前TCP连接样本:")
            tcp_conns = list(psutil.net_connections(kind='tcp'))
            sample_count = min(5, len(tcp_conns))
            for i, conn in enumerate(tcp_conns[:sample_count]):
                if hasattr(conn.laddr, 'port'):
                    print(f"  端口 {conn.laddr.port} -> PID: {conn.pid}")
        except Exception as e:
            print(f"连接枚举失败: {e}")
    
    return 0, 0

def get_writer(flow_key, config, ui_flag, pid):
    """获取或创建PcapWriter实例"""
    if flow_key not in writers:
        src_ip, dst_ip = flow_key[:2]
        src_port, dst_port = flow_key[2:]
        timestamp = int(time.time())
        
        safe_src = sanitize_filename(f"{src_ip}_{src_port}", config)
        safe_dst = sanitize_filename(f"{dst_ip}_{dst_port}", config)
        # 文件名包含UI标志和PID
        filename = f"TCP_{safe_src}_to_{safe_dst}_{timestamp}_{ui_flag}_{pid}.pcap"
        filepath = os.path.join(config["SAVE_PATH"], filename)
        
        os.makedirs(config["SAVE_PATH"], exist_ok=True)
        try:
            writers[flow_key] = PcapWriter(filepath, append=True, sync=True)
            if args.debug:
                print(f"[+] 创建新的捕获文件: {filename}")
        except Exception as e:
            print(f"[-] 创建文件写入器失败: {e}")
            # 使用临时文件名作为备选
            temp_filename = f"temp_{timestamp}_{src_port}_{dst_port}.pcap"
            temp_filepath = os.path.join(config["SAVE_PATH"], temp_filename)
            writers[flow_key] = PcapWriter(temp_filepath, append=True, sync=True)
    
    return writers[flow_key]

def handle_packet(packet, config):
    global packet_count
    if IP in packet and TCP in packet:
        ip_pkt = packet[IP]
        tcp_pkt = packet[TCP]

        packet_count += 1
        if args.debug and packet_count % 1000 == 0:
            print(f"[*] 已处理数据包: {packet_count}")

        # 生成标准化流标识符
        src_ip, dst_ip = sorted([ip_pkt.src, ip_pkt.dst])
        src_port, dst_port = sorted([tcp_pkt.sport, tcp_pkt.dport])
        flow_key = (src_ip, dst_ip, src_port, dst_port)

        with lock:
            if flow_key not in streams:
                # 改进：同时检查源端口和目的端口
                ui_flag, pid = get_process_ui_flag_and_pid(tcp_pkt.sport, tcp_pkt.dport, args.debug)
                
                if args.debug:
                    src_process = get_process_info_by_port(tcp_pkt.sport)
                    dst_process = get_process_info_by_port(tcp_pkt.dport)
                    print(f"[+] 新建流: {src_ip}:{tcp_pkt.sport} -> {dst_ip}:{tcp_pkt.dport}")
                    print(f"    | 源端口进程: {src_process['name'] if src_process else 'None'}")
                    print(f"    | 目的端口进程: {dst_process['name'] if dst_process else 'None'}")
                    print(f"    | 最终PID: {pid}, UI标志: {ui_flag}")
                
                streams[flow_key] = {
                    'start_time': time.time(),
                    'last_active': time.time(),
                    'ui_flag': ui_flag,
                    'pid': pid,
                    'src_port': tcp_pkt.sport,
                    'dst_port': tcp_pkt.dport
                }
                get_writer(flow_key, config, ui_flag, pid)
            
            try:
                if flow_key in writers:
                    writers[flow_key].write(packet)
                    streams[flow_key]['last_active'] = time.time()
                else:
                    if args.debug:
                        print(f"[-] 写入器不存在，为流 {flow_key} 重新创建")
                    # 重新创建写入器
                    stream_info = streams[flow_key]
                    get_writer(flow_key, config, stream_info['ui_flag'], stream_info['pid'])
                    writers[flow_key].write(packet)
            except Exception as e:
                print(f"[-] 写入数据包失败: {str(e)[:100]}")
                if args.debug:
                    import traceback
                    traceback.print_exc()

def cleanup_streams(config):
    """清理超时会话并关闭写入器"""
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
                
            # 清理超时的流
            streams_to_remove = []
            for flow_key, stream_info in streams.items():
                if current_time - stream_info['last_active'] > config["TIMEOUT"]:
                    streams_to_remove.append(flow_key)
            
            for flow_key in streams_to_remove:
                if flow_key in writers:
                    try:
                        writers[flow_key].close()
                        if args.debug:
                            print(f"[+] 关闭流: {flow_key}, 持续时间: {current_time - stream_info['start_time']:.2f}s")
                    except Exception as e:
                        print(f"[-] 关闭写入器失败: {e}")
                    del writers[flow_key]
                del streams[flow_key]

def test_psutil_functionality():
    """测试psutil功能"""
    try:
        # 测试网络连接获取
        tcp_conns = list(psutil.net_connections(kind='tcp'))
        udp_conns = list(psutil.net_connections(kind='udp'))
        
        print(f"psutil测试结果:")
        print(f"  TCP连接数: {len(tcp_conns)}")
        print(f"  UDP连接数: {len(udp_conns)}")
        
        # 显示一些样本连接
        sample_tcp = [conn for conn in tcp_conns if hasattr(conn.laddr, 'port')][:3]
        for i, conn in enumerate(sample_tcp):
            print(f"  样本TCP {i+1}: 端口 {conn.laddr.port} -> PID: {conn.pid}")
            
        return True
    except Exception as e:
        print(f"psutil功能测试失败: {e}")
        return False

if __name__ == "__main__":
    # 检查操作系统
    if os.name != 'nt':
        print("错误：此功能仅支持Windows系统")
        sys.exit(1)
    
    args = parse_args()
    config = load_config(args.config)
    
    # 详细系统信息
    print("=" * 50)
    print("TCP流量捕获工具 - 增强版")
    print("=" * 50)
    print("系统信息:")
    print(f"操作系统: Windows")
    print(f"Python版本: {sys.version.split()[0]}")
    print(f"psutil版本: {psutil.__version__}")
    print(f"Scapy版本: {scapy.__version__}")
    
    # 权限检查
    is_admin = check_admin_privileges()
    print(f"管理员权限: {'是' if is_admin else '否'}")
    
    if not is_admin:
        print("警告：建议以管理员身份运行以获得完整进程信息！")
        print("右键点击命令提示符或PowerShell，选择'以管理员身份运行'")
        print("或者使用: runas /user:Administrator python script.py")
    
    # 测试psutil功能
    psutil_ok = test_psutil_functionality()
    if not psutil_ok:
        print("psutil功能异常，请尝试: pip install --upgrade psutil")
    
    print("=" * 50)
    
    # 启动清理线程
    cleaner = Thread(target=cleanup_streams, args=(config,))
    cleaner.daemon = True
    cleaner.start()
    
    os.makedirs(config['SAVE_PATH'], exist_ok=True)
    print(f"正在捕获 {config['IFACE']} 接口的所有TCP流量...")
    print(f"保存路径: {config['SAVE_PATH']}")
    print(f"超时时间: {config['TIMEOUT']}秒")
    print(f"检查间隔: {config['CHECK_INTERVAL']}秒")
    print(f"调试模式: {'启用' if args.debug else '禁用'}")
    print("按 Ctrl+C 停止捕获...")
    print("=" * 50)
    
    try:
        sniff(
            prn=lambda pkt: handle_packet(pkt, config),
            store=False,
            filter="tcp",
            iface=config["IFACE"]
        )
    except KeyboardInterrupt:
        print("\n正在停止捕获并保存剩余会话...")
        with lock:
            for flow_key, writer in writers.items():
                try:
                    writer.close()
                    if args.debug:
                        stream_info = streams.get(flow_key, {})
                        duration = time.time() - stream_info.get('start_time', time.time())
                        print(f"[+] 关闭流: {flow_key}, 持续时间: {duration:.2f}s")
                except Exception as e:
                    print(f"[-] 关闭写入器失败: {e}")
            streams.clear()
            writers.clear()
        print(f"捕获完成，总共处理了 {packet_count} 个TCP数据包")
        sys.exit(0)
    except Exception as e:
        print(f"捕获过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)