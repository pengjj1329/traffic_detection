import pandas as pd
import numpy as np
import os
from datetime import datetime
import warnings
import time
import json
import glob
import csv

# Scapy 导入
from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, Raw
from scapy.layers.inet import IP, TCP, UDP

warnings.filterwarnings('ignore')


class PcapngToCsvConverter:
    """
    PCAPNG文件转换为CSV格式的转换器
    基于Scapy的版本：无需安装Wireshark
    输出格式与tshark版本完全一致
    """

    def __init__(self, config_file=r"C:\Users\彭俊杰\Desktop\新建文件夹\config.json"):
        self.config = self. load_config(config_file)
        self.processed_count = 0
        self.start_time = None
        self.processed_files = set()
        
        # 确保输出目录存在
        os.makedirs(self.config["output_dir"], exist_ok=True)

    def load_config(self, config_file):
        """加载配置文件"""
        default_config = {
            "monitor_dir": r"F:\python\traffic_detection\pcapng",
            "output_dir": r"F:\python\traffic_detection\converted_data",
            "check_interval": 60,
            "timeout_minutes": 30,
            "use_streaming": True,
            "packet_limit": 0
        }

        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json. load(f)
                default_config.update(user_config)
                print(f"✅ 加载配置文件:  {config_file}")
            except Exception as e:
                print(f"⚠️ 配置文件加载失败，使用默认配置: {e}")
        else: 
            try:
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=4, ensure_ascii=False)
                print(f"✅ 创建默认配置文件: {config_file}")
            except Exception as e:
                print(f"⚠️ 创建配置文件失败: {e}")

        return default_config

    def extract_packets_to_csv(self, pcapng_file, output_csv):
        """使用Scapy提取数据包信息到CSV - 与tshark输出格式一致"""
        try:
            print("🚀🚀🚀🚀 使用Scapy开始提取数据包信息...")
            print(f"📁 输入文件: {pcapng_file}")
            
            file_size = os.path. getsize(pcapng_file) / (1024 * 1024)
            print(f"📊 文件大小: {file_size:.2f} MB")
            
            # 与tshark输出完全一致的表头
            headers = [
                'frame.time_epoch',
                'ip.src',
                'ip.dst',
                'tcp.srcport',
                'tcp.dstport',
                'frame.len',
                'ip.len',
                'tcp.len',
                'tcp.window_size',
                'ip.ttl',
                'tcp.analysis.ack_rtt',
                'frame.time_delta',
                'tcp.flags',
                'tcp.seq',
                'tcp.ack'
            ]
            
            rows = []
            packet_count = 0
            tcp_count = 0
            
            # 用于计算RTT的会话追踪（模拟tshark的tcp.analysis.ack_rtt）
            session_tracker = {}
            # 用于计算frame.time_delta（与同一流中前一个包的时间差）
            flow_last_time = {}
            
            if self.config. get("use_streaming", True):
                print("📖 使用流式读取模式...")
                packet_iterator = PcapReader(pcapng_file)
            else:
                print("📖 使用完整读取模式...")
                packet_iterator = rdpcap(pcapng_file)
            
            for pkt in packet_iterator:
                packet_count += 1
                
                if self.config.get("packet_limit", 0) > 0:
                    if packet_count > self. config["packet_limit"]:
                        break
                
                if packet_count % 10000 == 0:
                    print(f"  已处理 {packet_count} 个数据包...")
                
                if IP in pkt and TCP in pkt: 
                    tcp_count += 1
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]
                    
                    current_time = float(pkt.time)
                    
                    # 创建流标识（双向）
                    flow_key = tuple(sorted([
                        (ip_layer.src, tcp_layer.sport),
                        (ip_layer.dst, tcp_layer. dport)
                    ]))
                    
                    # 计算frame.time_delta（与同一流中前一个包的时间差，模拟tshark行为）
                    if flow_key in flow_last_time: 
                        time_delta = current_time - flow_last_time[flow_key]
                    else: 
                        time_delta = 0
                    flow_last_time[flow_key] = current_time
                    
                    tcp_payload_len = len(tcp_layer.payload) if tcp_layer. payload else 0
                    
                    # 计算RTT（模拟tshark的tcp.analysis. ack_rtt）
                    rtt = self._calculate_rtt(
                        ip_layer.src, ip_layer.dst,
                        tcp_layer.sport, tcp_layer. dport,
                        tcp_layer.seq, tcp_layer. ack,
                        current_time, session_tracker
                    )
                    
                    # TCP flags转换为tshark格式（十六进制）
                    tcp_flags = self._extract_tcp_flags_hex(tcp_layer)
                    
                    row = [
                        current_time,
                        ip_layer.src,
                        ip_layer. dst,
                        tcp_layer.sport,
                        tcp_layer.dport,
                        len(pkt),
                        ip_layer.len,
                        tcp_payload_len,
                        tcp_layer. window,
                        ip_layer.ttl,
                        rtt if rtt else '',
                        time_delta,
                        tcp_flags,
                        tcp_layer.seq,
                        tcp_layer.ack,
                    ]
                    rows.append(row)
            
            if self.config.get("use_streaming", True):
                packet_iterator.close()
            
            print(f"📝 写入CSV文件...")
            with open(output_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer. writerows(rows)
            
            print(f"✅ 数据包提取完成: {output_csv}")
            print(f"📊 总数据包:  {packet_count}, TCP数据包: {tcp_count}")
            return True
            
        except Exception as e: 
            print(f"❌❌❌❌ 提取过程中出错:  {e}")
            import traceback
            traceback.print_exc()
            return False

    def _extract_tcp_flags_hex(self, tcp_layer):
        """提取TCP标志位 - 转换为tshark的十六进制格式"""
        flags_value = int(tcp_layer. flags)
        return f"0x{flags_value:04x}"

    def _calculate_rtt(self, src_ip, dst_ip, src_port, dst_port, seq, ack, timestamp, tracker):
        """
        计算TCP RTT - 模拟tshark的tcp. analysis.ack_rtt
        """
        rtt = None
        
        if ack > 0:
            ack_key = (src_ip, src_port, dst_ip, dst_port, ack)
            if ack_key in tracker:
                rtt = timestamp - tracker[ack_key]
                del tracker[ack_key]
        
        if seq > 0:
            seq_key = (dst_ip, dst_port, src_ip, src_port, seq + 1)
            tracker[seq_key] = timestamp
        
        if len(tracker) > 100000:
            keys_to_delete = list(tracker.keys())[: 50000]
            for key in keys_to_delete:
                del tracker[key]
        
        return rtt

    def clean_csv_file(self, csv_file_path):
        """更安全的CSV文件清理方法"""
        try:
            print(f"🧹🧹🧹🧹 清理CSV文件:  {csv_file_path}")

            backup_path = csv_file_path + ".backup"
            if not os.path.exists(backup_path):
                os.rename(csv_file_path, backup_path)

            cleaned_lines = []
            with open(backup_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            header = lines[0] if lines else ""
            cleaned_lines.append(header)

            for i, line in enumerate(lines[1:], 1):
                line = line.strip()

                fields = line.split(',')
                expected_fields = len(header.split(','))

                if len(fields) > expected_fields: 
                    fields = fields[:expected_fields - 1] + [','.join(fields[expected_fields - 1:])]
                elif len(fields) < expected_fields:
                    fields.extend([''] * (expected_fields - len(fields)))

                cleaned_fields = []
                for field in fields:
                    field = field.replace('\n', ' ').replace('\r', ' ').strip()
                    field = field.replace('\\', '/')
                    field = field.replace('"', "'")
                    cleaned_fields.append(field)

                cleaned_line = ','. join(cleaned_fields)
                cleaned_lines.append(cleaned_line + '\n')

                if i % 10000 == 0:
                    print(f"  已清理 {i}/{len(lines) - 1} 行")

            with open(csv_file_path, 'w', encoding='utf-8') as f:
                f. writelines(cleaned_lines)

            print(f"✅ CSV文件清理完成，共清理 {len(lines) - 1} 行数据")

            if os.path.exists(backup_path):
                os.remove(backup_path)

            return True

        except Exception as e:
            print(f"❌❌ CSV文件清理失败: {e}")
            if 'backup_path' in locals() and os.path. exists(backup_path):
                os. rename(backup_path, csv_file_path)
            return False

    def safe_read_csv(self, file_path):
        """安全读取CSV文件，处理各种格式问题"""
        try:
            try:
                df = pd.read_csv(file_path, encoding='utf-8')
                return df
            except: 
                try:
                    df = pd.read_csv(file_path, encoding='latin-1')
                    return df
                except:
                    df = pd.read_csv(file_path, encoding='utf-8',
                                     on_bad_lines='skip',
                                     quoting=0,
                                     skipinitialspace=True)
                    return df
        except Exception as e: 
            print(f"❌❌ 读取CSV文件失败: {e}")
            return None

    def process_session(self, session_id, group, session_features):
        """处理单个会话（与第一段代码完全一致）"""
        try:
            packet_count = len(group)

            # 计算前向流量的到达时间间隔
            forward_mask = group['source_IP_address'] == group['source_IP_address'].iloc[0]
            forward_group = group[forward_mask]. sort_values('timestamp')

            if len(forward_group) > 1:
                deltas = forward_group['timestamp'].diff().dropna()
                mean_interval_forward = deltas.mean() if not deltas. empty else 0
                std_interval_forward = deltas.std() if not deltas. empty else 0
            else:
                mean_interval_forward = 0
                std_interval_forward = 0

            # 与第一段代码完全一致的session_data结构
            session_data = {
                'session':  session_id,
                'source_IP_address': group['source_IP_address']. iloc[0],
                'Destination_IP_address':  group['Destination_IP_address'].iloc[0],
                'Source_port':  group['Source_port'].iloc[0],
                'Destination_port':  group['Destination_port'].iloc[0],

                # 基本流量特征
                'flow duration': group['timestamp'].max() - group['timestamp'].min(),
                'Packets_From_Clients': len(forward_group),
                'Packets_From_Servers': len(group[~forward_mask]),
                'Bytes_From_Clients(IPpacket)': group[forward_mask]['Length_of_IP_packets'].sum(),
                'Bytes_From_Servers(IPpacket)': group[~forward_mask]['Length_of_IP_packets']. sum(),

                # 统计特征
                'mean_Length_of_IP_packets': group['Length_of_IP_packets'].mean(),
                'std_Length_of_IP_packets': group['Length_of_IP_packets'].std(),
                'mean_Length_of_TCP_payload': group['Length_of_TCP_payload'].mean(),
                'std_Length_of_TCP_payload': group['Length_of_TCP_payload'].std(),
                'mean_Time_difference_between_packets_per_session': group[
                    'Time_difference_between_packets_per_session'].mean(),
                'std_Time_difference_between_packets_per_session':  group[
                    'Time_difference_between_packets_per_session'].std(),

                # 新添加的特征
                'mean_Interval_of_arrival_time_of_forward_traffic': mean_interval_forward,
                'std_Interval_of_arrival_time_of_forward_traffic': std_interval_forward,

                # 其他重要特征
                'Total_length_of_forward_payload': group[forward_mask]['Length_of_TCP_payload'].sum(),
                'Total_length_of_backward_payload': group[~forward_mask]['Length_of_TCP_payload'].sum(),

                # 添加更多特征
                'Time_to_live': group['Time_to_live']. mean(),
                'TCP_windows_size_value': group['TCP_windows_size_value'].mean(),
                'Original_Packet_Count': packet_count,
            }

            session_features.append(session_data)
            self.processed_count += 1

            if self.processed_count % 10 == 0:
                elapsed = time.time() - self.start_time
                print(f"  已处理 {self.processed_count} 个会话，耗时:  {elapsed:.2f}秒")

            return True

        except Exception as e:
            print(f"❌❌ 处理会话 {session_id} 时出错: {e}")
            return False

    def process_to_session_level(self, raw_csv_file, output_session_csv, timeout_minutes=30):
        """优化的会话级特征处理（与第一段代码完全一致）"""
        self.start_time = time.time()
        self.processed_count = 0

        try:
            print("📊📊📊📊 开始处理会话级特征...")

            if not self.clean_csv_file(raw_csv_file):
                print("⚠️⚠️ CSV清理可能不完整，继续处理...")

            print("📖📖 读取CSV文件...")
            df = self.safe_read_csv(raw_csv_file)
            if df is None or df.empty:
                print("❌❌ 读取的CSV文件为空或格式错误")
                return None

            print(f"原始数据包数量: {len(df)}")

            # 清理列名中可能存在的空格
            df. columns = df.columns.str. strip()

            # 检查必要的列是否存在
            required_columns = ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport']
            missing_columns = [col for col in required_columns if col not in df. columns]
            if missing_columns: 
                print(f"❌❌ 缺少必要列:  {missing_columns}")
                print(f"可用列: {df. columns.tolist()}")
                return None

            # 重命名列（与第一段代码完全一致）
            column_mapping = {
                'frame.time_epoch': 'timestamp',
                'ip.src': 'source_IP_address',
                'ip.dst': 'Destination_IP_address',
                'tcp.srcport': 'Source_port',
                'tcp.dstport': 'Destination_port',
                'frame.len':  'frame_length',
                'ip.len': 'Length_of_IP_packets',
                'tcp.len': 'Length_of_TCP_payload',
                'tcp.window_size': 'TCP_windows_size_value',
                'ip.ttl':  'Time_to_live',
                'tcp.analysis.ack_rtt': 'TCP_ACK_RTT',
                'frame.time_delta': 'Time_difference_between_packets_per_session',
                'tcp.flags':  'TCP_flags'
            }

            existing_columns = {col: column_mapping[col] for col in column_mapping. keys() if col in df.columns}
            df = df.rename(columns=existing_columns)

            # 基本数据清理和类型转换
            print("🔧🔧 数据清理和类型转换...")
            numeric_columns = ['timestamp', 'Source_port', 'Destination_port', 'frame_length',
                               'Length_of_IP_packets', 'Length_of_TCP_payload', 'TCP_windows_size_value',
                               'Time_to_live', 'TCP_ACK_RTT', 'Time_difference_between_packets_per_session']

            for col in numeric_columns:
                if col in df. columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

            # 处理无穷大值
            numeric_cols = df.select_dtypes(include=[np. number]).columns
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)

            # 创建会话标识
            print("🔍🔍 创建会话标识...")
            df['session_id'] = df['source_IP_address']. astype(str) + '_' + \
                               df['Destination_IP_address'].astype(str) + '_' + \
                               df['Source_port'].astype(str) + '_' + \
                               df['Destination_port'].astype(str)

            # 统计所有会话
            print("📊📊 统计会话...")
            session_sizes = df['session_id'].value_counts()
            all_sessions = session_sizes.index.tolist()

            print(f"总会话数量: {len(session_sizes)}")

            if not all_sessions:
                print("⚠️⚠️ 没有找到任何会话")
                empty_df = pd.DataFrame(columns=['session', 'source_IP_address', 'Destination_IP_address',
                                                 'Source_port', 'Destination_port', 'flow duration',
                                                 'Packets_From_Clients', 'Packets_From_Servers'])
                empty_df.to_csv(output_session_csv, index=False)
                return empty_df

            # 处理所有会话
            print("⚙️⚙️ 开始处理会话...")
            session_features = []
            batch_size = 50
            total_sessions = len(all_sessions)

            for i in range(0, total_sessions, batch_size):
                batch_sessions = all_sessions[i:i + batch_size]
                batch_df = df[df['session_id'].isin(batch_sessions)]

                if time.time() - self.start_time > timeout_minutes * 60:
                    print(f"⏰⏰⏰ 处理超时（{timeout_minutes}分钟），已处理 {self.processed_count} 个会话")
                    break

                for session_id, group in batch_df.groupby('session_id'):
                    self.process_session(session_id, group, session_features)

            # 创建会话级DataFrame
            session_df = pd. DataFrame(session_features)

            if session_df.empty:
                print("⚠️⚠️ 没有成功处理任何会话")
                session_df = pd. DataFrame(columns=['session', 'source_IP_address', 'Destination_IP_address',
                                                   'Source_port', 'Destination_port', 'flow duration',
                                                   'Packets_From_Clients', 'Packets_From_Servers'])

            # 处理NaN值
            numeric_cols = session_df.select_dtypes(include=[np.number]).columns
            session_df[numeric_cols] = session_df[numeric_cols].fillna(0)

            # 保存为CSV
            session_df.to_csv(output_session_csv, index=False)
            elapsed = time.time() - self.start_time
            print(f"✅ 会话级CSV保存完成:  {output_session_csv}")
            print(f"⏱️⏱️⏱️ 总耗时: {elapsed:.2f}秒")
            print(f"📊📊 处理的会话数量:  {len(session_df)}")

            return session_df

        except Exception as e: 
            print(f"❌❌❌❌❌❌❌❌ 会话级处理失败: {e}")
            import traceback
            traceback.print_exc()
            return None

    def convert_pcapng_to_csv(self, pcapng_file):
        if not os.path.exists(pcapng_file):
            print(f"❌ 文件不存在: {pcapng_file}")
            return False

        base_name = os. path.splitext(os.path.basename(pcapng_file))[0]

        # 输出文件：直接加 _session.csv
        output_csv = os.path.join(self.config["output_dir"], base_name + "_session.csv")

        print(f"📁 输入:  {pcapng_file}")
        print(f"📁 输出: {output_csv}")

        temp_raw = output_csv. replace(".csv", "_temp_raw.csv")
        if not self.extract_packets_to_csv(pcapng_file, temp_raw):
            return False

        session_df = self.process_to_session_level(temp_raw, output_csv, self.config["timeout_minutes"])

        if os.path.exists(temp_raw):
            os.remove(temp_raw)

        return session_df is not None

    def monitor_and_convert(self):
        """监控文件夹并转换新文件"""
        print(f"🔍🔍🔍🔍 开始监控文件夹: {self. config['monitor_dir']}")
        print(f"⏰⏰ 检查间隔:  {self.config['check_interval']}秒")

        while True:
            try:
                if not os.path.exists(self.config["monitor_dir"]):
                    print(f"❌❌ 监控文件夹不存在: {self. config['monitor_dir']}")
                    time.sleep(self.config["check_interval"])
                    continue

                pcap_files = []
                for ext in ['*.pcap', '*.pcapng']:
                    pattern = os.path. join(self.config["monitor_dir"], ext)
                    pcap_files.extend(glob.glob(pattern))

                new_files = [f for f in pcap_files if f not in self.processed_files]

                if new_files: 
                    print(f"📁📁 发现 {len(new_files)} 个新文件")

                    for pcap_file in new_files:
                        print(f"\n🔄🔄 处理文件: {pcap_file}")
                        if self.convert_pcapng_to_csv(pcap_file):
                            self.processed_files.add(pcap_file)
                            print(f"✅✅ 文件处理完成: {pcap_file}")
                        else: 
                            print(f"❌❌ 文件处理失败:  {pcap_file}")
                else:
                    print(f"⏳⏳ 未发现新文件，等待 {self.config['check_interval']} 秒...")

                time.sleep(self.config["check_interval"])

            except KeyboardInterrupt:
                print("\n⏹️⏹️ 用户中断监控")
                break
            except Exception as e: 
                print(f"❌❌ 监控过程中出错: {e}")
                time.sleep(self.config["check_interval"])


def main():
    """主函数"""
    converter = PcapngToCsvConverter(r"C:\Users\10544\Downloads\python314\config.json")

    print("=" * 60)
    print("📊📊 PCAP文件监控转换器 (Scapy版本 - 兼容tshark输出)")
    print("=" * 60)
    print(f"监控文件夹: {converter.config['monitor_dir']}")
    print(f"输出文件夹: {converter. config['output_dir']}")
    print(f"检查间隔: {converter.config['check_interval']}秒")
    print("=" * 60)

    converter.monitor_and_convert()


if __name__ == "__main__": 
    main()