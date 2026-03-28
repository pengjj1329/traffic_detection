import pandas as pd
import numpy as np
import warnings
import joblib
import json
import os
from datetime import datetime
import re
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

warnings.filterwarnings('ignore')


class PaperBasedPredictor:
    """
    基于论文的预测器，持续监控模式
    """

    def __init__(self, predict_malicious_config_path="predict_malicious_config.json"):
        self.model = None
        self.scaler = None
        self.features = []
        self.predict_malicious_config = self.load_predict_malicious_config(predict_malicious_config_path)
        self.processed_files = set()  # 记录已处理的文件
        self.running = True  # 控制监控循环
        self.malicious_events = []  # 存储恶意事件

        # 初始化结果文件
        self.init_result_file()

    def load_predict_malicious_config(self, predict_malicious_config_path):
        """加载配置文件"""
        try:
            with open(predict_malicious_config_path, 'r', encoding='utf-8') as f:
                predict_malicious_config = json.load(f)
            print("✅ 配置文件加载成功")
            return predict_malicious_config
        except Exception as e:
            print(f"❌ 配置文件加载失败: {e}")
            # 创建默认配置
            default_predict_malicious_config = {
                "model_path": "trained_model_paper_20251022_112659.pkl",
                "monitor_folder": "E:/project/process_data/converted_data",
                "result_file": "E:/project/process_data/malicious_events.json",
                "check_interval": 60  # 检查间隔（秒）
            }
            # 保存默认配置
            with open(predict_malicious_config_path, 'w', encoding='utf-8') as f:
                json.dump(default_predict_malicious_config, f, ensure_ascii=False, indent=4)
            print("✅ 已创建默认配置文件")
            return default_predict_malicious_config

    def init_result_file(self):
        """初始化结果文件，确保有正确的结构"""
        try:
            result_file = self.predict_malicious_config["result_file"]
            result_dir = os.path.dirname(result_file)

            # 确保目录存在
            if not os.path.exists(result_dir):
                os.makedirs(result_dir)
                print(f"✅ 创建目录: {result_dir}")

            # 如果文件不存在，创建并写入基本结构
            if not os.path.exists(result_file):
                # 创建基本JSON结构
                json_data = {
                    "events": []
                }

                with open(result_file, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, ensure_ascii=False, indent=4)
                print(f"✅ JSON结果文件已初始化: {result_file}")
            else:
                # 如果文件存在，尝试加载现有事件
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)

                    if "events" in existing_data:
                        # 将现有事件加载到内存中
                        self.malicious_events = existing_data["events"]
                        print(f"✅ 已加载 {len(self.malicious_events)} 个现有恶意事件")
                    else:
                        # 如果结构不正确，重新初始化
                        json_data = {
                            "events": []
                        }
                        with open(result_file, 'w', encoding='utf-8') as f:
                            json.dump(json_data, f, ensure_ascii=False, indent=4)
                        print(f"✅ 已重新初始化JSON结果文件: {result_file}")
                except Exception as e:
                    # 如果读取失败，重新创建
                    print(f"⚠️ 读取现有结果文件失败，将重新创建: {e}")
                    json_data = {
                        "events": []
                    }
                    with open(result_file, 'w', encoding='utf-8') as f:
                        json.dump(json_data, f, ensure_ascii=False, indent=4)

        except Exception as e:
            print(f"❌ 初始化结果文件失败: {e}")

    def load_model(self):
        """加载模型"""
        try:
            model_path = self.predict_malicious_config["model_path"]
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.features = model_data['features']
            print("✅ 模型加载成功")
            return True
        except Exception as e:
            print(f"❌ 模型加载失败: {e}")
            return False

    def load_and_preprocess_data(self, data_path):
        """加载和预处理数据"""
        try:
            df = pd.read_csv(data_path)
            print(f"✅ 数据加载成功: {df.shape}")

            # 预处理
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
            df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())

            return df
        except Exception as e:
            print(f"❌ 数据加载错误: {e}")
            return None

    def extract_connection_info_from_filename(self, filename):
        """
        匹配格式：
        TCP_srcIP_srcPort_to_dstIP_dstPort_timestamp_label_pid_session.csv
        """
        pattern = (
            r'^TCP_(\d+\.\d+\.\d+\.\d+)_(\d+)_to_(\d+\.\d+\.\d+\.\d+)_(\d+)'
            r'_(\d{10,})'  # timestamp
            r'_([01])'  # label
            r'_(\d+)'  # pid
            r'_session\.csv$'
        )
        match = re.match(pattern, filename)
        if match:
            src_ip, src_port, dst_ip, dst_port, timestamp, label, pid = match.groups()
            return {
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "timestamp": int(timestamp),
                "label": int(label),
                "pid": int(pid),
                # 注意：原代码中的 session_time 是从 date_str/time_str 来的，但现在没有这些字段
                # 如果不需要，可以移除；如果需要时间，可从 timestamp 转换
                "session_time": datetime.fromtimestamp(int(timestamp)).strftime("%Y%m%d_%H%M%S")
            }
        else:
            print(f"⚠️ 无法从文件名提取连接信息: {filename}")
            return None

    def save_malicious_events_to_json(self, df, malicious_indices, connection_info):
        """保存恶意事件到JSON文件"""
        try:
            result_file = self.predict_malicious_config["result_file"]

            # 为每个恶意索引创建事件
            new_events = []
            for idx in malicious_indices:
                if idx < len(df):
                    # 创建事件对象
                    event = {
                        "local_ip": connection_info["dst_ip"],  # 目标IP作为本地IP
                        "local_port": connection_info["dst_port"],  # 目标端口作为本地端口
                        "pid": connection_info["pid"],
                        "timestamp": connection_info["timestamp"]
                    }
                    new_events.append(event)

            # 添加到内存中的事件列表
            self.malicious_events.extend(new_events)

            # 保存到JSON文件
            json_data = {
                "events": self.malicious_events
            }

            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=4)

            print(f"✅ 恶意事件已保存到: {result_file}")
            print(f"📊 共保存 {len(new_events)} 个新恶意事件，总计 {len(self.malicious_events)} 个事件")

            # 显示新保存的事件信息
            if new_events:
                print("\n=== 新保存的恶意事件信息 ===")
                for event in new_events:
                    print(f"  - PID: {event['pid']}, 本地IP: {event['local_ip']}, 本地端口: {event['local_port']}")

            return True
        except Exception as e:
            print(f"❌ 保存恶意事件到JSON错误: {e}")
            return False

    def predict_file(self, file_path):
        """对单个文件进行预测"""
        try:
            # 检查是否已处理过该文件
            if file_path in self.processed_files:
                print(f"⏭️ 文件已处理过，跳过: {os.path.basename(file_path)}")
                return

            print(f"\n🔍 开始处理文件: {os.path.basename(file_path)}")

            # 加载模型（如果尚未加载）
            if self.model is None:
                if not self.load_model():
                    return

            # 加载数据
            test_df = self.load_and_preprocess_data(file_path)
            if test_df is None:
                return

            # 检查特征是否存在
            missing_features = [f for f in self.features if f not in test_df.columns]
            if missing_features:
                print(f"⚠️ 缺失特征列: {missing_features}")
                return

            # 从文件名提取连接信息
            filename = os.path.basename(file_path)
            connection_info = self.extract_connection_info_from_filename(filename)
            if connection_info is None:
                return

            # 提取特征并进行预测
            X_test = test_df[self.features]
            X_test_scaled = self.scaler.transform(X_test)

            predictions = self.model.predict(X_test_scaled)
            probabilities = self.model.predict_proba(X_test_scaled)

            # 检测恶意流量
            malicious_indices = [i for i, pred in enumerate(predictions) if pred == 1]

            if malicious_indices:
                print(f"🔍 检测到 {len(malicious_indices)} 个恶意流量")
                # 保存恶意事件到JSON
                self.save_malicious_events_to_json(test_df, malicious_indices, connection_info)
            else:
                print("✅ 未检测到恶意流量")

            # 标记文件为已处理
            self.processed_files.add(file_path)
            print(f"✅ 文件处理完成: {filename}")

            return True

        except Exception as e:
            print(f"❌ 文件预测错误: {e}")
            return False

    def monitor_folder(self):
        """监控文件夹并处理新文件"""
        try:
            monitor_folder = self.predict_malicious_config["monitor_folder"]

            if not os.path.exists(monitor_folder):
                print(f"❌ 监控文件夹不存在: {monitor_folder}")
                return

            # 查找CSV文件
            csv_files = []
            for file in os.listdir(monitor_folder):
                if file.endswith('.csv') and 'TCP' in file:
                    file_path = os.path.join(monitor_folder, file)
                    csv_files.append(file_path)

            # 处理新文件
            new_files = [f for f in csv_files if f not in self.processed_files]

            if new_files:
                print(f"\n📁 发现 {len(new_files)} 个新文件")
                for file_path in new_files:
                    self.predict_file(file_path)
            else:
                print("⏰ 未发现新文件，等待下次检查...")

        except Exception as e:
            print(f"❌ 文件夹监控错误: {e}")

    def start_periodic_monitoring(self):
        """启动定期监控"""
        check_interval = self.predict_malicious_config.get("check_interval", 60)
        print(f"⏰ 启动定时检查模式，每隔 {check_interval} 秒检查一次...")

        # 立即执行一次检查
        self.monitor_folder()

        # 定期检查循环
        while self.running:
            time.sleep(check_interval)
            self.monitor_folder()


class FileMonitorHandler(FileSystemEventHandler):
    """文件系统事件处理器"""

    def __init__(self, predictor):
        self.predictor = predictor

    def on_created(self, event):
        """文件创建事件 - 只处理最终的 _session.csv 文件"""
        if not event.is_directory and event.src_path.endswith('.csv'):
            filename = os.path.basename(event.src_path)
            # 忽略临时文件（如 _temp_raw.csv, _raw_...）
            if '_temp_raw' in filename or '_raw_' in filename:
                print(f"⏭️ 忽略临时文件: {filename}")
                return
            # 只处理以 _session.csv 结尾的文件
            if not filename.endswith('_session.csv'):
                print(f"⏭️ 忽略非会话文件: {filename}")
                return

            print(f"📁 检测到新会话文件: {filename}")
            time.sleep(2)  # 等待写入完成
            # 强制使用配置目录拼接路径（避免路径错乱）
            full_path = os.path.join(
                self.predictor.predict_malicious_config["monitor_folder"],
                filename
            )
            self.predictor.predict_file(full_path)


def main():
    """主函数 - 持续监控模式"""
    print("🚀 启动流量检测系统...")

    # 创建预测器
    predictor = PaperBasedPredictor("predict_malicious_config.json")

    # 显示配置信息
    print("\n=== 系统配置 ===")
    for key, value in predictor.predict_malicious_config.items():
        print(f"  {key}: {value}")

    # 选择监控模式
    print("\n=== 监控模式选择 ===")
    print("1. 定时检查模式（每分钟检查一次）")
    print("2. 实时监控模式（文件创建时立即检测）")

    choice = input("请选择监控模式 (1/2): ").strip()

    if choice == "1":
        # 定时检查模式 - 使用简单的time.sleep实现
        try:
            predictor.start_periodic_monitoring()
        except KeyboardInterrupt:
            predictor.running = False
            print("\n👋 程序已退出")

    elif choice == "2":
        # 实时监控模式
        print("🔍 启动实时监控模式...")
        monitor_folder = predictor.predict_malicious_config["monitor_folder"]

        # 确保监控文件夹存在
        if not os.path.exists(monitor_folder):
            print(f"❌ 监控文件夹不存在: {monitor_folder}")
            return

        # 创建观察者
        observer = Observer()
        event_handler = FileMonitorHandler(predictor)
        observer.schedule(event_handler, monitor_folder, recursive=False)
        observer.start()

        print(f"👀 开始监控文件夹: {monitor_folder}")
        print("按 Ctrl+C 退出程序")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            predictor.running = False
            print("\n👋 程序已退出")
        observer.join()

    else:
        print("❌ 无效选择，使用定时检查模式")
        # 默认使用定时检查模式
        try:
            predictor.start_periodic_monitoring()
        except KeyboardInterrupt:
            predictor.running = False
            print("\n👋 程序已退出")


if __name__ == "__main__":
    main()