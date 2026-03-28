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

    def __init__(self, predict_all_config_path="predict_all_config.json"):
        self.model = None
        self.scaler = None
        self.features = []
        self.predict_all_config = self.load_predict_all_config(predict_all_config_path)
        self.processed_files = set()  # 记录已处理的文件
        self.running = True  # 控制监控循环

        # 初始化结果文件
        self.init_result_file()

    def load_predict_all_config(self, predict_all_config_path):
        """加载配置文件"""
        try:
            with open(predict_all_config_path, 'r', encoding='utf-8') as f:
                predict_all_config = json.load(f)
            print("✅ 配置文件加载成功")
            return predict_all_config
        except Exception as e:

            print(f"❌ 配置文件加载失败: {e}")
            # 创建默认配置
            default_predict_all_config = {
                "model_path": "trained_model_paper_20251022_112659.pkl",
                "monitor_folder": "F:/python/traffic_detection/converted_data",
                "result_file": "F:/python/traffic_detection/predictions_results.csv",
                "check_interval": 60  # 检查间隔（秒）
            }
            # 保存默认配置
            with open(predict_all_config_path, 'w', encoding='utf-8') as f:
                json.dump(default_predict_all_config, f, ensure_ascii=False, indent=4)
            print("✅ 已创建默认配置文件")
            return default_predict_all_config

    def init_result_file(self):
        """初始化结果文件，确保有正确的字段名"""
        try:
            result_file = self.predict_all_config["result_file"]
            result_dir = os.path.dirname(result_file)

            # 确保目录存在
            if not os.path.exists(result_dir):
                os.makedirs(result_dir)
                print(f"✅ 创建目录: {result_dir}")

            # 如果文件不存在，创建并写入表头
            if not os.path.exists(result_file):
                # 定义字段名
                columns = ["源IP", "源端口", "目标IP", "目标端口", "pid", "是否为恶意"]

                # 创建带字段名的空DataFrame
                header_df = pd.DataFrame(columns=columns)
                header_df.to_csv(result_file, index=False, encoding='utf-8-sig')
                print(f"✅ 结果文件已初始化: {result_file}")
            else:
                # 检查现有文件是否有正确的字段名
                try:
                    existing_df = pd.read_csv(result_file)
                    expected_columns = ["源IP", "源端口", "目标IP", "目标端口", "pid", "是否为恶意"]

                    if not all(col in existing_df.columns for col in expected_columns):
                        # 如果字段名不正确，重新创建文件
                        columns = ["源IP", "源端口", "目标IP", "目标端口", "pid", "是否为恶意"]
                        header_df = pd.DataFrame(columns=columns)
                        header_df.to_csv(result_file, index=False, encoding='utf-8-sig')
                        print(f"✅ 已重新初始化结果文件字段: {result_file}")
                    else:
                        print(f"✅ 结果文件已存在且字段正确: {result_file}")
                except Exception as e:
                    # 如果读取现有文件失败，重新创建
                    print(f"⚠️ 读取现有结果文件失败，将重新创建: {e}")
                    columns = ["源IP", "源端口", "目标IP", "目标端口", "pid", "是否为恶意"]
                    header_df = pd.DataFrame(columns=columns)
                    header_df.to_csv(result_file, index=False, encoding='utf-8-sig')

        except Exception as e:
            print(f"❌ 初始化结果文件失败: {e}")

    def load_model(self):
        """加载模型"""
        try:
            model_path = self.predict_all_config["model_path"]
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
        """从文件名中提取连接信息（修正后的格式）"""
        try:
            # 修正后的格式：TCP_源IP_源端口_to_目标IP_目标端口_时间戳_标签_pid_session_日期_时间
            # 示例：TCP_10.201.149.158_5301_to_183.60.183.105_60932_1763110980_0_0_session_20251114_170427.csv
            pattern = r'TCP_([\d\.]+)_(\d+)_to_([\d\.]+)_(\d+)_(\d+)_([01])_(\d+)_session_(\d+)_(\d+)\.csv'
            match = re.search(pattern, filename)

            if match:
                src_ip, src_port, dst_ip, dst_port, timestamp, label, pid, session_date, session_time = match.groups()

                connection_info = {
                    "src_ip": src_ip,
                    "src_port": int(src_port),
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port),
                    "pid": int(pid),
                    "timestamp": int(timestamp),
                    "session_timestamp": f"{session_date}_{session_time}",
                    "filename": filename
                }

                print(f"✅ 成功提取连接信息: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, PID: {pid}")
                return connection_info
            else:
                # 尝试另一种可能的格式（没有.pcapng部分）
                pattern2 = r'TCP_([\d\.]+)_(\d+)_to_([\d\.]+)_(\d+)_(\d+)_([01])_(\d+)_(\d+)_(\d+)_session_(\d+)_(\d+)\.csv'
                match2 = re.search(pattern2, filename)

                if match2:
                    src_ip, src_port, dst_ip, dst_port, timestamp, label, pid, date1, time1, session_date, session_time = match2.groups()

                    connection_info = {
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "dst_ip": dst_ip,
                        "dst_port": int(dst_port),
                        "pid": int(pid),
                        "timestamp": int(timestamp),
                        "session_timestamp": f"{session_date}_{session_time}",
                        "filename": filename
                    }

                    print(f"✅ 成功提取连接信息（格式2）: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, PID: {pid}")
                    return connection_info

                print(f"⚠️ 无法从文件名提取连接信息: {filename}")
                return None
        except Exception as e:
            print(f"❌ 提取连接信息错误: {e}")
            return None

    def save_predictions_to_result_file(self, df, predictions, connection_info):
        """保存预测结果到结果文件"""
        try:
            result_file = self.predict_all_config["result_file"]

            # 创建结果数据，只包含要求的字段
            results_data = []
            for idx, (_, row) in enumerate(df.iterrows()):
                result_row = {
                    "源IP": connection_info["src_ip"],
                    "源端口": connection_info["src_port"],
                    "目标IP": connection_info["dst_ip"],
                    "目标端口": connection_info["dst_port"],
                    "pid": connection_info["pid"],
                    "是否为恶意": int(predictions[idx])  # 确保是整数类型
                }
                results_data.append(result_row)

            # 创建DataFrame
            results_df = pd.DataFrame(results_data)

            # 检查文件是否存在
            if os.path.exists(result_file) and os.path.getsize(result_file) > 0:
                # 追加到现有文件
                results_df.to_csv(result_file, mode='a', header=False, index=False, encoding='utf-8-sig')
            else:
                # 创建新文件（包含表头）
                results_df.to_csv(result_file, index=False, encoding='utf-8-sig')

            print(f"✅ 预测结果已保存到: {result_file}")
            print(f"📊 共保存 {len(results_data)} 条记录")

            # 显示恶意流量统计
            malicious_count = sum(predictions)
            if malicious_count > 0:
                print(f"🔍 检测到 {malicious_count} 个恶意流量")
            else:
                print("✅ 未检测到恶意流量")

            return True
        except Exception as e:
            print(f"❌ 保存预测结果错误: {e}")
            return False

    def predict_file(self, file_path):
        """对单个文件进行预测"""
        try:
            # 检查是否已处理过该文件
            if file_path in self.processed_files:
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

            # 保存预测结果
            self.save_predictions_to_result_file(test_df, predictions, connection_info)

            # 标记文件为已处理
            self.processed_files.add(file_path)

            return True

        except Exception as e:
            print(f"❌ 文件预测错误: {e}")
            return False

    def monitor_folder(self):
        """监控文件夹并处理新文件"""
        try:
            monitor_folder = self.predict_all_config["monitor_folder"]

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
        check_interval = self.predict_all_config.get("check_interval", 60)
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
        """文件创建事件"""
        if not event.is_directory and event.src_path.endswith('.csv'):
            print(f"📁 检测到新文件: {os.path.basename(event.src_path)}")
            # 等待文件完全写入
            time.sleep(2)
            self.predictor.predict_file(event.src_path)


def main():
    """主函数 - 持续监控模式"""
    print("🚀 启动流量检测系统...")

    # 创建预测器
    predictor = PaperBasedPredictor("predict_all_config.json")

    # 显示配置信息
    print("\n=== 系统配置 ===")
    for key, value in predictor.predict_all_config.items():
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
        monitor_folder = predictor.predict_all_config["monitor_folder"]

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