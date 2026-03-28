import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import warnings
import os
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib as mpl

# 设置全局字体（支持Windows/macOS/Linux）
plt.rcParams['font.sans-serif'] = ['SimHei']  # Windows系统黑体
# plt.rcParams['font.sans-serif'] = ['Heiti TC']  # macOS系统黑体
# plt.rcParams['font.sans-serif'] = ['WenQuanYi Micro Hei']  # Linux系统

# 解决负号显示问题
plt.rcParams['axes.unicode_minus'] = False
warnings.filterwarnings('ignore')


class PaperBasedModelTrainer:
    """
    基于论文严格实现的模型训练器
    """

    # 论文中明确的FOS特征集
    FOS_FEATURES = [
        'flow duration',
        'Packets_From_Clients',
        'Packets_From_Servers',
        'Bytes_From_Clients(IPpacket)',
        'Bytes_From_Servers(IPpacket)',
        'mean_Length_of_IP_packets',
        'std_Length_of_IP_packets',
        'mean_Length_of_TCP_payload',
        'std_Length_of_TCP_payload',
        'mean_Time_difference_between_packets_per_session',
        'std_Time_difference_between_packets_per_session',
        'mean_Interval_of_arrival_time_of_forward_traffic',
        'std_Interval_of_arrival_time_of_forward_traffic',
        'Total_length_of_forward_payload',
        'Total_length_of_backward_payload'
    ]

    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.actual_features = []
        self.train_history = []

    def load_data(self, data_path):
        """加载数据"""
        print("=== 加载数据 ===")
        try:
            df = pd.read_csv(data_path)
            print(f"✅ 数据集大小: {df.shape}")
            return df
        except Exception as e:
            print(f"❌ 数据加载错误: {e}")
            return None

    def validate_and_extract_features(self, df):
        """验证并提取论文中的FOS特征集"""
        print("=== 验证和提取FOS特征 ===")

        missing_features = []
        available_features = []

        for feature in self.FOS_FEATURES:
            if feature in df.columns:
                available_features.append(feature)
            else:
                missing_features.append(feature)
                # 尝试模糊匹配
                matching_cols = [col for col in df.columns if feature.lower() in col.lower()]
                if matching_cols:
                    available_features.extend(matching_cols[:1])  # 只取第一个匹配项

        print(f"✅ 可用的FOS特征: {len(available_features)}/{len(self.FOS_FEATURES)}")
        if missing_features:
            print(f"⚠️  缺失的特征: {missing_features}")

        # 检查特征有效性
        if len(available_features) < 10:
            print("❌ 可用特征过少，将使用所有数值特征")
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if 'label' in numeric_cols:
                numeric_cols.remove('label')
            available_features = numeric_cols[:20]  # 限制特征数量

        self.actual_features = available_features
        return available_features

    def advanced_preprocessing(self, df):
        """高级数据预处理"""
        print("=== 高级数据预处理 ===")

        # 创建副本
        processed_df = df.copy()

        # 1. 处理缺失值和异常值
        numeric_cols = processed_df.select_dtypes(include=[np.number]).columns
        processed_df[numeric_cols] = processed_df[numeric_cols].replace([np.inf, -np.inf], np.nan)

        # 2. 基于分位数的异常值处理
        for col in numeric_cols:
            if col in processed_df.columns:
                Q1 = processed_df[col].quantile(0.25)
                Q3 = processed_df[col].quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR

                # 缩尾处理
                processed_df[col] = np.where(processed_df[col] < lower_bound, lower_bound, processed_df[col])
                processed_df[col] = np.where(processed_df[col] > upper_bound, upper_bound, processed_df[col])

        # 3. 填充缺失值
        processed_df[numeric_cols] = processed_df[numeric_cols].fillna(processed_df[numeric_cols].mean())

        print("✅ 数据预处理完成")
        return processed_df

    def train_paper_model(self, X_train, y_train, X_val, y_val):
        """按照论文参数训练模型"""
        print("=== 按照论文参数训练模型 ===")

        # 论文中的参数设置
        self.model = RandomForestClassifier(
            n_estimators=500,  # 论文中使用的树数量
            max_depth=None,  # 不限制深度，让树充分生长
            min_samples_split=2,  # 论文中的默认设置
            min_samples_leaf=1,  # 论文中的默认设置
            max_features='sqrt',  # 论文中的特征选择策略
            bootstrap=True,  # 使用bootstrap采样
            oob_score=True,  # 计算袋外分数
            random_state=42,  # 确保可重复性
            n_jobs=-1,  # 使用所有CPU核心
            verbose=1  # 显示训练进度
        )

        print("开始训练模型...")
        self.model.fit(X_train, y_train)

        # 计算训练和验证准确率
        train_pred = self.model.predict(X_train)
        val_pred = self.model.predict(X_val)

        train_acc = accuracy_score(y_train, train_pred)
        val_acc = accuracy_score(y_val, val_pred)

        print(f"📊 训练准确率: {train_acc:.4f}")
        print(f"📊 验证准确率: {val_acc:.4f}")

        if hasattr(self.model, 'oob_score_'):
            print(f"📊 袋外分数: {self.model.oob_score_:.4f}")

        # 检查过拟合
        overfit_gap = train_acc - val_acc
        if overfit_gap > 0.1:
            print(f"⚠️  可能存在过拟合: 训练-验证差距 = {overfit_gap:.4f}")

        return train_acc, val_acc

    def analyze_feature_importance(self, feature_names):
        """分析特征重要性"""
        print("=== 特征重要性分析 ===")

        if self.model is None:
            print("❌ 请先训练模型")
            return

        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]

        # 创建特征重要性DataFrame
        importance_df = pd.DataFrame({
            'feature': [feature_names[i] for i in indices],
            'importance': importances[indices]
        })

        print("🔝 特征重要性排名:")
        print(importance_df.head(15))

        # 可视化
        plt.figure(figsize=(12, 8))
        plt.title("基于论文的特征重要性分析")
        top_features = min(15, len(importance_df))
        plt.barh(range(top_features), importance_df['importance'].head(top_features)[::-1])
        plt.yticks(range(top_features), importance_df['feature'].head(top_features)[::-1])
        plt.xlabel('重要性分数')
        plt.tight_layout()
        plt.savefig('feature_importance_paper.png')
        plt.show()

        return importance_df

    def diagnose_model_issues(self, X_train, y_train, X_val, y_val):
        """模型问题诊断"""
        print("=== 模型问题诊断 ===")

        # 预测结果
        y_train_pred = self.model.predict(X_train)
        y_val_pred = self.model.predict(X_val)

        # 准确率差异
        train_acc = accuracy_score(y_train, y_train_pred)
        val_acc = accuracy_score(y_val, y_val_pred)
        accuracy_gap = train_acc - val_acc

        print(f"训练准确率: {train_acc:.4f}")
        print(f"验证准确率: {val_acc:.4f}")
        print(f"准确率差距: {accuracy_gap:.4f}")

        # 过拟合诊断
        if accuracy_gap > 0.15:
            print("❌ 严重过拟合: 训练-验证差距 > 0.15")
            print("💡 建议: 增加正则化、减少特征数量、增加数据")
        elif accuracy_gap > 0.05:
            print("⚠️  中等过拟合: 训练-验证差距 > 0.05")
        else:
            print("✅ 过拟合程度正常")

        # 类别分布检查
        unique, counts = np.unique(y_train, return_counts=True)
        print(f"训练集类别分布: {dict(zip(unique, counts))}")

        unique, counts = np.unique(y_val, return_counts=True)
        print(f"验证集类别分布: {dict(zip(unique, counts))}")

        # 特征数量评估
        print(f"使用特征数量: {len(self.actual_features)}")
        if len(self.actual_features) > 50:
            print("⚠️  特征数量较多，可能增加过拟合风险")

    def save_model(self, model_name=None):
        """保存模型"""
        if self.model is None:
            print("❌ 没有模型可保存")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if model_name:
            filename = f"{model_name}_paper_{timestamp}.pkl"
        else:
            filename = f"trained_model_paper_{timestamp}.pkl"

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'features': self.actual_features,
            'feature_importance': self.analyze_feature_importance(self.actual_features) if self.model else None
        }

        joblib.dump(model_data, filename)
        print(f"✅ 模型已保存为: {filename}")

        return filename


def main():
    """主训练函数"""
    trainer = PaperBasedModelTrainer()

    # 加载数据
    train_df = trainer.load_data(r'D:\ztyk4h3v6s-1\Machine_Learning\train_set.csv')
    if train_df is None:
        return

    # 高级预处理
    processed_df = trainer.advanced_preprocessing(train_df)

    # 验证和提取特征
    features = trainer.validate_and_extract_features(processed_df)

    # 准备数据
    X = processed_df[features]
    y = processed_df['label']

    # 分割数据集
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 标准化特征
    X_train_scaled = trainer.scaler.fit_transform(X_train)
    X_val_scaled = trainer.scaler.transform(X_val)

    # 训练模型
    train_acc, val_acc = trainer.train_paper_model(X_train_scaled, y_train, X_val_scaled, y_val)

    # 特征重要性分析
    trainer.analyze_feature_importance(features)

    # 模型问题诊断
    trainer.diagnose_model_issues(X_train_scaled, y_train, X_val_scaled, y_val)

    # 保存模型
    trainer.save_model()

    print("🎉 基于论文的训练完成!")


if __name__ == "__main__":
    main()