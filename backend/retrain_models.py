"""
Retrain models with sklearn 1.7.4 for HF Spaces compatibility
This will fix the version mismatch issue
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.metrics import classification_report, mean_absolute_error, mean_squared_error
import joblib
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("MODEL RETRAINING FOR HF SPACES COMPATIBILITY")
print("="*60)

# Load master dataset
print("\n[1] Loading master dataset...")
df = pd.read_csv('Master_DDoS_Dataset.csv', low_memory=False)
df.columns = df.columns.str.strip()

print(f"    Loaded {len(df):,} rows")

# Drop non-numeric columns
NON_NUMERIC = [
    'Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP',
    'Timestamp', 'SimillarHTTP'
]
df = df.drop(columns=NON_NUMERIC, errors='ignore')

# Replace infinity and drop NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

print(f"    After cleaning: {len(df):,} rows")

# Select features
FEATURE_COLUMNS = [
    'Source Port', 'Destination Port', 'Protocol', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Inbound'
]

X = df[FEATURE_COLUMNS].copy()
y = df['Label'].copy()

# Convert to numeric
for col in X.columns:
    X[col] = pd.to_numeric(X[col], errors='coerce')
X = X.dropna()

print(f"\n[2] Preparing data for training...")
print(f"    Features shape: {X.shape}")
print(f"    Labels shape: {y.shape}")
print(f"    Unique classes: {y.nunique()}")

# Create severity mapping
SEVERITY_MAP = {
    'BENIGN': 0,
    'WebDDoS': 30,
    'UDP-lag': 50,
    'Portmap': 40,
    'DrDoS_DNS': 60,
    'DrDoS_LDAP': 60,
    'DrDoS_SNMP': 60,
    'DrDoS_SSDP': 60,
    'DrDoS_NTP': 60,
    'DrDoS_UDP': 60,
    'DrDoS_NetBIOS': 60,
    'DrDoS_MSSQL': 60,
    'LDAP': 70,
    'MSSQL': 70,
    'NetBIOS': 70,
    'TFTP': 70,
    'UDP': 80,
    'Syn': 80
}

y_severity = y.map(SEVERITY_MAP)

# Train/test split
X_train, X_test, y_train, y_test, y_sev_train, y_sev_test = train_test_split(
    X, y, y_severity, test_size=0.2, random_state=42, stratify=y
)

print(f"    Train size: {len(X_train):,}")
print(f"    Test size: {len(X_test):,}")

# Train classifier
print(f"\n[3] Training XGBoost Classifier...")
classifier = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1
)
classifier.fit(X_train, y_train)

# Evaluate classifier
y_pred = classifier.predict(X_test)
print(f"    Classifier trained")
print(f"    Accuracy: {classifier.score(X_test, y_test):.4f}")

# Save classifier
Path('Classification model').mkdir(exist_ok=True)
classifier.save_model('Classification model/xgboost_ddos_classifier.json')
print(f"    Saved: Classification model/xgboost_ddos_classifier.json")

# Encode labels
print(f"\n[4] Encoding labels...")
label_encoder = LabelEncoder()
label_encoder.fit(y)
joblib.dump(label_encoder, 'Classification model/label_encoder.joblib')
print(f"    Saved: Classification model/label_encoder.joblib")

# Scale severity
print(f"\n[5] Training severity scaler...")
severity_scaler = MinMaxScaler()
severity_scaled = severity_scaler.fit_transform(y_sev_train.values.reshape(-1, 1))
joblib.dump(severity_scaler, 'Regression Model/traffic_scaler.joblib')
print(f"    Saved: Regression Model/traffic_scaler.joblib")

# Train regressor
print(f"\n[6] Training XGBoost Regressor...")
regressor = xgb.XGBRegressor(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1
)
regressor.fit(X_train, severity_scaled.ravel())

# Evaluate regressor
y_sev_pred_scaled = regressor.predict(X_test)
y_sev_pred = severity_scaler.inverse_transform(y_sev_pred_scaled.reshape(-1, 1)).flatten()
mae = mean_absolute_error(y_sev_test, y_sev_pred)
rmse = np.sqrt(mean_squared_error(y_sev_test, y_sev_pred))

print(f"    Regressor trained")
print(f"    MAE: {mae:.2f}%")
print(f"    RMSE: {rmse:.2f}%")

# Save regressor
Path('Regression Model').mkdir(exist_ok=True)
regressor.save_model('Regression Model/xgboost_severity_regressor.json')
print(f"    Saved: Regression model/xgboost_severity_regressor.json")

print(f"\n{'='*60}")
print(f"[SUCCESS] Models retrained with sklearn {joblib.__version__}")
print(f"{'='*60}")
print(f"\nThese models will work on HF Spaces with sklearn 1.7.4!")
print(f"\nNext steps:")
print(f"  1. Copy the model folders to your HF Space")
print(f"  2. Update requirements.txt with scikit-learn==1.7.4")
print(f"  3. Redeploy your HF Space")
