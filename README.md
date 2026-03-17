# AI-Powered DDoS Detection System

A complete machine learning system for detecting DDoS attacks in network traffic using XGBoost models trained on the CICDDoS2019 dataset.

## 📖 Project Overview

This system provides end-to-end DDoS attack detection by analyzing network flow data using trained machine learning models. It consists of a FastAPI backend for ML inference and a modern web interface for user interaction.

### What It Does

The system analyzes network traffic data (CSV files) and provides:

- **Attack Classification**: Identifies 14 different DDoS attack types
- **Threat Scoring**: Predicts severity levels (0-100%) for each network flow
- **Critical Alerts**: Flags high-risk traffic requiring immediate attention
- **Comprehensive Analysis**: Full statistics and visualizations

### Use Cases

- **Network Security Monitoring**: Continuous analysis of network traffic
- **Incident Response**: Quick identification of active attacks
- **Forensic Analysis**: Post-attack investigation and evidence gathering
- **Security Research**: Study of DDoS attack patterns
- **Educational**: Learn about ML applications in cybersecurity

## 🏗️ Architecture

```
┌─────────────────┐
│  Frontend       │  HTML/CSS/JS Dashboard
│  (Dashboard)    │  - File upload
└────────┬────────┘  - Visualizations
         │            - Results display
         ↓
┌─────────────────┐
│  Backend API    │  FastAPI Server
└────────┬────────┘  - Endpoint: /upload-csv
         │            - Rate limiting
         ↓
┌─────────────────┐
│  XGBoost Models │  ML Inference
│                 │  - Classifier (14 classes)
│  • Classifier   │  - Regressor (0-100%)
│  • Regressor    │  - GPU-accelerated
└─────────────────┘
```

## 📁 Project Structure

```
cybersecurity_dashboard/
├── backend/                # FastAPI backend API
│   ├── app.py             # Main application
│   ├── requirements.txt   # Python dependencies
│   ├── Dockerfile         # Container configuration
│   ├── README.md          # Backend documentation
│   ├── Classification model/
│   │   ├── xgboost_ddos_classifier.json
│   │   └── label_encoder.joblib
│   └── Regression Model/
│       ├── xgboost_severity_regressor.json
│       └── traffic_scaler.joblib
│
├── frontend/              # Web dashboard
│   ├── index.html        # Main HTML
│   ├── styles.css        # Custom styles
│   ├── app.js           # JavaScript logic
│   └── README.md        # Frontend documentation
│
├── model_train.ipynb     # Model training notebook
├── Master_DDoS_Dataset.csv  # CICDDoS2019 dataset
└── README.md            # This file
```

## 🚀 Components

### 1. Backend API (`backend/`)

FastAPI-based REST API that handles ML inference.

**Key Features:**
- XGBoost model loading and inference
- CSV data preprocessing
- Attack classification (14 types)
- Severity prediction (0-100%)
- Rate limiting (10 uploads/minute)
- GPU acceleration support

**Main Endpoint:**
- `POST /upload-csv` - Upload CSV for analysis

**Documentation:** See [backend/README.md](backend/README.md)

### 2. Frontend Dashboard (`frontend/`)

Modern web interface for user interaction.

**Key Features:**
- Drag-and-drop file upload
- Interactive charts (Chart.js)
- Real-time results display
- Critical alerts table
- User guide and documentation

**Technologies:**
- HTML5, CSS3, Vanilla JavaScript
- Tailwind CSS (CDN)
- Chart.js for visualizations

**Documentation:** See [frontend/README.md](frontend/README.md)

### 3. ML Models

Two XGBoost models trained on CICDDoS2019:

**Classifier:**
- 14-class multi-class classification
- Detects specific DDoS attack types
- F1-score: 80%

**Regressor:**
- Predicts threat severity (0-100%)
- MAE: 4.18%, RMSE: 6.96%
- Based on attack type + traffic volume

## 🎯 Detected Attack Types

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| BENIGN | Normal traffic | 0% |
| SYN Flood | TCP connection flood | 80% |
| UDP Flood | UDP packet flood | 80% |
| DrDoS_DNS | DNS amplification | 60% |
| DrDoS_NTP | NTP amplification | 60% |
| DrDoS_SNMP | SNMP amplification | 60% |
| DrDoS_SSDP | SSDP amplification | 60% |
| LDAP | LDAP protocol attack | 70% |
| MSSQL | MSSQL attack | 70% |
| NetBIOS | NetBIOS attack | 70% |
| TFTP | TFTP attack | 70% |
| Portmap | Portmapper attack | 40% |
| UDP-lag | UDP lag attack | 50% |
| WebDDoS | Web DDoS | 30% |

## 📊 Required Data Format

### CSV Requirements

Input CSV files must contain **81 numeric features** in exact order:

**Network Layer:**
- Source Port, Destination Port, Protocol

**Flow Statistics:**
- Flow Duration, Total Fwd Packets, Total Backward Packets
- Flow Bytes/s, Flow Packets/s

**Packet Metrics:**
- Packet Length Mean/Std/Max/Min
- Forward/Backward packet lengths

**Timing:**
- Flow IAT (Inter-Arrival Time)
- Active/Idle times

**Flags:**
- TCP Flags (FIN, SYN, RST, PSH, ACK, URG)
- Protocol-specific flags

**And 50+ more features...**

*See [Column Reference](frontend/README.md#-csv-column-reference) for complete list.*

### Sample Data Flow

```csv
Source Port,Destination Port,Protocol,Flow Duration,Total Fwd Packets,...
12345,80,6,1000000,500,...
54321,443,6,2000000,1000,...
```

*Download template from the frontend dashboard.*

## 🔬 Model Performance

### Training Details

| Metric | Value |
|--------|-------|
| **Dataset** | CICDDoS2019 |
| **Training Samples** | 635,110 (post-SMOTE) |
| **Test Samples** | 69,438 |
| **Features** | 81 numeric features |
| **Balancing** | SMOTE oversampling |

### Model Metrics

| Model | Metric | Score |
|-------|--------|-------|
| **Classifier** | F1-Score | 80% |
| **Classifier** | Accuracy | 80% |
| **Regressor** | MAE | 4.18% |
| **Regressor** | RMSE | 6.96% |

## 🔍 How It Works

### Analysis Pipeline

1. **Data Input**: User uploads CSV with network traffic data
2. **Preprocessing**:
   - Strip column names
   - Remove non-numeric columns
   - Handle infinity/NaN values
   - Validate feature presence
3. **Inference**:
   - Classify attack type (Classifier)
   - Predict severity score (Regressor)
4. **Results**:
   - Generate comprehensive report
   - Calculate statistics
   - Identify critical alerts
5. **Visualization**:
   - Display attack distribution
   - Show severity levels
   - List critical threats

### Severity Calculation

Severity scores (0-100%) are computed from:
- **Base Score**: Attack type (0-80%)
- **Traffic Factor**: Network volume (0-20%)
- **Final Score**: Base + Traffic (capped at 100%)

Example:
- SYN Flood base: 80%
- High traffic factor: +15%
- **Final severity**: 95%

## 📖 Usage Guide

### Quick Start

1. **Prepare your CSV** with network traffic data (81 columns)
2. **Access the dashboard** by opening `frontend/index.html`
3. **Upload your file** using drag-and-drop or browse
4. **View results** with interactive charts and alerts

### Getting Data

**Option 1: Network Capture**
- Export from Wireshark/tshark
- Convert to CSV format
- Ensure all 81 features are present

**Option 2: Use Sample Data**
- Download template from dashboard
- Add synthetic/mock data for testing
- Verify column order matches

**Option 3: Public Datasets**
- CICDDoS2019 (training dataset)
- Other network traffic datasets
- Ensure feature compatibility

### Interpreting Results

**Summary Cards:**
- **Total Flows**: Data points analyzed
- **Attack Types**: Different attacks detected
- **Avg Severity**: Overall threat level
- **Critical Alerts**: High-risk flow count

**Attack Distribution:**
- Shows which attacks are present
- Proportion of each attack type
- Identifies dominant threats

**Severity Distribution:**
- Low Risk (0-30%): Monitor
- Medium Risk (31-60%): Investigate
- High Risk (61-85%): Mitigate
- Critical (86-100%): Act immediately

**Critical Alerts:**
- Most severe threats first
- Network flow details
- Protocol and port information
- Actionable intelligence

## 🔒 Security Features

- **Rate Limiting**: 10 uploads/minute prevents abuse
- **Input Validation**: Ensures data integrity
- **No Data Storage**: Files analyzed and discarded
- **Privacy**: IP addresses automatically removed
- **CORS Protection**: Controlled access

## 🛠️ Technical Stack

### Backend
- FastAPI 0.109.0
- XGBoost 2.0.3
- Pandas 2.1.4
- NumPy 1.26.3
- Scikit-learn 1.4.0
- SlowAPI 0.1.9 (rate limiting)

### Frontend
- HTML5
- CSS3 (Tailwind CSS CDN)
- Vanilla JavaScript
- Chart.js 4.4.0

### ML/AI
- XGBoost (gradient boosting)
- SMOTE (oversampling)
- MinMaxScaler (normalization)

## 📚 Documentation

- **Backend**: [backend/README.md](backend/README.md) - API documentation
- **Frontend**: [frontend/README.md](frontend/README.md) - Dashboard usage
- **Training**: `model_train.ipynb` - Model training notebook

## ❓ FAQ

**Q: What's the maximum file size?**
A: Up to 100MB CSV files. Larger files may timeout.

**Q: How accurate is the detection?**
A: 80% F1-score on test set. May vary with different data.

**Q: Can I use this for real-time detection?**
A: Designed for batch analysis. For real-time, consider streaming approaches.

**Q: What if my data has different features?**
A: All 81 features must match. Consider retraining models for different features.

**Q: Can I retrain the models?**
A: Yes, see `model_train.ipynb` for training code.

**Q: Is this suitable for production?**
A: Yes, with proper deployment and monitoring. Rate limiting is included.

**Q: Can I add new attack types?**
A: Retrain models with new labeled data including the new attack types.

## 🙏 Acknowledgments

- **Dataset**: CICDDoS2019 from Canadian Institute for Cybersecurity
- **Models**: XGBoost by DMLC
- **Inspiration**: Network security research community

## 📄 License

MIT License - Free to use, modify, and distribute

---

Built with ❤️ for cybersecurity and network protection
