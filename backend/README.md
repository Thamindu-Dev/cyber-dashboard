---
title: AI-Powered DDoS Detection System
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
pinned: false
license: mit
tags:
  - cybersecurity
  - ddos-detection
  - xgboost
  - machine-learning
  - network-security
---

# AI-Powered DDoS Detection System - Backend API

Production-ready FastAPI backend for detecting DDoS attacks using XGBoost models trained on the CICDDoS2019 dataset.

## 📖 Project Overview

This backend API provides machine learning-powered DDoS attack detection by analyzing network traffic flow data. It uses two XGBoost models trained on the CICDDoS2019 dataset to classify 14 different DDoS attack types and predict threat severity scores.

### What It Does

The API accepts CSV files containing network traffic data and returns:

- **Attack Classification**: Identifies which type of DDoS attack (if any)
- **Severity Scoring**: Predicts threat level from 0-100%
- **Critical Alerts**: Flags high-risk flows (>70% severity)
- **Comprehensive Analysis**: Full attack distribution and statistics

### Architecture

```
CSV Input → Preprocessing → XGBoost Models → Analysis Report
                     ↓
              [Classifier]     [Regressor]
                     ↓               ↓
              Attack Type    Severity Score
```

## 🚀 Features

- **14-Class Attack Classification**: Detects various DDoS attack types including SYN Flood, UDP Flood, DNS Amplification, and more
- **Threat Severity Scoring**: Predicts severity scores (0-100%) for each network flow
- **GPU-Accelerated**: Fast inference with CUDA support for RTX GPUs
- **Batch Processing**: Analyze entire CSV files in a single request
- **Critical Alert Detection**: Automatically flags high-severity threats (>70%)
- **API Rate Limiting**: Built-in protection against abuse (10 uploads/minute)
- **CORS Enabled**: Ready for frontend integration

## 📡 API Endpoints

### 1. POST /upload-csv

Main endpoint for analyzing network traffic data.

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body: CSV file with network traffic flows

**Required CSV Format:**
The CSV must contain exactly **81 numeric features** in the correct order:

```
Source Port, Destination Port, Protocol, Flow Duration, Total Fwd Packets,
Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean,
Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min,
Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s,
Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total,
Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total,
Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags,
Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length,
Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length,
Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,
FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count,
URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size,
Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length.1,
Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate,
Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate,
Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets,
Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward,
act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std,
Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Inbound
```

**Non-numeric columns** (automatically removed if present):
- `Unnamed: 0`, `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`, `SimillarHTTP`

**Response:**
```json
{
  "timestamp": "2024-01-01T12:00:00.000000Z",
  "input_filename": "traffic_data.csv",
  "processing_time_seconds": 2.34,
  "summary": {
    "total_flows_analyzed": 10000,
    "unique_attack_types_detected": 5,
    "average_severity_score": 45.67,
    "max_severity_score": 95.2,
    "min_severity_score": 0.0,
    "critical_alerts_count": 234,
    "benign_flow_count": 5000
  },
  "attack_distribution": {
    "BENIGN": 5000,
    "SYN": 2000,
    "UDP": 1500,
    "DrDoS_DNS": 800,
    "LDAP": 400,
    "MSSQL": 300
  },
  "severity_distribution": {
    "low_risk (0-30%)": 5500,
    "medium_risk (31-60%)": 2500,
    "high_risk (61-85%)": 1500,
    "critical (86-100%)": 500
  },
  "critical_alerts_sample": [
    {
      "flow_index": 42,
      "attack_type": "SYN",
      "severity_score": 92.5,
      "source_port": 12345,
      "destination_port": 80,
      "protocol": 6
    }
  ]
}
```

### 2. GET /health

Health check endpoint to verify API status and model availability.

**Response:**
```json
{
  "status": "healthy",
  "detail": "All systems operational",
  "models_loaded": {
    "classifier": true,
    "regressor": true,
    "label_encoder": true,
    "traffic_scaler": true
  },
  "gpu_enabled": true
}
```

### 3. GET /

Root endpoint with API information.

**Response:**
```json
{
  "message": "AI-Powered DDoS Detection System",
  "version": "1.0.0",
  "status": "operational",
  "rate_limits": {
    "upload_csv": "10 requests per minute",
    "health_check": "60 requests per minute",
    "root": "60 requests per minute"
  },
  "endpoints": {
    "/upload-csv": "POST - Upload CSV for analysis (10/minute)",
    "/health": "GET - Health check (60/minute)",
    "/": "GET - API information (60/minute)"
  }
}
```

## 🎯 Detected Attack Types

The classifier can identify 14 different attack types:

| Attack Type | Description | Base Severity |
|-------------|-------------|---------------|
| BENIGN | Normal traffic | 0% |
| DrDoS_DNS | DNS Amplification Attack | 60% |
| DrDoS_NTP | NTP Amplification Attack | 60% |
| DrDoS_SNMP | SNMP Amplification Attack | 60% |
| DrDoS_SSDP | SSDP Amplification Attack | 60% |
| LDAP | LDAP-based Attack | 70% |
| MSSQL | MSSQL Database Attack | 70% |
| NetBIOS | NetBIOS Attack | 70% |
| Portmap | Portmapper Attack | 40% |
| SYN | SYN Flood Attack | 80% |
| TFTP | TFTP Attack | 70% |
| UDP | UDP Flood Attack | 80% |
| UDP-lag | UDP Lag Attack | 50% |
| WebDDoS | Web-based DDoS | 30% |

## ⚡ Rate Limiting

To ensure fair usage and prevent abuse, the API implements rate limiting:

| Endpoint | Rate Limit | Purpose |
|----------|------------|---------|
| `POST /upload-csv` | 10 requests/minute | Resource-intensive ML inference |
| `GET /health` | 60 requests/minute | Lightweight status checks |
| `GET /` | 60 requests/minute | API information |

**Rate Limit Headers:**
Every response includes rate limit information:
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1641234567
```

**Rate Limited Response:**
```json
{
  "detail": "Rate limit exceeded: 10 per 1 minute"
}
```

## 📈 Model Performance

Models were trained on the CICDDoS2019 dataset with SMOTE balancing:

| Metric | Value | Description |
|--------|-------|-------------|
| Classification F1-Score | 80% | Overall accuracy across 14 classes |
| Regression MAE | 4.18% | Mean absolute error in severity prediction |
| Regression RMSE | 6.96% | Root mean squared error |

### Training Details

- **Dataset**: CICDDoS2019 (Canadian Institute for Cybersecurity)
- **Balancing**: SMOTE oversampling for minority classes
- **Training Size**: 635,110 flows (post-SMOTE)
- **Test Size**: 69,438 flows
- **Features**: 81 numeric network flow features

## 🛠️ Technical Stack

- **Framework**: FastAPI 0.109.0
- **Models**: XGBoost 2.0.3
- **Preprocessing**: Pandas 2.1.4, NumPy 1.26.3
- **Scaler**: Scikit-learn MinMaxScaler
- **Rate Limiting**: SlowAPI 0.1.9
- **GPU Support**: CUDA-compatible (RTX 4050 tested)

## 📖 Usage Guide

### Making API Requests

**Using cURL:**
```bash
# Health check
curl http://your-api-url/health

# Upload CSV for analysis
curl -X POST http://your-api-url/upload-csv \
  -F "file=@traffic_data.csv"
```

**Using Python:**
```python
import requests

# Upload CSV
with open("traffic_data.csv", "rb") as f:
    response = requests.post(
        "http://your-api-url/upload-csv",
        files={"file": f}
    )

result = response.json()
print(f"Total flows: {result['summary']['total_flows_analyzed']}")
print(f"Critical alerts: {result['summary']['critical_alerts_count']}")
```

**Using JavaScript:**
```javascript
// Upload CSV
const formData = new FormData();
formData.append('file', csvFile);

fetch('http://your-api-url/upload-csv', {
    method: 'POST',
    body: formData
})
.then(response => response.json())
.then(data => {
    console.log('Total flows:', data.summary.total_flows_analyzed);
    console.log('Critical alerts:', data.summary.critical_alerts_count);
});
```

## 🔍 Understanding the Results

### Summary Section

- **total_flows_analyzed**: Number of network flows processed
- **unique_attack_types_detected**: Different attack types found
- **average_severity_score**: Mean severity across all flows (0-100%)
- **max_severity_score**: Highest severity score detected
- **critical_alerts_count**: Number of flows with >70% severity
- **benign_flow_count**: Normal (non-attack) flows

### Attack Distribution

Breakdown of detected attacks by type, showing count for each category.

### Severity Distribution

Four risk categories:
- **Low Risk (0-30%)**: Minimal threat
- **Medium Risk (31-60%)**: Moderate threat level
- **High Risk (61-85%)**: Significant threat
- **Critical (86-100%)**: Severe threat requiring immediate attention

### Critical Alerts Sample

Up to 100 most severe flows with:
- Flow index (row number in CSV)
- Attack type
- Severity score
- Source port
- Destination port
- Protocol (6=TCP, 17=UDP, 1=ICMP)

## ❓ FAQ

**Q: What's the maximum file size?**
A: The API handles CSV files up to 100MB. Larger files may timeout.

**Q: How long does analysis take?**
A: Typically 1-3 seconds per 100,000 flows on GPU, 5-10 seconds on CPU.

**Q: Can I analyze real-time traffic?**
A: This API is designed for batch analysis. For real-time processing, consider streaming the data or using smaller batches.

**Q: What happens if my CSV has missing columns?**
A: You'll receive a 400 error listing the missing required features.

**Q: Are IP addresses stored?**
A: No, IP address columns (Source IP, Destination IP) are automatically removed during preprocessing.

**Q: Can I use this for commercial purposes?**
A: Yes, the system is licensed under MIT. Please ensure compliance with data privacy regulations.

---

Built with ❤️ for cybersecurity research and network protection.
