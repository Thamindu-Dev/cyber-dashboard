# DDoS Detection System - Frontend Dashboard

A modern, cybersecurity-themed web interface for the AI-Powered DDoS Detection System. Built with pure HTML5, CSS3, and Vanilla JavaScript.

## 📖 Project Overview

The frontend dashboard provides an intuitive interface for analyzing network traffic data using machine learning models. Users can upload CSV files containing network flow data and receive real-time attack detection analysis with interactive visualizations.

### What It Does

- **Upload Interface**: Drag-and-drop CSV file upload with visual feedback
- **Real-time Analysis**: Sends data to backend API and displays results
- **Interactive Visualizations**: Charts showing attack distribution and severity levels
- **Critical Alerts**: Detailed table of high-severity threats
- **User Guidance**: Built-in documentation and CSV format reference

### Architecture

```
User Interface (HTML/CSS/JS)
         ↓
   API Communication
         ↓
   Backend API Response
         ↓
   Chart.js Visualization
```

## 🎨 Features

- **Dark Cybersecurity Theme**: Professional dark mode with neon blue accents
- **Drag & Drop Upload**: Intuitive file upload with visual feedback
- **Interactive Charts**: Real-time visualization using Chart.js
  - Attack Distribution (Pie Chart)
  - Severity Distribution (Bar Chart)
- **Critical Alerts Table**: Detailed view of high-severity threats (>70%)
- **User Guide Modal**: Comprehensive documentation
- **Column Reference**: Complete list of 81 required CSV columns
- **Sample CSV Download**: Template generator for proper data format
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Status Badges**: Color-coded severity indicators
- **Protocol Badges**: TCP/UDP/ICMP color coding

## 📁 Project Structure

```
frontend/
├── index.html          # Main HTML structure
├── styles.css          # Custom CSS styles (uses Tailwind CDN)
├── app.js             # All JavaScript functionality
└── README.md          # This file
```

## 🚀 How to Use

### 1. Access the Dashboard

Open the `index.html` file in your web browser or access the deployed URL.

### 2. Understand the Interface

**Header Section:**
- **Logo**: DDoS Detection System branding
- **User Guide Button**: Opens comprehensive documentation
- **Column Reference Button**: Shows required CSV format

**Upload Section:**
- **Drag & Drop Area**: Drop your CSV file here
- **Browse Button**: Alternative file selection method
- **File Info**: Shows selected file name and size
- **Analyze Button**: Starts the analysis process

**Results Section:**
- **Summary Cards**: Key statistics at a glance
- **Charts**: Visual representation of attacks and severity
- **Critical Alerts Table**: Detailed threat information

### 3. Prepare Your Data

**Required CSV Format:**
Your CSV must contain exactly **81 columns** in the correct order.

**Get the Template:**
1. Click the **"Column Reference"** button
2. Click **"Download Sample CSV Template"**
3. Open the template and add your network traffic data
4. Ensure all 81 columns are present and in order

**Data Requirements:**
- All features must be numeric
- Non-numeric columns (IPs, timestamps) are automatically removed
- Missing values should be removed before upload
- Infinity values are automatically handled

### 4. Upload and Analyze

**Step-by-Step:**
1. Prepare your CSV file with network traffic data
2. Drag and drop the file into the upload area
3. Verify file information is displayed correctly
4. Click the **"Analyze"** button
5. Wait for processing (1-10 seconds depending on file size)
6. View results automatically displayed below

### 5. Interpret Results

**Summary Cards:**
- **Total Flows**: Number of network flows analyzed
- **Attack Types**: Different attack types detected
- **Avg Severity**: Mean severity score across all flows
- **Critical Alerts**: Number of high-severity threats (>70%)

**Attack Distribution Chart:**
- Shows proportion of each attack type
- Hover for detailed percentages
- Color-coded by attack category

**Severity Distribution Chart:**
- Four risk levels with flow counts
- Green (Low) → Red (Critical)
- Identify overall threat landscape

**Critical Alerts Table:**
- Lists most severe threats first
- Shows flow index, attack type, severity
- Displays network ports and protocol
- Color-coded severity badges

## 🎯 Understanding Attack Types

The system detects 14 different attack types:

| Attack Type | Severity | Description |
|-------------|----------|-------------|
| **BENIGN** | 0% | Normal traffic, no threat |
| **SYN Flood** | 80% | Overwhelms with TCP connection requests |
| **UDP Flood** | 80% | Floods target with UDP packets |
| **DrDoS_DNS** | 60% | DNS amplification attack |
| **DrDoS_NTP** | 60% | NTP amplification attack |
| **DrDoS_SNMP** | 60% | SNMP amplification attack |
| **DrDoS_SSDP** | 60% | SSDP amplification attack |
| **LDAP** | 70% | LDAP protocol attack |
| **MSSQL** | 70% | MSSQL database attack |
| **NetBIOS** | 70% | NetBIOS protocol attack |
| **TFTP** | 70% | TFTP protocol attack |
| **Portmap** | 40% | Portmapper attack |
| **UDP-lag** | 50% | UDP-based lag attack |
| **WebDDoS** | 30% | Web-layer DDoS attack |

## 📊 Severity Levels

The severity score ranges from 0-100%:

| Range | Level | Action Required |
|-------|-------|-----------------|
| **0-30%** | Low Risk | Monitor |
| **31-60%** | Medium Risk | Investigate |
| **61-85%** | High Risk | Mitigate |
| **86-100%** | Critical | Immediate Action |

## 🎨 UI Components

### Color Scheme

- **Background**: Dark gray (#0a0a0f, #1a1a2e)
- **Primary Accent**: Neon Cyan (#06b6d4)
- **Alert Color**: Red (#ef4444)
- **Success Color**: Green (#22c55e)
- **Warning Color**: Yellow/Orange (#fbbf24)

### Interactive Elements

**Severity Badges:**
- 🟢 Low Risk (Green)
- 🟡 Medium Risk (Orange)
- 🟠 High Risk (Yellow)
- 🔴 Critical (Red)

**Protocol Badges:**
- 🔵 TCP (Blue)
- 🟣 UDP (Purple)
- 🟠 ICMP (Orange)

### Animations

- **Fade-in Modals**: Smooth appearance
- **Hover Effects**: Visual feedback on interactive elements
- **Chart Animations**: Data visualization transitions
- **Table Rows**: Slide-in effect for alerts

## ⚙️ Configuration

### API URL Configuration

To connect to your backend, edit the API URL in `app.js`:

```javascript
// Line 2 in app.js
const API_BASE_URL = 'http://localhost:8000';
```

For different environments:
```javascript
// Local development
const API_BASE_URL = 'http://localhost:8000';

// Production server
const API_BASE_URL = 'https://your-api-domain.com';

// HuggingFace Spaces
const API_BASE_URL = 'https://your-space.hf.space';
```

### Customization

**Change Colors:**
Edit `styles.css` to modify the color scheme:

```css
/* Primary accent color */
:root {
    --primary-color: #06b6d4;  /* Cyan */
}

/* Alert colors */
.severity-critical {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
}
```

**Modify Chart Settings:**
Chart configurations are in `app.js`:

```javascript
// Attack Distribution Chart (pie chart)
// Severity Distribution Chart (bar chart)
```

## 🔍 CSV Column Reference

The complete list of 81 required columns (in order):

### Network Basics
1. Source Port
2. Destination Port
3. Protocol
4. Flow Duration

### Packet Counts
5. Total Fwd Packets
6. Total Backward Packets
7. Total Length of Fwd Packets
8. Total Length of Bwd Packets

### Packet Length Statistics
9. Fwd Packet Length Max
10. Fwd Packet Length Min
11. Fwd Packet Length Mean
12. Fwd Packet Length Std
13. Bwd Packet Length Max
14. Bwd Packet Length Min
15. Bwd Packet Length Mean
16. Bwd Packet Length Std

### Flow Metrics
17. Flow Bytes/s
18. Flow Packets/s
19. Flow IAT Mean
20. Flow IAT Std
21. Flow IAT Max
22. Flow IAT Min

### Forward IAT
23. Fwd IAT Total
24. Fwd IAT Mean
25. Fwd IAT Std
26. Fwd IAT Max
27. Fwd IAT Min

### Backward IAT
28. Bwd IAT Total
29. Bwd IAT Mean
30. Bwd IAT Std
31. Bwd IAT Max
32. Bwd IAT Min

### Flags
33. Fwd PSH Flags
34. Bwd PSH Flags
35. Fwd URG Flags
36. Bwd URG Flags
37. Fwd Header Length
38. Bwd Header Length

### Packet Rates
39. Fwd Packets/s
40. Bwd Packets/s

### Packet Statistics
41. Min Packet Length
42. Max Packet Length
43. Packet Length Mean
44. Packet Length Std
45. Packet Length Variance

### TCP Flags
46. FIN Flag Count
47. SYN Flag Count
48. RST Flag Count
49. PSH Flag Count
50. ACK Flag Count
51. URG Flag Count
52. CWE Flag Count
53. ECE Flag Count

### Ratios
54. Down/Up Ratio
55. Average Packet Size
56. Avg Fwd Segment Size
57. Avg Bwd Segment Size
58. Fwd Header Length.1

### Bulk Transfer
59. Fwd Avg Bytes/Bulk
60. Fwd Avg Packets/Bulk
61. Fwd Avg Bulk Rate
62. Bwd Avg Bytes/Bulk
63. Bwd Avg Packets/Bulk
64. Bwd Avg Bulk Rate

### Subflow Statistics
65. Subflow Fwd Packets
66. Subflow Fwd Bytes
67. Subflow Bwd Packets
68. Subflow Bwd Bytes

### Window Size
69. Init_Win_bytes_forward
70. Init_Win_bytes_backward
71. act_data_pkt_fwd
72. min_seg_size_forward

### Active/Idle Time
73. Active Mean
74. Active Std
75. Active Max
76. Active Min
77. Idle Mean
78. Idle Std
79. Idle Max
80. Idle Min
81. Inbound

*Click "Column Reference" button in the app and use "Copy List" to get all columns.*

## ❓ FAQ

**Q: What file format is supported?**
A: Only CSV files are supported. The file must contain exactly 81 numeric columns.

**Q: Is there a file size limit?**
A: The browser can handle files up to 100MB. Larger files may be slow to upload.

**Q: How long does analysis take?**
A: Typically 1-10 seconds depending on file size and server performance.

**Q: Can I analyze multiple files?**
A: Yes, upload files one at a time. Previous results remain visible until you upload a new file.

**Q: What if my CSV has missing columns?**
A: The analysis will fail with an error message listing missing features.

**Q: Are my files stored anywhere?**
A: No, files are only used for analysis and not stored on the server.

**Q: Can I download the results?**
A: Currently, results are displayed on screen. You can use browser print/save to PDF.

**Q: Which browsers are supported?**
A: All modern browsers: Chrome, Firefox, Safari, Edge (desktop and mobile).

## 🛠️ Technical Stack

- **HTML5**: Semantic markup
- **CSS3**: Custom styles with Tailwind CSS CDN
- **Vanilla JavaScript**: No frameworks required
- **Chart.js 4.4.0**: Data visualization
- **Google Fonts**: Inter, JetBrains Mono

## 📱 Browser Support

✅ Chrome/Edge (Full support)
✅ Firefox (Full support)
✅ Safari (Full support)
✅ Mobile browsers (Responsive)

---

Built with ❤️ using HTML5, CSS3, and Vanilla JavaScript
