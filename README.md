# 🛡️ Network Intrusion Log Analyser

A professional web-based cybersecurity application for analyzing network/firewall logs and detecting suspicious network behavior using rule-based detection and machine learning.

## 📋 Overview

This system provides SOC-style security analysis capabilities including log parsing, threat detection, incident correlation, timeline analysis, and ML-based anomaly classification. Built for educational purposes and college project demonstration.

## ✨ Features

### Core Capabilities
- **Log Parsing & Validation** - Parse firewall logs with regex-based extraction and field validation
- **Database Storage** - Efficient SQLite storage with indexed queries
- **Statistical Analysis** - Pandas-powered analytics and aggregations
- **Rule-Based Detection** - Explainable threat detection with configurable thresholds
- **Machine Learning** - Random Forest classifier for anomaly detection
- **Incident Correlation** - Group related alerts into cohesive security incidents
- **Interactive Dashboard** - Professional Streamlit UI with Plotly visualizations
- **Report Generation** - Export security reports in CSV format

### Detection Rules
1. **Port Scanning** - Detects sources contacting many unique ports within short time windows
2. **Repeated Connection Attempts** - Identifies brute-force-like behavior
3. **Excessive Denied Traffic** - Flags sources with high denial rates
4. **High Connection Frequency** - Detects unusually rapid connection patterns

### Analysis Features
- Top source/destination IPs
- Port distribution analysis
- Protocol statistics
- Traffic over time visualization
- Denied traffic tracking
- IP investigation tools
- Event timeline generation

## 🚀 Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.14 |
| Web Framework | Streamlit |
| Data Analysis | Pandas |
| Database | SQLite |
| Machine Learning | Scikit-learn (Random Forest) |
| Visualization | Plotly |
| Parsing | Regex |
| Testing | Pytest |

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Setup

1. **Clone/Download the repository**
```bash
cd network-intrusion-analyser
```

2. **Install dependencies**
```bash
python -m pip install -r requirements.txt
```

3. **Generate sample data** (Optional - UI can do this too)
```bash
python -m app.utils.generate_data
```

4. **Run the application**
```bash
python run.py
```

Or directly:
```bash
streamlit run app/main.py
```

The application will open in your browser at `http://localhost:8501`

## 📖 Usage Guide

### 1. Upload Logs
- Navigate to **Upload Logs** page
- Click **Load Sample Data** to use pre-generated dataset
- Or upload custom TXT log files

**Expected Log Format:**
```
YYYY-MM-DD HH:MM:SS SOURCE_IP:PORT -> DEST_IP:PORT PROTOCOL ACTION
```

Example:
```
2024-10-01 09:00:01 203.0.113.5:45123 -> 10.0.1.15:443 TCP ALLOW
```

### 2. View Dashboard
- Overview KPIs (total events, allowed/denied, unique IPs)
- Traffic over time charts
- Top source IPs and destination ports
- Protocol distribution
- Real-time threat summary

### 3. Threat Detection
- View detected alerts with severity (CRITICAL, HIGH, MEDIUM, LOW)
- Filter by severity and alert type
- Read detailed explanations and recommendations
- Review evidence for each detection

### 4. Incidents
- Grouped related alerts by source IP
- Incident timelines showing event sequences
- Risk scoring and status tracking
- Investigative context for analysts

### 5. IP Analysis
- Select any source IP for deep investigation
- View connection patterns and behavior
- Analyze targeted ports and destinations
- Identify anomalies

### 6. ML Analysis
- View ML model predictions and confidence scores
- Feature importance visualization
- Suspicious IP ranking by threat probability
- Model metrics and evaluation

### 7. Reports
- Generate comprehensive security reports
- Export alerts, incidents, and logs to CSV
- Download for documentation or further analysis

## 🏗️ Architecture

```
network-intrusion-analyser/
├── app/
│   ├── main.py                 # Streamlit app entry point
│   ├── parser/
│   │   └── log_parser.py       # Regex-based log parsing
│   ├── database/
│   │   ├── schema.sql          # SQLite schema
│   │   └── db.py               # Database operations
│   ├── detection/
│   │   ├── rules.py            # Rule-based detection engine
│   │   └── incidents.py        # Incident correlation
│   ├── ml/
│   │   ├── features.py         # Feature engineering
│   │   ├── train.py            # Model training
│   │   └── predict.py          # ML predictions
│   ├── analysis/
│   │   └── analytics.py        # Pandas analytics
│   ├── reporting/
│   │   └── reports.py          # Report generation
│   ├── ui/                     # Streamlit UI pages
│   │   ├── dashboard.py
│   │   ├── upload.py
│   │   ├── logs.py
│   │   ├── threats.py
│   │   ├── incidents.py
│   │   ├── ip_analysis.py
│   │   ├── ml_page.py
│   │   └── reports.py
│   └── utils/
│       └── generate_data.py    # Synthetic data generator
├── data/
│   └── sample/                 # Sample datasets
├── models/                     # Trained ML models
├── tests/                      # Unit tests
├── reports/                    # Generated reports
├── database/                   # SQLite database files
├── requirements.txt
├── run.py
└── README.md
```

## 🧪 Testing

Run unit tests:
```bash
pytest tests/
```

Tests cover:
- Log parser validation
- Database operations
- Detection rule logic
- ML pipeline functionality

## 🔍 Detection Methodology

### Rule-Based Detection

Each rule uses configurable thresholds and provides:
- Clear explanation of detected pattern
- Evidence (counts, ratios, time windows)
- Risk score (0-100)
- Severity classification
- Remediation recommendations

**Example: Port Scanning Detection**
- Threshold: 20+ unique ports in 10 minutes
- Evidence: Port list, target count, denied ratio
- Risk calculation: Base score + port count + denial ratio

### Machine Learning Detection

- **Model:** Random Forest Classifier
- **Training Data:** Synthetic labeled dataset (normal vs suspicious)
- **Features:** Connection count, deny ratio, port diversity, frequency, suspicious port access
- **Output:** Threat probability (0-1) and binary classification
- **Evaluation:** Accuracy, precision, recall, F1-score, confusion matrix

**Feature Engineering:**
- Total connections
- Denied connection ratio
- Unique destination ports/IPs
- Port diversity ratio
- Protocol distribution
- Connections per minute
- Port scan indicators
- Suspicious port targeting

## 📊 Database Schema

### network_events
- Stores all parsed log entries
- Indexed by source_ip, destination_ip, destination_port, action, timestamp

### alerts
- Detection results from rule engine
- Risk scores and severity levels
- Evidence and recommendations

### incidents
- Correlated alerts grouped by source IP
- Status tracking (New, Investigating, Resolved, False Positive)
- Timeline and summary information

## ⚠️ Important Notes

### Data Source
- Uses **simulated/synthetic data** for demonstration
- Safe for educational and portfolio purposes
- No real attack traffic or private user data

### ML Model
- Trained on **synthetic labeled data**
- Demonstrates ML concepts, not production-grade accuracy
- Clearly labeled as educational

### Security Analysis Approach
- Uses evidence-based terminology ("suspicious activity", "requires investigation")
- Avoids unsupported accusations ("hacker", "attacker" without proof)
- Designed for analyst-driven investigation, not automated blocking

## 🎯 Use Cases

- ✅ College project demonstration
- ✅ Learning cybersecurity concepts
- ✅ Portfolio/resume project
- ✅ Understanding SIEM/SOC workflows
- ✅ Practicing Python data analysis
- ✅ ML in cybersecurity applications

## 🚧 Limitations

1. **Log Format** - Currently supports one firewall log format (extendable)
2. **No Deep Packet Inspection** - Analysis based on metadata only
3. **Synthetic Training Data** - ML model not trained on real attacks
4. **Threshold Tuning** - Detection thresholds may need adjustment per environment
5. **False Positives** - Human analyst review required
6. **No Real-Time Integration** - Batch analysis only (not live monitoring)
7. **Single-User** - Not multi-tenant or cloud-deployed

## 🔮 Future Enhancements

- Support for multiple log formats (Snort, Suricata, Windows Event Logs)
- Real-time log ingestion and analysis
- Integration with external threat intelligence feeds
- Geolocation mapping for source IPs
- PDF report generation with charts
- Email alerting for critical incidents
- User authentication and multi-user support
- Dashboard customization and saved views
- Advanced ML models (LSTM for sequences, ensemble methods)
- Integration with MITRE ATT&CK framework

## 📚 References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Scikit-learn Documentation](https://scikit-learn.org/)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [SANS Internet Storm Center](https://isc.sans.edu/)

## 👨‍💻 Author

**College Project - Network Security Analysis**

Built as an educational cybersecurity project demonstrating:
- Network log analysis
- Threat detection algorithms
- Machine learning applications in security
- Full-stack Python development
- Data analysis and visualization

## 📄 License

This is an educational project. Use for learning and demonstration purposes.

## 🙏 Acknowledgments

- Synthetic data generation inspired by realistic firewall behavior
- Detection rules based on common attack patterns documented in security literature
- UI/UX follows SOC dashboard conventions

---

**Version:** 1.0.0  
**Last Updated:** October 2026
