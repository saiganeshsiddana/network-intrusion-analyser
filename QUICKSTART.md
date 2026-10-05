# Network Intrusion Log Analyser - Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### Step 1: Install & Run

```bash
# Install dependencies (one time)
python -m pip install -r requirements.txt

# Run the application
python run.py
```

The app opens at `http://localhost:8501`

### Step 2: Load Sample Data

1. Go to **Upload Logs** tab
2. Click **Load Sample Data** button
3. Wait for analysis to complete (~10-15 seconds)

### Step 3: Explore the Dashboard

- **Dashboard** - View KPIs and charts
- **Threat Detection** - See detected alerts
- **Incidents** - Review grouped security incidents
- **IP Analysis** - Investigate specific source IPs
- **ML Analysis** - See ML predictions
- **Reports** - Generate CSV exports

## 📊 What You'll See

### Sample Dataset Contains:
- ~7,750 network log events
- Normal internal traffic
- Port scanning patterns
- Brute force-like attempts
- High-frequency connections

### Expected Detections:
- 3+ Port Scanning alerts
- 2+ Brute Force alerts
- Multiple Excessive Deny alerts
- High frequency detections
- 4-8 total incidents

## 🔧 Configuration

All detection thresholds can be adjusted in `app/detection/rules.py`:

```python
# Port Scanning (min_unique_ports, time_window_minutes)
detector.detect_port_scanning(min_unique_ports=20, time_window_minutes=10)

# Brute Force (min_attempts, time_window_minutes)
detector.detect_brute_force(min_attempts=50, time_window_minutes=5)

# Excessive Denies (min_denies)
detector.detect_excessive_denies(min_denies=100)

# High Frequency (min_connections, time_window_minutes)
detector.detect_high_frequency(min_connections=150, time_window_minutes=5)
```

## 📝 Upload Custom Logs

**Format Required:**
```
YYYY-MM-DD HH:MM:SS SOURCE_IP:PORT -> DEST_IP:PORT PROTOCOL ACTION
```

Example file (`my_logs.txt`):
```
2024-10-01 09:00:01 192.168.1.100:50123 -> 10.0.0.5:22 TCP DENY
2024-10-01 09:00:02 192.168.1.100:50124 -> 10.0.0.5:23 TCP DENY
2024-10-01 09:00:03 192.168.1.100:50125 -> 10.0.0.5:25 TCP DENY
```

Then upload via **Upload Logs → Upload Custom Logs**

## 🧪 Run Tests

```bash
python -m pytest tests/test_all.py -v
```

## 📂 Key Files to Know

| File | Purpose |
|------|---------|
| `app/main.py` | Streamlit app entry point |
| `app/parser/log_parser.py` | Log parsing with regex |
| `app/database/db.py` | SQLite database layer |
| `app/detection/rules.py` | Threat detection rules |
| `app/ml/train.py` | ML model training |
| `app/ml/predict.py` | ML predictions |
| `app/ui/dashboard.py` | Main dashboard |

## 💾 Database

SQLite database created automatically at: `database/intrusion_analyser.db`

To reset: Delete the `.db` file and restart the app.

## 🎓 Learning Path

1. Start with **Dashboard** - Understand overall security posture
2. Check **Threat Detection** - See what patterns were found
3. Review **Incidents** - Understand incident grouping
4. Investigate **IP Analysis** - Deep dive into suspicious IPs
5. Study **ML Analysis** - See ML predictions
6. Generate **Reports** - Export findings

## 🔍 Example Workflow

1. Load sample data
2. See ~8 total incidents detected
3. Click on a CRITICAL incident
4. Review the timeline of events
5. Read the recommendation
6. Export to CSV for documentation

## ⚙️ Troubleshooting

**Port 8501 already in use:**
```bash
streamlit run app/main.py --server.port 8502
```

**Module not found errors:**
```bash
python -m pip install -r requirements.txt
```

**Database locked error:**
Close the app and delete `database/intrusion_analyser.db`, then restart.

## 📞 Support

This is a college project for educational purposes. For issues:
1. Check the README.md for detailed documentation
2. Review test cases in `tests/test_all.py`
3. Check GitHub issues if deployed there

## ✅ Verification Checklist

- [x] All dependencies installed
- [x] Sample data generates (7750+ events)
- [x] Parser validates log format
- [x] Database creates with proper schema
- [x] Detection engine finds patterns
- [x] ML model trains and predicts
- [x] Streamlit dashboard displays
- [x] All UI pages load
- [x] Reports generate
- [x] Tests pass

---

**You're all set! Launch with `python run.py` and start analyzing.**
