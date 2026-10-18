# 🚀 HOW TO RUN AND DEMONSTRATE

## Start Here

### 1. Install Dependencies (One Time)
```bash
python -m pip install -r requirements.txt
```

### 2. Launch the Application
```bash
python run.py
```

The application will open automatically in your browser at `http://localhost:8501`

### 3. Load Sample Data
- Go to **Upload Logs** tab (left sidebar)
- Click the blue **Load Sample Data** button
- Wait 10-15 seconds for analysis to complete
- You'll see "✅ Upload and analysis complete!" message

---

## Demo Walkthrough (3-5 minutes)

### Step 1: View Dashboard (1 min)
**Purpose:** Show overall security posture

1. Click **Dashboard** in sidebar
2. Point out:
   - Total events: ~7,750
   - KPI cards showing allowed/denied ratio
   - Charts showing traffic patterns
   - Top source IPs and targeted ports

**Talking Points:**
- "This shows normal and suspicious traffic in one view"
- "Notice the traffic patterns over time"
- "Top IPs help identify repeat offenders"

### Step 2: Review Threat Detection (1 min)
**Purpose:** Show detected patterns

1. Click **Threat Detection** in sidebar
2. Show alerts in severity order (CRITICAL first)
3. Click "Alert #1 - Details" to expand

**Talking Points:**
- "The system detected 4-8 incidents automatically"
- "Each alert shows the evidence and reasoning"
- "Notice we use cautious language: 'suspicious', 'requires investigation'"
- "We don't call anyone a 'hacker' without proof"

### Step 3: Examine Incidents (1 min)
**Purpose:** Show incident grouping and timeline

1. Click **Incidents** in sidebar
2. Click on the top CRITICAL incident expander
3. Point out:
   - Summary of suspicious behavior
   - Related alerts grouped together
   - Event timeline showing sequence

**Talking Points:**
- "Related alerts are grouped into incidents"
- "The timeline shows exactly what happened, minute by minute"
- "An analyst can drill down into the full sequence of events"

### Step 4: Investigate an IP (1 min)
**Purpose:** Show individual IP analysis

1. Click **IP Analysis** in sidebar
2. Pick a suspicious source IP from dropdown
3. Show:
   - Total events, allowed/denied counts
   - Unique ports targeted
   - Destination IPs
   - Time range of activity

**Talking Points:**
- "This is where an analyst investigates a specific IP"
- "We can see all behavior from this source"
- "The metrics help determine if it's truly malicious"

### Step 5: ML Analysis (30 sec)
**Purpose:** Show machine learning component

1. Click **ML Analysis** in sidebar
2. Show:
   - Model type: Random Forest
   - Prediction distribution pie chart
   - Feature importance bar chart

**Talking Points:**
- "The ML model independently scores threat probability"
- "It uses 11 engineered features"
- "Features are ranked by importance"

### Step 6: Generate Report (30 sec)
**Purpose:** Show reporting capability

1. Click **Reports** in sidebar
2. Click **Generate Full Security Report**
3. Wait for report to generate
4. Click **Download Report CSV**

**Talking Points:**
- "Reports summarize findings for documentation"
- "Exported as CSV for use in presentations or submissions"
- "Can be imported into spreadsheets or other tools"

---

## 🎯 Key Points to Emphasize

### Architecture & Design
- "The system is modular - 9 separate packages"
- "Clear separation of concerns: parsing, detection, ML, UI"
- "Easy to extend with new detection rules or ML models"

### Detection Quality
- "Rule-based detection is explainable - we show our reasoning"
- "Not a black box - analysts understand why something was flagged"
- "Configurable thresholds for different environments"

### Data Handling
- "Gracefully handles malformed logs"
- "SQLite with optimized indexes for fast queries"
- "7,750 events processed and analyzed in seconds"

### Machine Learning Integration
- "ML complements rule-based detection"
- "Trained on realistic synthetic data patterns"
- "Provides probability scores, not just binary classifications"

### Production Quality
- "Full error handling and validation"
- "Unit tests verify core functionality"
- "Git repository for version control"
- "Comprehensive documentation"

---

## Common Demo Questions & Answers

**Q: Why use simulated data?**
A: Real attack data is hard to obtain and may contain sensitive information. Synthetic data demonstrates the system works while maintaining confidentiality for educational use.

**Q: Can you add my own detection rules?**
A: Yes! Edit `app/detection/rules.py` to add new detection classes. Each rule must implement the same interface.

**Q: How would this scale to real production?**
A: Replace SQLite with PostgreSQL, add distributed processing with Kafka, use cloud infrastructure, add authentication, implement real-time streaming instead of batch.

**Q: How accurate is the ML model?**
A: On synthetic data, ~85-90%. With real labeled attack data, would be higher. This demonstrates the ML concept; production would need real data.

**Q: What about false positives?**
A: The system is designed for analyst review - no automated blocking. Humans verify each alert using the timeline and evidence provided.

**Q: How is this different from commercial SOCs?**
A: This is educational and local-only. Real SOCs handle petabytes, integrate with 100s of data sources, have 24/7 teams, and years of tuning.

---

## 📹 Demo Script (For Presentation)

**Opening (30 sec):**
"This is the Network Intrusion Log Analyser - a security analysis tool that takes raw network logs and detects suspicious behavior. It combines rule-based detection, machine learning, and analyst tools into one platform."

**Walkthrough (3 min):**
1. Dashboard shows overall posture
2. Detection found 8 security incidents
3. Incidents are grouped related alerts
4. IP analysis lets analysts investigate
5. ML provides independent scoring
6. Reports enable documentation

**Closing (30 sec):**
"The system demonstrates core concepts: log parsing, threat detection, machine learning, database design, and web applications - all built from scratch in Python."

---

## ⚙️ Customization for Demo

### To use your own log file:
1. Create a TXT file with format:
   ```
   YYYY-MM-DD HH:MM:SS SOURCE_IP:PORT -> DEST_IP:PORT PROTOCOL ACTION
   ```
2. Go to **Upload Logs → Upload Custom Logs**
3. Select your file
4. Click "Parse and Analyze"

### To adjust detection sensitivity:
Edit `app/detection/rules.py` before running:
- `min_unique_ports`: Lower = more sensitive to port scanning
- `min_attempts`: Lower = more sensitive to brute force
- `min_denies`: Lower = more sensitive to denied traffic

### To see specific alerts:
Click filters in **Threat Detection** to show only CRITICAL alerts, or specific types.

---

## 🔍 What to Show During Viva

### Technical Knowledge
- Explain the architecture decisions
- Walk through the regex pattern for log parsing
- Describe the detection algorithm for one rule
- Explain feature engineering for ML

### Problem Solving
- Show how malformed logs are handled
- Demonstrate filtering and searching
- Explain why you chose Random Forest over other algorithms
- Discuss trade-offs (accuracy vs speed, complexity vs simplicity)

### Code Quality
- Show examples of well-structured code
- Demonstrate error handling
- Point out documentation and comments
- Show Git commit history

---

## 📊 Expected Results

When you load sample data, you should see:
- ✅ 7,750 total events parsed
- ✅ ~5,400 normal, ~2,350 suspicious
- ✅ 4-8 security incidents detected
- ✅ Severity mix: some CRITICAL, some HIGH, some MEDIUM
- ✅ Multiple alert types: port scans, brute force, excessive denies
- ✅ Identified 10-15 top suspicious source IPs
- ✅ Top targeted ports: 22, 23, 25, 80, 443, etc.

---

## Troubleshooting During Demo

**If port 8501 is in use:**
```bash
streamlit run app/main.py --server.port 8502
```

**If it's slow to load:**
- First load takes time because ML model is trained
- Subsequent interactions are fast
- Sample data processes in ~10-15 seconds

**If database is locked:**
- Close the app
- Delete `database/intrusion_analyser.db`
- Restart the app

**If "No logs loaded" appears:**
- Click Upload Logs tab
- Click "Load Sample Data" button
- Wait for completion

---

## ✅ Pre-Demo Checklist

- [ ] Python 3.14 installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Sample data generated (`python -m app.utils.generate_data` - already done)
- [ ] Tested running the app once (`python run.py`)
- [ ] Know the demo script above
- [ ] Have alternate log file ready (optional)
- [ ] Know answers to common questions

---

## 🎬 You're Ready!

Run with:
```bash
python run.py
```

Then follow the demo walkthrough above. Good luck! 🎉

