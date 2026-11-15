# Ransomware Simulation & Detection System

A **safe, educational** web application that simulates ransomware-like behaviour inside an
isolated sandbox folder, monitors the file activity in real time, and detects it using
**heuristic rules + a Machine Learning (Decision Tree) model**. Results are shown on a live web dashboard.

> PBL project · Department of Information Technology, Manipal University Jaipur
> Educational use only. No real malware is used. All activity is confined to the sandbox and is fully reversible.

---

## Workflow

```
User → Load Files → Simulate Encryption → Monitor Activity → Detect Anomalies → Generate Alerts → Dashboard Display
```

| Stage | What really happens | Code |
|---|---|---|
| **Load Files** | Uploaded files are copied into `sandbox/<session>/files/` | `app.py` → `/api/upload` |
| **Simulate** | Files are **AES-256-GCM encrypted** and renamed to `.locked` (ransomware mode) | `backend/simulator.py` |
| **Monitor** | `watchdog` records every *modified / renamed / created / deleted* event with timestamps | `backend/monitor.py` |
| **Detect (heuristics)** | Rename rate, Shannon entropy, modification speed and extension changes are scored | `backend/detector.py` |
| **Detect (ML)** | A Decision Tree predicts the probability the activity is ransomware | `backend/ml_model.py` |
| **Alerts + Display** | Threat score, level, patterns, alerts, logs, charts, run history (SQLite) | `templates/`, `static/` |

### Test scenarios (from the report's testing method)

| Scenario | Behaviour | Expected result |
|---|---|---|
| Normal activity | A few small edits, no renaming | **SAFE** (no alert) |
| Moderate | ~60% of files renamed, no encryption | **WARNING** |
| Ransomware-like attack | All files AES-encrypted + renamed `.locked` + ransom note dropped, very fast | **CRITICAL** |

**Restore** decrypts the files and renames them back, because the key is kept in the sandbox. **Reset** deletes the sandbox.

### Detection rules (`backend/detector.py`)

| Rule | Threshold | Points |
|---|---|---|
| Rename rate | ≥ 70% → critical, ≥ 40% → warning | 35 / 25 |
| Entropy | ≥ 50% of files rewritten with entropy ≥ 7.5 / 8 | 35 |
| Modification speed | ≥ 300 files/min → critical, ≥ 100 → warning | 20 / 10 |
| Extension change | `.locked`, `.enc`, `.crypt` … | 10 |
| Ransom note | new file like `README_RESTORE_FILES.txt` | 15 |

Score 0–29 = **SAFE**, 30–69 = **WARNING**, 70–100 = **CRITICAL**.

### ML model (`backend/ml_model.py`)
* `DecisionTreeClassifier(max_depth=4)` trained on a synthetic behavioural dataset of 4,000 samples
  (normal edits, bulk photo renaming, zip/backup compression, user encryption, fast ransomware, slow "stealth" ransomware).
* 7 features: rename rate, entropy after, entropy change, high-entropy ratio, log(speed), extension-change ratio, ransomware-extension ratio.
* Approx. **97% accuracy** on a held-out test set. The learned if/else rules and the feature importances are shown on the dashboard.
* Hybrid decision: the rule-based score sets the level, and the ML model can escalate a SAFE result to WARNING when it is ≥ 80% confident.
* Model comparison on the same test set (Decision Tree chosen: best accuracy **and** explainable):

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| **Decision Tree** | **97.2%** | **97.0%** | **94.7%** | **95.9%** |
| Random Forest | 97.1% | 96.7% | 94.7% | 95.7% |
| Logistic Regression | 94.9% | 92.4% | 92.7% | 92.5% |

* Retrain and print the metrics with `python -m backend.ml_model`.

### Incident report (PDF)
After every run, **Incident Report (PDF)** downloads a report with the verdict, metrics, detected patterns, ML assessment, affected files, recommended response steps and the event log (`backend/report_pdf.py`, ReportLab).

### URL checker (`backend/url_checker.py`)
Static analysis of a link: IP-address host, no HTTPS, `@` trick, suspicious TLD, punycode, phishing keywords,
brand impersonation, URL shorteners, executable downloads. **The link is never opened.**

---

## Run locally (Mac / Linux)

```bash
cd ransomware-sim
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:8000** in your browser.

(Windows: `venv\Scripts\activate` instead of `source venv/bin/activate`.)

## Deploy (free) on Render
1. Push this folder to a GitHub repository.
2. On https://render.com, click **New → Web Service** and pick the repo.
3. Set the Build Command to `pip install -r requirements.txt`.
4. Set the Start Command to `gunicorn app:app --workers 1 --threads 4 --timeout 120`.
5. Choose the **Free** plan, then click **Deploy**. You get a public `https://….onrender.com` link.

The free plan sleeps after inactivity, so the first load can take about a minute.

## Project structure
```
ransomware-sim/
├── app.py                 # Flask server + REST API
├── backend/
│   ├── simulator.py       # safe AES-256 encryption / rename simulation + restore
│   ├── monitor.py         # watchdog file-system monitoring
│   ├── detector.py        # heuristic detection engine
│   ├── ml_model.py        # Decision Tree ML detection
│   ├── entropy.py         # Shannon entropy
│   └── url_checker.py     # phishing / malicious URL checks
├── templates/index.html   # dashboard
├── static/                # CSS, JS, Chart.js
├── sample_files/          # demo test files
├── sandbox/               # isolated working folder (auto-created)
└── logs/                  # activity.log + history.db (SQLite)
```

## Tech stack
Python 3, Flask, cryptography (AES-256-GCM), watchdog, scikit-learn, NumPy, ReportLab, SQLite, HTML/CSS/JavaScript, Chart.js. UI designed in Figma.
