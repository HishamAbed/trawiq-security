# TRAWIQ Security

### Think Beyond Traffic.

**AI-Powered Network Intrusion Detection & Threat Intelligence System**

**Team Leader:** Engineer Hisham Abed

TRAWIQ Security is a cybersecurity project designed to monitor, analyze, and detect suspicious network activities.

The project aims to help security analysts identify potential network threats, analyze network traffic, extract meaningful traffic features, and support security investigations through detection techniques and intelligent analysis.

---

## Project Objectives

- Network traffic monitoring and analysis.
- Packet capture and network protocol analysis.
- Network flow generation and feature extraction.
- Rule-based intrusion detection.
- Machine Learning-based attack classification.
- Behavioral analysis and threat correlation.
- Security alert generation.
- AI-assisted security investigation and reporting.

---

## Technologies

- **Python** – Main programming language.
- **Scapy** – Packet capture and network analysis.
- **Pandas** – Data processing and analysis.
- **NumPy** – Numerical operations.
- **Scikit-learn** – Machine Learning (planned for a later development phase).
- **FastAPI** – Backend API (planned).
- **React** – Dashboard interface (planned).
- **PostgreSQL** – Database (planned).

---

# Project Development

## Function 1: Packet Capture & Network Analysis

**Status: Completed**

This function is responsible for capturing and analyzing network traffic.

### Implemented Features

- Reading PCAP files.
- Live network traffic capture.
- Automatic network interface selection.
- IPv4 and IPv6 packet identification.
- TCP, UDP, ICMP, ICMPv6, and ARP classification.
- Source and destination IP extraction.
- Source and destination port extraction.
- Packet size analysis.
- Protocol statistics.
- Exporting captured traffic to CSV.

### Live Capture Test

| Metric | Result |
|---|---:|
| Total Captured Packets | 1032 |
| TCP | 976 |
| UDP | 50 |
| ICMPv6 | 4 |
| ARP | 2 |

**Output Files:**
- `data/processed/live_capture.pcap`
- `data/processed/live_traffic.csv`

---

## Function 2: Data Preprocessing & Flow Feature Extraction

**Status: Core Implementation and Tests Completed**

### A. CIC-IDS2017 Dataset Processing

Implemented operations:

- Dataset inspection.
- Missing and infinite values detection and handling.
- Data cleaning and validation.
- Feature analysis and removal of constant features.
- Class distribution analysis.
- Duplicate records analysis.
- Conflicting label investigation.
- Dataset preparation and training data shuffling.

### Dataset Processing Results

| Metric | Result |
|---|---:|
| Original Dataset Files | 8 |
| Original Rows | 2,830,743 |
| Original Columns | 79 |
| Prepared Features | 70 |
| Prepared Columns Including Label | 71 |
| Classes | 15 |
| Rows in ML Dataset Copy | 2,823,723 |
| Training Rows Shuffled | 2,258,978 |

Eight constant features were removed during feature preparation.

Conflicting-label feature groups were investigated and excluded from the ML-ready copy, without modifying the original cleaned and prepared datasets.

### B. Live Flow Feature Extraction

Implemented features:

- Bidirectional flow identification.
- Source and destination endpoint tracking.
- Forward and backward packet classification.
- TCP connection termination using FIN and RST flags.
- Flow inactivity timeout (120 seconds).
- Packet length statistics.
- Flow duration calculation.
- Flow packet and byte counts.
- Flow bytes-per-second and packets-per-second.
- TCP flag statistics.
- Flow inter-arrival time statistics.
- CSV export.

### Live Flow Extraction Test

| Metric | Result |
|---|---:|
| Total Captured Packets | 1032 |
| Extracted IP Packets | 1030 |
| ARP Packets | 2 |
| Total Extracted Flows | 98 |
| Extracted Flow Columns | 37 |
| Forward Packets | 534 |
| Backward Packets | 496 |
| Unsupported Packets | 0 |
| Empty Flows | 0 |
| Negative Durations | 0 |
| NaN Values | 0 |
| Infinite Values | 0 |

Forward and backward packet totals were verified:

`534 + 496 = 1030`

**Output File:**

`data/processed/flows/live_capture_flows.csv`

**Technical Note:** The current custom flow extractor provides 37 output columns. Its feature definitions are not identical to CICFlowMeter or the original CIC-IDS2017 feature schema. Additional validation is required before using live flow features in a production detection pipeline.

---

# Project Structure

```text
TRAWIQ-Security/
│
├── data/
│   ├── raw/
│   └── processed/
│       ├── cleaned/
│       ├── analysis/
│       ├── prepared/
│       ├── ml_ready/
│       ├── splits/
│       ├── shuffled/
│       └── flows/
│
├── capture/
│   ├── packet_capture.py
│   └── generate_sample.py
│
├── preprocessing/
│   ├── inspect_dataset.py
│   ├── data_cleaning.py
│   ├── validate_cleaned_data.py
│   ├── feature_analysis.py
│   ├── prepare_features.py
│   ├── analyze_class_balance.py
│   ├── analyze_source_distribution.py
│   ├── analyze_duplicates.py
│   ├── inspect_conflicting_labels.py
│   ├── verify_conflicting_labels.py
│   ├── create_ml_dataset.py
│   ├── analyze_ml_class_balance.py
│   ├── shuffle_training_data.py
│   └── feature_extraction.py
│
├── detection/
├── ml_models/
├── ai_assistant/
├── backend/
├── dashboard/
├── tests/
│
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Installation & Setup

### 1. Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
cd TRAWIQ-Security
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate the Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Project

### Live Packet Capture

```powershell
python .\capture\packet_capture.py --live --duration 30
```

### Flow Feature Extraction

```powershell
python -m preprocessing.feature_extraction
```

The flow extraction module searches for PCAP files inside `data/raw/` and saves processed flow CSV files inside `data/processed/flows/`.

---

# Development Roadmap

| Function | Description | Status |
|---|---|---|
| Function 1 | Packet Capture & Network Analysis | Completed |
| Function 2 | Data Preprocessing & Feature Extraction | Core tests passed |
| Function 3 | Detection Rules & Security Research | Planned |
| Function 4 | Machine Learning | Deferred |
| Function 5 | AI Security Assistant | Planned |
| Function 6 | Backend & Dashboard | Planned |

---

## Current Project Status

TRAWIQ Security is currently under development.

Functions 1 and 2 have reached their current implementation and testing milestones. Further validation and integration will be performed before moving toward a complete intrusion detection system.

**Project Name:** TRAWIQ Security

**Team Leader:** Engineer Hisham Abed

**Slogan:** Think Beyond Traffic.