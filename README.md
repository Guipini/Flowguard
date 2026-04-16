# AI-Powered Network Traffic Anomaly Detector

> **CPAN226 Network Programming — Final Project (Winter/Summer 2026)**
> Captures live network traffic with Scapy, aggregates packets into flows, and uses a Random Forest classifier trained on CICIDS2017 to flag DDoS and port-scan attacks in real time. A Streamlit dashboard visualizes alerts as they happen.

## Architecture (high level)

```
attack_simulator.py ─▶ 127.0.0.1 ─▶ capture.py (Scapy sniff)
                                          │
                                          ▼
                                   flow_builder.py ─▶ detector.py (RF model)
                                                              │
                                                              ▼
                                                       alerts.db (SQLite)
                                                              │
                                                              ▼
                                                     dashboard.py (Streamlit)
```

- **Offline** (Jupyter notebooks): train the Random Forest on CICIDS2017, export `models/detector.pkl`, `models/scaler.pkl`, `models/metadata.json`, `models/feature_names.json`.
- **Online** (Python scripts): 3-terminal demo — capture, attack simulator, dashboard.

## Repository layout

```
.
├── notebooks/                # offline ML pipeline
│   ├── 01_data_exploration.ipynb
│   ├── 02_feature_engineering.ipynb
│   ├── 03_model_training.ipynb
│   └── 04_evaluation.ipynb
├── src/                      # online runtime
│   ├── flow_builder.py
│   ├── capture.py
│   ├── detector.py
│   ├── dashboard.py
│   └── attack_simulator.py
├── data/                     # CICIDS2017 CSVs (gitignored)
├── models/                   # exported artifacts
├── report/                   # PDF report + figures
├── demo/                     # video script, fallback clip
├── requirements.txt
└── README.md
```

## Setup (Windows 11)

> The project targets Windows 11 + Python 3.11. Commands assume Git Bash or PowerShell.

### 1. Install Npcap (required for Scapy sniffing)

1. Download Npcap from https://nmap.org/npcap/
2. Run the installer **and check "Support loopback traffic (Npcap Loopback Adapter)"** — without this, you cannot sniff localhost traffic.
3. Reboot if prompted.

### 2. Create and activate virtual environment

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Download CICIDS2017 dataset

From https://www.unb.ca/cic/datasets/ids-2017.html → **CSVs folder** → download **`MachineLearningCSV.zip`** (≈500 MB). This archive contains pre-computed flow feature CSVs (CICFlowMeter output), one per capture day.

Extract the zip and copy these two files into `data/`:

```
data/
├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

(You can delete the other extracted days — we only train on DDoS + Port Scan.)

> **Why not `GeneratedLabelledFlows.zip`?** That archive has a slightly different schema and requires more preprocessing. `MachineLearningCSV.zip` is the standard "ML-ready" format most CICIDS2017 tutorials and papers use.

### 4. Train the model

```bash
jupyter lab
```

Run notebooks in order: `01` → `02` → `03` → `04`. After `03`, `models/detector.pkl` exists.

## Running the Live Demo

**Three terminals required. All three must be running as Administrator** (raw-socket capture and send need it).

> **Important**: When you open a new terminal as Administrator, its shell does NOT inherit your venv activation. You must re-activate the venv *inside* the elevated shell:
> ```bash
> cd "path\to\Final Project"
> .\.venv\Scripts\activate
> ```

### Terminal 1 — Dashboard

```bash
streamlit run src/dashboard.py
```

A browser opens at `http://localhost:8501`.

### Terminal 2 — Live capture

```bash
python src/capture.py --iface "\Device\NPF_Loopback"
```

### Terminal 3 — Launch an attack (rehearse at low rate first)

```bash
# SYN flood
python src/attack_simulator.py --attack syn_flood --target 127.0.0.1 --rate 50

# Port scan
python src/attack_simulator.py --attack port_scan --target 127.0.0.1
```

Within ~1–2 seconds the dashboard should show a flagged alert.

## Protocols & Network Concepts Exercised

- **Raw socket capture** (Scapy's `sniff()` — Layer 2/3)
- **Ethernet / IP headers** — source/dest IPs, TTL, protocol number
- **TCP** — ports, flags (SYN/ACK/FIN/RST/PSH/URG), window size
- **UDP** — ports, length
- **Flow construction** — NetFlow-style 5-tuple aggregation (src IP, dst IP, src port, dst port, protocol)
- **Encapsulation** — Ethernet → IP → TCP/UDP → payload

## Ethics

All attack traffic stays on `127.0.0.1`. **Do not run the attack simulator against networks you do not own.** This project is educational.

## License

Educational use, individual academic project. Not for redistribution.
