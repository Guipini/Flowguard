# Flowguard

A small, working version of an ML-based Network Detection and Response (NDR) system. It sniffs packets on a local interface, groups them into 5-tuple flows, and scores each flow with a Random Forest trained on CICIDS2017. Alerts show up live on a Streamlit dashboard.

Runs locally against `127.0.0.1`. Written in Python. No cloud required.

## What it does, concretely

- **Captures** TCP and UDP packets on any interface via Scapy.
- **Aggregates** packets into flows keyed by `(src_ip, src_port, dst_ip, dst_port, protocol)` using a 5-tuple state machine that closes on FIN, RST, or idle timeout.
- **Scores** each closed flow with a 15-feature Random Forest trained on CICIDS2017 (DDoS and Port Scan subsets).
- **Alerts** via a Streamlit dashboard that reads a WAL-mode SQLite database, auto-refreshing every second.
- **Simulates** attacks (SYN flood, port scan) safely, hard-locked to loopback, so the whole pipeline can be exercised end-to-end on one machine.

## Why build it

Signature-based intrusion detection has ruled enterprise networks for two decades and is increasingly outpaced by attacks it has never seen before. The industry direction for 2026 is ML-based NDR, where a model learns what normal traffic looks like and flags deviations. This repo is a small working version of that pattern: public dataset, classical ML (no deep learning), real packet capture, honest failure modes documented.

## Results

On the CICIDS2017 held-out test set:

| Metric | Value |
|---|---|
| Accuracy | 99.96% |
| Macro F1 | 0.9996 |
| Per-class F1 (benign / DDoS / PortScan) | 0.9996 / 0.9995 / 0.9998 |
| Training time (100-tree RF, 306k rows) | 2.92 s on laptop CPU |
| Model file size | 1.5 MB (compressed) |

Under live Windows loopback (different distribution from CICIDS2017), the calibrated `0.1322` alert threshold was too tight and had to be retuned down to `0.05`. The original calibration is preserved in `models/metadata.json` under `alert_threshold_calibrated` for audit. This kind of retuning is standard when moving a model from a lab dataset to production traffic.

## Architecture

```
Offline (Jupyter)                         Online (Python scripts)
------------------                        -----------------------
CICIDS2017 CSVs                           attack_simulator.py
      |                                         |
      v                                         v  (127.0.0.1 only)
01_data_exploration.ipynb                 capture.py
02_feature_engineering.ipynb                    |
03_model_training.ipynb                         v
04_evaluation.ipynb                       flow_builder.py  (5-tuple aggregator)
      |                                         |
      v                                         v
models/detector.pkl                       detector.py      (Random Forest)
models/metadata.json                            |
models/feature_names.json                       v
                                          alerts.db        (SQLite, WAL mode)
                                                |
                                                v
                                          dashboard.py     (Streamlit live UI)
```

The runtime is a three-thread pipeline: one thread sniffs packets into a bounded queue, one pulls packets through the flow builder and scores closed flows, one persists `AlertDecision` rows to SQLite. WAL mode lets the dashboard read concurrently with the writer without blocking. The thread separation means a slow `predict_proba` cannot drop packets.

## Quick start

Tested on Windows 11 + Python 3.11. Linux and macOS should work with different interface names.

### 1. Install Npcap (Windows only)

Download from https://nmap.org/npcap/ and install with **"Support loopback traffic"** enabled. Without that checkbox, sniffing `127.0.0.1` does not work.

### 2. Set up Python environment

```bash
python -m venv .venv
.\.venv\Scripts\activate         # Windows
# source .venv/bin/activate      # Linux / macOS
pip install -r requirements.txt
```

### 3. Get the dataset

From https://www.unb.ca/cic/datasets/ids-2017.html download `MachineLearningCSV.zip`. Extract and copy these two files into `data/`:

- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`

### 4. Train the model

```bash
jupyter lab
```

Run the notebooks in order: `01`, `02`, `03`, `04`. Takes under a minute end-to-end on a laptop. Produces `models/detector.pkl`, `models/metadata.json`, and four PNG figures in `report/figures/`.

### 5. Run the live demo

Three terminals, all **Administrator** on Windows (raw sockets need it), all with the venv activated.

```bash
# Terminal 1: dashboard
streamlit run src/dashboard.py

# Terminal 2: capture pipeline
python src/capture.py --iface "\Device\NPF_Loopback"

# Terminal 3: fire an attack
python src/attack_simulator.py --attack port_scan --rate 30 --start-port 80 --end-port 200
```

Within a second the dashboard shows the attack flows flagged in red.

## The interesting findings

Three things came out of end-to-end testing that I would not have predicted from the literature:

**1. Packet-size features dominate. TCP flag counts are almost worthless.** The top five Random Forest importances are all about packet size (`fwd_packet_length_mean`, `average_packet_size`, `bwd_packet_length_mean`) plus `total_fwd_packets` and `flow_duration`. `rst_flag_count` has literally zero importance. `syn_flag_count` has 0.001. The intuitive "SYN flood = lots of SYNs" feature is redundant once size statistics are in the model.

**2. Calibration does not transfer across environments.** A threshold calibrated at 0.1% FPR on CICIDS2017 validation produced zero alerts on Windows loopback traffic. The loopback environment has microsecond timing and kernel-generated RST responses that do not appear in the training distribution. Lowering the threshold recovered detection. Any production NDR system faces the same issue at a larger scale.

**3. Flow-level features cannot distinguish intent.** Windows services routinely probe local TCP ports that are not listening. Each probe is one SYN forward, one RST backward, microseconds long. That packet pattern is identical to a port scan. The model correctly flags both. Whether one is legitimate IPC and the other is reconnaissance is information that is not in the flow statistics.

The full write-up, including ROC curves, confusion matrix, and feature importance chart, is in [report/report.pdf](report/report.pdf).

## Tech stack

| Component | Choice | Why |
|---|---|---|
| Packet capture | Scapy + Npcap | Cross-platform, readable Python, handles raw sockets |
| Flow state | Custom dataclasses + Welford's algorithm | O(1) memory per flow for running mean and std |
| ML framework | scikit-learn `RandomForestClassifier` | Tree-based, interpretable, tiny inference cost, no scaler needed |
| Dataset | CICIDS2017 (DDoS + PortScan) | Labeled, widely benchmarked, realistic flow statistics |
| Inter-process storage | SQLite WAL mode | Single writer, many readers, no extra daemon |
| Dashboard | Streamlit | Python-only, auto-refreshing, easy to ship |
| Attack simulation | Custom Scapy scripts | Safer and more controllable than running real nmap or hping3 |

## Repository layout

```
.
├── notebooks/                       offline ML pipeline
│   ├── 01_data_exploration.ipynb
│   ├── 02_feature_engineering.ipynb
│   ├── 03_model_training.ipynb
│   └── 04_evaluation.ipynb
├── src/                             online runtime
│   ├── flow_builder.py              5-tuple flow state machine
│   ├── detector.py                  RF inference + severity policy
│   ├── capture.py                   three-thread capture pipeline
│   ├── dashboard.py                 Streamlit live UI
│   └── attack_simulator.py          SYN flood + port scan (loopback only)
├── models/                          trained artifacts
│   ├── detector.pkl
│   ├── metadata.json
│   └── feature_names.json
├── data/                            gitignored CSVs (see data/README.md)
├── report/                          PDF report + figures
│   ├── report.pdf
│   └── figures/
├── demo/                            5-minute video script
├── requirements.txt
└── README.md
```

## Development notes

A few things worth knowing if you clone this:

- **Feature-name contract**: `models/feature_names.json` is the single source of truth for feature order between training and runtime. `detector.py` asserts every feature in that file exists on the incoming `FlowRecord` dataclass. Change one side without the other and the check trips at startup.
- **Admin shell on Windows**: opening a new PowerShell "as Administrator" does not inherit venv activation. Re-activate inside every elevated shell.
- **Interface selection**: without `--iface`, Scapy picks your default adapter (Wi-Fi in most cases). Run `python -c "from scapy.all import get_if_list; print(get_if_list())"` to list available interfaces and pick the right one.
- **Scapy 2.5 API change**: older tutorials recommend `conf.L3socket = L3RawSocket` for Windows loopback. Scapy 2.5 removed that class. The default `L3pcapSocket` handles loopback via Npcap without any override.
- **Schema migration**: `capture.py` runs a tiny `ALTER TABLE ADD COLUMN` migration at startup, so upgrading the column set does not require deleting `alerts.db`.
- **Threshold retuning**: `models/metadata.json` holds both `alert_threshold` (runtime value) and `alert_threshold_calibrated` (original, from notebook 04). The runtime value can be edited without retraining.

## Ethics and safety

All attack traffic is hard-locked to 127.0.0.0/8 and ::1 by `src/attack_simulator.py`. The check is an early `return 1`, not a warning. Do not patch it around to point at external hosts. Even on a network you own, port scanning can trip monitoring systems and should only happen with explicit authorisation.

This repo is for education and personal research. Flow-level ML detection is one layer in a real security stack, not a replacement for it.

## References

- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- Scapy: https://scapy.net/
- Scikit-learn `RandomForestClassifier`: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
- Streamlit: https://docs.streamlit.io/
- SQLite WAL mode: https://www.sqlite.org/wal.html
- Npcap: https://nmap.org/npcap/

## Context

Built as the final project for CPAN226 Network Programming (Winter/Summer 2026) in the Python: AI & Automation track. The report in `report/report.pdf` is the submitted coursework; the code and findings are general-purpose.

## License

Educational and personal research use. Not warranted for production. If you build on this, a link back is appreciated but not required.
