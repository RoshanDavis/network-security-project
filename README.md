# 🛡️ Network Intrusion Detection System (IDS)

A real-time Network Intrusion Detection System powered by Machine Learning. The project has three components:

1. **ML Training Pipeline** — Jupyter Notebook that trains a Random Forest classifier on the CICIDS2017 dataset.
2. **Live Dashboard** — Streamlit app that sniffs packets in real-time, extracts features, and displays predictions.
3. **Attack Simulator** — Scapy script that generates a SYN flood to test the detector.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Python** | 3.10, 3.11, or 3.12 |
| **OS** | Windows 10/11 |
| **Npcap** | Download from [npcap.com](https://npcap.com/#download). During install, check **"Install Npcap in WinPcap API-compatible Mode"** and **"Support loopback traffic"**. |
| **Admin privileges** | Required for live packet capture (`app.py`) and attack simulation (`attack_sim.py`). |

---

## Setup

### 1. Create and activate the virtual environment

```powershell
# If you haven't already created one:
python -m venv venv

# Activate it:
.\venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Download the CICIDS2017 dataset

1. Go to the [UNB CICIDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) or download from [Kaggle](https://www.kaggle.com/datasets/uciml/cicids2017).
2. Download the **MachineLearningCSV.zip** file.
3. Extract all CSV files into the `data/` folder:

```
data/
├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Monday-WorkingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
└── Wednesday-workingHours.pcap_ISCX.csv
```

---

## Usage

### Step 1: Train the Model (Jupyter Notebook)

```powershell
jupyter notebook notebooks/ids_training_pipeline.ipynb
```

Run each cell sequentially. The notebook has checkpoints — wait for your review at each one. After completion, two files will appear in `models/`:
- `rf_model.joblib` — trained Random Forest classifier
- `scaler.joblib` — fitted StandardScaler

### Step 2: Launch the Live Dashboard

> ⚠️ **Run from an Administrator PowerShell**

```powershell
streamlit run app.py
```

The dashboard will open in your browser and begin sniffing loopback traffic.

### Step 3: Simulate an Attack

> ⚠️ **Run from a second Administrator PowerShell**

```powershell
python attack_sim.py
```

Watch the dashboard switch from ✅ **BENIGN** to 🚨 **ATTACK DETECTED**. Press `Ctrl+C` to stop the attack.

---

## Project Structure

```
network-security-project/
├── data/                       # CICIDS2017 CSV files (you provide)
├── models/                     # Trained model + scaler (auto-generated)
│   ├── rf_model.joblib
│   └── scaler.joblib
├── notebooks/
│   └── ids_training_pipeline.ipynb
├── app.py                      # Streamlit live dashboard
├── attack_sim.py               # SYN flood simulator
├── requirements.txt
└── README.md
```
