# AI DNS Threat Detection

AI DNS Threat Detection is a real-time network security project that monitors DNS traffic, extracts domain-level features, and classifies suspicious activity using machine learning and fast-flux detection logic. The system combines live packet sniffing, a Flask API, interactive dashboards, and SQLite-backed logging to support threat analysis and operational monitoring.

## What It Does

- Captures live DNS queries from network traffic using Scapy.
- Extracts lexical and network-based features from domains.
- Classifies domains into `Benign`, `DGA`, `Fast-Flux`, or `Suspicious`.
- Exposes a REST API for manual or external classification requests.
- Stores detections in SQLite for history, statistics, and monitoring.
- Provides both a Streamlit dashboard and a Tkinter-based sniffer UI.

## Core Features

- Real-time DNS packet capture and background threat classification
- Machine learning-based domain analysis
- Fast-flux scoring and override logic
- REST API for classification and health checks
- SQLite persistence for detections and metrics
- Streamlit dashboard for stats, recent detections, and manual testing
- Tkinter desktop UI for live traffic inspection
- Logging for application, audit, and error events

## Project Architecture

The project is organized around four main layers:

1. **Traffic Ingestion**
   DNS queries are captured through Scapy and passed into a background processing pipeline.
2. **Detection Engine**
   Domains are scored using feature extraction, trained ML models, and fast-flux heuristics.
3. **Service Layer**
   A Flask API exposes classification endpoints and persists results in SQLite.
4. **Monitoring Layer**
   Streamlit and Tkinter interfaces visualize detections, sniffer status, and threat statistics.

## Tech Stack

- Python
- Flask
- Waitress
- Streamlit
- Scapy
- scikit-learn
- XGBoost
- Pandas / NumPy
- Plotly
- SQLite

## Repository Structure

```text
.
|-- app.py                      # Flask API for DNS threat classification
|-- dashboard.py                # Streamlit monitoring dashboard
|-- dns_sniffer.py              # Tkinter live DNS sniffer UI
|-- core/
|   |-- fastflux_integration.py # ML + fast-flux classification logic
|   |-- dns_sniffer_integration.py
|   |-- sniffer_manager.py
|   |-- db_service.py
|   |-- data_engg.py
|   |-- validators.py
|   `-- config.py
|-- scripts/
|   |-- retrain_model.py        # Model retraining workflow
|   |-- model.py
|   |-- data_set.py
|   `-- Analysis.py
|-- models/                     # Trained model artifacts
|-- Datasets/                   # DGA / fast-flux datasets
|-- logs/                       # Runtime logs
`-- threat_detection.db         # SQLite detection database
```

## Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd AI_DNS
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

```bash
# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

### Run the Flask API

```bash
python app.py
```

The API starts on:

```text
http://0.0.0.0:5000
```

### Run the Streamlit Dashboard

```bash
streamlit run dashboard.py
```

The dashboard includes:

- threat statistics
- recent and malicious detections
- manual domain classification
- start/stop controls for the DNS sniffer

### Run the Tkinter Sniffer UI

```bash
python dns_sniffer.py
```

This interface provides live DNS traffic inspection with local classification output.

## API Endpoints

### Health Check

```http
GET /api/v1/health
```

Example:

```bash
curl http://127.0.0.1:5000/api/v1/health
```

### Classify a Domain

```http
POST /api/v1/classify
Content-Type: application/json
```

Example request:

```json
{
  "domain": "example.com",
  "ttl": 3600,
  "unique_ip_count": 1,
  "query_rate": 100
}
```

Example `curl`:

```bash
curl -X POST http://127.0.0.1:5000/api/v1/classify ^
  -H "Content-Type: application/json" ^
  -d "{\"domain\":\"example.com\",\"ttl\":3600,\"unique_ip_count\":1,\"query_rate\":100}"
```

Example response:

```json
{
  "domain": "example.com",
  "label": "Benign",
  "status": "Benign",
  "confidence": 0.91,
  "recommendation": "ALLOW",
  "is_fastflux": false,
  "ff_score": 0.02,
  "timestamp": "2026-04-17T10:30:00"
}
```

## Detection Logic

The classifier combines:

- domain lexical features such as length, entropy, digit ratio, and subdomain depth
- network-related features such as TTL, query rate, and unique IP count
- trained ML model predictions
- fast-flux scoring to override base predictions when flux behavior is strongly indicated

Threat classes used in the system:

- `0` = Benign
- `1` = DGA
- `2` = Fast-Flux
- `3` = Suspicious

## Data and Models

- Trained models are stored in the `models/` directory.
- Detection history is stored in `threat_detection.db`.
- Sample and training datasets are stored in `Datasets/`.
- Retraining utilities are available in `scripts/`.

## Logs

Runtime logs are written to the `logs/` directory, including:

- `dns_threat.log`
- `dns_threat_audit.log`
- `dns_threat_error.log`
- `dns_sniffer.log`

## Notes

- Running packet capture may require administrator or root privileges.
- The sniffer depends on the host machine having access to DNS traffic on the selected interface.
- The dashboard expects the Flask API to be running if you want to use manual classification from the UI.

## Future Improvements

- automated alerting via webhook or email
- model feedback loop and active learning integration
- richer model evaluation and experiment tracking
- deployment hardening for production monitoring

## Resume-Friendly Summary

This project demonstrates practical application of:

- real-time network traffic analysis
- ML-based cybersecurity detection
- full-stack Python development
- API and dashboard integration
- security event persistence and monitoring

## License

Add a license here if you plan to open-source the project.
