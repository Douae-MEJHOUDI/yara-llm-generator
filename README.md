# YARA LLM Generator

Automated YARA rule generation from malware behavioral analysis using LLMs.

## About
This tool extracts behavioral features from CAPEv2 sandbox reports and will use LLM to generate YARA detection rules.

## Current Status
- [x] Project setup and Docker environment
- [x] Suspicious indicators configuration (API calls, registry keys, network patterns)
- [x] Dynamic feature extraction from CAPEv2 JSON reports
- [x] Test script for extraction validation
- [ ] LLM integration for rule generation
- [ ] YARA rule validation

## Setup

### Prerequisites
- Docker and docker-compose
- Python 3.12 (if running locally)

### Running Locally
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running with Docker
```bash
cp .env.example .env
docker-compose build
docker-compose up
```

## Testing Feature Extraction
```bash
python -m tests.test_extraction
```
This runs the extractor on samples in `data/malware_samples/` and prints a breakdown of detected behaviors (registry, API calls, network, file ops, process injection).

## Project Structure
```
├── src/
│   ├── config/
│   │   └── suspicious_indicators.py   # Known malicious patterns
│   └── extractors/
│       └── dynamic_features.py        # CAPEv2 feature extraction
├── data/
│   └── malware_samples/               # CAPEv2 JSON reports
├── test_extraction.py
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Team
- Khaoula MEJHOUDI
- Mounia BADDOU
