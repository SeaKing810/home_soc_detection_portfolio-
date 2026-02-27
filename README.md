# Home SOC Detection Portfolio

This project is a small blue team style pipeline that takes Sysmon style events, normalizes them, runs detection rules, and generates an incident style report.

What this demonstrates
1. Log thinking and event normalization
2. Detection logic and false positive awareness
3. Report writing that resembles real SOC workflow
4. Clean project structure and automated tests

Repo contents
- `data/sample_sysmon_events.jsonl` contains sample Sysmon style events (JSON lines)
- `src/` contains the pipeline and CLI
- `detections/rules.yaml` contains detection rules
- `reports/` is where generated reports are saved
- `tests/` contains unit tests

Quick start

1. Create a virtual environment
   - macOS and Linux
     `python3 -m venv .venv && source .venv/bin/activate`
   - Windows PowerShell
     `python -m venv .venv; .\.venv\Scripts\Activate.ps1`

2. Install dependencies
   `pip install -r requirements.txt`

3. Run the pipeline on the sample data
   `python -m src.cli run --input data/sample_sysmon_events.jsonl --out reports`

4. Run tests
   `python -m pytest -q`

How to extend this project
- Replace the sample file with your own exported logs from a lab VM
- Add rules in `detections/rules.yaml`
- Add new event mappings in `src/normalizer.py`
- Add new report sections in `src/report.py`

MITRE ATT&CK mapping (examples)
- Suspicious PowerShell usage: T1059.001
- Credential access patterns via brute force: T1110
- Signed binary proxy execution hints: T1218

Disclaimer
This project is defensive and educational. It does not include exploit steps or offensive tooling.
