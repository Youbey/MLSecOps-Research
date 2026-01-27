import json
import os
import re
import requests
from datetime import datetime

# Config
PUSHGATEWAY_URL = "http://localhost:9092/metrics/job/jenkins_pipeline"

def push_metric(name, value, help_text):
    data = f"# HELP {name} {help_text}\n# TYPE {name} gauge\n{name} {value}\n"
    try:
        requests.post(PUSHGATEWAY_URL, data=data)
    except Exception as e:
        print(f"Warning: Could not push metric {name}: {e}")

def parse_pylint():
    # Pylint usually outputs a score out of 10 in the logs,
    # but for automation, we might want to parse a JSON report if generated.
    # For now, let's assume we capture the exit code or a score file.
    # Simple placeholder:
    return 0

def parse_bandit():
    if not os.path.exists("bandit-report.json"): return
    with open("bandit-report.json") as f:
        data = json.load(f)
        high = sum(1 for x in data.get('results', []) if x['issue_severity'] == 'HIGH')
        push_metric("sast_bandit_high_severity", high, "Bandit High Severity Issues")

def parse_semgrep():
    if not os.path.exists("semgrep-report.json"): return
    with open("semgrep-report.json") as f:
        data = json.load(f)
        # Semgrep JSON structure varies slightly by version, checking generic 'results'
        count = len(data.get('results', []))
        push_metric("sast_semgrep_issues", count, "Semgrep Findings")

if __name__ == "__main__":
    print("Exporting metrics...")
    parse_bandit()
    parse_semgrep()
    # parse_pylint() # Implementation depends on how you run pylint output
    push_metric("jenkins_build_last_run", datetime.now().timestamp(), "Last build timestamp")