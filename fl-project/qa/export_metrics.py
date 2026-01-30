import os
import json
import requests
import logging

# Configuration
PUSHGATEWAY_URL = "http://localhost:9092/metrics/job/jenkins_pipeline"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MetricsExporter")

def push_to_gateway(metrics_data):
    data = "\n".join(metrics_data) + "\n"
    try:
        response = requests.post(PUSHGATEWAY_URL, data=data)
        if response.status_code == 200: # Pushgateway returns 200 or 202
            logger.info("Metrics successfully pushed to Gateway.")
        else:
            logger.error(f"Failed to push metrics. Status: {response.status_code}")
    except Exception as e:
        logger.error(f"Error pushing metrics: {e}")

def parse_bandit():
    metrics = []
    try:
        with open('bandit-report.json', 'r') as f:
            data = json.load(f)
            # High/Medium/Low severity counts
            high = sum(1 for i in data.get('results', []) if i['issue_severity'] == 'HIGH')
            medium = sum(1 for i in data.get('results', []) if i['issue_severity'] == 'MEDIUM')
            low = sum(1 for i in data.get('results', []) if i['issue_severity'] == 'LOW')

            metrics.append(f'sast_bandit_issues_high {high}')
            metrics.append(f'sast_bandit_issues_medium {medium}')
            metrics.append(f'sast_bandit_issues_low {low}')
            logger.info(f"Bandit: High={high}, Medium={medium}, Low={low}")
    except FileNotFoundError:
        logger.warning("bandit-report.json not found.")
    return metrics

def parse_semgrep():
    metrics = []
    try:
        with open('semgrep-report.json', 'r') as f:
            data = json.load(f)
            total = len(data.get('results', []))
            metrics.append(f'sast_semgrep_issues {total}')
            logger.info(f"Semgrep: Total Issues={total}")
    except FileNotFoundError:
        logger.warning("semgrep-report.json not found.")
    return metrics

def parse_pylint():
    metrics = []
    try:
        # Pylint JSON output is a list of issues
        with open('pylint-report.json', 'r') as f:
            data = json.load(f)

            # Count by type
            errors = sum(1 for i in data if i['type'] == 'error')
            warnings = sum(1 for i in data if i['type'] == 'warning')
            convention = sum(1 for i in data if i['type'] == 'convention')
            refactor = sum(1 for i in data if i['type'] == 'refactor')

            # Calculate a rough score (10 - deductions) if not provided
            # Or just export raw counts (better for Grafana)
            metrics.append(f'sast_pylint_errors {errors}')
            metrics.append(f'sast_pylint_warnings {warnings}')
            metrics.append(f'sast_pylint_convention {convention}')
            metrics.append(f'sast_pylint_refactor {refactor}')

            # Export total count
            metrics.append(f'sast_pylint_total_issues {len(data)}')

            logger.info(f"Pylint: Errors={errors}, Warnings={warnings}")
    except FileNotFoundError:
        logger.warning("pylint-report.json not found.")
    except json.JSONDecodeError:
        logger.warning("pylint-report.json is empty or invalid.")
    return metrics

def main():
    print("Exporting metrics...")
    all_metrics = []
    all_metrics.extend(parse_bandit())
    all_metrics.extend(parse_semgrep())
    all_metrics.extend(parse_pylint())

    # Add a timestamp metric for the last run
    all_metrics.append(f'jenkins_build_last_run {1}')

    if all_metrics:
        push_to_gateway(all_metrics)
    else:
        logger.warning("No metrics found to export.")

if __name__ == "__main__":
    main()