pipeline {
    agent any
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 2, unit: 'HOURS')
        timestamps()
    }

    parameters {
        choice(
            name: 'ATTACK_MODE',
            choices: [
                'NONE',
                'POISONING',
                'STEALTHY',
                'SYBIL_SIMULATION',
                'GRADIENT_INVERSION',
                'ALL_SEQUENTIAL'  // Run all attacks one after another
            ],
            description: 'Attack scenario to test'
        )
        
        string(
            name: 'FL_ROUNDS',
            defaultValue: '5',
            description: 'Number of FL training rounds'
        )
        
        string(
            name: 'FL_WAIT',
            defaultValue: '15',
            description: 'Wait time between rounds (seconds)'
        )
        
        booleanParam(
            name: 'RUN_SECURITY_AUDIT',
            defaultValue: true,
            description: 'Run security audits after training'
        )
        
        booleanParam(
            name: 'GENERATE_REPORT',
            defaultValue: true,
            description: 'Generate security report'
        )
    }
    
    stages {
        stage(' Checkout') {
            steps {
                echo '========== STAGE: Checkout =========='
                checkout scm
                sh 'git log --oneline -5'
            }
        }
        
        stage(' Code Quality') {
            steps {
                echo '========== STAGE: Code Quality =========='
                dir('fl-project') {
                    script {
                        sh '''
                        docker run --rm -v $(pwd):/code --user $(id -u):$(id -g) python:3.10-slim sh -c "
                            pip install bandit -q &&
                            bandit -c /code/quality_assurance/bandit.yml -r /code -f json -o /code/bandit-report.json --exit-zero
                        "
                        '''

                        sh '''
                        docker run --rm -v $(pwd):/src --user $(id -u):$(id -g) returntocorp/semgrep \
                            semgrep scan --config=/src/quality_assurance/semgrep-rules.yaml \
                            --json -o semgrep-report.json --metrics=off
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'fl-project/*-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage(' Build (Single Time)') {
            steps {
                echo '========== STAGE: Docker Build =========='
                dir('fl-project') {
                    sh '''
                        echo "Building Docker images once (no rebuilds per attack)"
                        docker compose -f docker-compose-app.yml build
                        docker images | grep -E "fl-project|python"
                        echo " Docker images built"
                    '''
                }
            }
        }
        
        stage(' Deploy & Setup') {
            steps {
                echo '========== STAGE: Deploy =========='
                dir('fl-project') {
                    sh '''
                        # 1. Start Infrastructure (Background, won't restart if running)
                        docker compose -f docker-compose-infra.yml up -d

                        # 2. Restart Application (Force recreate to clear state)
                        docker compose -f docker-compose-app.yml down -v
                        docker compose -f docker-compose-app.yml up -d --build

                        echo "Waiting for services to start..."
                        sleep 10 # Shorter wait because infra is already up

                        # Health check loop
                        for i in {1..12}; do
                            if curl -s http://localhost:5000/health > /dev/null; then
                                echo " Services deployed successfully"
                                exit 0
                            fi
                            echo "Waiting for server... ($i/12)"
                            sleep 5
                        done
                        echo "Server failed to start"
                        exit 1
                    '''
                }
            }
        }

        stage(' Acquisition & Preparation') {
            steps {
                echo '========== STAGE: Data Preparation =========='
                dir('fl-project') {
                    sh '''
                        # Run the preparation inside a container to ensure dependencies exist
                        docker run --rm -v $(pwd):/app -w /app python:3.10-slim sh -c "pip install requests numpy tensorflow && python fetch_and_split.py"
                        ls -lah data/
                    '''
                }
            }
        }   
                
        // =====================================================
        // DYNAMIC: Run selected attack scenario(s)
        // =====================================================
        
        stage(' Run Attack Scenarios') {
            steps {
                echo "========== STAGE: Attack Scenarios =========="
                script {
                    // Define all attack modes
                    def attacks = [
                        'POISONING',
                        'STEALTHY',
                        'SYBIL_SIMULATION',
                        'GRADIENT_INVERSION'
                    ]
                    
                    if (params.ATTACK_MODE == 'ALL_SEQUENTIAL') {
                        // Run all attacks sequentially
                        echo " Running ALL attack scenarios sequentially"
                        attacks.each { attack ->
                            runAttackScenario(attack)
                        }
                        // Also run baseline (no attack)
                        runAttackScenario('NONE')
                    } else {
                        // Run single selected attack
                        echo " Running single attack scenario: ${params.ATTACK_MODE}"
                        runAttackScenario(params.ATTACK_MODE)
                    }
                }
            }
        }
        
        stage(' Security Analysis') {
            when {
                expression { params.RUN_SECURITY_AUDIT == true }
            }
            steps {
                echo '========== STAGE: Security Analysis =========='
                dir('fl-project') {
                    sh '''
                        mkdir -p security_analysis_reports
                        
                        # Analyze audit trails
                        python3 << 'PYTHON_SCRIPT'
import json
import os
from pathlib import Path

audit_dir = 'security_audits'
report = {
    'total_rounds': 0,
    'attacks_detected': 0,
    'attacks_rejected': 0,
    'client_stats': {},
    'detection_results': []
}

for audit_file in sorted(Path(audit_dir).glob('*.json')):
    with open(audit_file) as f:
        audit = json.load(f)
    
    report['total_rounds'] += 1
    
    # Count rejections
    if audit.get('rejected_updates'):
        report['attacks_rejected'] += len(audit['rejected_updates'])
        
        # Extract attack types
        for update_id, rejection in audit['rejected_updates'].items():
            analysis = rejection.get('security_analysis', {})
            for attack in analysis.get('detected_attacks', []):
                report['detection_results'].append({
                    'round': audit['round'],
                    'attack_type': attack.get('type'),
                    'confidence': attack.get('confidence'),
                    'evidence': attack.get('evidence')
                })
    
    # Track client stats
    for client_id, state in audit.get('client_states', {}).items():
        if client_id not in report['client_stats']:
            report['client_stats'][client_id] = {
                'updates_accepted': 0,
                'updates_rejected': 0
            }
        report['client_stats'][client_id]['updates_accepted'] += state.get('updates_accepted', 0)
        report['client_stats'][client_id]['updates_rejected'] += state.get('updates_rejected', 0)

# Save analysis
with open('security_analysis_reports/analysis.json', 'w') as f:
    json.dump(report, f, indent=2)

print(" Security analysis completed")
print(f"  Rounds analyzed: {report['total_rounds']}")
print(f"  Attacks detected: {len(report['detection_results'])}")
print(f"  Attacks rejected: {report['attacks_rejected']}")
PYTHON_SCRIPT
                '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security_analysis_reports/**', allowEmptyArchive: true
                }
            }
        }
        
        stage(' Generate Report') {
            when {
                expression { params.GENERATE_REPORT == true }
            }
            steps {
                echo '========== STAGE: Report Generation =========='
                dir('fl-project') {
                sh '''
                    python3 << 'PYTHON_SCRIPT'
import json
from datetime import datetime

# Read analysis
with open('security_analysis_reports/analysis.json') as f:
    analysis = json.load(f)

attack_mode = "${params.ATTACK_MODE}"

# Generate HTML report
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>FL Security Test Report - Attack Scenario: {attack_mode}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        .header {{ background: #4ecdc4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #f9f9f9; border-left: 4px solid #4ecdc4; padding: 15px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #4ecdc4; }}
        .detection {{ background: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high-confidence {{ border-left: 4px solid #51cf66; }}
        .medium-confidence {{ border-left: 4px solid #ffd93d; }}
        .low-confidence {{ border-left: 4px solid #ff6b6b; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #4ecdc4; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> FL Security Test Report</h1>
            <p>Attack Scenario: <strong>{attack_mode}</strong></p>
            <p>Generated: {datetime.now().isoformat()}</p>
        </div>
        
        <h2>Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{analysis['total_rounds']}</div>
                <p>Training Rounds</p>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(analysis['detection_results'])}</div>
                <p>Attacks Detected</p>
            </div>
            <div class="stat-box">
                <div class="stat-value">{analysis['attacks_rejected']}</div>
                <p>Attacks Rejected</p>
            </div>
        </div>
        
        <h2>Client Statistics</h2>
        <table>
            <tr>
                <th>Client ID</th>
                <th>Accepted Updates</th>
                <th>Rejected Updates</th>
                <th>Status</th>
            </tr>
"""

for client_id, stats in analysis['client_stats'].items():
    status = " BENIGN" if stats['updates_rejected'] == 0 else " MALICIOUS"
    html += f"""
            <tr>
                <td>{client_id}</td>
                <td>{stats['updates_accepted']}</td>
                <td>{stats['updates_rejected']}</td>
                <td>{status}</td>
            </tr>
"""

html += """
        </table>
        
        <h2>Attack Detection Results</h2>
"""

if analysis['detection_results']:
    for detection in analysis['detection_results']:
        confidence = detection['confidence']
        conf_class = 'high-confidence' if confidence > 0.8 else ('medium-confidence' if confidence > 0.6 else 'low-confidence')
        html += f"""
        <div class="detection {conf_class}">
            <strong>Round {detection['round']}: {detection['attack_type']}</strong><br>
            Confidence: {confidence:.1%}<br>
            Evidence: {detection['evidence']}
        </div>
"""
else:
    html += "<p>No attacks detected.</p>"

html += """
        <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>MLSecOps FL Security Testing Pipeline</p>
        </footer>
    </div>
</body>
</html>
"""

with open('security_analysis_reports/report.html', 'w') as f:
    f.write(html)

print(" HTML report generated")
PYTHON_SCRIPT
                '''
            }
            }
            post {
                always {
                    publishHTML([
                        reportDir: 'fl-project/security_analysis_reports',
                        reportFiles: 'report.html',
                        reportName: "Security Report - ${params.ATTACK_MODE}"
                    ])
                }
            }
        }
        
        stage(' Performance Metrics') {
            steps {
                echo '========== STAGE: Metrics Collection =========='
                dir('fl-project') {
                    sh '''
                    mkdir -p performance_reports
                    
                    # Collect Prometheus metrics
                    curl -s http://localhost:5000/metrics > performance_reports/prometheus-metrics.txt || true
                    
                    # Collect server status
                    curl -s http://localhost:5000/status | python3 -m json.tool > performance_reports/server-status.json || echo "{}" > performance_reports/server-status.json

                    # Collect security status
                    curl -s http://localhost:5000/security/status | python3 -m json.tool > performance_reports/security-status.json || echo "{}" > performance_reports/security-status.json
                                        
                    echo " Metrics collected"
                    '''
                }   
            }
            post {
                always {
                    archiveArtifacts artifacts: 'fl-project/performance_reports/**', allowEmptyArchive: true
                }
            }
        }
        
        stage(' Approval Gate (Optional)') {
            when {
                expression { params.ATTACK_MODE == 'ALL_SEQUENTIAL' }
            }
            steps {
                echo '========== STAGE: Review Results =========='
                input message: 'Review results. Deploy to production?', ok: 'Deploy'
            }
        }
        
        stage(' Cleanup') {
            steps {
                echo '========== STAGE: Cleanup =========='
                sh '''
                    # Only stop the app, keep Grafana running!
                    # Uncomment below to stop:
                    docker compose -f docker-compose-app.yml down -v
                    echo " Application stopped. Monitoring infrastructure is still running."
                    
                    echo " System ready for inspection"
                    echo "   Server: http://localhost:5000"
                    echo "   Security Status: curl http://localhost:5000/security/status"
                '''
            }
        }

        // Push reports (bandit, semgrep, pylint..) to grafana
        stage(' Publish Metrics to Grafana') {
            steps {
                echo '========== STAGE: Publish Metrics =========='
                dir('fl-project') {
                    sh '''
                        # Ensure we are in the same environment or reinstall requests
                        python3 -m venv venv
                        . venv/bin/activate
                        pip install requests

                        # Run the exporter script
                        python3 quality_assurance/export_metrics.py
                    '''
                }
            }
        }
    }
    
    post {
        always {
            echo '========== Build Complete =========='
            archiveArtifacts artifacts: 'fl-project/*-report.html, fl-project/performance_reports/*.json, fl-project/security_analysis_reports/*.json', allowEmptyArchive: true

            dir('fl-project') {
                sh '''
                    # Capture logs from the containers we know exist
                    # || true ensures the build doesn't fail if a container is missing
                    docker logs fl_server > server.log 2>&1 || true
                    docker logs fl_malicious_client > malicious_client.log 2>&1 || true
                    docker logs fl_client_1 > client_1.log 2>&1 || true
                '''
            }
            archiveArtifacts artifacts: 'fl-project/*.log', allowEmptyArchive: true
        }
        success {
            echo ' Pipeline completed successfully!'
        }
        failure {
            echo ' Pipeline failed!'
        }
    }
}

// =====================================================
// HELPER FUNCTION: Run single attack scenario
// =====================================================
def runAttackScenario(String attackMode) {
    echo "Running Attack Scenario: $attackMode"
    
    dir('fl-project') {
        sh '''
            set -e
            
            # FIX: Point to the new APP compose file
            sed -i.bak "s/ATTACK_MODE=.*/ATTACK_MODE=''' + attackMode + '''/" docker-compose-app.yml

            # FIX: Point to the new APP compose file
            docker compose -f docker-compose-app.yml up -d --no-deps --build malicious_client

            sleep 5

            # This remains the same
            docker exec fl_server python3 control.py --mode train --rounds ${FL_ROUNDS} --wait ${FL_WAIT}
            
            echo " Attack scenario ''' + attackMode + ''' completed"
        '''
    }
}