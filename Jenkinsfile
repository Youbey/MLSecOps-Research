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
                sh '''
                    pip install bandit semgrep pylint -q
                    bandit -r . -f json -o bandit-report.json || true
                    semgrep --config=p/security-audit . --json -o semgrep-report.json || true
                    echo " Code quality checks completed"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: '*-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage(' Build (Single Time)') {
            steps {
                echo '========== STAGE: Docker Build =========='
                dir('fl-project') {
                    sh '''
                        echo "Building Docker images once (no rebuilds per attack)"
                        docker compose build
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
                        # Stop any existing containers
                        docker compose down -v || true
                        
                        # Start fresh
                        docker compose up -d
                        echo "Waiting for services to start..."
                        sleep 60
                        
                        # Verify services
                        curl -f http://localhost:5000/health || exit 1
                        echo " Services deployed successfully"
                    '''
                }
            }
        }
        
        stage(' Generate Training Data') {
            steps {
                echo '========== STAGE: Data Generation =========='
                dir('fl-project') {
                    sh '''
                        python generate_data.py
                        ls -lah data/
                        echo " Training data generated"
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
                        python << 'PYTHON_SCRIPT'
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
                    archiveArtifacts artifacts: 'security_analysis_reports/**'
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
                    python << 'PYTHON_SCRIPT'
import json
from datetime import datetime

# Read analysis
with open('security_analysis_reports/analysis.json') as f:
    analysis = json.load(f)

# Generate HTML report
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>FL Security Test Report - Attack Scenario: {params.ATTACK_MODE}</title>
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
            <p>Attack Scenario: <strong>{params.ATTACK_MODE}</strong></p>
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
                        reportDir: 'security_analysis_reports',
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
                    curl -s http://localhost:5000/status | jq . > performance_reports/server-status.json || true
                    
                    # Collect security status
                    curl -s http://localhost:5000/security/status | jq . > performance_reports/security-status.json || true
                    
                    echo " Metrics collected"
                    '''
                }   
            }
            post {
                always {
                    archiveArtifacts artifacts: 'performance_reports/**'
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
                    # Keep containers running for inspection
                    # Uncomment below to stop:
                    # docker compose down
                    
                    echo " System ready for inspection"
                    echo "   Server: http://localhost:5000"
                    echo "   Security Status: curl http://localhost:5000/security/status"
                '''
            }
        }
    }
    
    post {
        always {
            echo '========== Build Complete =========='
            archiveArtifacts artifacts: 'security_audits/**, security_analysis_reports/**, performance_reports/**', allowEmptyArchive: true
            
            // Cleanup
            dir('fl-project') {
                sh '''
                    # Save Docker logs
                    docker compose logs > docker compose.log || true
                    docker compose logs fl_server > server.log || true
                    docker compose logs fl_malicious_client > malicious-client.log || true
                '''
            }
            archiveArtifacts artifacts: '*.log', allowEmptyArchive: true
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
    echo "\n${'='*70}"
    echo "Running Attack Scenario: $attackMode"
    echo "${'='*70}\n"
    
    dir('fl-project') {
        sh '''
            set -e
            
            # Update docker compose with attack mode
            sed -i.bak "s/ATTACK_MODE=.*/ATTACK_MODE=''' + attackMode + '''/" docker compose.yml
            
            # Restart malicious client with new attack mode
            docker compose up -d --no-deps --build malicious_client 2>/dev/null || true
            
            # Wait for malicious client to reconnect
            sleep 5
            
            # Run training rounds
            echo "Starting training with attack mode: ''' + attackMode + '''"
            python control.py --mode train \\
                --rounds ${FL_ROUNDS} \\
                --wait ${FL_WAIT}
            
            # Save audit files with attack mode prefix
            if [ -d "security_audits" ]; then
                for file in security_audits/round_*.json; do
                    [ -f "$file" ] && mv "$file" "$file.''' + attackMode + '''"
                done
            fi
            
            echo " Attack scenario ''' + attackMode + ''' completed"
        '''
    }
}