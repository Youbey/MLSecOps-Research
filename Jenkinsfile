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
                            bandit -c /code/qa/bandit.yml -r /code/app -f json -o /code/bandit-report.json --exit-zero
                        "
                        '''

                        sh '''
                        docker run --rm -v $(pwd):/src --user $(id -u):$(id -g) returntocorp/semgrep \
                            semgrep scan --config=/src/qa/semgrep-rules.yaml \
                            --json -o semgrep-report.json --metrics=off /src/app
                        '''
                        // 3. Pylint (Scan folder 'app')
                        // the || true, prevents build failaure even if score is low
                        sh '''
                        docker run --rm -v $(pwd):/code --user $(id -u):$(id -g) python:3.10-slim sh -c "
                            pip install pylint flask tensorflow numpy requests prometheus-client -q &&
                            export PYTHONPATH=/code/app &&
                            pylint /code/app --output-format=json > /code/pylint-report.json || true
                        "
                        '''

                        stash includes: '*.json', name: 'sast-reports'
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'fl-project/*.json', allowEmptyArchive: true
                }
            }
        }
        
        stage(' Build ' ) {
            steps {
                echo '========== STAGE: Docker Build =========='
                dir('fl-project') {
                    sh '''
                        echo "Building Docker images once (no rebuilds per attack)"
                        docker compose -f infra/docker/docker-compose-app.yml build
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
                        # temporary fix for alerts (TO BE REMOVED AFTER FIX)
                        docker rm -f fl_grafana || true

                        # 1. Start Infrastructure (Background, won't restart if running)
                        docker compose -f infra/docker/docker-compose-infra.yml up -d

                        # 2. Restart Application (Force recreate to clear state)
                        docker compose -f infra/docker/docker-compose-app.yml down -v
                        docker compose -f infra/docker/docker-compose-app.yml up -d --build

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
        
        stage(' Cleanup') {
            steps {
                echo '========== STAGE: Cleanup =========='
                dir('fl-project') {
                    sh '''
                        # Only stop the app, keep Grafana running!
                        docker compose -f infra/docker/docker-compose-app.yml down -v
                        echo " Application stopped. Monitoring infrastructure is still running."
                    '''
                }
            }
        }

        // Push reports (bandit, semgrep, pylint..) to grafana
        stage(' Publish Metrics to Grafana') {
            steps {
                echo '========== STAGE: Publish Metrics =========='
                dir('fl-project') {
                    unstash 'sast-reports'
                    sh '''
                        # Ensure we are in the same environment or reinstall requests
                        python3 -m venv venv
                        . venv/bin/activate
                        pip install requests

                        # Run the exporter script
                        python3 qa/export_metrics.py
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
            sed -i.bak "s/ATTACK_MODE=.*/ATTACK_MODE=''' + attackMode + '''/" infra/docker/docker-compose-app.yml

            # FIX: Point to the new APP compose file
            docker compose -f infra/docker/docker-compose-app.yml up -d --no-deps --build malicious_client

            sleep 5

            # This remains the same
            docker exec fl_server python3 scripts/control.py --mode train --rounds ${FL_ROUNDS} --wait ${FL_WAIT}
            
            echo " Attack scenario ''' + attackMode + ''' completed"
        '''
    }
}