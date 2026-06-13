// Jenkinsfile — CI/CD pipeline for RT-IDRS
//
// Pipeline stages:
//   1. Checkout source from GitHub
//   2. Set up Python and run unit tests for analyzer & response-engine
//   3. Build Docker images for all services
//   4. Scan images for vulnerabilities with Trivy (fails on HIGH/CRITICAL)
//   5. Push images to Docker Hub (tagged with build number + latest)
//   6. Deploy via docker-compose on the target host
//
// Required Jenkins setup:
//   - "Docker Pipeline" plugin
//   - Credentials: "dockerhub-creds" (username/password) for Docker Hub
//   - Credentials: "deploy-server-ssh" (SSH key) if deploying remotely
//   - A GitHub webhook pointing at <jenkins-url>/github-webhook/

pipeline {
    agent any

    environment {
        DOCKERHUB_USER = "yourdockerhub"          // change to your Docker Hub username
        IMAGE_TAG      = "${env.BUILD_NUMBER}"
        COMPOSE_FILE   = "docker-compose.yml"
    }

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    triggers {
        githubPush()
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Unit Tests') {
            steps {
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --upgrade pip
                    pip install -r analyzer/requirements.txt -r response-engine/requirements.txt pytest

                    echo "Running analyzer tests..."
                    pytest analyzer/tests --junitxml=analyzer-test-results.xml

                    echo "Running response-engine tests..."
                    pytest response-engine/tests --junitxml=response-engine-test-results.xml
                '''
            }
            post {
                always {
                    junit '**/*-test-results.xml'
                }
            }
        }

        stage('Build Docker Images') {
            steps {
                sh '''
                    docker build -t ${DOCKERHUB_USER}/rt-idrs-suricata:${IMAGE_TAG} ./suricata
                    docker build -t ${DOCKERHUB_USER}/rt-idrs-analyzer:${IMAGE_TAG} ./analyzer
                    docker build -t ${DOCKERHUB_USER}/rt-idrs-response-engine:${IMAGE_TAG} ./response-engine
                    docker build -t ${DOCKERHUB_USER}/rt-idrs-dashboard:${IMAGE_TAG} ./dashboard
                '''
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                sh '''
                    # Install Trivy if not already present on the agent
                    if ! command -v trivy &> /dev/null; then
                        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
                    fi

                    for SERVICE in suricata analyzer response-engine dashboard; do
                        echo "Scanning rt-idrs-${SERVICE}..."
                        trivy image --exit-code 1 --severity HIGH,CRITICAL \
                            ${DOCKERHUB_USER}/rt-idrs-${SERVICE}:${IMAGE_TAG}
                    done
                '''
            }
        }

        stage('Push Images') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-creds',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin

                        for SERVICE in suricata analyzer response-engine dashboard; do
                            docker tag ${DOCKERHUB_USER}/rt-idrs-${SERVICE}:${IMAGE_TAG} ${DOCKERHUB_USER}/rt-idrs-${SERVICE}:latest
                            docker push ${DOCKERHUB_USER}/rt-idrs-${SERVICE}:${IMAGE_TAG}
                            docker push ${DOCKERHUB_USER}/rt-idrs-${SERVICE}:latest
                        done
                    '''
                }
            }
        }

        stage('Deploy') {
            steps {
                sshagent(['deploy-server-ssh']) {
                    sh '''
                        ssh -o StrictHostKeyChecking=no deploy@$DEPLOY_HOST "
                            cd /opt/rt-idrs &&
                            export DOCKERHUB_USER=${DOCKERHUB_USER} &&
                            export IMAGE_TAG=${IMAGE_TAG} &&
                            docker compose pull &&
                            docker compose up -d --remove-orphans
                        "
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "Pipeline succeeded — RT-IDRS deployed with image tag ${IMAGE_TAG}"
        }
        failure {
            echo "Pipeline failed — check console output for details"
        }
        always {
            sh 'docker image prune -f || true'
        }
    }
}
