pipeline {
agent any

environment {
    DOCKERHUB_USER = "yourdockerhub"
    IMAGE_TAG = "${BUILD_NUMBER}"
}

options {
    timestamps()
}

stages {

    stage('Checkout') {
        steps {
            checkout scm
        }
    }

    stage('Build Docker Images') {
        steps {
            bat '''
            docker build -t %DOCKERHUB_USER%/rt-idrs-suricata:%IMAGE_TAG% suricata
            docker build -t %DOCKERHUB_USER%/rt-idrs-analyzer:%IMAGE_TAG% analyzer
            docker build -t %DOCKERHUB_USER%/rt-idrs-response-engine:%IMAGE_TAG% response-engine
            docker build -t %DOCKERHUB_USER%/rt-idrs-dashboard:%IMAGE_TAG% dashboard
            '''
        }
    }

    stage('Push Images') {
        steps {
            echo 'Skipping DockerHub push for now'
        }
    }

    stage('Deploy') {
        steps {
            bat '''
            docker compose down
            docker compose up -d
            '''
        }
    }
}

post {
    success {
        echo 'RT-IDRS Pipeline Successful'
    }

    failure {
        echo 'RT-IDRS Pipeline Failed'
    }
}


}
