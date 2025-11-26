pipeline {
    agent any

    environment {
        DOCKERHUB_REPO = "srivenkat31666"      // your Docker Hub username
        K8S_NAMESPACE  = "ems"

        // Always use :latest tag
        IMAGE_BACKEND  = "${DOCKERHUB_REPO}/ems-backend:latest"
        IMAGE_FRONTEND = "${DOCKERHUB_REPO}/ems-frontend:latest"
    }

    stages {

        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/SriVenkatG/ems2_k8s_deploy.git'
            }
        }

        stage('Build & Push Images') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-creds',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    // Windows shell => use bat and %VAR%
                    bat """
                    docker login -u %DOCKER_USER% -p %DOCKER_PASS%

                    docker build -f ems-backend/Dockerfile.backend -t %IMAGE_BACKEND% ems-backend
                    docker build -f ems-frontend/Dockerfile.frontend -t %IMAGE_FRONTEND% ems-frontend

                    docker push %IMAGE_BACKEND%
                    docker push %IMAGE_FRONTEND%
                    """
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                withCredentials([
                    file(credentialsId: 'kubeconfig-ems',    variable: 'KUBECONFIG_FILE'),
                    string(credentialsId: 'EMS_DB_PASSWORD', variable: 'EMS_DB_PASSWORD'),
                    string(credentialsId: 'EMS_JWT_SECRET',  variable: 'EMS_JWT_SECRET'),
                    usernamePassword(
                        credentialsId: 'EMS_MAIL_CREDS',
                        usernameVariable: 'EMS_MAIL_USER',
                        passwordVariable: 'EMS_MAIL_PASS'
                    )
                ]) {
                    bat """
                    REM use kubeconfig file from Jenkins credential
                    set KUBECONFIG=%KUBECONFIG_FILE%

                    REM make sure namespace exists
                    kubectl create namespace %K8S_NAMESPACE% --dry-run=client -o yaml | kubectl apply -f -

                    REM recreate ems-secrets from Jenkins credentials
                    kubectl -n %K8S_NAMESPACE% delete secret ems-secrets --ignore-not-found

                    kubectl -n %K8S_NAMESPACE% create secret generic ems-secrets ^
                      --from-literal=MYSQL_ROOT_PASSWORD=%EMS_DB_PASSWORD% ^
                      --from-literal=APP_JWT_SECRET=%EMS_JWT_SECRET% ^
                      --from-literal=SPRING_MAIL_PASSWORD=%EMS_MAIL_PASS%

                    REM apply manifests
                    kubectl -n %K8S_NAMESPACE% apply -f "%WORKSPACE%\\k8s\\configmap.yml"
                    kubectl -n %K8S_NAMESPACE% apply -f "%WORKSPACE%\\k8s\\mysql-deployment.yml"
                    kubectl -n %K8S_NAMESPACE% apply -f "%WORKSPACE%\\k8s\\backend-deployment.yml"
                    kubectl -n %K8S_NAMESPACE% apply -f "%WORKSPACE%\\k8s\\frontend-deployment.yml"
                    """
                }
            }
        }
    }
}
