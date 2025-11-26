pipeline {
    agent any

    environment {
        DOCKERHUB_REPO = "your-docker-id"   // <<< change this to your DockerHub username
        K8S_NAMESPACE  = "ems"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/SriVenkatG/ems2_deploy.git'
            }
        }

        stage('Build & Push Images') {
            environment {
                IMAGE_BACKEND  = "${env.DOCKERHUB_REPO}/ems-backend:${env.BUILD_NUMBER}"
                IMAGE_FRONTEND = "${env.DOCKERHUB_REPO}/ems-frontend:${env.BUILD_NUMBER}"
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds',
                        usernameVariable: 'DOCKER_USER',
                        passwordVariable: 'DOCKER_PASS')]) {
                    sh '''
                      echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin

                      docker build -f ems-backend/Dockerfile.backend -t $IMAGE_BACKEND ems-backend
                      docker build -f ems-frontend/Dockerfile.frontend -t $IMAGE_FRONTEND ems-frontend

                      docker push $IMAGE_BACKEND
                      docker push $IMAGE_FRONTEND
                    '''
                }
            }
        }

        stage('Deploy to Kubernetes') {
            environment {
                IMAGE_BACKEND  = "${env.DOCKERHUB_REPO}/ems-backend:${env.BUILD_NUMBER}"
                IMAGE_FRONTEND = "${env.DOCKERHUB_REPO}/ems-frontend:${env.BUILD_NUMBER}"
            }
            steps {
                withCredentials([
                    file(credentialsId: 'kubeconfig-ems', variable: 'KUBECONFIG_FILE'),
                    string(credentialsId: 'EMS_DB_PASSWORD', variable: 'EMS_DB_PASSWORD'),
                    string(credentialsId: 'EMS_JWT_SECRET', variable: 'EMS_JWT_SECRET'),
                    usernamePassword(credentialsId: 'EMS_MAIL_CREDS',
                        usernameVariable: 'EMS_MAIL_USER',
                        passwordVariable: 'EMS_MAIL_PASS')
                ]) {
                    sh '''
                      export KUBECONFIG=$KUBECONFIG_FILE

                      kubectl create namespace ${K8S_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

                      kubectl -n ${K8S_NAMESPACE} apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ems-secrets
type: Opaque
stringData:
  MYSQL_ROOT_PASSWORD: "$EMS_DB_PASSWORD"
  APP_JWT_SECRET: "$EMS_JWT_SECRET"
  SPRING_MAIL_PASSWORD: "$EMS_MAIL_PASS"
EOF

                      sed -i "s|your-docker-id/ems-backend:latest|$IMAGE_BACKEND|g" k8s/backend-deployment.yml
                      sed -i "s|your-docker-id/ems-frontend:latest|$IMAGE_FRONTEND|g" k8s/frontend-deployment.yml

                      kubectl -n ${K8S_NAMESPACE} apply -f k8s/configmap.yml
                      kubectl -n ${K8S_NAMESPACE} apply -f k8s/mysql-deployment.yml
                      kubectl -n ${K8S_NAMESPACE} apply -f k8s/backend-deployment.yml
                      kubectl -n ${K8S_NAMESPACE} apply -f k8s/frontend-deployment.yml
                    '''
                }
            }
        }
    }
}
