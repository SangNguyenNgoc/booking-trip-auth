pipeline {
    agent any

    environment {
        DEPLOY_SERVER = '178.128.214.157'
        DEPLOY_PATH = '/mywork/auth'
        SSH_CREDENTIALS_ID = 'discovery-server-key' // Sử dụng ID từ Jenkins Credentials
        GITHUB_REPO = 'https://github.com/SangNguyenNgoc/booking-trip-auth.git'
    }

    stages {
        stage('SSH to Deploy Server and Setup') {
            steps {
                sshagent([SSH_CREDENTIALS_ID]) {
                    sh """
                        ssh -o StrictHostKeyChecking=no root@${DEPLOY_SERVER} '
                            # 1: Truy cập vào thư mục làm việc
                            cd ${DEPLOY_PATH} &&
                            
                            # Xóa thư mục clone cũ nếu tồn tại để đảm bảo clean build
                            rm -rf cloned_repo
                        '
                    """
                }
            }
        }

        stage('Clone Source Code') {
            steps {
                sshagent([SSH_CREDENTIALS_ID]) {
                    sh """
                        ssh -o StrictHostKeyChecking=no root@${DEPLOY_SERVER} '
                            # 2: Clone mã nguồn từ GitHub
                            git clone ${GITHUB_REPO} ${DEPLOY_PATH}/cloned_repo
                        '
                    """
                }
            }
        }

        stage('Copy .env File') {
            steps {
                sshagent([SSH_CREDENTIALS_ID]) {
                    sh """
                        ssh -o StrictHostKeyChecking=no root@${DEPLOY_SERVER} '
                            # 3: Copy file .env vào thư mục vừa clone
                            cd ${DEPLOY_PATH}/cloned_repo &&
                            cp ../.env .
                        '
                    """
                }
            }
        }

        stage('Build and Deploy with Docker Compose') {
            steps {
                sshagent([SSH_CREDENTIALS_ID]) {
                    sh """
                        ssh -o StrictHostKeyChecking=no root@${DEPLOY_SERVER} '
                            # 4: Chạy docker-compose để build và deploy
                            cd ${DEPLOY_PATH}/cloned_repo &&
                            docker compose -f auth.yml -p auth-server up -d --build
                        '
                    """
                }
            }
        }

        stage('Clean Up') {
            steps {
                sshagent([SSH_CREDENTIALS_ID]) {
                    sh """
                        ssh -o StrictHostKeyChecking=no root@${DEPLOY_SERVER} '
                            # 5: Xóa thư mục clone sau khi deploy xong
                            cd ${DEPLOY_PATH} &&
                            rm -rf cloned_repo
                        '
                    """
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
