pipeline {
    agent any

    environment {
        DEPLOY_SERVER = '178.128.214.157'
        DEPLOY_PATH = '/mywork/auth'
        SSH_CREDENTIALS_ID = 'discovery-server-key' // Sử dụng ID từ Jenkins Credentials
        GITHUB_REPO = 'https://github.com/SangNguyenNgoc/booking-trip-auth.git'
    }

    stages {
        stage('Deploy Application') {
            steps {
                sshagent([SSH_CREDENTIALS_ID]) {
                    sh """
                        ssh -o StrictHostKeyChecking=no root@${DEPLOY_SERVER} '
                            # 1: Truy cập vào thư mục làm việc và xóa clone cũ nếu có
                            cd ${DEPLOY_PATH} &&
                            rm -rf cloned_repo &&
                            
                            # 2: Clone mã nguồn từ GitHub
                            git clone ${GITHUB_REPO} cloned_repo &&
                            
                            # 3: Copy file .env vào thư mục vừa clone
                            cd cloned_repo &&
                            cp ../.env . &&
                            
                            # 4: Chạy docker-compose để build và deploy
                             docker compose -f auth.yml -p auth-server up -d --build &&
                            
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
