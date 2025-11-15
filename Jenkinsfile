pipeline {
  agent any
  options { timestamps() }

  triggers {
    githubPush()
    pollSCM('H/2 * * * *')
  }

  environment {
    APP_DIR = "/home/monitoring-devops"
    VENV = "${WORKSPACE}/venv"
    SERVICE = "monitoring2.service"
    SCRIPT = "monitoring-wa.py"
  }

  stages {

    /* -------------------------------------------
       ✅ CHECKOUT REPOSITORY
    -------------------------------------------- */
    stage('Checkout') {
      steps {
        checkout scm
        sh 'ls -la'
      }
    }

    /* -------------------------------------------
       🐍 ENSURE PYTHON ENV + DEPENDENCIES
    -------------------------------------------- */
    stage('Setup Python Environment') {
      steps {
        sh '''
          if [ ! -x "$VENV/bin/python" ]; then
            echo "[VENV] Creating virtual environment..."
            python3 -m venv "$VENV"
          fi

          "$VENV/bin/pip" install --upgrade pip
          "$VENV/bin/pip" install requests google-generativeai python-dotenv
        '''
      }
    }

    /* -------------------------------------------
       🚀 CI START NOTIFICATION (NOW SAFE)
    -------------------------------------------- */
    stage('Notify Build Start') {
      steps {
        sh '''
          . "$VENV/bin/activate"
          python3 - << 'EOF'
from dotenv import load_dotenv
import os, requests, socket, datetime

load_dotenv('/home/monitoring-devops/.env')
token = os.getenv("FONNTE_TOKEN")
targets = [t.strip() for t in os.getenv("FONNTE_TARGETS","").split(',') if t.strip()]

hostname = socket.gethostname()
ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

msg = f"""🚀 *CI Deploy Started*
Server: {hostname}
Time: {ts}"""

for t in targets:
    requests.post("https://api.fonnte.com/send",
        headers={"Authorization": token},
        data={"target": t, "message": msg})
EOF
        '''
      }
    }

    /* -------------------------------------------
       📦 DEPLOY SCRIPT TO SERVER
    -------------------------------------------- */
    stage('Deploy File') {
      steps {
        sh '''
            sudo install -m 644 $SCRIPT $APP_DIR/$SCRIPT
        '''
      }
    }

    /* -------------------------------------------
       🔁 RESTART SYSTEMD SERVICE
    -------------------------------------------- */
    stage('Restart Monitoring Service') {
      steps {
        sh '''
          sudo systemctl daemon-reload
          sudo systemctl restart "$SERVICE"
          sleep 2
          sudo systemctl is-active "$SERVICE"
        '''
      }
    }

    /* -------------------------------------------
       📄 CAPTURE LOGS FOR CI DOC
    -------------------------------------------- */
    stage('Fetch Logs') {
      steps {
        sh '''
          sudo journalctl -u "$SERVICE" -n 500 --no-pager > jenkins_service_tail.txt || true
        '''
      }
    }
  }

  /* -------------------------------------------
     ✅ POST BUILD NOTIFICATIONS
  -------------------------------------------- */
  post {

    always {
      archiveArtifacts artifacts: 'jenkins_service_tail.txt', allowEmptyArchive: true
    }

    success {
      sh '''
        . "$VENV/bin/activate"
        python3 - << 'EOF'
from dotenv import load_dotenv
import os, requests, socket, datetime

load_dotenv('/home/monitoring-devops/.env')
token = os.getenv("FONNTE_TOKEN")
targets = [t.strip() for t in os.getenv("FONNTE_TARGETS","").split(',') if t.strip()]

hostname = socket.gethostname()
ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

msg = f"""✅ *CI Deploy Success*
Server: {hostname}
Time: {ts}"""

for t in targets:
    requests.post("https://api.fonnte.com/send",
        headers={"Authorization": token},
        data={"target": t, "message": msg})
EOF
      '''
    }

    failure {
      sh '''
        . "$VENV/bin/activate"
        python3 - << 'EOF'
from dotenv import load_dotenv
import os, requests, socket, datetime

load_dotenv('/home/monitoring-devops/.env')
token = os.getenv("FONNTE_TOKEN")
targets = [t.strip() for t in os.getenv("FONNTE_TARGETS","").split(',') if t.strip()]

hostname = socket.gethostname()
ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

msg = f"""❌ *CI Deploy Failed*
Server: {hostname}
Time: {ts}"""

for t in targets:
    requests.post("https://api.fonnte.com/send",
        headers={"Authorization": token},
        data={"target": t, "message": msg})
EOF
      '''
    }
  }
}
