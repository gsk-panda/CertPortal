#!/bin/bash
# CertPortal EC2 bootstrap (Amazon Linux 2023).
# Placeholders __BUCKET__ / __EIP__ / __REGION__ are filled in at launch time.
set -euxo pipefail
exec > /var/log/certportal-init.log 2>&1

dnf install -y docker
systemctl enable --now docker

mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
# compose >= 2.30 delegates builds to buildx, which AL2023's docker package lacks
BUILDX_V=$(curl -fsSL https://api.github.com/repos/docker/buildx/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
curl -fsSL "https://github.com/docker/buildx/releases/download/${BUILDX_V}/buildx-${BUILDX_V}.linux-amd64" \
  -o /usr/local/lib/docker/cli-plugins/docker-buildx
chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx

aws s3 cp s3://__BUCKET__/certportal.tar.gz /opt/certportal.tar.gz --region __REGION__
mkdir -p /opt/certportal
tar -xzf /opt/certportal.tar.gz -C /opt/certportal
cd /opt/certportal

p() { aws ssm get-parameter --name "$1" --with-decryption --region __REGION__ --query Parameter.Value --output text; }
# optional parameter: empty string when not present in SSM
po() { p "$1" 2>/dev/null || true; }

cat > .env <<EOF
MASTER_KEK=$(p /certportal/master_kek)
SESSION_SECRET=$(p /certportal/session_secret)
ADMIN_EMAIL=cmc.1974@outlook.com
ADMIN_PASSWORD=$(p /certportal/admin_password)
POSTGRES_PASSWORD=$(p /certportal/db_password)
BASE_URL=https://certportal.azotech.net
COOKIE_SECURE=true
ACME_DIRECTORY=staging
ACME_DNS_ZONE=acme.certportal.azotech.net
ACME_DNS_PUBLIC_IP=__EIP__
ACME_DNS_PORT=5353
PORTAL_PUBLIC_IP=__EIP__
SMTP_HOST=email-smtp.__REGION__.amazonaws.com
SMTP_PORT=587
SMTP_USER=$(po /certportal/smtp_user)
SMTP_PASS=$(po /certportal/smtp_pass)
SMTP_FROM=noreply@azotech.net
EOF
chmod 600 .env

docker compose -f docker-compose.yml -f deploy/aws/docker-compose.aws.yml up -d --build
echo "certportal bootstrap complete"
