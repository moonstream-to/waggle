#!/usr/bin/env bash

# Deployment script

# Colors
C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'

# Logs
PREFIX_INFO="${C_GREEN}[INFO]${C_RESET} [$(date +%d-%m\ %T)]"
PREFIX_WARN="${C_YELLOW}[WARN]${C_RESET} [$(date +%d-%m\ %T)]"
PREFIX_CRIT="${C_RED}[CRIT]${C_RESET} [$(date +%d-%m\ %T)]"

# Main
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
APP_DIR="${APP_DIR:-/home/ubuntu/waggle}"
SECRETS_DIR="${SECRETS_DIR:-/home/ubuntu/waggle-secrets}"
PARAMETERS_ENV_PATH="${SECRETS_DIR}/app.env"
SCRIPT_DIR="$(realpath $(dirname $0))"

# Service file
WAGGLE_SERVICE_FILE="waggle.service"

set -eu

echo
echo
echo -e "${PREFIX_INFO} Install checkenv"
HOME=/home/ubuntu /usr/local/go/bin/go install github.com/bugout-dev/checkenv@latest

echo
echo
echo -e "${PREFIX_INFO} Retrieving addition deployment parameters"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION}" /home/ubuntu/go/bin/checkenv show aws_ssm+waggle:true >> "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Add instance local IP to parameters"
echo "AWS_LOCAL_IPV4=$(ec2metadata --local-ipv4)" >> "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Building executable waggle script with Go"
EXEC_DIR=$(pwd)
cd "${APP_DIR}"
HOME=/home/ubuntu /usr/local/go/bin/go build -o "${APP_DIR}/waggle" .
cd "${EXEC_DIR}"

echo
echo
echo -e "${PREFIX_INFO} Replacing existing waggle service definition with ${WAGGLE_SERVICE_FILE}"
chmod 644 "${SCRIPT_DIR}/${WAGGLE_SERVICE_FILE}"
cp "${SCRIPT_DIR}/${WAGGLE_SERVICE_FILE}" "/home/ubuntu/.config/systemd/user/${WAGGLE_SERVICE_FILE}"
XDG_RUNTIME_DIR="/run/user/$UID" systemctl --user daemon-reload
XDG_RUNTIME_DIR="/run/user/$UID" systemctl --user restart "${WAGGLE_SERVICE_FILE}"
