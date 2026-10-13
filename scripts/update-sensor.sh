#!/usr/bin/env bash
# Push changes in sensor/ to the running VM.
#
# Azure does not allow changing a VM's custom data (cloud-init) after creation,
# so re-running the Bicep deployment cannot update these files. Copy them over SSH.
set -euo pipefail
cd "$(dirname "$0")/.."

RG=${RG:-rg-honeypot}
PREFIX=${PREFIX:-hpot}
PORT=${PORT:-22222}
IP=$(az network public-ip show --resource-group "$RG" --name "$PREFIX-pip" --query ipAddress -o tsv)

scp -P "$PORT" sensor/docker-compose.yml sensor/shipper.py "azureuser@$IP:/tmp/"
ssh -p "$PORT" "azureuser@$IP" '
  set -e
  sudo install -m 0644 /tmp/docker-compose.yml /opt/honeypot/docker-compose.yml
  sudo install -m 0755 /tmp/shipper.py /opt/honeypot/shipper.py
  sudo docker compose -f /opt/honeypot/docker-compose.yml pull --quiet
  sudo docker compose -f /opt/honeypot/docker-compose.yml up -d
  sudo docker ps --format "{{.Names}}  {{.Image}}  {{.Status}}"
'
