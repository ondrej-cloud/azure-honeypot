#!/usr/bin/env bash
# Your home IP changed and SSH to the admin port times out? Point the NSG rule at your current IP.
set -euo pipefail

RG=${RG:-rg-honeypot}
PREFIX=${PREFIX:-hpot}
ADMIN_IP=${ADMIN_IP:-$(curl -fsS https://api.ipify.org)}

az network nsg rule update --resource-group "$RG" --nsg-name "$PREFIX-nsg" --name Allow-Admin-SSH \
  --source-address-prefixes "$ADMIN_IP/32" --output none
echo "Admin SSH is now open to $ADMIN_IP only."
