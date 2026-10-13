#!/usr/bin/env bash
# Deploy the honeypot to Azure and point this GitHub repository at it.
#
#   scripts/deploy.sh
#
# Optional overrides: LOCATION, RG, VM_SIZE, PREFIX, SSH_KEY, GITHUB_REPO, ADMIN_IP
set -euo pipefail
cd "$(dirname "$0")/.."

RG=${RG:-rg-honeypot}
LOCATION=${LOCATION:-germanywestcentral}
VM_SIZE=${VM_SIZE:-Standard_B1s}
PREFIX=${PREFIX:-hpot}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519.pub}
GITHUB_REPO=${GITHUB_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)}

die() { echo "error: $*" >&2; exit 1; }

command -v az >/dev/null || die "Azure CLI not found. Install it with: brew install azure-cli"
az account show >/dev/null 2>&1 || die "not logged in to Azure. Run: az login"
[[ -f $SSH_KEY ]] || die "no SSH public key at $SSH_KEY. Create one with: ssh-keygen -t ed25519"
[[ -n $GITHUB_REPO ]] || die "push this repo to GitHub first, or set GITHUB_REPO=owner/name"
ADMIN_IP=${ADMIN_IP:-$(curl -fsS https://api.ipify.org)} || die "could not detect your public IP, set ADMIN_IP"

cat <<EOF
Subscription  $(az account show --query name -o tsv)
Region        $LOCATION
VM size       $VM_SIZE
GitHub repo   $GITHUB_REPO
Admin IP      $ADMIN_IP  (the only address allowed to reach the real SSH port)

EOF

echo "Checking that $VM_SIZE is offered in $LOCATION..."
offered=$(az vm list-skus --location "$LOCATION" --size "$VM_SIZE" --resource-type virtualMachines \
  --query "[?name=='$VM_SIZE'].name" -o tsv)
[[ -n $offered ]] || die "$VM_SIZE is not available to this subscription in $LOCATION.
Try another region, e.g. LOCATION=swedencentral scripts/deploy.sh (Azure for Students limits regions)."

az group create --name "$RG" --location "$LOCATION" --output none
admin_id=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)

echo "Deploying (about 2 minutes)..."
outputs=$(az deployment group create \
  --resource-group "$RG" \
  --name honeypot \
  --template-file infra/main.bicep \
  --parameters prefix="$PREFIX" vmSize="$VM_SIZE" adminSourceCidr="$ADMIN_IP/32" \
               sshPublicKey="$(cat "$SSH_KEY")" githubRepo="$GITHUB_REPO" adminPrincipalId="$admin_id" \
  --query properties.outputs -o json)

out() { python3 -c "import json, sys; print(json.load(sys.stdin)['$1']['value'])" <<<"$outputs"; }

if command -v gh >/dev/null; then
  echo "Configuring GitHub Actions variables on $GITHUB_REPO..."
  gh variable set AZURE_CLIENT_ID --repo "$GITHUB_REPO" --body "$(out githubClientId)"
  gh variable set AZURE_TENANT_ID --repo "$GITHUB_REPO" --body "$(out tenantId)"
  gh variable set STORAGE_ACCOUNT --repo "$GITHUB_REPO" --body "$(out storageAccount)"
else
  echo "GitHub CLI not found. Add these repository variables by hand (Settings > Secrets and variables > Actions > Variables):"
  echo "  AZURE_CLIENT_ID=$(out githubClientId)"
  echo "  AZURE_TENANT_ID=$(out tenantId)"
  echo "  STORAGE_ACCOUNT=$(out storageAccount)"
fi

cat <<EOF

Done. The honeypot is live at $(out publicIp) (ports 22 and 23).
First boot installs Docker and Cowrie, which takes about 5 minutes. Then:

  $(out sshCommand) 'cloud-init status --wait && sudo docker ps'

Logs reach Azure Storage every hour; GitHub Actions turns them into stats every 6 hours.
EOF
