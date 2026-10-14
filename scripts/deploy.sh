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
# "Azure for Students Starter" and similar offers block VMs, networks and storage outright.
if ! err=$(az provider show --namespace Microsoft.Compute --query registrationState -o tsv 2>&1); then
  grep -q DisallowedProvider <<<"$err" && die "subscription '$(az account show --query name -o tsv)' does not allow virtual machines.
Azure for Students Starter only permits App Service, SQL and a few other services. Activate the full
Azure for Students offer (\$100 credit) at https://azure.microsoft.com/free/students, then select it:
  az account set --subscription \"Azure for Students\""
  die "$err"
fi
[[ -f $SSH_KEY ]] || die "no SSH public key at $SSH_KEY. Create one with: ssh-keygen -t ed25519"
[[ -n $GITHUB_REPO ]] || die "push this repo to GitHub first, or set GITHUB_REPO=owner/name"
ADMIN_IP=${ADMIN_IP:-$(curl -fsS https://api.ipify.org)} || die "could not detect your public IP, set ADMIN_IP"
# Newer repositories sign Actions OIDC tokens with immutable IDs (repo:owner@123/name@456), older ones with
# names. The federated credential must match exactly, so ask GitHub which one this repository uses.
SUBJECT_PREFIX=$(gh api "repos/$GITHUB_REPO/actions/oidc/customization/sub" -q .sub_claim_prefix 2>/dev/null || true)
SUBJECT_PREFIX=${SUBJECT_PREFIX:-repo:$GITHUB_REPO}

cat <<EOF
Subscription  $(az account show --query name -o tsv)
Region        $LOCATION
VM size       $VM_SIZE
GitHub repo   $GITHUB_REPO
Admin IP      $ADMIN_IP  (the only address allowed to reach the real SSH port)

EOF

echo "Registering resource providers (first run only)..."
for provider in Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.ManagedIdentity; do
  az provider register --namespace "$provider" --wait --output none
done

echo "Checking that $VM_SIZE is offered in $LOCATION..."
# Raw REST is minutes faster than `az vm list-skus`. Restrictions say why a size is unusable
# (student subscriptions often get NotAvailableForSubscription in busy regions).
sku=$(az rest --method get \
  --url "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/providers/Microsoft.Compute/skus?api-version=2021-07-01&\$filter=location eq '$LOCATION'" \
  --query "value[?resourceType=='virtualMachines' && name=='$VM_SIZE'] | [0]" -o json)
restrictions=$(python3 -c '
import json, sys
sku = json.loads(sys.stdin.read().strip() or "null")
print(",".join(sorted({r["reasonCode"] for r in sku.get("restrictions", [])})) if sku else "not offered there")
' <<<"$sku")
[[ -z $restrictions ]] || die "$VM_SIZE is not available to this subscription in $LOCATION ($restrictions).
Student subscriptions only allow some regions and sizes. Try another, e.g.
  LOCATION=polandcentral scripts/deploy.sh
  VM_SIZE=Standard_B2ats_v2 scripts/deploy.sh"

# Azure enforces MFA on create/update/delete only, so this is the first call that can hit it.
if ! err=$(az group create --name "$RG" --location "$LOCATION" --output none 2>&1); then
  grep -q AADSTS50079 <<<"$err" && err+="

Azure requires multi-factor authentication to create resources, and this account has no MFA method yet.
Run the az logout / az login commands above and set up a method when the browser asks for one
(or beforehand at https://aka.ms/mfasetup), then run this script again."
  die "$err"
fi
admin_id=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)

echo "Deploying (about 2 minutes)..."
outputs=$(az deployment group create \
  --resource-group "$RG" \
  --name honeypot \
  --template-file infra/main.bicep \
  --parameters prefix="$PREFIX" vmSize="$VM_SIZE" adminSourceCidr="$ADMIN_IP/32" \
               sshPublicKey="$(cat "$SSH_KEY")" githubRepo="$GITHUB_REPO" githubSubjectPrefix="$SUBJECT_PREFIX" \
               adminPrincipalId="$admin_id" \
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

# Re-applies the recent admin IPs to the NSG and excludes them from the published stats.
RG=$RG PREFIX=$PREFIX ADMIN_IP=$ADMIN_IP GITHUB_REPO=$GITHUB_REPO scripts/allow-my-ip.sh

cat <<EOF

Done. The honeypot is live at $(out publicIp) (ports 22 and 23).
First boot installs Docker and Cowrie, which takes about 5 minutes. Then:

  $(out sshCommand) 'cloud-init status --wait && sudo docker ps'

Logs reach Azure Storage every hour; GitHub Actions turns them into stats every 6 hours.
EOF
