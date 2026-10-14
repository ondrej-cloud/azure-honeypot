#!/usr/bin/env bash
# Open the admin SSH port to your current IP and keep all of your IPs out of the published stats.
#
# Laptops move between networks (home, school, a phone hotspot), so the NSG keeps the last few
# addresses instead of only the newest. Every address you have used goes into the IGNORE_IPS
# Actions secret, which the pipeline uses to drop your own test connections.
set -euo pipefail
cd "$(dirname "$0")/.."

RG=${RG:-rg-honeypot}
PREFIX=${PREFIX:-hpot}
KEEP=${KEEP:-3}
LIST=.admin-ips   # gitignored, newest first
GITHUB_REPO=${GITHUB_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)}
ADMIN_IP=${ADMIN_IP:-$(curl -fsS https://api.ipify.org)}

[[ $ADMIN_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "error: '$ADMIN_IP' is not an IPv4 address" >&2; exit 1; }

{ echo "$ADMIN_IP"; cat "$LIST" 2>/dev/null || true; } | awk 'NF && !seen[$1]++' > "$LIST.tmp"
mv "$LIST.tmp" "$LIST"

cidrs=()
while read -r ip; do cidrs+=("$ip/32"); done < <(head -n "$KEEP" "$LIST")
az network nsg rule update --resource-group "$RG" --nsg-name "$PREFIX-nsg" --name Allow-Admin-SSH \
  --source-address-prefixes "${cidrs[@]}" --output none
echo "Admin SSH is open to: ${cidrs[*]}"

if command -v gh >/dev/null && [[ -n $GITHUB_REPO ]]; then
  paste -sd , "$LIST" | gh secret set IGNORE_IPS --repo "$GITHUB_REPO"
  echo "Excluded $(wc -l < "$LIST" | tr -d ' ') address(es) of yours from the stats (IGNORE_IPS secret)."
else
  echo "Add this as the IGNORE_IPS repository secret so your own connections stay out of the stats:"
  paste -sd , "$LIST"
fi
