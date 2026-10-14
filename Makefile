PY     ?= python3
RG     ?= rg-honeypot
PREFIX ?= hpot
PORT   ?= 22222
VM_IP   = $$(az network public-ip show -g $(RG) -n $(PREFIX)-pip --query ipAddress -o tsv)

.PHONY: help test demo serve build report deploy allow-ip ssh logs update-sensor destroy

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

test: ## Run the unit tests
	$(PY) -m unittest discover -s tests -t .

demo: ## Build a dashboard preview from synthetic attacks
	$(PY) -m pipeline demo

serve: ## Serve the dashboard at http://localhost:8000 (demo: /?demo)
	$(PY) -m http.server 8000 -d docs

build: ## Rebuild stats.json, charts and README from data/daily
	$(PY) -m pipeline build

report: ## Write the weekly reports into reports/
	$(PY) -m pipeline report

deploy: ## Create or update everything in Azure
	scripts/deploy.sh

allow-ip: ## Open the admin SSH port to your current IP
	scripts/allow-my-ip.sh

ssh: ## SSH into the VM (real sshd on the admin port)
	ssh -p $(PORT) azureuser@$(VM_IP)

logs: ## Watch attacks arrive live
	ssh -p $(PORT) azureuser@$(VM_IP) 'sudo tail -f /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json'

update-sensor: ## Push changes in sensor/ to the running VM
	scripts/update-sensor.sh

destroy: ## Delete every Azure resource of the honeypot (asks first)
	az group delete --name $(RG)
