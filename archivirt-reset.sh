#!/bin/bash
# ARCHIVIRT — Full reset and campaign launcher
# Usage: ARCHIVIRT_CONFIRM_DESTROY=yes ./archivirt-reset.sh
#
# DANGER: destroys and recreates ALL Terraform-managed lab VMs, then runs the
# scenarios. Never run it on the infrastructure that produced frozen results
# without an explicit decision. Requires ~/.archivirt/vault_pass (ansible-vault).
set -euo pipefail
cd "$(dirname "$0")"

if [ "${ARCHIVIRT_CONFIRM_DESTROY:-}" != "yes" ]; then
  echo "Refusing to run: set ARCHIVIRT_CONFIRM_DESTROY=yes to destroy and rebuild the lab." >&2
  exit 2
fi

VAULT_PASS_FILE="${ARCHIVIRT_VAULT_PASS_FILE:-$HOME/.archivirt/vault_pass}"
if [ ! -r "$VAULT_PASS_FILE" ]; then
  echo "Missing ansible-vault password file: $VAULT_PASS_FILE" >&2
  exit 2
fi

terraform -chdir=terraform/ destroy -auto-approve
sudo ovs-vsctl --if-exists del-br ovs-manager
ansible-playbook ansible/playbooks/setup_ovs.yml -i ansible/inventory/hosts.ini
terraform -chdir=terraform/ apply -auto-approve
sleep 30
if ! ip route show 10.0.5.0/24 | grep -q .; then
  sudo ip route add 10.0.5.0/24 dev virbr1 src 10.0.5.1
fi
sleep 90
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# Monitoring stack: single provisioning path = Ansible role "manager"
# (pinned packages from the local mirror, secrets from ansible-vault,
# Grafana datasource uid archivirt-influx + dashboard provisioned from files,
# end-to-end validation). Then Telegraf on monitor-ids.
ansible-playbook ansible/playbooks/deploy_monitoring.yml -i ansible/inventory/hosts.ini \
  --vault-password-file "$VAULT_PASS_FILE"
ansible-playbook ansible/playbooks/deploy_telegraf.yml \
  -i ansible/inventory/hosts.ini \
  --vault-password-file "$VAULT_PASS_FILE"

echo "Monitoring stack validated by Ansible — Grafana: http://10.0.5.10:3000 (credentials in ansible-vault)"
