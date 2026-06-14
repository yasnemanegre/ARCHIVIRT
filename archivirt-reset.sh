#!/bin/bash
# ARCHIVIRT — Full reset and campaign launcher
# Usage: ./archivirt-reset.sh
set -e
cd "$(dirname "$0")"
terraform -chdir=terraform/ destroy -auto-approve
sudo ovs-vsctl --if-exists del-br ovs-manager
ansible-playbook ansible/playbooks/setup_ovs.yml -i ansible/inventory/hosts.ini
terraform -chdir=terraform/ apply -auto-approve
sleep 30 && sudo ip route add 10.0.5.0/24 dev virbr1 src 10.0.5.1 2>/dev/null || true
sleep 90
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
