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

# Setup monitoring stack
ansible-playbook ansible/playbooks/setup_influxdb.yml \
  -i ansible/inventory/hosts.ini
ansible-playbook ansible/playbooks/deploy_telegraf.yml \
  -i ansible/inventory/hosts.ini

# Reset Grafana password after fresh deploy
sleep 10
ssh ubuntu@10.0.5.10 "sudo grafana-cli admin reset-admin-password archivirt 2>/dev/null || true"

# Import Grafana dashboard
DASHBOARD=$(cat monitoring/grafana/dashboard.json)
ssh ubuntu@10.0.5.10 "curl -s -X POST \
  -H 'Content-Type: application/json' \
  -u admin:${GRAFANA_PASSWORD:-archivirt} \
  http://localhost:3000/api/datasources \
  -d '{\"name\":\"InfluxDB-ARCHIVIRT\",\"type\":\"influxdb\",\"url\":\"http://localhost:8086\",\"access\":\"proxy\",\"jsonData\":{\"version\":\"Flux\",\"organization\":\"archivirt\",\"defaultBucket\":\"archivirt\"},\"secureJsonData\":{\"token\":\"archivirt-telegraf-token\"}}' 2>/dev/null || true"

ssh ubuntu@10.0.5.10 "curl -s -X POST \
  -H 'Content-Type: application/json' \
  -u admin:${GRAFANA_PASSWORD:-archivirt} \
  http://localhost:3000/api/dashboards/import \
  -d '{\"dashboard\": $DASHBOARD, \"overwrite\": true, \"folderId\": 0}' 2>/dev/null"

echo '✅ Monitoring stack ready — Grafana: http://10.0.5.10:3000 (admin/archivirt)'
