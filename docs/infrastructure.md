# ARCHIVIRT Infrastructure Reference

## Network Layout
- **Internal network:** 10.0.0.0/8 (isolated virtual networks)
- **Host:** Ubuntu 22.04 with KVM/libvirt, IP 192.168.4.10 (Hyper-V switch)

### Virtual Machines (6 total)
| VM Name                | IP          | Role          |
|------------------------|-------------|---------------|
| archivirt-manager      | 10.0.5.10   | InfluxDB, Telegraf, Grafana, DBSCAN |
| archivirt-attacker     | 10.0.4.10   | nmap, ncrack, sqlmap, hping3, masscan |
| archivirt-monitor-ids  | 10.0.3.10   | Snort 3.1.74.0, Suricata 6.0.4, Telegraf |
| archivirt-target-01     | 10.0.2.11   | DVWA/Apache   |
| archivirt-target-02     | 10.0.2.12   | vsftpd/SSH    |
| archivirt-target-03     | 10.0.2.13   | Samba/MariaDB |

### Subnets
- 10.0.2.0/24 – Target network
- 10.0.3.0/24 – Monitoring network (mirrors)
- 10.0.4.0/24 – Attack/Control network
- 10.0.5.0/24 – Management network

## Local APT Mirror
- **Host**: 192.168.4.10:8080 (nginx)
- **Path**: `/var/spool/apt-mirror/packages/` (227+ packages)
- **Setup**: `ansible-playbook ansible/playbooks/setup_host.yml`
- **VMs config**: `/etc/apt/sources.list.d/archivirt-local.list`

## Monitoring Stack
- **Telegraf** → monitor-ids + manager → **InfluxDB** (10.0.5.10:8086)
- **Grafana** (optional, `archivirt_grafana_enabled`) → http://10.0.5.10:3000 — authentication required; credentials in ansible-vault (`group_vars/all/vault.yml`), never documented in clear
- **Route**: monitor-ids → manager via 10.0.3.1 (netplan persistent)

## Terraform Variables
Edit `terraform/variables.tf` to adjust resources (vCPU, RAM, disk).
Default: 2 vCPU, 4 GB RAM per VM.

## Ansible Inventory
- `ansible/inventory/hosts.ini` – IP addresses and groups
- SSH key: `~/.ssh/archivirt_key` (distributed to all VMs)
- Key variables: `target_subnet`, `attack_subnet`, `monitor_subnet`, `manager_subnet`
- `snort_binary=/usr/local/bin/snort`
- `archivirt_project_dir=/home/archivirt/ARCHIVIRT`
- `ansible_python_interpreter=/usr/bin/python3`

## Important Scripts
- `scripts/archivirt_mirrors.sh` – Sets up traffic mirroring for the monitor.
- `scripts/run_snort.sh` / `run_suricata.sh` – Lifecycle management for IDS engines.

## Bootstrapping a New Environment
1. `cd terraform && terraform apply`
2. `cd ../ansible && ansible-playbook site.yml -i inventory/hosts.ini`
3. (Optional) `ansible-playbook playbooks/calibrate_performance.yml -i inventory/hosts.ini`
4. Run tests: `ansible-playbook playbooks/run_all_scenarios.yml -i inventory/hosts.ini`
