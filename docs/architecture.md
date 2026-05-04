# ARCHIVIRT Architecture (IaC Pipeline)

## Overview
ARCHIVIRT follows a 5‑layer architecture fully automated by Infrastructure as Code (Terraform + Ansible).

1. **Physical Host** – KVM/libvirt hypervisor.
2. **Orchestration Layer** – Terraform for VMs/networks, Ansible for configuration and test execution.
3. **Virtual Layer** – Isolated VMs connected by virtual networks.
4. **Functional Roles**:
   - *Targets* (10.0.2.0/24): DVWA, SSH, SMB, MariaDB.
   - *Monitor* (10.0.3.10): Snort 3 / Suricata 6 in passive mode.
   - *Attacker* (10.0.4.10): Nmap, Hydra, sqlmap, Slowloris.
   - *Manager* (10.0.5.10): InfluxDB, Grafana, DBSCAN, report generation.
5. **Data & Metrics** – Centralised logs, PCAPs, and performance reports.

## IaC Pipeline
- **Terraform** provisions the VMs and networks.
- **Ansible playbooks** handle:
  - `site.yml` – Initial configuration (base packages, IDS installation, services).
  - `snort_scenario.yml` / `suricata_scenario.yml` – Execute a single attack scenario, collect results.
  - `calibrate_performance.yml` – Measures CPU, RAM, latency under load.
  - `run_all_scenarios.yml` – Master playbook running all 5 scenarios for both IDS engines (10 runs each).
- **Scripts:**
  - `run_snort.sh` / `run_suricata.sh` – Lifecycle management (start/stop per scenario, PID‑based).
  - `generate_report.py` – Reads JSON results and produces Table 2, Table 3, DBSCAN table.
  - `dbscan_analysis.py` – DBSCAN anomaly detection on alerts.

## Reproducibility
- All configuration is stored in the Git repository.
- A new environment can be bootstrapped with `terraform apply && ansible-playbook site.yml`.
- Tests are started with a single command: `ansible-playbook playbooks/run_all_scenarios.yml`.

## Metrics Collected
- Alerts per scenario
- Detection rate (DR)
- False‑positive rate (FPR)
- Latency (ms)
- CPU / RAM peak (via `ps` on the IDS process)
- Throughput (Mbps)
- DBSCAN clusters and anomaly count
