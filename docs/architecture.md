# ARCHIVIRT — Architecture Documentation

## Overview

ARCHIVIRT follows a 5-layer architecture fully automated by Infrastructure as Code
(Terraform v1.15.3 + Ansible-core v2.17.14). All layers are defined declaratively in the
repository — no manual step is required between `git clone` and a running test campaign.

---

## Layer Description

### Layer 1 — Physical Host
- Ubuntu 22.04 LTS server with KVM/libvirt hypervisor.
- Hardware reference: Intel Xeon E5-2690 v4, 16 cores, 64 GB RAM, NVMe SSD.

### Layer 2 — Orchestration (IaC)
- **Terraform v1.15.3**: provisions VMs and virtual networks (`terraform/`).
- **Ansible-core v2.17.14**: configures VMs, deploys IDS engines, runs attack scenarios (`ansible/`).

### Layer 3 — Virtual Layer
- All VMs run on isolated KVM networks — no external routing.
- **Local APT mirror**: nginx on host 192.168.4.10:8080 (227+ packages) — offline IaC
- Network isolation enforced via `nftables` (no host forwarding) and `ebtables` (ARP per subnet).
- Traffic mirroring handled by `scripts/archivirt_mirrors.sh` (all vnets → monitor interface).

### Layer 4 — Functional Roles
> Monitoring stack: Telegraf (monitor-ids + manager) → InfluxDB → Grafana (http://10.0.5.10:3000)


| Role | Subnet | VMs | Services |
|------|--------|-----|----------|
| Targets | 10.0.2.0/24 | 3 × (2 vCPU, 4 GB) | DVWA v1.10, OpenSSH 8.9, Samba 4.15.9 |
| Monitor | 10.0.3.0/24 | 1 × (2 vCPU, 4 GB) | Snort 3.1.74.0 / Suricata 6.0.4 (passive IDS) |
| Attacker | 10.0.4.0/24 | 1 × (2 vCPU, 4 GB) | Nmap, sqlmap, Slowloris, tcpreplay |
| Manager | 10.0.5.0/24 | 1 × (2 vCPU, 4 GB) | Telegraf, result aggregation |

### Layer 5 — Data & Metrics
- Per-scenario alert logs: `/var/log/snort3/SCN-XXX/alert_json.txt` and `/var/log/suricata/SCN-XXX/eve.json`
- JSON result snippets fetched to localhost `/tmp/` during campaign, then cleaned up.
- Final results written to `results/` (gitignored except committed snapshots).

---

## IaC Pipeline

### Provisioning
```bash
cd terraform
terraform init
terraform apply -var-file=../configs/lab.tfvars
```

### Configuration
```bash
ansible-playbook ansible/site.yml -i ansible/inventory/hosts.ini
```

### Evaluation Campaign
```bash
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

The master playbook `run_all_scenarios.yml` orchestrates:
1. `snort_scenario.yml` × 5 (SCN-001 to SCN-005, `ids_prefix=snort3`)
2. `suricata_scenario.yml` × 5 (SCN-001 to SCN-005, `ids_prefix=suricata`)
3. `build_final_results.py` — DR, FPR, latency computation
4. `dbscan_from_fetched.py` — DBSCAN/UEBA behavioural analysis
5. `generate_report.py` — Tables 2, 3, 4 report
6. Cleanup of all `/tmp/` artefacts

### Key Design: Prefixed Start-Time Files

Attack start-time files are written as:
```
/tmp/{ids_prefix}_attack_start_times_{scenario}.txt
```
This prevents cross-contamination between Snort and Suricata timing data when
both engines run sequentially in the same campaign.

---

## Scripts Reference

| Script | Role |
|--------|------|
| `archivirt_mirrors.sh` | Sets up AF_PACKET traffic mirrors (all vnets → monitor vnet5) |
| `run_snort.sh` | Snort 3 lifecycle: start/stop per scenario, PID-based |
| `run_suricata.sh` | Suricata 6 lifecycle: start/stop per scenario, PID-based |
| `build_final_results.py` | Parses alert timestamps, computes DR/FPR/latency, writes JSON |
| `dbscan_from_fetched.py` | Samples 3 000 alerts per IDS, runs DBSCAN (ε=0.5, min_samples=5) |
| `generate_report.py` | Reads result JSON files, prints Tables 2/3/4 to stdout and JSON |

---

## Reproducibility

- All configuration is version-controlled in this repository.
- A fresh environment is bootstrapped with two commands: `terraform apply` + `ansible-playbook site.yml`.
- The full campaign is launched with a single command: `ansible-playbook run_all_scenarios.yml`.
- `terraform destroy/apply` between campaign runs guarantees clean-state isolation.
- Reproducibility validated: σ < 2% across 10 runs for all metrics.
- Inter-VM clock skew (~800 ms between attacker and monitor VMs) is documented and compensated by a 2 s tolerance window in `compute_metrics()` and latency clamping to ≥ 0 ms.

---

## Metrics Collected

| Metric | Source | Script |
|--------|--------|--------|
| Alerts per scenario | `alert_fast.txt` / `fast.log` | Ansible `wc -l` |
| Detection rate (DR%) | Alert timestamps vs. start-time files | `build_final_results.py` |
| False-positive rate (FPR%) | Normal traffic alerts / total alerts | `build_final_results.py` |
| Latency (ms) | First alert − attack start (`+%s.%N`), clamped ≥ 0 (inter-VM clock skew ~800 ms) | `build_final_results.py` |
| CPU / RAM peak | `top` + `/proc/meminfo` via Telegraf | `calibrate_performance.yml` |
| Throughput (Mbps) | `performance_baseline.json` | `calibrate_performance.yml` |
| DBSCAN clusters / anomalies | 3 000-alert sample | `dbscan_from_fetched.py` |
