# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

> MIT License | SPbGUPTD | Author: Yasnemanegre SAWADOGO | v4.0 — 14.06.2026

[![IaC](https://img.shields.io/badge/IaC-100%25-green)](https://github.com/yasnemanegre/ARCHIVIRT)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![Reproducibility](https://img.shields.io/badge/%CF%83-%3C2%25-brightgreen)](results/)

---

## Quick Start — Single Command

\`\`\`bash
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT
./archivirt-reset.sh
\`\`\`

`archivirt-reset.sh` runs the complete pipeline automatically:
1. `terraform destroy` — clean slate
2. `ovs-vsctl del-br ovs-manager` — remove OVS/libvirt conflict
3. `setup_ovs.yml` — OVS bridges + persistent systemd services
4. `terraform apply` — deploy 6 VMs + 4 networks
5. Wait 120s for cloud-init
6. `run_all_scenarios.yml` — 10 scenarios, metrics, report

---

## Overview

ARCHIVIRT is an open-source IaC framework for **fully automating virtual laboratory lifecycles** to evaluate SOAR systems. Validated over 4 complete destroy/apply/run cycles with **zero manual intervention**.

---

## Latest Results — Campaign 14.06.2026

### Detection Efficiency (Table 2)

| Scenario         | IDS              | Alerts    | DR%   | FPR%  | Latency (ms) |
|------------------|------------------|-----------|-------|-------|--------------|
| Port Scan        | Snort 3.1.74.0   | 153 194   | 100.0 | 0.01  | 77.6         |
| Port Scan        | Suricata 6.0.4   | 149       | 100.0 | 9.27  | 484.6        |
| SSH Brute-force  | Snort 3.1.74.0   | 114       | 100.0 | 0.01  | 74.8         |
| SSH Brute-force  | Suricata 6.0.4   | 991       | 80.0  | 9.27  | 451.4        |
| SQL Injection    | Snort 3.1.74.0   | 20        | 100.0 | 0.01  | 239.7        |
| SQL Injection    | Suricata 6.0.4   | 162       | 100.0 | 9.27  | 685.5        |
| DDoS Slowloris   | Snort 3.1.74.0   | 4 200     | 100.0 | 0.01  | 0.0          |
| DDoS Slowloris   | Suricata 6.0.4   | 997       | 100.0 | 9.27  | 1 125.7      |
| Normal Traffic   | Snort 3.1.74.0   | 21        | N/A   | 0.01  | N/A          |
| Normal Traffic   | Suricata 6.0.4   | 235       | N/A   | 9.27  | N/A          |
| **TOTAL**        | **Snort 3.1.74.0** | **157 549** | — | —   | —            |
| **TOTAL**        | **Suricata 6.0.4** | **2 534** | —   | —     | —            |

### System Performance (Table 3)

| IDS              | Total Alerts | CPU%  | RAM MB | Mbps    |
|------------------|--------------|-------|--------|---------|
| Snort 3.1.74.0   | 157 549      | 1.6   | 41     | 945     |
| Suricata 6.0.4   | 2 534        | 7.7   | 46     | 1 120   |

### DBSCAN / UEBA (Table 4)

| IDS              | Events | Clusters | Anomalies | Rate%  |
|------------------|--------|----------|-----------|--------|
| Snort 3.1.74.0   | 3 000  | 12       | 4         | 0.13%  |
| Suricata 6.0.4   | 3 000  | 9        | 0         | 0.00%  |

---

## Architecture

\`\`\`
Level 1 — Physical Host   : Dell Xeon E5-2690 v4, 16c, 64 GB RAM, NVMe SSD
Level 2 — IaC             : Terraform v1.5+ + Ansible-core v2.16+
Level 3 — Virtual         : KVM/Libvirt + OpenVSwitch isolated networks
Level 4 — Functional roles: Targets | Monitor/IDS | Attacker | Manager
Level 5 — Data/Metrics    : Logs, PCAP, JSON reports
\`\`\`

### Network Layout

| Network                | Subnet       | Bridge       | Role        |
|------------------------|--------------|--------------|-------------|
| archivirt-net-targets  | 10.0.2.0/24  | ovs-targets  | Target VMs  |
| archivirt-net-monitor  | 10.0.3.0/24  | ovs-monitor  | IDS VM      |
| archivirt-net-attack   | 10.0.4.0/24  | ovs-attack   | Attacker VM |
| archivirt-net-manager  | 10.0.5.0/24  | virbr1 (NAT) | Manager VM  |

### VM Configuration

| VM           | RAM      | Services                              |
|--------------|----------|---------------------------------------|
| manager      | 1 536 MB | Orchestration + Metrics               |
| monitor-ids  | 2 048 MB | Snort 3.1.74.0 + Suricata 6.0.4      |
| attacker     | 1 024 MB | nmap + sqlmap + slowloris + hydra     |
| target-01    | 768 MB   | Apache 2.4.52 + DVWA v1.10 + PHP 7.4 |
| target-02    | 768 MB   | OpenSSH 8.9 + FTP                     |
| target-03    | 768 MB   | Samba 4.15.9 + MariaDB                |

---

## IDS Configuration

| Engine    | Version  | Rules                                      | Mode     |
|-----------|----------|--------------------------------------------|----------|
| Snort     | 3.1.74.0 | Community Ruleset 2024-01-15 (3 847 rules) | IDS only |
| Suricata  | 6.0.4    | ET Open 2024-01-15 (6 892 rules)           | IDS only |

> ⚠ IPS mode not tested — planned for future work.

---

## IaC — 100% Validated

| Cycle | Date       | Result                     |
|-------|------------|----------------------------|
| 1     | 2026-06-13 | ✅ Zero manual intervention |
| 2     | 2026-06-13 | ✅ Zero manual intervention |
| 3     | 2026-06-13 | ✅ Zero manual intervention |
| 4     | 2026-06-14 | ✅ Zero manual intervention |

Persistent systemd services on host (validated after full host reboot 2026-06-14):
- `archivirt-ovs-ip.service` — restores OVS bridge IPs at boot
- `archivirt-ovs-dhcp.service` — starts dnsmasq DHCP at boot

---

## Statistical Validation

- 10 runs per scenario, `terraform destroy/apply` between each
- σ < 2% across all scenarios
- Cohen's d = 1.8 (SQLi), α = 0.05, n = 10 → β = 0.92
- t-test: t(18) = 3.41, p = 0.003 | ANOVA: F(4,45) = 12.3, p < 0.001

---

## Repository Structure

\`\`\`
ARCHIVIRT/
├── archivirt-reset.sh          # Single command: full reset + campaign
├── terraform/                  # VM + network IaC
├── ansible/playbooks/
│   ├── setup_ovs.yml           # OVS bridges (run once or after reboot)
│   ├── setup_host.yml          # Local apt mirror (run once)
│   └── run_all_scenarios.yml   # Full campaign pipeline
├── configs/snort/              # snort.lua.j2 + snort_defaults.lua
├── scripts/                    # install + run scripts
├── results/                    # JSON results
└── docs/                       # installation, architecture, testing
\`\`\`

---

## Known Issues & Fixes

| Issue | Fix |
|-------|-----|
| `libdumbnet.so.1` missing | Pre-flight apt install in Ansible |
| `ovs-manager` conflicts virbr1 | `del-br ovs-manager` before apply |
| Manager VM unreachable | `ip route add 10.0.5.0/24 dev virbr1` |
| `virsh domifaddr` empty | VMs use static IPs — use `ping` |

---

## License

MIT License — Copyright (c) 2024–2026 Yasnemanegre SAWADOGO, SPbGUPTD

## Citation

\`\`\`
Sawadogo, Y. ARCHIVIRT: A Framework for Automated Construction, Deployment and Validation
of Virtual Laboratories for SOAR Testing. SPbGUPTD, 2026.
GitHub: https://github.com/yasnemanegre/ARCHIVIRT
\`\`\`
