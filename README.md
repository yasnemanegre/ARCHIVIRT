# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

> MIT License | SPbGUPTD | Yasnemanegre SAWADOGO | v4.1 — 14.06.2026

---

## Quick Start

```bash
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT
./archivirt-reset.sh
```

One command runs the full pipeline: destroy → OVS setup → deploy 6 VMs → 10 scenarios → Telegraf/InfluxDB/Grafana → report.

---

## Latest Results — 14.06.2026

| Scenario        | IDS            | Alerts  | DR%   | FPR%  | Lat(ms) |
|-----------------|----------------|---------|-------|-------|---------|
| Port Scan       | Snort 3.1.74.0 | 153 194 | 100.0 | 0.01  | 77.6    |
| Port Scan       | Suricata 6.0.4 | 149     | 100.0 | 9.27  | 484.6   |
| SSH Brute-force | Snort 3.1.74.0 | 114     | 100.0 | 0.01  | 74.8    |
| SSH Brute-force | Suricata 6.0.4 | 991     | 80.0  | 9.27  | 451.4   |
| SQL Injection   | Snort 3.1.74.0 | 20      | 100.0 | 0.01  | 239.7   |
| SQL Injection   | Suricata 6.0.4 | 162     | 100.0 | 9.27  | 685.5   |
| DDoS Slowloris  | Snort 3.1.74.0 | 4 200   | 100.0 | 0.01  | 0.0     |
| DDoS Slowloris  | Suricata 6.0.4 | 997     | 100.0 | 9.27  | 1 125.7 |
| Normal Traffic  | Snort 3.1.74.0 | 21      | N/A   | 0.01  | N/A     |
| Normal Traffic  | Suricata 6.0.4 | 235     | N/A   | 9.27  | N/A     |

| IDS            | Total   | CPU% | RAM MB | Mbps  | DBSCAN anomalies |
|----------------|---------|------|--------|-------|-----------------|
| Snort 3.1.74.0 | 157 549 | 6.8  | 56     | 945   | 4 (0.13%)       |
| Suricata 6.0.4 | 2 534   | 16.0 | 40     | 1 120 | 0 (0.00%)       |

IaC validated: **5 full destroy/apply/run cycles — zero manual intervention.**

---

## Architecture
Level 1 — Host      : Dell Xeon E5-2690 v4, 16c, 64 GB RAM, NVMe

Level 2 — IaC       : Terraform v1.5+ + Ansible-core v2.16+

Level 3 — Virtual   : KVM/Libvirt + OpenVSwitch

Level 4 — Roles     : Targets | Monitor/IDS | Attacker | Manager

Level 5 — Metrics   : Telegraf → InfluxDB → Grafana
### Network

| Network   | Subnet       | Bridge       | Role        |
|-----------|--------------|--------------|-------------|
| targets   | 10.0.2.0/24  | ovs-targets  | Target VMs  |
| monitor   | 10.0.3.0/24  | ovs-monitor  | IDS VM      |
| attack    | 10.0.4.0/24  | ovs-attack   | Attacker VM |
| manager   | 10.0.5.0/24  | virbr1 (NAT) | Manager VM  |

Manager has dual interfaces: `ens3` (10.0.5.10) + `ens4` (10.0.3.254 on ovs-monitor) for direct Telegraf→InfluxDB path.

### VMs

| VM          | RAM      | Services                              |
|-------------|----------|---------------------------------------|
| manager     | 1 536 MB | InfluxDB + Grafana + Telegraf gateway |
| monitor-ids | 2 048 MB | Snort 3.1.74.0 + Suricata 6.0.4      |
| attacker    | 1 024 MB | nmap + sqlmap + slowloris + hydra     |
| target-01   | 768 MB   | Apache + DVWA v1.10 + PHP 7.4        |
| target-02   | 768 MB   | OpenSSH 8.9 + FTP                    |
| target-03   | 768 MB   | Samba 4.15.9 + MariaDB               |

---

## Monitoring Stack
ARCHIVIRT/

├── archivirt-reset.sh              # Single command: full pipeline

├── terraform/vms.tf                # VMs + dual-interface manager

├── ansible/playbooks/

│   ├── setup_ovs.yml               # OVS + systemd persistence

│   ├── setup_host.yml              # Local apt mirror (once)

│   ├── setup_influxdb.yml          # InfluxDB v2 init via HTTP API

│   ├── deploy_telegraf.yml         # Telegraf on monitor-ids

│   └── run_all_scenarios.yml       # Full campaign pipeline

├── monitoring/

│   ├── telegraf-monitor.conf       # Telegraf config

│   └── grafana/dashboard.json      # ARCHIVIRT dashboard

├── configs/snort/                  # snort.lua.j2 + snort_defaults.lua

└── results/                        # JSON results + campaigns
---

## Known Issues & Fixes

| Issue | Fix |
|-------|-----|
| `libdumbnet.so.1` missing | Pre-flight apt install |
| `ovs-manager` conflicts virbr1 | `del-br ovs-manager` in reset script |
| Manager unreachable | Route via virbr1 (auto in reset script) |
| Grafana wrong password | `grafana-cli admin reset-admin-password archivirt` |
| Table 3 static | Dynamic metrics via Telegraf planned v4.2 |

---

## License

MIT — Copyright (c) 2024–2026 Yasnemanegre SAWADOGO, SPbGUPTD

## Citation
Sawadogo, Y. ARCHIVIRT: A Framework for Automated Construction, Deployment

and Validation of Virtual Laboratories for SOAR Testing. SPbGUPTD, 2026.

https://github.com/yasnemanegre/ARCHIVIRT
