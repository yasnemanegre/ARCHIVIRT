# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

> Author: **Яснеманегре САВАДОГО** (Аспирант СПБГУПТД)  
> Institution: Saint Petersburg State University of Industrial Technologies and Design  
> Published: *"A framework for automated construction, deployment, and validation of virtual laboratories for testing the SOAR properties"*

---

## Overview

ARCHIVIRT is an open-source framework for fully automating the lifecycle of virtual laboratories designed to evaluate SOAR (Security Orchestration, Automation and Response), SIEM, IDS, and IPS properties. It leverages **Infrastructure as Code (IaC)** principles to automatically deploy, configure, execute tests, and collect metrics.

### Key Metrics
| Metric | Result |
|--------|--------|
| Setup time reduction | **85%** (from ~4h to ~35min) |
| Test reproducibility (std dev) | **< 2%** across 10 runs |
| Detection rate improvement | up to **+13%** (Suricata vs Snort on SQLi) |

---

## Architecture

ARCHIVIRT is organized around a **5-layer architecture**:

```
Layer 1 – Physical/Host    : Ubuntu Server (archivirt@archivirt-lab)
Layer 2 – Orchestration    : Terraform (IaC) + Ansible (Configuration)
Layer 3 – Virtual          : KVM/Libvirt VMs on isolated private networks
Layer 4 – Functional Roles : Targets | Monitoring | Attack | Manager
Layer 5 – Data & Metrics   : Logs, PCAP, Reports, Grafana Dashboards
```

### Network Topology

```
Host Server: archivirt@archivirt-lab
  Interface enp0s3: 192.168.4.11

  ┌─────────────────────────────────────────────┐
  │              KVM Hypervisor                 │
  │                                             │
  │  10.0.2.0/24  ──── Target VMs              │
  │                     (web, ssh, smb targets) │
  │                                             │
  │  10.0.3.0/24  ──── IDS/IPS Monitor VM      │
  │                     (Snort 3 / Suricata 6)  │
  │                                             │
  │  10.0.4.0/24  ──── Attacker VM             │
  │                     (Metasploit, Nmap...)   │
  │                                             │
  │  10.0.5.0/24  ──── Manager VM              │
  │                     (Orchestration, Metrics) │
  └─────────────────────────────────────────────┘
```

---

## Repository Structure

```
ARCHIVIRT/
├── README.md
├── LICENSE
├── docs/
│   ├── architecture.md          # Full architecture documentation
│   ├── installation.md          # Step-by-step installation guide
│   └── testing-guide.md         # Test scenarios guide
├── terraform/
│   ├── main.tf                  # Provider and core config
│   ├── variables.tf             # All configurable variables
│   ├── networks.tf              # Virtual network definitions
│   ├── vms.tf                   # VM definitions
│   └── outputs.tf               # Output values (IPs, etc.)
├── ansible/
│   ├── site.yml                 # Master playbook
│   ├── inventory/
│   │   └── hosts.ini            # Dynamic inventory
│   └── roles/
│       ├── common/              # Base configuration (all VMs)
│       ├── target/              # Vulnerable services setup
│       ├── ids_snort/           # Snort 3 IDS deployment
│       ├── ids_suricata/        # Suricata 6 IDS deployment
│       ├── attacker/            # Attack tools installation
│       └── manager/             # Orchestration & analysis
├── scenarios/
│   ├── port_scan.yml            # Nmap port scanning scenario
│   ├── ssh_bruteforce.yml       # Hydra SSH brute-force
│   ├── sqli_exploit.yml         # SQLMap web exploitation
│   ├── slowloris_ddos.yml       # Slowloris DDoS scenario
│   └── normal_traffic.yml       # Baseline normal traffic
├── scripts/
│   ├── deploy.sh                # One-command deploy script
│   ├── run_tests.sh             # Execute all test scenarios
│   ├── collect_metrics.py       # Metrics aggregation script
│   └── generate_report.py       # HTML/PDF report generator
├── tests/
│   ├── test_deployment.py       # Infrastructure validation tests
│   ├── test_connectivity.py     # Network connectivity tests
│   └── test_scenarios.py        # Scenario execution tests
├── configs/
│   ├── snort/                   # Snort 3 configuration files
│   └── suricata/                # Suricata 6 configuration files
└── monitoring/
    ├── telegraf.conf            # Telegraf metrics agent config
    ├── influxdb.conf            # InfluxDB storage config
    └── grafana/
        └── dashboard.json       # Pre-built Grafana dashboard
```

---

## Quick Start

### Prerequisites
```bash
# On archivirt@archivirt-lab (192.168.4.11)
sudo apt update && sudo apt install -y \
    terraform ansible \
    qemu-kvm libvirt-daemon-system \
    python3-pip git

pip3 install pandas matplotlib jinja2 pytest paramiko
```

### Deploy Full Laboratory
```bash
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT

# 1. Deploy infrastructure
./scripts/deploy.sh

# 2. Run all test scenarios
./scripts/run_tests.sh

# 3. Generate report
python3 scripts/generate_report.py
```

---

## Test Scenarios

| Scenario | Tool | Target Subnet |
|----------|------|---------------|
| Port Scan | Nmap | 10.0.2.0/24 |
| SSH Brute-force | Hydra | 10.0.2.0/24 |
| Web SQLi Exploit | sqlmap | 10.0.2.0/24 |
| Slow DDoS | Slowloris | 10.0.2.0/24 |
| Normal Traffic | curl/scp | 10.0.2.0/24 |

---

## Experimental Results (Snort 3 vs Suricata 6)

### Detection Metrics (average over 10 runs)
| Scenario | IDS | Detection Rate (%) | False Positives (%) | Avg Latency (ms) |
|----------|-----|--------------------|---------------------|------------------|
| Port Scan | Snort 3 | 100.0 | 0.5 | 12.3 |
| Port Scan | Suricata 6 | 100.0 | 0.2 | 8.7 |
| SSH Brute-force | Snort 3 | 98.5 | 1.1 | 45.6 |
| SSH Brute-force | Suricata 6 | 99.8 | 0.8 | 32.1 |
| SQLi Exploit | Snort 3 | 85.2 | 0.3 | 102.4 |
| SQLi Exploit | Suricata 6 | 92.7 | 0.4 | 87.9 |
| DDoS Slowloris | Snort 3 | 65.3 | 0.0 | 210.5 |
| DDoS Slowloris | Suricata 6 | 78.9 | 0.0 | 185.2 |

### System Performance (peak during tests)
| IDS | Avg CPU (%) | RAM Usage (MB) | Max Throughput (Mbps) |
|-----|-------------|----------------|-----------------------|
| Snort 3 | 68.2 | 512 | 945 |
| Suricata 6 | 75.4 | 610 | 1120 |

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Citation

```
Савадого Я. ARCHIVIRT: A framework for automated construction, deployment,
and validation of virtual laboratories for testing the SOAR properties. — СПбГУПТД, 2026.
```
