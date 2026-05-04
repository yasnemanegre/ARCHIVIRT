# ARCHIVIRT Testing Guide

## Prerequisites
- Ubuntu 22.04 LTS host with KVM/libvirt
- Terraform ≥ 1.5, Ansible ≥ 2.12
- Python 3.10+ with `pandas`, `scikit-learn`, `numpy`
- All VMs deployed via `terraform apply` and `ansible-playbook site.yml`

## Running a Single Scenario

### Snort 3
```bash
cd ~/ARCHIVIRT/ansible
ansible-playbook playbooks/snort_scenario.yml \
  -i inventory/hosts.ini \
  -e "scenario=SCN-001"

###Suricata 6
bash
ansible-playbook playbooks/suricata_scenario.yml \
  -i inventory/hosts.ini \
  -e "scenario=SCN-001"

###Running the Complete Pipeline
This executes 5 attack scenarios × 10 runs for both IDS engines:

bash
ansible-playbook playbooks/run_all_scenarios.yml \
  -i inventory/hosts.ini

###Calibrating Performance
Measure real CPU, RAM, and latency with:

bash
ansible-playbook playbooks/calibrate_performance.yml \
  -i inventory/hosts.ini

###Generating the Final Report
bash
python3 scripts/generate_report.py
Output is written to results/archivirt_final_comparison.json and displayed in the terminal.

###Stopping the Virtual Lab
bash
ansible-playbook playbooks/teardown.yml \
  -i inventory/hosts.ini

###Understanding the Results
##Table 2 – Detection Metrics
| Scenario | IDS | Alerts | DR% | FPR% | Latency (ms) |

##Table 3 – Performance Metrics
| IDS | Total Alerts | CPU% | RAM MB | Mbps |

##DBSCAN Anomaly Table
| IDS | Events | Clusters | Anomalies | Anomaly Rate% |

###Scenario Descriptions
SCN-001 : Port scan (Nmap -sS, ports 1-1024)

SCN-002 : SSH brute-force (Nmap port 22)

SCN-003 : SQL injection (sqlmap against DVWA)

SCN-004 : DDoS Slowloris (Python script, 150 sockets)

SCN-005 : Normal traffic (curl)

###Logs Location
Snort 3: /var/log/snort3/SCN-XXX/alert_fast.txt

Suricata 6: /var/log/suricata/SCN-XXX/eve.json

text

**4. Sauvegarde et ferme :** `Ctrl+X`, `Y`, `Entrée`.

**5. Vérifie le contenu :**
```bash
cat ~/ARCHIVIRT/docs/testing-guide.md

