# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual IDS/IPS Testing Labs**

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

## Article 2 — Experimental Results

> **Scope note.** The results below characterize the **tested ARCHIVIRT configuration and the controlled, discriminative Article-2 signature set** (4 threshold-based signatures + 1 benign control). They are **not** a universal benchmark of Suricata, and must be read as *"in the experimental conditions considered…"*.

- **Engine:** Suricata 6.0.4 (IDS af-packet on ens6/ens7; IPS inline NFQUEUE).
- **Campaigns:** IDS ×10, IPS ×10, baseline ×3 — **115 runs** total (100 VALID, 15 INVALID *by design* = baseline without an engine; 0 PREREQUISITE_MISSING).
- **Detection / blocking (run-level confusion, VALID runs):** IDS and IPS each **TP=40, TN=10, FP=0, FN=0** → Accuracy = Precision = Recall = F1 = 1.0, FPR = FNR = 0 **for this signature set**.
- **IPS blocking:** real `action:blocked` events observed — 100 % of attack runs blocked, **0 %** of benign runs (no false blocking).
- **Detection latency (mean, n=10):** ≈105–311 ms depending on scenario (real timestamps; see Table D).
- **Engine impact:** CPU ≈ 13–15 %, RSS ≈ 44–50 MB, 0 capture drops.

Full audited dataset, tables, figures and the scientific audit: **`results/campaign-v1/article2/`**
(`aggregated_metrics.json`, `statistical_summary.json`, `article2_results.csv`, `tables/`, `tables/publication/`, `figures/`, `synthesis.md`, `scientific_audit.md`).

**Limitation (SCN-002):** the SSH target enforces public-key-only authentication, so this scenario measures an **SSH connection-rate attack pattern**, not password guessing.

---

## Historical results — v4.1, 14.06.2026 (superseded methodology, kept for reference)

> ⚠️ The table below predates the Article-2 audited methodology (different pipeline, includes Snort 3 and DBSCAN figures that are **out of scope** for the current Article-2 freeze). It is retained for historical reference only and is **superseded** by the Article-2 results above and by `results/campaign-v1/article2/scientific_audit.md`.

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
| Snort 3.1.74.0 | 157 549 | 10.4 | 56     | 2.4   | 4 (0.13%)       |
| Suricata 6.0.4 | 2 534   | 18.5 | 61     | 2.4   | 0 (0.00%)       |

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

## Monitoring (InfluxDB, Telegraf, optional Grafana)

- **Collection/storage (always on):** Telegraf (manager, monitor-ids) → InfluxDB 2 on the manager (org/bucket `archivirt`).
- **Grafana (optional UI):** controlled by `archivirt_grafana_enabled` in `ansible/inventory/group_vars/all/monitoring.yml` (default `true`).
  - `true`: Grafana is installed from the local mirror, hardened (authentication required, no anonymous access, no sign-up, no outbound calls) and validated.
  - `false`: Grafana is stopped and disabled if present (package and data kept); InfluxDB and Telegraf keep collecting. One-off override: `-e archivirt_grafana_enabled=false`.
- **Credentials:** generated randomly and stored in ansible-vault (`ansible/inventory/group_vars/all/vault.yml`, never committed; template and rotation procedure in `vault.yml.example`). There is no default or documented password.
- **Deploy:** `ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_monitoring.yml --vault-password-file ~/.archivirt/vault_pass`
- **Inventory path:** always the *file* `ansible/inventory/hosts.ini` (default of `ansible.cfg` when run from the repository root). Passing the *directory* (`-i ansible/inventory`) makes Ansible skip `hosts.ini`, because `.ini` is in the default `INVENTORY_IGNORE_EXTS` for directory inventories — only `localhost` is then seen. Check: `ansible-inventory -i ansible/inventory/hosts.ini --graph --vault-password-file ~/.archivirt/vault_pass`.
- Monitoring metrics are operational telemetry only; detection/blocking evidence comes from Suricata `eve.json` and the per-run records.

## Known Issues & Fixes

| Issue | Fix |
|-------|-----|
| `libdumbnet.so.1` missing | Pre-flight apt install |
| `ovs-manager` conflicts virbr1 | `del-br ovs-manager` in reset script |
| Manager unreachable | Route via virbr1 (auto in reset script) |
| Grafana wrong password | Credentials live in ansible-vault (`vault_grafana_password`). Re-run `ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_monitoring.yml --vault-password-file ~/.archivirt/vault_pass` — the role restores the vault password. Never set a fixed password by hand. |
| Table 3 static | Dynamic metrics via Telegraf planned v4.2 |

---

## License

MIT — Copyright (c) 2024–2026 Yasnemanegre SAWADOGO, SPbGUPTD

## Citation
Sawadogo, Y. ARCHIVIRT — Automated Reproducible Cyber Hybrid Infrastructure for Virtual IDS/IPS
Testing Labs. SPbGUPTD, 2026. Machine-readable metadata: [`CITATION.cff`](CITATION.cff).

https://github.com/yasnemanegre/ARCHIVIRT

---

## Secrets Management

Credentials are managed via Ansible Vault — never committed to the repo.

```bash
# Create secrets file (first time)
cp ansible/vars/secrets.yml.example ansible/vars/secrets.yml
ansible-vault encrypt ansible/vars/secrets.yml

# Run playbooks with vault
ansible-playbook ansible/playbooks/setup_influxdb.yml \
  -i ansible/inventory/hosts.ini \
  --ask-vault-pass
```

---

## campaign_v1 — Experimental Engine (Article 2)

`campaign_v1/` is the **current experimental reference** for Article 2 (independent of the legacy `archivirt-reset.sh` pipeline). It owns the single sources of truth:

```
campaign_v1/
├── engines/      suricata.sh (IDS/IPS), snort3.sh (offline-gated stub), stop.sh
├── scenarios/    SCN-001..005 (attack + benign control), machine-readable markers
├── rules/        archivirt-article2-ids.rules / -ips.rules (discriminative signatures)
├── manifest/     offline_manifest.json (offline artifact set)
├── schema/       result.json (canonical per-run schema)
└── preflight.sh  per-scenario prerequisite report (no install)

scripts/campaign_v1/   orchestrator + processors + analysis
├── campaign_v1.sh     orchestrator (engine dispatch, offline gate, provenance, perf)
├── validate_run.py    per-run validation + ground-truth TP/FP/FN/TN classification
├── summarize.py       campaign summary
├── compute_perf.py    CPU/RAM + capture throughput per run
├── offline_audit.sh / offline_audit.py   offline readiness (READY/MISSING/...)
├── analyze.py         metrics, confusion matrix, statistics, tables
├── figures.py         figures (matplotlib)
├── synthesize.py      scientific synthesis
└── scientific_audit.py  audit answers
```

### Run one qualification
```bash
bash campaign_v1/preflight.sh                              # prerequisites report (no install)
MODE=ids RUNS=1 SCENARIOS_LIST="SCN-001" bash scripts/campaign_v1/campaign_v1.sh
```
Modes: `MODE=ids|ips|baseline`. Engine: `ENGINE=suricata-6.0.4` (default) or `ENGINE=snort3` (offline-gated). Offline gate: `ENFORCE_OFFLINE=1` (default) aborts if required local artifacts are missing — nothing is ever downloaded.

### Validation method
A run is `VALID` only when the attack really ran, EVE was really collected, and (for attack scenarios) the scenario's expected signature fired. `INVALID` / `PREREQUISITE_MISSING` runs are kept, never silently dropped, and never enter VALID statistics. Each run records provenance (git commit, versions, artifact SHA-256).

### Reproduce the analysis
```bash
python3 scripts/campaign_v1/analyze.py  results/campaign-v1/article2 <IDS_dir> <baseline_dir> <IPS_dir>
python3 scripts/campaign_v1/figures.py  results/campaign-v1/article2 <IDS_dir> <baseline_dir> <IPS_dir>
python3 scripts/campaign_v1/synthesize.py      results/campaign-v1/article2
python3 scripts/campaign_v1/scientific_audit.py results/campaign-v1/article2 <IDS_dir> <baseline_dir> <IPS_dir>
```

## Results location
- **Article-2 deliverables:** `results/campaign-v1/article2/`
- **Raw per-run records (committed):** `results/campaign-v1/ARTICLE-*/` (result.json, perf.json, timestamps, summary, provenance, readiness).
- **Bulky packet-level EVE (`eve.json`, `*_raw.txt`):** retained locally for deep traceability but **not committed** (size); see `.gitignore`.

## Project status
- ✅ Suricata IDS/IPS Article-2 campaigns executed, analysed, audited and **frozen** (`article2-experimental-v1`).
- ⏳ Phase 2 (out of scope here): fully offline Artifact Set, destroy/rebuild without Internet, Snort 3 integration, DBSCAN/ML/UEBA.
