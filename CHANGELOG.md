# ARCHIVIRT — CHANGELOG
# Repository: https://github.com/yasnemanegre/ARCHIVIRT
# Author: Yasnemanegre SAWADOGO | SPbGUPTD

---

## [v3.2] — 2026-05-17
### Fixed (session 16-17.05.2026)
- **Snort 3.1.74.0**: règles SQLi granulaires (encodé/non-encodé)
- **IaC**: HOME_NET résolu via ips.variables.nets Snort 3.1.74
- **IaC**: snort.lua converti en template Jinja2
- **IaC**: archivirt_project_dir variable portable dans hosts.ini
- **IaC**: ansible_python_interpreter explicite
- **Attacker**: hydra → ncrack v0.7 (X11 incompatible)
- **Attacker**: john/medusa/scapy supprimés
- **IP hôte**: 192.168.4.11 → 192.168.4.10 corrigé partout
- **NTP**: ntp → systemd-timesyncd
- **DVWA**: déploiement via miroir local offline
- **Dépôt apt**: nginx:8080, 227 packages, setup_host.yml

### Added
- **Telegraf monitor-ids**: métriques IDS → InfluxDB manager
- **Grafana**: datasource + dashboard IaC
- **InfluxDB**: initialisé (archivirt/archivirt-metrics)
- **Route réseau**: monitor-ids → manager via 10.0.3.1
- **setup_host.yml**: dépendances complètes IaC reproductibles

### Results (campagne 16.05.2026)
- Snort  : 157 549 alertes | CPU 1.6% | RAM 41MB | DR=100%
- Suricata:   3 244 alertes | CPU 7.7% | RAM 46MB | DR=100%
- DBSCAN: Snort 14 clusters/12 anomalies | Suricata 3/0

---
## [v3.1] — 2026-05-15

### Added
- **Table 2**: TOTAL rows added for Snort (33 253) and Suricata (12 344)
- **Table 2 ↔ Table 3 coherence**: Total alerts now verifiable by summing per-scenario alerts
  - Snort: 30 562 + 27 + 0 + 2 664 + 0 = 33 253 ✓
  - Suricata: 41 + 41 + 1 143 + 11 034 + 85 = 12 344 ✓
- **RESULTS.md**: Dedicated file for all validated experimental results
- **§6.3**: New discussion section on cross-table observations

### Fixed
- **FPR Suricata**: corrected from 0.10% (v2.0) to **0.69%** (real: 85 alerts / 50 000 packets)
- **Latency values**: updated post-NTP chrony fix (offset now < 1 ms)
- **Table 2 Latency footnote (★)**: documented NTP clock skew ~800 ms clamping behaviour

### Notes
- Snort Port Scan = 91.9% of Snort's total alerts (30 562 / 33 253) — verbosity to document
- Snort generates 2.7× more alerts than Suricata with 4.8× lower CPU

---

## [v3.0] — 2026-05-15

### Added
- Snort 3.1.74.0 compiled from source (libdaq 3.0.13 + snort3 3.1.74.0)
- 1 GB swap workaround for OOM during linking on 768 MB VM
- Local apt mirror (nginx + dpkg-repack) for offline VM provisioning
- σ = 0.00% validated on 10 complete campaigns

### Fixed
- **Snort version**: corrected from 3.12.2.0 → **3.1.74.0** (article v2.0 was wrong)
- **bad_tcp4_checksum**: `network = { checksum_eval = 'none' }` in snort.lua
- **SQLi Snort DR**: signatures updated for URL-encoded payloads (%27, %20AND%20)
- **NTP clock skew**: chrony installed offline, host stratum 8
- **Suricata rule-files**: corrected paths in suricata.yaml
- **tc mirrors reset**: re-applied before each Suricata scenario
- **Attacker ens4 DOWN**: netplan 99-ens4.yaml + static IP 10.0.2.100/24
- **nmap exit 127**: dpkg-repack liblinear.so.4, liblua5.3 → scp to attacker VM

---

## [v2.0] — 2026-05-05 (Sterenberg corrections)

### Added (corrections Sterenberg §1–§17)
- Table 1: formal comparison with DISSUADER, KYPO, Security Onion (6 parameters)
- MIT License + GitHub URL in abstract, §3, conclusion
- DVWA v1.10, Apache 2.4.52, OpenSSH 8.9, Samba 4.15.9 versions specified (§4.2)
- Snort Community Ruleset (3 847 rules), ET Open (6 892 rules) specified (§4.2)
- Normal traffic generation: tcpreplay v4.4.2 + CAIDA 2023 (§4.3)
- σ column added to Table 2 (§5)
- t-test + ANOVA statistical significance (§5.2)
- Post-hoc power analysis, β = 0.92 (§5.1)
- 85% metric documented: engineer profile, 3 attempts, avg 4h08min (§6.1)
- Scalability: theoretical cluster estimate + Terraform overhead (§6.2)
- Network isolation: nftables + ebtables rules (§3.2)
- Modularity examples: Ubuntu→Windows, Metasploit→CALDERA (§3.1)
- DBSCAN/UEBA results table (§4.6)

### Fixed
- **IDS mode**: IDS-only explicitly stated (IPS not tested) — abstract, §4.1, conclusion
- **DDoS Slowloris Snort DR**: 65.3% → 100.0% (real results)
- **CPU/RAM Table 3**: Snort 68.2%/512MB → **1.6%/41MB** (real, previous values ×40 error)
- **CPU/RAM Table 3**: Suricata 75.4%/610MB → **7.7%/46MB** (real)
- **Scarfone/Mell duplicate**: refs §4 and §6 were same NIST SP 800-94 — duplicate removed
- Architecture levels 4–5 separated: roles vs data/persistence

---

## [v1.0] — 2026-04 (initial submission — contains errors)

> ⚠ DO NOT USE — contains multiple critical errors:
> - Snort version wrong (3.12.2.0)
> - CPU/RAM values inflated by ×40 (68.2%/512MB, 75.4%/610MB)
> - DDoS Slowloris Snort DR wrong (65.3% instead of 100.0%)
> - FPR Suricata wrong (0.10% instead of 0.69%)
> - No DBSCAN results
> - No σ values
> - No statistical tests
> - IPS claimed but not tested

## [v3.3-wip] — 2026-05-18
### En cours
- Suricata regles ASCII corrigees (syntaxe Suricata 6)
- cloud-init toutes VMs corrige (hostname indentation + EOF)
- monitor-ids : 2GB RAM, 3 interfaces (ens3/ens4/ens5)
- pre-flight checks dans run_all_scenarios.yml
- Campagnes IPS Suricata : a lancer

### Prochaines etapes
1. Valider targets accessibles apres cloud-init
2. Relancer campagnes IDS Suricata (0 alertes a corriger)
3. Demonstration Grafana (tunnel Tailscale 100.65.253.128)
   - Dashboard IDS : alertes/min, CPU, RAM
   - Dashboard IPS : drops/min, blocked IPs
4. Lancer campagnes IPS (ids_mode=ips)
5. Tableau 5 IDS vs IPS dans l article
6. Mise a jour article + push final GitHub

---
## [Roadmap — v4.1]

### Planned
- [ ] InfluxDB + Grafana + Telegraf configuration on manager VM (10.0.5.10)
      → CPU/RAM/Mbps metrics currently from static `performance_baseline.json`
      → Target: live metrics updated automatically each campaign run
- [ ] `calibrate_performance.yml` integrated into `run_all_scenarios.yml`
      → Table 3 currently frozen — needs dynamic update per campaign
- [ ] IPS mode validation (Snort + Suricata inline blocking)
- [ ] Multi-node cluster support (AWS/Azure/GCP)
- [ ] CALDERA integration for advanced attack scenarios
- [ ] Windows target VMs (Metasploitable3)

---
## [v4.1] — 2026-06-14 — Monitoring Stack

### Added
- Telegraf 1.29.5 deployed on monitor-ids via `deploy_telegraf.yml`
- InfluxDB v2 initialized via HTTP API in `setup_influxdb.yml` (no CLI required)
- Grafana datasource + dashboard auto-imported in `archivirt-reset.sh`
- Manager VM gets secondary interface `ens4` on `ovs-monitor` (10.0.3.254/24)
  → Telegraf → InfluxDB direct path without cross-subnet routing (Option A)
- `archivirt-reset.sh` updated with full monitoring stack setup
- Grafana accessible via SSH tunnel: `ssh -L 3000:10.0.5.10:3000 archivirt@<tailscale-ip>`

### Fixed
- `telegraf-monitor.conf`: bucket `archivirt-metrics` → `archivirt`
- `telegraf-monitor.conf`: ips_metrics.json exec command quotes fixed
- `deploy_telegraf.yml`: v2.0 — uses apt mirror package, telegraf-monitor.conf
- Grafana default password reset via `grafana-cli`

### Validated
- Telegraf → InfluxDB: `archivirt_snort_alerts` + `archivirt_suricata_alerts` every 10s
- Grafana dashboard: ARCHIVIRT — IDS/IPS Testing Dashboard imported
- Full pipeline: `archivirt-reset.sh` includes monitoring stack auto-setup
