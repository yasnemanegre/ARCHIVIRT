# ARCHIVIRT — Installation Guide

> **Server:** `archivirt@archivirt-lab` | IP: `192.168.4.10`
> **Author:** Yasnemanegre SAWADOGO (PhD Candidate, SPbGUPTD)
> **License:** MIT — https://github.com/yasnemanegre/ARCHIVIRT
> **Version:** 4.0 — 2026-06-14

---

## Table of Contents

1. [Host Prerequisites](#1-host-prerequisites)
2. [KVM/Libvirt + OVS Setup](#2-kvmlibvirt--ovs-setup)
3. [Terraform Installation](#3-terraform-installation)
4. [Ansible Installation](#4-ansible-installation)
5. [Python Dependencies](#5-python-dependencies)
6. [Clone Repository](#6-clone-repository)
7. [One-time Host Setup](#7-one-time-host-setup)
8. [Run Full Campaign](#8-run-full-campaign)
9. [View Reports](#9-view-reports)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Host Prerequisites

```bash
lsb_release -a                    # Expected: Ubuntu 22.04.x LTS
egrep -c '(vmx|svm)' /proc/cpuinfo  # Must be > 0
nproc && free -h                  # Recommended: 16+ cores, 64 GB RAM, NVMe
```

---

## 2. KVM/Libvirt + OVS Setup

```bash
sudo apt update && sudo apt install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    bridge-utils virtinst cpu-checker \
    genisoimage cloud-image-utils \
    nftables ebtables \
    openvswitch-switch openvswitch-common

sudo kvm-ok
sudo usermod -aG libvirt,kvm archivirt
sudo systemctl enable --now libvirtd openvswitch-switch
sudo ovs-vsctl show
```

---

## 3. Terraform Installation

```bash
wget -O- https://apt.releases.hashicorp.com/gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform libvirt-dev
terraform --version    # Expected: v1.5+
```

---

## 4. Ansible Installation

```bash
pip3 install --user ansible passlib
ansible --version    # Expected: ansible [core 2.16+]
```

---

## 5. Python Dependencies

```bash
sudo apt install -y python3 python3-pip
pip3 install --user numpy scikit-learn python-dateutil pandas PyYAML paramiko
python3 -c "import sklearn, dateutil, numpy, pandas, passlib; print('All OK')"
```

---

## 6. Clone Repository

```bash
sudo apt install -y git
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT
chmod +x scripts/*.sh archivirt-reset.sh
```

---

## 7. One-time Host Setup

Run these **once** before the first campaign:

```bash
cd ~/ARCHIVIRT

# 7a. Local apt mirror (nginx:8080, 800+ packages — required for offline IaC)
ansible-playbook ansible/playbooks/setup_host.yml -i localhost,

# 7b. Password hash for VM console access
python3 -c "import crypt; print('ubuntu_password_hash = \"' + \
  crypt.crypt('archivirt123', crypt.mksalt(crypt.METHOD_SHA512)) + '\"')" \
  > terraform/terraform.tfvars

# 7c. SSH key pair
ssh-keygen -t ed25519 -f ~/.ssh/archivirt-lab -N ""

# 7d. OVS bridges + systemd persistence (also run after host reboot)
ansible-playbook ansible/playbooks/setup_ovs.yml -i ansible/inventory/hosts.ini
```

After `setup_ovs.yml`, two systemd services are installed and enabled:
- `archivirt-ovs-ip.service` — restores OVS bridge IPs at boot
- `archivirt-ovs-dhcp.service` — starts dnsmasq DHCP at boot

---

## 8. Run Full Campaign

```bash
cd ~/ARCHIVIRT
./archivirt-reset.sh
```

The script runs automatically:
1. `terraform destroy` — destroy existing VMs/networks
2. `ovs-vsctl del-br ovs-manager` — remove OVS/libvirt NAT conflict
3. `setup_ovs.yml` — configure OVS bridges
4. `terraform apply` — deploy 6 VMs + 4 networks
5. Wait 30s + add virbr1 route for manager VM
6. Wait 90s for cloud-init
7. `run_all_scenarios.yml`:
   - SCN-001 Port Scan (nmap -sS, ports 1-1024)
   - SCN-002 SSH Brute-force (hydra)
   - SCN-003 SQL Injection (sqlmap vs DVWA v1.10)
   - SCN-004 DDoS Slowloris (150 sockets, 15s)
   - SCN-005 Normal traffic (curl HTTP GET)
   - Both Snort 3.1.74.0 and Suricata 6.0.4
   - DBSCAN/UEBA analysis
   - Final report → `results/archivirt_final_comparison.json`

---

## 9. View Reports

```bash
# Results printed to terminal at campaign end
cat results/archivirt_final_comparison.json | python3 -m json.tool

# Re-generate from existing data
python3 scripts/generate_report.py
```

---

## 10. Troubleshooting

### OVS/libvirt conflict
```bash
sudo ovs-vsctl --if-exists del-br ovs-manager
```

### VMs unreachable (virsh domifaddr empty)
VMs use **static IPs** via cloud-init — `virsh domifaddr` won't show them:
```bash
for ip in 10.0.2.11 10.0.2.12 10.0.2.13 10.0.3.10 10.0.4.10 10.0.5.10; do
  echo -n "$ip: "; ping -c1 -W1 $ip &>/dev/null && echo UP || echo DOWN
done
```

### Manager VM (10.0.5.10) unreachable
```bash
sudo ip route add 10.0.5.0/24 dev virbr1 src 10.0.5.1
```

### Snort fails: libdumbnet.so.1 not found
Ansible pre-flight installs deps automatically. Manual fix:
```bash
ssh ubuntu@10.0.3.10 "sudo apt-get install -y libdumbnet1 libhwloc15 libdaq2"
```

### cloud-init install_monitor.sh failed
```bash
ssh ubuntu@10.0.3.10 \
  "sudo wget -q http://10.0.3.1:8080/install_monitor.sh -O /tmp/install.sh \
  && sudo bash /tmp/install.sh"
```

### OVS bridges missing after host reboot
```bash
# Services should auto-restart, but if not:
ansible-playbook ansible/playbooks/setup_ovs.yml -i ansible/inventory/hosts.ini
```

---

## Full Teardown

```bash
terraform -chdir=terraform/ destroy -auto-approve
sudo ovs-vsctl --if-exists del-br ovs-manager
virsh list --all    # Expected: empty
```
