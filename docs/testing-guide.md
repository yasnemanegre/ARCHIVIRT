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

