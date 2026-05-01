#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Full Lab Deployment Script
# Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)
#
# Usage:
#   ./scripts/deploy.sh [--ids snort|suricata] [--skip-terraform]
#   ./scripts/deploy.sh --destroy
#
# Environment:
#   Host: archivirt@archivirt-lab (192.168.4.11)
# ─────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$ROOT_DIR/terraform"
ANSIBLE_DIR="$ROOT_DIR/ansible"

# ── Defaults ─────────────────────────────────────────────────
IDS_ENGINE="suricata"
SKIP_TERRAFORM=false
DESTROY=false

# ── Argument parsing ─────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ids)    IDS_ENGINE="$2"; shift 2 ;;
        --skip-terraform) SKIP_TERRAFORM=true; shift ;;
        --destroy) DESTROY=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--ids snort|suricata] [--skip-terraform] [--destroy]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log()  { echo -e "${GREEN}[ARCHIVIRT]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${BLUE}  STEP: $*${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

# ── SSH Key setup ─────────────────────────────────────────────
ensure_ssh_key() {
    if [[ ! -f ~/.ssh/archivirt_key ]]; then
        log "Generating SSH key pair for ARCHIVIRT lab..."
        ssh-keygen -t ed25519 -f ~/.ssh/archivirt_key -N "" -C "archivirt-lab"
    fi
    log "SSH key: ~/.ssh/archivirt_key"
}

# ── Prerequisites check ───────────────────────────────────────
check_prerequisites() {
    step "Checking prerequisites"
    local missing=()
    for cmd in terraform ansible virsh python3; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing tools: ${missing[*]}"
        err "Run: sudo apt install terraform ansible qemu-kvm libvirt-daemon-system"
        exit 1
    fi
    log "All prerequisites met ✓"
    terraform --version | head -1
    ansible --version | head -1
}

# ── Destroy mode ──────────────────────────────────────────────
destroy_lab() {
    step "DESTROYING ARCHIVIRT Lab"
    warn "This will delete ALL VMs and networks!"
    read -r -p "Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        log "Aborted."
        exit 0
    fi
    cd "$TERRAFORM_DIR"
    terraform destroy -auto-approve
    log "Lab destroyed successfully."
    exit 0
}

# ── Terraform phase ───────────────────────────────────────────
deploy_infrastructure() {
    step "Phase 1 — Deploying infrastructure with Terraform"
    cd "$TERRAFORM_DIR"

    log "Initializing Terraform..."
    terraform init -upgrade

    log "Planning infrastructure..."
    terraform plan \
        -var="ids_engine=$IDS_ENGINE" \
        -out=/tmp/archivirt.tfplan

    log "Applying infrastructure..."
    terraform apply /tmp/archivirt.tfplan

    log "Infrastructure deployed ✓"
    terraform output lab_summary
}

# ── Generate Ansible inventory ────────────────────────────────
generate_inventory() {
    step "Phase 2 — Generating Ansible inventory"
    cd "$ROOT_DIR"
    python3 scripts/generate_inventory.py
    log "Inventory generated: ansible/inventory/hosts.ini ✓"
}

# ── Wait for VMs ──────────────────────────────────────────────
wait_for_vms() {
    step "Waiting for VMs to boot..."
    local max_wait=180
    local waited=0
    local vms=("10.0.2.11" "10.0.2.12" "10.0.2.13" "10.0.3.10" "10.0.4.10" "10.0.5.10")

    for vm_ip in "${vms[@]}"; do
        waited=0
        echo -n "  Waiting for $vm_ip ..."
        while ! ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
                   -i ~/.ssh/archivirt_key ubuntu@"$vm_ip" "exit" &>/dev/null; do
            sleep 5
            waited=$((waited + 5))
            echo -n "."
            if [[ $waited -ge $max_wait ]]; then
                warn " TIMEOUT (VM may still be booting, continuing...)"
                break
            fi
        done
        echo -e " ${GREEN}UP${NC}"
    done
}

# ── Ansible configuration ─────────────────────────────────────
configure_vms() {
    step "Phase 3 — Configuring VMs with Ansible"
    cd "$ANSIBLE_DIR"

    log "Running common base configuration..."
    ansible-playbook -i inventory/hosts.ini site.yml --tags common

    log "Configuring target VMs (vulnerable services)..."
    ansible-playbook -i inventory/hosts.ini site.yml --tags targets

    log "Deploying IDS/IPS: $IDS_ENGINE..."
    ansible-playbook -i inventory/hosts.ini site.yml --tags "ids_$IDS_ENGINE"

    log "Configuring attacker VM..."
    ansible-playbook -i inventory/hosts.ini site.yml --tags attacker

    log "Configuring manager VM..."
    ansible-playbook -i inventory/hosts.ini site.yml --tags manager

    log "All VMs configured ✓"
}

# ── Final summary ─────────────────────────────────────────────
print_summary() {
    step "Deployment Complete!"
    echo -e """
${GREEN}════════════════════════════════════════════
  ARCHIVIRT Lab Ready
════════════════════════════════════════════${NC}

  Host Server      : archivirt@192.168.4.11

  Manager VM       : 10.0.5.10   (Grafana: http://10.0.5.10:3000)
  Attacker VM      : 10.0.4.10
  Monitor VM (IDS) : 10.0.3.10   (IDS: $IDS_ENGINE)
  Target VM 01     : 10.0.2.11   (DVWA: http://10.0.2.11/dvwa/)
  Target VM 02     : 10.0.2.12   (SSH/FTP)
  Target VM 03     : 10.0.2.13   (SMB/DB)

${CYAN}Next steps:${NC}
  1. Run tests:    ./scripts/run_tests.sh
  2. View reports: python3 scripts/generate_report.py
  3. Grafana:      http://10.0.5.10:3000 (admin/archivirt)

${YELLOW}To destroy the lab:${NC}
  ./scripts/deploy.sh --destroy
════════════════════════════════════════════
"""
}

# ── Main ──────────────────────────────────────────────────────
main() {
    echo -e "${CYAN}"
    echo "    _    ____   ____ _   _ _____     _____ ____ _____ "
    echo "   / \  |  _ \ / ___| | | |_ _\ \   / /_ _|  _ \_   _|"
    echo "  / _ \ | |_) | |   | |_| || | \ \ / / | || |_) || |  "
    echo " / ___ \|  _ <| |___|  _  || |  \ V /  | ||  _ < | |  "
    echo "/_/   \_\_| \_\\\\____|_| |_|___|  \_/  |___|_| \_\|_|  "
    echo -e "${NC}"
    echo -e "  ${BLUE}Framework for Virtual IDS/IPS Lab Automation${NC}"
    echo -e "  Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)\n"

    [[ "$DESTROY" == true ]] && destroy_lab

    check_prerequisites
    ensure_ssh_key

    if [[ "$SKIP_TERRAFORM" == false ]]; then
        deploy_infrastructure
    else
        warn "Skipping Terraform (--skip-terraform)"
    fi

    generate_inventory
    wait_for_vms
    configure_vms
    print_summary
}

main "$@"

# Enable inter-subnet routing (attack -> targets)
enable_inter_subnet_routing() {
  sudo iptables -I FORWARD 1 -i virbr2 -o virbr3 -j ACCEPT
  sudo iptables -I FORWARD 1 -i virbr3 -o virbr2 -j ACCEPT
  sudo netfilter-persistent save
  echo "[+] Inter-subnet routing enabled"
}
enable_inter_subnet_routing
