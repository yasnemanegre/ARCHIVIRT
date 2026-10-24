# =============================================================================
# ARCHIVIRT — OFFLINE REBUILD VALIDATION ENVIRONMENT (isolated, disposable)
# =============================================================================
# Purpose: prove that a VM can be created, provisioned, destroyed and rebuilt
# from LOCAL resources only, without touching the production lab.
#
# Isolation guarantees:
#   - separate directory => separate Terraform state (never the production one)
#   - every resource name is prefixed "archivirt-val-"
#   - its own base volume (copied from the local cloud image), never the
#     production "ubuntu-22.04-base.qcow2"
#   - network in libvirt "isolated" mode (no <forward>): no route to the
#     Internet; only the host gateway 10.99.0.1 (local mirror on :8080)
#
# Running it creates a new libvirt bridge and libvirt-managed iptables rules
# on the host: requires explicit authorization (host network change).
#
# Usage (offline):
#   export TF_CLI_CONFIG_FILE=~/archivirt-offline/terraform/terraformrc
#   terraform -chdir=terraform/validation init
#   terraform -chdir=terraform/validation apply
#   terraform -chdir=terraform/validation destroy   # validation resources only
# =============================================================================

terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7.6"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

variable "base_image_path" {
  default = "/home/archivirt/archivirt-offline/images/ubuntu-22.04-server-cloudimg-amd64.img"
}
variable "ssh_public_key_path" { default = "~/.ssh/archivirt_key.pub" }
variable "val_ram_mb" { default = 1024 }
variable "val_vcpu" { default = 1 }
variable "val_ip" { default = "10.99.0.10" }

locals {
  ssh_pub_key = file(pathexpand(var.ssh_public_key_path))
  mirror      = "http://10.99.0.1:8080"
}

resource "libvirt_network" "val" {
  name      = "archivirt-val-isolated"
  mode      = "none" # isolated: no forwarding / NAT to the outside
  bridge    = "virbr-arcval"
  addresses = ["10.99.0.0/24"]
  autostart = false
  dhcp {
    enabled = false
  }
  dns {
    enabled = false
  }
}

resource "libvirt_volume" "val_base" {
  name   = "archivirt-val-base.qcow2"
  pool   = "default"
  source = var.base_image_path
  format = "qcow2"
}

resource "libvirt_volume" "val_disk" {
  name           = "archivirt-val-manager.qcow2"
  pool           = "default"
  base_volume_id = libvirt_volume.val_base.id
  size           = 12 * 1073741824
}

resource "libvirt_cloudinit_disk" "val" {
  name           = "archivirt-val-manager-cloudinit.iso"
  pool           = "default"
  user_data      = <<-EOF
    #cloud-config
    hostname: archivirt-val-manager
    users:
      - name: ubuntu
        groups: sudo
        shell: /bin/bash
        sudo: ['ALL=(ALL) NOPASSWD:ALL']
        lock_passwd: true
        ssh_authorized_keys:
          - ${local.ssh_pub_key}
    ssh_pwauth: false
    package_update: false
    apt:
      sources_list: |
        # local mirror only
    runcmd:
      - until wget -q "${local.mirror}/install_manager.sh" -O /tmp/install.sh; do sleep 5; done && ARCHIVIRT_MIRROR=${local.mirror} bash /tmp/install.sh
  EOF
  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.val_ip}/24]
  EOF
}

resource "libvirt_domain" "val" {
  name      = "archivirt-val-manager"
  memory    = var.val_ram_mb
  vcpu      = var.val_vcpu
  autostart = false
  cloudinit = libvirt_cloudinit_disk.val.id

  network_interface {
    network_id = libvirt_network.val.id
  }

  disk {
    volume_id = libvirt_volume.val_disk.id
  }

  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }
}

output "val_ip" { value = var.val_ip }
