# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Virtual Machine Definitions
# Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)
# ─────────────────────────────────────────────────────────────

locals {
  ssh_pub_key = file(pathexpand(var.ssh_public_key_path))

  # cloud-init common user-data template
  cloud_init_common = <<-EOF
    #cloud-config
    users:
      - name: ubuntu
        groups: sudo
        shell: /bin/bash
        sudo: ['ALL=(ALL) NOPASSWD:ALL']
        ssh_authorized_keys:
          - ${local.ssh_pub_key}
    chpasswd:
      list: |
        ubuntu:archivirt123
      expire: false
    package_update: true
    packages:
      - openssh-server
      - net-tools
      - tcpdump
      - curl
      - wget
      - python3
      - python3-pip
  EOF
}

# ─────────────────────────────────────────────────────────────
# MANAGER VM — Orchestration & Metrics (10.0.5.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "manager" {
  name = "archivirt-manager-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: archivirt-manager
    ${local.cloud_init_common}
    packages:
      - openssh-server
      - net-tools
      - python3
      - python3-pip
      - influxdb2
      - grafana
      - telegraf
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_manager}/24]
        gateway4: 10.0.5.1
  EOF
}

resource "libvirt_volume" "manager_disk" {
  name           = "archivirt-manager.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "manager" {
  name   = "archivirt-manager"
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.manager.id

  network_interface {
    network_id = libvirt_network.manager.id
    addresses  = [var.ip_manager]
  }

  disk {
    volume_id = libvirt_volume.manager_disk.id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  graphics {
    type        = "vnc"
    listen_type = "address"
  }

  autostart = true
}

# ─────────────────────────────────────────────────────────────
# ATTACKER VM — Penetration Testing Tools (10.0.4.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "attacker" {
  name = "archivirt-attacker-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: archivirt-attacker
    ${local.cloud_init_common}
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_attacker}/24]
        gateway4: 10.0.4.1
      eth1:
        addresses: [10.0.2.100/24]
  EOF
}

resource "libvirt_volume" "attacker_disk" {
  name           = "archivirt-attacker.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "attacker" {
  name   = "archivirt-attacker"
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.attacker.id

  network_interface {
    network_id = libvirt_network.attack.id
    addresses  = [var.ip_attacker]
  }

  # Also connected to target network to reach targets directly
  network_interface {
    network_id = libvirt_network.targets.id
  }

  disk {
    volume_id = libvirt_volume.attacker_disk.id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  autostart = true
}

# ─────────────────────────────────────────────────────────────
# MONITOR VM — IDS/IPS (Snort or Suricata) (10.0.3.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "monitor" {
  name = "archivirt-monitor-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: archivirt-monitor-ids
    ${local.cloud_init_common}
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_monitor}/24]
        gateway4: 10.0.3.1
      eth1:
        addresses: [10.0.2.200/24]
  EOF
}

resource "libvirt_volume" "monitor_disk" {
  name           = "archivirt-monitor.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "monitor" {
  name   = "archivirt-monitor-ids"
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.monitor.id

  network_interface {
    network_id = libvirt_network.monitor.id
    addresses  = [var.ip_monitor]
  }

  # Tap interface connected to target network for passive monitoring
  network_interface {
    network_id = libvirt_network.targets.id
  }

  disk {
    volume_id = libvirt_volume.monitor_disk.id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  autostart = true
}

# ─────────────────────────────────────────────────────────────
# TARGET VMs — Vulnerable Services (10.0.2.11 to 10.0.2.13)
# ─────────────────────────────────────────────────────────────
locals {
  targets = {
    "01" = { ip = var.ip_target_01, hostname = "archivirt-target-01", role = "web" }
    "02" = { ip = var.ip_target_02, hostname = "archivirt-target-02", role = "ssh_ftp" }
    "03" = { ip = var.ip_target_03, hostname = "archivirt-target-03", role = "smb_db" }
  }
}

resource "libvirt_cloudinit_disk" "target" {
  for_each = local.targets

  name = "archivirt-target-${each.key}-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: ${each.value.hostname}
    ${local.cloud_init_common}
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${each.value.ip}/24]
        gateway4: 10.0.2.1
  EOF
}

resource "libvirt_volume" "target_disk" {
  for_each = local.targets

  name           = "archivirt-target-${each.key}.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "target" {
  for_each = local.targets

  name   = each.value.hostname
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.target[each.key].id

  network_interface {
    network_id = libvirt_network.targets.id
    addresses  = [each.value.ip]
  }

  disk {
    volume_id = libvirt_volume.target_disk[each.key].id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  autostart = true
}
