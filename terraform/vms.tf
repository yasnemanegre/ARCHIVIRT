# Author: Yasnemanegre SAWADOGO (PhD Student, SPbSUITD)
# ─────────────────────────────────────────────────────────────

locals {
  ssh_pub_key = file(pathexpand(var.ssh_public_key_path))

  # Common cloud-init user-data template shared across all VMs
  # FIX: added ssh_pwauth + SHA-512 hash (var.ubuntu_password_hash) — plaintext password removed
  cloud_init_common = <<-EOF
    users:
      - name: ubuntu
        groups: sudo
        shell: /bin/bash
        sudo: ['ALL=(ALL) NOPASSWD:ALL']
        lock_passwd: true
        ssh_authorized_keys:
          - ${local.ssh_pub_key}
    ssh_pwauth: false
    chpasswd:
      expire: false
    package_update: false
    apt:
      sources_list: |
        # Disabled by ARCHIVIRT IaC — local mirror only
      conf: |
        Acquire::AllowInsecureRepositories "true";
        Acquire::AllowDowngradeToInsecureRepositories "true";
  EOF
}

# ─────────────────────────────────────────────────────────────
# MANAGER VM — Orchestration & Metrics (10.0.5.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "manager" {
  name = "archivirt-manager-cloudinit.iso"
  pool = var.storage_pool

  user_data      = <<-EOF
    #cloud-config
    hostname: archivirt-manager
    ${local.cloud_init_common}
    runcmd:
      - until wget -q "http://10.0.5.1:8080/install_manager.sh" -O /tmp/install.sh; do echo "Waiting for mirror..."; sleep 10; done && bash /tmp/install.sh
  EOF
  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_manager}/24]
        gateway4: 10.0.5.1
      ens4:
        addresses: [10.0.3.254/24]
  EOF
}

resource "libvirt_volume" "manager_disk" {
  name           = "archivirt-manager.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

# Staged start (host RAM 6.9 GiB for 6.9 GiB of VMs): wave 1 = manager + monitor,
# wave 2 = attacker + targets (started later, one by one, by 04_configure.sh).
variable "archivirt_start_wave2" {
  type    = bool
  default = true
}

resource "libvirt_domain" "manager" {
  name   = "archivirt-manager"
  vcpu   = var.vm_vcpu
  memory = var.vm_ram_manager

  cloudinit = libvirt_cloudinit_disk.manager.id

  network_interface {
    network_id = libvirt_network.manager.id
  }
  # Secondary interface on ovs-monitor for Telegraf → InfluxDB
  network_interface {
    bridge = "ovs-monitor"
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

  # Cycle fix (B3, 2026-10-08 apply failure): libvirt must attach this domain's
  # OVS-backed NICs with <virtualport type="openvswitch"/>, otherwise
  # "Unable to add bridge ovs-* port vnetX: Operation not supported".
  xml {
    xslt = file("${path.module}/xslt/ovs-domain-interfaces.xslt")
  }
}

# ─────────────────────────────────────────────────────────────
# ATTACKER VM — Penetration Testing Tools (10.0.4.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "attacker" {
  name = "archivirt-attacker-cloudinit.iso"
  pool = var.storage_pool

  user_data      = <<-EOF
    #cloud-config
    hostname: archivirt-attacker
    ${local.cloud_init_common}
    runcmd:
      - until wget -q "http://10.0.4.1:8080/install_attacker.sh" -O /tmp/install.sh; do echo "Waiting for mirror..."; sleep 10; done && bash /tmp/install.sh
  EOF
  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_attacker}/24]
        gateway4: 10.0.4.1
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
  memory = var.vm_ram_attacker

  # Memory strategy (cycle): created stopped when archivirt_start_wave2=false;
  # 04_configure.sh then starts them one at a time after manager + monitor.
  running = var.archivirt_start_wave2

  cloudinit = libvirt_cloudinit_disk.attacker.id

  network_interface {
    bridge = "ovs-attack"
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

  # Cycle fix (B3, 2026-10-08 apply failure): libvirt must attach this domain's
  # OVS-backed NICs with <virtualport type="openvswitch"/>, otherwise
  # "Unable to add bridge ovs-* port vnetX: Operation not supported".
  xml {
    xslt = file("${path.module}/xslt/ovs-domain-interfaces.xslt")
  }
}

# ─────────────────────────────────────────────────────────────
# MONITOR VM — IDS/IPS (Snort or Suricata) (10.0.3.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "monitor" {
  name = "archivirt-monitor-cloudinit.iso"
  pool = var.storage_pool

  user_data      = <<-EOF
    #cloud-config
    hostname: archivirt-monitor-ids
    ${local.cloud_init_common}
    runcmd:
      - until wget -q "http://10.0.3.1:8080/install_monitor.sh" -O /tmp/install.sh; do echo "Waiting for mirror..."; sleep 10; done && bash /tmp/install.sh
  EOF
  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_monitor}/24]
        gateway4: 10.0.3.1
      ens4:
        addresses: [10.0.2.200/24]
      ens5:
        addresses: [10.0.4.200/24]
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
  memory = var.vm_ram_monitor

  cpu {
    mode = "host-passthrough"
  }

  cloudinit = libvirt_cloudinit_disk.monitor.id

  # ens3 — management
  network_interface {
    bridge = "ovs-monitor"
    mac    = "52:54:00:76:BB:98"
  }

  # ens4 — IPS egress toward targets
  network_interface {
    bridge = "ovs-targets"
    mac    = "52:54:00:42:CB:E6"
  }

  # ens5 — IPS ingress from attacker
  network_interface {
    bridge = "ovs-attack"
    mac    = "52:54:00:2A:CB:A8"
  }

  # ens6 — passive IDS capture from attack network
  network_interface {
    bridge = "ovs-attack"
    mac    = "52:54:00:8C:8B:E0"
  }

  # ens7 — passive IDS capture from target network
  network_interface {
    bridge = "ovs-targets"
    mac    = "52:54:00:8C:8B:E1"
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
  running   = true   # cycle fix (B2): the IDS VM must run after apply

  xml {
    xslt = file("${path.module}/xslt/ovs-domain-interfaces.xslt")
  }
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
    runcmd:
      - until wget -q "http://10.0.2.1:8080/install_targets.sh" -O /tmp/install.sh; do echo "Waiting for mirror..."; sleep 10; done && bash /tmp/install.sh
  EOF
  # Static IP + dhcp-identifier:mac ensures consistent libvirt DHCP lease binding by MAC address
  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${each.value.ip}/24]
        gateway4: 10.0.2.1
        dhcp-identifier: mac
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
  memory = var.vm_ram_target

  # Memory strategy (cycle): created stopped when archivirt_start_wave2=false;
  # 04_configure.sh then starts them one at a time after manager + monitor.
  running = var.archivirt_start_wave2

  cloudinit = libvirt_cloudinit_disk.target[each.key].id

  network_interface {
    bridge = "ovs-targets"
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

  # Cycle fix (B3, 2026-10-08 apply failure): libvirt must attach this domain's
  # OVS-backed NICs with <virtualport type="openvswitch"/>, otherwise
  # "Unable to add bridge ovs-* port vnetX: Operation not supported".
  xml {
    xslt = file("${path.module}/xslt/ovs-domain-interfaces.xslt")
  }
}
