# =============================================================================
# ARCHIVIRT — Virtual Network Definitions (OVS-based)
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 3.0.0 — 2026-05-19
#
# Networks use Open vSwitch (OVS) bridges for native port mirroring support.
# OVS bridges must be created BEFORE terraform apply via:
#   ansible-playbook ansible/playbooks/setup_ovs.yml -i ansible/inventory/hosts.ini
#
# Bridge mapping:
#   ovs-targets  → 10.0.2.0/24  Target VMs     (port mirror source)
#   ovs-monitor  → 10.0.3.0/24  IDS/IPS Monitor
#   ovs-attack   → 10.0.4.0/24  Attacker VM    (port mirror source)
#   ovs-manager  → 10.0.5.0/24  Manager VM     (NAT, standard libvirt)
#
# Port mirror: ovs-targets + ovs-attack → monitor capture port (ens4)
# Configured at runtime by scripts/archivirt_mirrors.sh via ovs-vsctl
# =============================================================================

# --- Target Network (10.0.2.0/24) — OVS bridge ovs-targets ------------------
resource "libvirt_network" "targets" {
  name      = "archivirt-net-targets"
  mode      = "bridge"
  bridge    = "ovs-targets"
  autostart = true

  xml {
    xslt = file("${path.module}/xslt/ovs-network.xslt")
  }
}

# --- Monitor Network (10.0.3.0/24) — OVS bridge ovs-monitor -----------------
resource "libvirt_network" "monitor" {
  name      = "archivirt-net-monitor"
  mode      = "bridge"
  bridge    = "ovs-monitor"
  autostart = true

  xml {
    xslt = file("${path.module}/xslt/ovs-network.xslt")
  }
}

# --- Attack Network (10.0.4.0/24) — OVS bridge ovs-attack -------------------
resource "libvirt_network" "attack" {
  name      = "archivirt-net-attack"
  mode      = "bridge"
  bridge    = "ovs-attack"
  autostart = true

  xml {
    xslt = file("${path.module}/xslt/ovs-network.xslt")
  }
}


# --- Dedicated IDS Capture Network — OVS bridge ovs-capture ------------------
# Passive IDS capture only.
# No IP subnet, gateway, or routing is configured on this network.
resource "libvirt_network" "capture" {
  name      = "archivirt-net-capture"
  mode      = "bridge"
  bridge    = "ovs-capture"
  autostart = true

  xml {
    xslt = file("${path.module}/xslt/ovs-network.xslt")
  }
}


# --- Manager Network (10.0.5.0/24) — standard libvirt NAT -------------------
# Manager needs external access for package installs — kept as libvirt NAT
resource "libvirt_network" "manager" {
  name      = "archivirt-net-manager"
  mode      = "nat"
  bridge    = "virbr1"  # pinned: isolation allow-list, archivirt-ovs-ip.sh and v3.1 route use virbr1
  addresses = [var.net_manager_cidr]
  autostart = true
  dhcp {
    enabled = true
  }
  dns {
    enabled = true
  }
}
