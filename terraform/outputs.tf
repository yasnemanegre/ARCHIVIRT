# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Terraform Outputs
# Used by generate_inventory.py to build Ansible hosts.ini
# ─────────────────────────────────────────────────────────────

output "manager_ip" {
  description = "Manager VM IP address"
  value       = var.ip_manager
}

output "attacker_ip" {
  description = "Attacker VM IP address"
  value       = var.ip_attacker
}

output "monitor_ip" {
  description = "Monitor (IDS/IPS) VM IP address"
  value       = var.ip_monitor
}

output "target_ips" {
  description = "Map of target VM IPs"
  value = {
    target_01 = var.ip_target_01
    target_02 = var.ip_target_02
    target_03 = var.ip_target_03
  }
}

output "ids_engine" {
  description = "Deployed IDS engine"
  value       = var.ids_engine
}

output "lab_summary" {
  description = "Full lab network summary"
  value       = <<-EOF
    ════════════════════════════════════════════
    ARCHIVIRT Lab Summary
    ════════════════════════════════════════════
    Host Server      : archivirt@192.168.4.10

    Manager VM       : ${var.ip_manager}    (10.0.5.0/24)
    Attacker VM      : ${var.ip_attacker}   (10.0.4.0/24)
    Monitor VM (IDS) : ${var.ip_monitor}   (10.0.3.0/24)
    Target VM 01     : ${var.ip_target_01}  (10.0.2.0/24) [web]
    Target VM 02     : ${var.ip_target_02}  (10.0.2.0/24) [ssh/ftp]
    Target VM 03     : ${var.ip_target_03}  (10.0.2.0/24) [smb/db]

    IDS Engine       : ${var.ids_engine}
    ════════════════════════════════════════════
  EOF
}
