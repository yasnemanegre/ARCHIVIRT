# ============================================================
# ARCHIVIRT - Lab Configuration
# Author: Yasnemanegre SAWADOGO (PhD Student, SPbGUPTD)
# ============================================================

lab_name            = "archivirt-lab"
host_bridge         = "enp0s3"
ubuntu_image_path   = "/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img"

net_targets_cidr    = "10.0.2.0/24"
net_monitor_cidr    = "10.0.3.0/24"
net_attack_cidr     = "10.0.4.0/24"
net_manager_cidr    = "10.0.5.0/24"

ip_manager          = "10.0.5.10"
ip_attacker         = "10.0.4.10"
ip_monitor          = "10.0.3.10"
ip_target_01        = "10.0.2.11"
ip_target_02        = "10.0.2.12"
ip_target_03        = "10.0.2.13"

vm_vcpu             = 2
vm_memory_mb        = 4096
vm_disk_gb          = 20
ids_engine          = "suricata"
ssh_public_key_path = "~/.ssh/archivirt_key.pub"
