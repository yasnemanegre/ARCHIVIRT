#!/bin/bash
# =============================================================================
# ARCHIVIRT - Prepare / extend the local offline mirror (PREPARATION PHASE ONLY)
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 5.0.0 — 2026-10-17
#
# Run on the HOST while Internet is still available. Afterwards the lab runs
# fully offline: VMs use only http://10.0.X.1:8080/ (nginx on the host).
#
# Changes vs 4.x (offline remediation 2026-10-17):
#   - NON-DESTRUCTIVE: existing .deb files are never deleted; only packages
#     whose name is not yet in the mirror are added (no silent upgrades).
#   - Grafana is fetched at a pinned version and its published SHA-256 is
#     verified (it is not in the Ubuntu archive).
#   - Python wheelhouse published under /wheels/ (pip --no-index).
#   - Fails loudly (set -euo pipefail, no masked pipelines); writes a
#     SHA-256 manifest of the whole mirror.
#
# Usage: sudo bash scripts/update_mirror.sh            (preparation: adds missing packages)
#        bash scripts/update_mirror.sh --verify          (STEP3.2: READ-ONLY check, writes nothing)
# =============================================================================
set -euo pipefail
export LC_ALL=C

MIRROR_DIR="${ARCHIVIRT_MIRROR_DIR:-/var/spool/apt-mirror/packages}"

# --- STEP3.2 (R-6): read-only verification mode -------------------------------
# Fails (exit 3) on: missing index, several versions of one package (same arch), index entry without
# file, .deb not indexed, size/sha256 mismatch, forbidden legacy package selectable (snort = Snort 2.9,
# snort-common*, libdaq0), MIRROR_SHA256SUMS present but not matching. Never modifies the mirror.
if [ "${1:-}" = "--verify" ]; then
  python3 -B -I - "$MIRROR_DIR" <<'PYV'
import collections, hashlib, os, subprocess, sys
m = sys.argv[1]; bad = []
FORBIDDEN = {"snort", "snort-common", "snort-common-libraries", "libdaq0"}
def entries(p):
    out, cur = [], {}
    for line in open(p, encoding="utf-8", errors="replace"):
        if not line.strip():
            if cur: out.append(cur); cur = {}
            continue
        if line[0] in " \t": continue
        k, _, v = line.partition(":"); cur[k.strip()] = v.strip()
    if cur: out.append(cur)
    return out
idx_path = os.path.join(m, "Packages")
if not os.path.isfile(idx_path): print("VERIFY_FAIL: no Packages index in %s" % m); sys.exit(3)
idx = entries(idx_path); by = collections.defaultdict(list)
for e in idx: by[(e.get("Package"), e.get("Architecture"))].append(e.get("Version"))
bad += ["several versions of %s [%s]: %s" % (k[0], k[1], v) for k, v in by.items() if len(v) > 1]
bad += ["forbidden legacy package selectable: %s %s" % (e["Package"], e.get("Version")) for e in idx if e.get("Package") in FORBIDDEN]
debs = {f for f in os.listdir(m) if f.endswith(".deb")}; named = set()
for e in idx:
    f = os.path.basename(e.get("Filename", "")); named.add(f); p = os.path.join(m, f)
    if f not in debs: bad.append("index entry without file: %s" % f); continue
    if e.get("Size") and int(e["Size"]) != os.path.getsize(p): bad.append("size mismatch: %s" % f)
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    if e.get("SHA256") != h: bad.append("sha256 mismatch: %s" % f)
bad += [".deb not indexed: %s" % f for f in sorted(debs - named)]
ms = os.path.join(m, "MIRROR_SHA256SUMS")
if os.path.isfile(ms):
    r = subprocess.run(["sha256sum", "-c", "--quiet", "MIRROR_SHA256SUMS"], cwd=m, capture_output=True, text=True)
    if r.returncode: bad.append("MIRROR_SHA256SUMS mismatch: %s" % r.stdout.strip()[:300])
else:
    print("VERIFY_WARN: MIRROR_SHA256SUMS absent (whole-mirror manifest not available; index checks only)")
for b in bad: print("VERIFY_FAIL: " + b)
print("VERIFY_RESULT: %d entries, %d .deb, %d failure(s)" % (len(idx), len(debs), len(bad)))
sys.exit(3 if bad else 0)
PYV
  exit $?
fi
RULES_DIR="$MIRROR_DIR/rules"
OFFLINE_DIR="${ARCHIVIRT_OFFLINE_DIR:-/home/archivirt/archivirt-offline}"
STAGING="$(mktemp -d /var/tmp/archivirt-mirror-staging.XXXXXX)"
GRAFANA_VERSION="13.2.3"
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$MIRROR_DIR" "$RULES_DIR"
chown root:archivirt "$MIRROR_DIR" "$RULES_DIR"
chmod 775 "$MIRROR_DIR" "$RULES_DIR"

# --- Top-level packages required by ARCHIVIRT VMs ----------------------------
TOP_PACKAGES="nmap nmap-common hydra sqlmap hping3 tcpreplay python3-scapy \
  suricata suricata-update \
  libdumbnet1 libhwloc15 libhyperscan5 \
  apache2 libapache2-mod-php8.1 php8.1 php8.1-mysql \
  mariadb-server samba vsftpd openssh-server \
  influxdb2 influxdb2-cli telegraf \
  curl wget git python3 python3-pip net-tools masscan ncrack \
  bison build-essential cmake flex libdumbnet-dev libhwloc-dev libnghttp2-dev \
  libpcap-dev libpcre3-dev libssl-dev pkg-config zlib1g-dev libluajit-5.1-dev \
  liblzma-dev libunwind-dev uuid-dev libhyperscan-dev"
# snort3 is not packaged for Ubuntu 22.04: sources are kept in
# $OFFLINE_DIR/src (snort3 3.1.74.0 + libdaq 3.0.13, see SHA256SUMS there).
# STEP3.2 (C-3): libdaq2 (Snort 2 DAQ) removed from the list: no reverse dependency in the mirror,
# unused by Suricata and Snort 3. The existing .deb is NOT deleted by this script (non-destructive);
# its quarantine is a separate, authorised step (STEP3_2_QUARANTINE_PLAN.md).
# Never add "snort" (= Snort 2.9 on jammy) to this list.

echo "[ARCHIVIRT] Resolving dependency closure..."
apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
  --no-breaks --no-replaces --no-enhances $TOP_PACKAGES \
  | grep -E '^[a-z0-9]' | grep -v systemd-standalone-tmpfiles | sort -u > "$STAGING/closure"

grep '^Package:' "$MIRROR_DIR/Packages" 2>/dev/null | awk '{print $2}' | sort -u > "$STAGING/in_mirror" || true
comm -23 "$STAGING/closure" "$STAGING/in_mirror" > "$STAGING/todo"
echo "[ARCHIVIRT] closure=$(wc -l < "$STAGING/closure") already_in_mirror=$(wc -l < "$STAGING/in_mirror") to_fetch=$(wc -l < "$STAGING/todo")"

if [ -s "$STAGING/todo" ]; then
  (cd "$STAGING" && while read -r p; do
     cand=$(apt-cache policy "$p" | awk '/Candidate:/ {print $2}')
     [ -n "$cand" ] && [ "$cand" != "(none)" ] && echo "$p"
   done < todo | xargs -r apt-get download)
  find "$STAGING" -maxdepth 1 -name '*.deb' -exec cp -n {} "$MIRROR_DIR/" \;
fi

# --- Grafana (pinned, checksum verified) --------------------------------------
GDEB="grafana_${GRAFANA_VERSION}_amd64.deb"
if [ ! -f "$MIRROR_DIR/$GDEB" ]; then
  curl -fsSL -o "$STAGING/$GDEB" "https://dl.grafana.com/oss/release/$GDEB"
  curl -fsSL -o "$STAGING/$GDEB.sha256" "https://dl.grafana.com/oss/release/$GDEB.sha256"
  echo "$(cut -c1-64 "$STAGING/$GDEB.sha256")  $STAGING/$GDEB" | sha256sum -c -
  cp -n "$STAGING/$GDEB" "$MIRROR_DIR/"
fi
echo "[ARCHIVIRT] grafana $GRAFANA_VERSION present in mirror"

# --- Python wheelhouse ---------------------------------------------------------
if [ -d "$OFFLINE_DIR/wheels" ]; then
  mkdir -p "$MIRROR_DIR/wheels"
  cp -n "$OFFLINE_DIR"/wheels/*.whl "$MIRROR_DIR/wheels/"
  (cd "$MIRROR_DIR/wheels" && sha256sum ./*.whl > SHA256SUMS)
  echo "[ARCHIVIRT] wheelhouse: $(ls "$MIRROR_DIR"/wheels/*.whl | wc -l) wheels"
else
  echo "[ARCHIVIRT] OFFLINE_ARTIFACT_MISSING=wheelhouse ($OFFLINE_DIR/wheels)"
  exit 1
fi

# --- ET Open rules (kept as-is if download fails; never emptied) -------------
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update --suricata-version 6.0.4 --output "$STAGING/rules" --no-reload --no-test
  if [ "$(grep -c '^alert' "$STAGING/rules/suricata.rules")" -gt 1000 ]; then
    cp "$STAGING/rules/suricata.rules" "$RULES_DIR/suricata.rules"
  fi
fi
ET_SNORT3_URL="https://rules.emergingthreats.net/open/snort-3.0/emerging.rules.tar.gz"
# STEP3.2 (R-6): the published MD5 is checked and a failed download is REPORTED (the previous ruleset
# is kept, never emptied) instead of being silently ignored.
if curl -fsSL --max-time 120 "$ET_SNORT3_URL" -o "$STAGING/et-snort3.tar.gz" \
   && curl -fsSL --max-time 60 "$ET_SNORT3_URL.md5" -o "$STAGING/et-snort3.tar.gz.md5" \
   && [ "$(md5sum < "$STAGING/et-snort3.tar.gz" | cut -c1-32)" = "$(tr -dc '0-9a-f' < "$STAGING/et-snort3.tar.gz.md5" | cut -c1-32)" ]; then
  mkdir -p "$STAGING/snort3" && tar -xzf "$STAGING/et-snort3.tar.gz" -C "$STAGING/snort3"
  cat "$STAGING"/snort3/rules/*.rules > "$RULES_DIR/snort.rules"
else
  echo "[ARCHIVIRT] WARN: ET Snort 3 rules NOT refreshed (download or published MD5 check failed); previous snort.rules kept" >&2
fi
# Public ET Open rules: must be readable by nginx (www-data), otherwise the
# VMs get HTTP 403 and the IDS bootstrap aborts.
chown -R root:archivirt "$RULES_DIR"
chmod 0755 "$RULES_DIR"
chmod 0644 "$RULES_DIR"/*.rules
(cd "$RULES_DIR" && sha256sum ./*.rules > RULES_SHA256SUMS && chmod 0644 RULES_SHA256SUMS)

# --- Rebuild Packages index ----------------------------------------------------
(cd "$MIRROR_DIR" && dpkg-scanpackages . /dev/null > Packages.new 2>/dev/null)
mv "$MIRROR_DIR/Packages.new" "$MIRROR_DIR/Packages"
gzip -k -f "$MIRROR_DIR/Packages"

# --- Mirror manifest ------------------------------------------------------------
(cd "$MIRROR_DIR" && find . -type f ! -name MIRROR_SHA256SUMS -printf '%P\n' | sort | xargs -d '\n' sha256sum > MIRROR_SHA256SUMS)

# STEP3.2 (R-6): the mirror is only declared ready if the read-only verification passes.
bash "$0" --verify
echo "[ARCHIVIRT] Mirror ready: $(grep -c '^Package:' "$MIRROR_DIR/Packages") packages, $(du -sh "$MIRROR_DIR" | cut -f1)"
echo "[ARCHIVIRT] Served via: http://10.0.X.1:8080/"
