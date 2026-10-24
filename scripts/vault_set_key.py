#!/usr/bin/env python3
"""ARCHIVIRT — set one key of the ansible-vault file without exposing secrets.

The new value is read from STDIN (never from argv). The vault is decrypted
into a private RAM-backed directory (/dev/shm, mode 0700), modified,
re-encrypted from a file, verified (all other values unchanged, new value
present) and only then atomically replaces the original. An encrypted backup
of the previous vault is written first. Nothing secret is printed.

Usage:
  printf '%s' "$NEW_VALUE" | scripts/vault_set_key.py --key vault_influx_token \
      [--vault ansible/inventory/group_vars/all/vault.yml] \
      [--vault-password-file ~/.archivirt/vault_pass] [--backup-dir ~/.archivirt]
Prints only the backup path. Exit code != 0 on any failure (vault untouched).
"""
import argparse
import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

import yaml


def vault(cmd, pwfile, *args):
    return subprocess.run(["ansible-vault", cmd, "--vault-password-file", pwfile, *args],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL)


def load(path, pwfile):
    r = vault("view", pwfile, path)
    if r.returncode != 0:
        sys.exit("cannot decrypt vault")
    data = yaml.safe_load(r.stdout) or {}
    if not isinstance(data, dict):
        sys.exit("vault content is not a mapping")
    return data


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--vault", default=os.path.join(here, "..", "ansible", "inventory", "group_vars", "all", "vault.yml"))
    ap.add_argument("--vault-password-file", default=os.path.expanduser("~/.archivirt/vault_pass"))
    ap.add_argument("--backup-dir", default=os.path.expanduser("~/.archivirt"))
    ap.add_argument("--allow-new-key", action="store_true", help="allow adding a key that does not exist yet")
    a = ap.parse_args()

    new_value = sys.stdin.read().strip()
    if len(new_value) < 16 or any(c.isspace() for c in new_value):
        sys.exit("refusing: new value missing, too short or contains whitespace")

    old = load(a.vault, a.vault_password_file)
    if a.key not in old and not a.allow_new_key:
        sys.exit(f"refusing: key {a.key} not present (use --allow-new-key)")

    os.makedirs(a.backup_dir, mode=0o700, exist_ok=True)
    # Never overwrite an existing backup (two calls within the same second
    # used to collide): microsecond stamp + exclusive creation.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = os.path.join(a.backup_dir, f"vault.yml.bak-{stamp}")
    with open(a.vault, "rb") as src, open(backup, "xb") as dst:
        shutil.copyfileobj(src, dst)
    os.chmod(backup, 0o600)

    new = dict(old)
    new[a.key] = new_value
    h = lambda v: hashlib.sha256(str(v).encode()).hexdigest()

    tmpdir = tempfile.mkdtemp(prefix="arcv.", dir="/dev/shm")
    os.chmod(tmpdir, 0o700)
    plain = os.path.join(tmpdir, "plain.yml")
    enc = os.path.join(tmpdir, "new.yml")
    try:
        fd = os.open(plain, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("---\n")
            for k in sorted(new):
                fh.write(f"{k}: {new[k]}\n")
        if vault("encrypt", a.vault_password_file, "--output", enc, plain).returncode != 0:
            sys.exit("encryption failed (vault untouched)")
        check = load(enc, a.vault_password_file)
        ok = (set(check) == set(new)
              and all(h(check[k]) == h(old[k]) for k in old if k != a.key)
              and h(check[a.key]) == h(new_value))
        if not ok:
            sys.exit("verification failed (vault untouched)")
        target_tmp = a.vault + ".tmp"
        shutil.copyfile(enc, target_tmp)
        os.chmod(target_tmp, 0o600)
        os.replace(target_tmp, a.vault)
    finally:
        for f in (plain, enc):
            if os.path.exists(f):
                subprocess.run(["shred", "-u", f], check=False)
        os.rmdir(tmpdir)
    print(backup)


if __name__ == "__main__":
    main()
