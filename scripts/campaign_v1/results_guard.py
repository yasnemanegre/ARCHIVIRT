#!/usr/bin/env python3
"""ARCHIVIRT — results destination guard (PROPOSAL C1.3, B6 + F-09/F-12).

Refuses (exit 4) any destination that resolves into a protected zone. Fails closed.
Protected: <repo>/results, the whole <repo>, every --protect path, and any destination
that CONTAINS a protected zone. Comparison is done on canonical paths (symlinks
resolved) AND, defensively, on case-folded canonical paths (a case variant of a
protected path is refused even on case-sensitive file systems).
--create : create the destination (mode 0700) and RE-CHECK its canonical path after
           creation (narrows the check/write race; does not eliminate it).
STEP2 (built-in zones, always active, independent of the caller and of $HOME):
  * every ARCHIVIRT tree: a directory holding .git AND scripts/campaign_v1/campaign_v1.sh
    (original repository, clones, worktrees) - the destination and ALL its ancestors are tested;
  * <home>/ARCHIVIRT, <home>/archivirt-backup (cycle/, reports, backups), <home>/.archivirt,
    where <home> is the passwd home of the real user (a forged $HOME cannot lift them).
Usage: results_guard.py --repo R --dest D [--protect P]... [--create]
"""
import argparse, os, pwd, sys

def builtin_zones():
    home = pwd.getpwuid(os.getuid()).pw_dir
    return [os.path.join(home, x) for x in ("ARCHIVIRT", "archivirt-backup", ".archivirt")]

def archivirt_tree_of(path):
    """Nearest ancestor (or the path itself) that is an ARCHIVIRT tree, else None."""
    d = path
    while True:
        if os.path.exists(os.path.join(d, ".git")) and os.path.isfile(os.path.join(d, "scripts", "campaign_v1", "campaign_v1.sh")):
            return d
        up = os.path.dirname(d)
        if up == d:
            return None
        d = up

def canon(p):
    p = os.path.abspath(os.path.expanduser(p))
    head, tail = p, []
    while not os.path.exists(head):
        head, t = os.path.split(head)
        if not t:
            raise ValueError("cannot resolve any existing prefix of %r" % p)
        tail.insert(0, t)
    real = os.path.realpath(head)
    out = os.path.normpath(os.path.join(real, *tail)) if tail else real
    if ".." in out.split(os.sep) or not os.path.isabs(out):
        raise ValueError("non-canonical path %r" % out)
    return out

def inside(child, parent):
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)

def check(repo, dest, protect):
    t = archivirt_tree_of(dest)
    if t:
        return "destination %s is inside an ARCHIVIRT tree %s" % (dest, t)
    zones = [os.path.join(repo, "results"), repo] + [canon(x) for x in protect] + [canon(x) for x in builtin_zones()]
    for z in zones:
        for a, b in ((dest, z), (dest.casefold(), z.casefold())):
            if inside(a, b):
                return "destination %s is inside protected zone %s" % (dest, z)
            if inside(b, a):
                return "destination %s contains protected zone %s" % (dest, z)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True); ap.add_argument("--dest", required=True)
    ap.add_argument("--protect", action="append", default=[]); ap.add_argument("--create", action="store_true")
    a = ap.parse_args()
    try:
        if not a.dest.strip() or not a.repo.strip():
            raise ValueError("empty argument")
        repo = canon(a.repo)
        if not os.path.exists(os.path.join(repo, ".git")):
            raise ValueError("repo root %r has no .git" % repo)
        dest = canon(a.dest)
        why = check(repo, dest, a.protect)
        if why:
            print("REFUSED: " + why, file=sys.stderr); return 4
        if a.create:
            os.makedirs(dest, mode=0o700, exist_ok=True)
            after = os.path.realpath(dest)
            why = check(repo, after, a.protect) or (None if after == dest else "destination changed during creation: %s -> %s" % (dest, after))
            if why:
                print("REFUSED (post-create): " + why, file=sys.stderr); return 4
    except Exception as e:
        print("REFUSED: guard error: %s" % e, file=sys.stderr); return 4
    print(dest)
    return 0

if __name__ == "__main__":
    sys.exit(main())
