# ============================================================
# ARCHIVIRT — Lab Configuration
# Never commit this file to git (already covered by .gitignore).
# ============================================================

# To regenerate after a password change:
#   python3 -c "import crypt; print(crypt.crypt('NEW_PASSWORD', crypt.mksalt(crypt.METHOD_SHA512)))"
# ubuntu_password_hash removed 2026-10-17: the previous value was public (treat as compromised).
# Not used by terraform/ (no such variable; accounts use lock_passwd: true and SSH keys only).