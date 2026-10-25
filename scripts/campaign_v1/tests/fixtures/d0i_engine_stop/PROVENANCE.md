# Fixtures D0I : `engine_stop.txt` originaux

Copies octet pour octet, vérifiées par `cmp` le 2026-10-25, des fichiers `engine_stop.txt` de la série
`/home/archivirt/archivirt-runs/P2-DIAG1/P2DIAG1D0I-ids-20261025T015442Z/ids/SCN-001/SCN-001-RUN-00{1,2,3}/`
(campagne D0I du 2026-10-25, lancée de 01:54:42Z à 01:55:55Z).

- Les trois contenus sont identiques (sha256 `75745f42…`, voir `SHA256SUMS`). Il s'agit de la sortie ad hoc d'Ansible (`-m script stop.sh`).
- L'évaluateur `99ba0711` les jugeait « engine stop status not recorded ». L'évaluateur r2 les accepte (STOPPED_CLEAN unique dans `stdout_lines`).
- Ces copies servent seulement de données de test. Les fichiers originaux et les `result.json` de la série ne sont pas modifiés ni réévalués.
