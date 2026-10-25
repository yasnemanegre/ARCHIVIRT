# Avenant r2 à l'amendement option B (`--engine-stop`) : lecture de `engine_stop.txt`

**Statut : correctif d'implémentation, décidé par le propriétaire du projet le 2026-10-25.** La décision porte sur deux points : la décision 1 (corriger l'évaluateur, pas la campagne) le point 1 du 2026-10-25 (exactement une ligne STOPPED_CLEAN) et la validation stricte de `rc` (2026-10-25). La règle scientifique de `B1_option_B_amendment.md` §3 ne change pas. Cet avenant ne modifie ni le protocole 13/10/2, ni les critères `bf466291`, ni les paramètres `30bf2ef8`, ni l'évaluateur T-A ni les critères M-6.

## 1. Défaut (OBSERVED, série D0I `P2DIAG1D0I-ids-20261025T015442Z`)
- Les 3 essais sont INVALID avec le motif `NOT_EVALUABLE: engine_drops (engine stop status not recorded)`, alors que le moteur s'est arrêté proprement (STOPPED_CLEAN, 3/3).
- `campaign_v1.sh` enregistre dans `engine_stop.txt` la sortie ad hoc d'Ansible : `<hôte> | CHANGED => {…"stdout_lines": ["ARCHIVIRT_ENGINE=STOPPED_CLEAN"]}`.
- L'évaluateur `99ba0711` cherchait une ligne nue qui contient exactement ce texte. Cette ligne n'existe jamais dans ce format.
- Le contrôle de l'option B rendait donc **tout** essai IDS NOT_EVALUABLE.

## 2. Correctif (`scripts/campaign_v1/archivirt_stopwatch_eval.py`, `99ba0711` → `9b4fa006`)

`9b4fa006` est l'empreinte du contenu proposé. Elle ne devient la référence qu'après le commit et la fusion autorisés.

- **Bloc ad hoc Ansible** : il doit être unique et de statut `CHANGED` ou `SUCCESS`. Le JSON est décodé strictement, `rc` doit être un **entier JSON égal à 0**, et seules les lignes de `stdout_lines` sont lues.
- **Validation stricte de `rc`** (décision du propriétaire du 2026-10-25) : `false`, `0.0`, `null`, une chaîne, une valeur absente ou non nulle sont refusés. Elle remplace la version intermédiaire `435f9496`, où `rc` était comparé par valeur, si bien que `false` et `0.0` y passaient pour 0.
- **Fichier sans en-tête Ansible** : il est lu comme la sortie brute de `stop.sh`.
- **Règle §3 appliquée littéralement** : exactement une ligne `ARCHIVIRT_ENGINE=STOPPED_CLEAN` et aucune ligne `STOPPED_FORCED`. Un doublon est refusé (`99ba0711` acceptait les doublons).
- **Cas qui rendent l'essai NOT_EVALUABLE**, avec un motif explicite :
  - statut contradictoire ;
  - `FAILED!` ou `UNREACHABLE!` ;
  - JSON invalide ;
  - plusieurs blocs d'hôtes ;
  - texte hors du bloc ;
  - `rc` autre que l'entier 0 ;
  - `stdout_lines` absent.
- Aucune recherche de sous-chaîne : un jeton présent seulement dans `stderr`, ou dans une ligne plus longue, ne compte pas.
- Seules `engine_stop_problem` et la nouvelle fonction `engine_stop_lines` changent. Sans `--engine-stop`, l'évaluateur se comporte comme avant.

## 3. Vérification
- `scripts/campaign_v1/tests/test_engine_stop.py` : 38/38 PASS avec `9b4fa006`. Le banc comprend 26 cas synthétiques, dont 5 sur `rc` (false, 0.0, null, absent, "0"), les 3 fichiers D0I originaux (fixtures vérifiées par sha256), le contrôle de leurs sommes et 8 contre-épreuves sur des versions affaiblies de l'évaluateur. Le même banc donne 33/38 avec `435f9496` et 8/38 avec `99ba0711`.
- **Non-régression sans `--engine-stop`** : la sortie et le code de retour sont identiques entre `99ba0711` et `9b4fa006` pour les 66 `stopwatch.jsonl` de `~/archivirt-runs` (2026-10-25).
- **Rejeu informatif des 3 essais D0I**, en lecture seule et sans `--result-json` :
  - RUN-001 : INVALID, `engine_drops` CONFIRMED (451/6162 pertes noyau) ;
  - RUN-002 et RUN-003 : VALID.

## 4. Non-rétroactivité
- Les `result.json` de la série D0I et le dossier de lancement v1.4 restent tels qu'enregistrés. Les empreintes historiques (`99ba0711` dans `B1_option_B_amendment.md` et `M6_TA_criteria.SIGNED.md`) ne sont pas modifiées.
- `9b4fa006` ne s'applique qu'aux séries lancées depuis un dossier qui l'épingle explicitement (v1.5 et suivants), après autorisation écrite.
