# Décision M-6 : critères T-A (D0I). Dossier de signature

**Statut : SIGNÉ (partiel) le 2026-10-24T23:52:38Z par le propriétaire du projet.** Copie signée de `DECISION_M6.md` (sha `297da5ec3f081bc5…`), ce dernier n'étant pas modifié. Rien n'est approuvé tant que la section « Signature » n'est pas remplie dans une **nouvelle** copie. La version PROPOSED (`e736f403…`) n'est pas modifiée.
Sources : `CONSOLIDATION-DECISIONS-20261023T052256Z/TA_CRITERIA_MATRIX.md` et `DECISIONS_REQUIRED.md` (recommandations reprises telles quelles), `B1_METHODOLOGY_AMENDMENT.md`, `CLOTURE-OPERATIONNELLE…/02_MATRICE_M6.md`.

## 1. Décisions proposées (recommandations consolidées, aucune inventée)
| Code | Décision proposée | Justification | Effet sur le code |
|---|---|---|---|
| M-1 | Adopter 1r1 + 2r1 | Implémentation plus stricte du critère approuvé `bf466291` | Déjà intégré (`335a1fa`, `main` `e2e4341`) |
| D-B2-1 | Sonde de géométrie r2 | Corrige le défaut G9 ; aucun verdict d'essai modifié | Déjà intégré |
| D-B2-3 | `INCONSISTENT` = désaccord de disposition ou de trames entre sockets, tailles de bloc ignorées → NOT_EVALUABLE | Définition technique de la sonde r2 | Déjà intégré |
| D-B2-2 | Socket requise absente → **NOT_EVALUABLE**, sans règle de recoupement | La sonde peut manquer une socket ; un recoupement serait une règle nouvelle, non testée | Évaluateur T-A **r1** (`e8526ebc…`) : règle explicite ; aucun verdict changé (l'évaluateur d'origine aboutissait déjà à NOT_EVALUABLE par incomplétude) |
| D-TA-1 | Résidu (c) évalué sur les **essais avec pertes** ; résidus des autres essais rapportés à part | ROOT_CAUSE §5 | Déjà le comportement |
| D-TA-2 | Garde RSS ≤ 30 Mio **descriptive** | Aucune statistique de référence définie | Statut de la garde : DESCRIPTIVE |
| D-TA-4 | Message de zéro-copie présent → **NOT_MET** (pas une réfutation sourcée) | Invalide l'argument de la réserve de paquets, pas le mécanisme | Déjà le comportement (test A06) |
| TA-g3 | Comparaison CPU **descriptive** | Aucun seuil défini | Statut : DESCRIPTIVE |
| D-B1 (+bis) | **Option B**, **Suricata IDS seul pour l'instant** (extension à Suricata IPS et Snort 3 par amendement séparé lors de leur intégration, étapes 2-3 de B11), **non rétroactive** : `engine_stop.txt` ≠ exactement `STOPPED_CLEAN` → `engine_drops` NOT_EVALUABLE → essai INVALID | Fail-safe, cohérent avec la règle existante « NOT_EVALUABLE → INVALID » ; plus strict, jamais favorable. Aucune série passée n'est requalifiée | **Code de l'option B non intégré** (évaluateur `99ba0711`, `p2_run_monitor.py` `787e1535`, campagne `8a8c746b`). Effective à partir de la première série exécutée avec ce code intégré et enregistré dans la provenance (intégration : PR séparée, à autoriser) |
| D-TA-3 | **Reportée** : source des pertes par RX (journal 3a, eve `threads`, accord) | Formats réels jamais observés : décider après V-1 | Comportement actuel conservé (accord exigé si deux sources), à **confirmer** après V-1 |

## 2. Statut des critères après signature
- APPROUVÉS : TA-a1 (2 sockets), a2 (TPACKET_V2, 2060 trames), a3, a4, a5, c1, d1, d2, d3, d4, g1 ; g2 et g3 approuvés comme descriptifs.
- REPORTÉS : TA-b1 et b2 (dépendent de D-TA-3).
- PROVISOIRE : TA-s1, la règle de série, tant que b1 et b2 sont reportés.
- Fichier candidat : `ta_criteria.D0I.APPROVED_PARTIAL.CANDIDATE.json`, statut `APPROVED_PARTIAL`. L'évaluateur traite tout statut ≠ `APPROVED` comme **provisoire** : vérifié sur la série nominale, il rend DEMONSTRATED, provisoire, code de sortie 5. **Aucun verdict T-A ne peut être présenté comme définitif avant la signature finale qui suivra V-1.**

## 3. Ce qui ne change pas
Critères d'arrêt `bf466291`, paramètres `30bf2ef8`, protocole 13 planifiés / ≥ 10 valides / ≤ 2 invalides, données gelées de l'Article 2 (545/545), verdicts des séries passées.

## 4. Preuves
- `test_outputs/baseline_original.txt` : suite d'origine **62/62** sur l'évaluateur d'origine, rejouée sur le banc persisté.
- `test_outputs/r1_on_r1.txt` : suite r1 **64/64** sur l'évaluateur r1.
- `test_outputs/r1_on_original.txt` : suite r1 sur l'évaluateur d'origine, **63/64** ; seul A10 échoue, attendu, ce qui prouve que le test distingue les deux versions.
- `test_outputs/candidate_on_N01.txt` : le candidat reste provisoire (code 5).
- `test_outputs/attempts/` : 2 tentatives de tests mal conçues (fixture : nombre de lignes « ring params » incohérent), corrigées et conservées.

## 5. Suites (chacune à autoriser)
1. Intégrer l'option B (D-B1) et l'évaluateur T-A r1 dans le dépôt, avec leurs tests : PR séparée.
2. Décision ARM (« D0I ») et outils du bras (B6), puis déploiement D3/D4, puis **V-1**.
3. D-TA-3 après V-1, puis **signature finale** : nouvelle copie `ta_criteria.D0I.APPROVED.json`.

## Signature
- Décisions du §1 approuvées telles que proposées, avec D-B1-bis précisé ci-dessus : **oui**
- Déclaration : « je suis daccord avec toutes tes recommandations » — réponse du propriétaire du projet (yasnemanegre), 2026-10-24, approuvant : D-B1 option B limitée à Suricata IDS (extension IPS/Snort 3 à l'intégration de ces modes), les décisions M-6 du DECISION_M6.md §1, et le périmètre B11 complet par étapes.
- Date (UTC) : 2026-10-24T23:52:38Z
- Fichier de critères signé : `ta_criteria.D0I.APPROVED_PARTIAL.json`
