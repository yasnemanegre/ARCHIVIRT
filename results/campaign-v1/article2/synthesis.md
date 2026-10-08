# ARCHIVIRT — Article 2 : synthèse scientifique expérimentale

> Moteur principal : Suricata 6.0.4. Généré automatiquement par `scripts/campaign_v1/synthesize.py` à partir de `aggregated_metrics.json`.
> Runs analysés (schéma Article-2, tous statuts) : **115**. Modes : ids, baseline, ips.

## 1. Objectifs
Évaluer quantitativement, de façon reproductible, l'efficacité de détection (IDS) et de blocage (IPS) dans le laboratoire virtuel ARCHIVIRT, selon un modèle d'évaluation fondé sur une vérité-terrain scénario→signature.

## 2. Environnement
- KVM/libvirt + OpenVSwitch ; VMs : monitor-ids, attacker, target-01..03.
- Moteur : Suricata 6.0.4 (IDS af-packet ens6/ens7 ; IPS inline NFQUEUE).
- Jeu de signatures ARCHIVIRT Article-2 (4 signatures discriminantes à seuil).
- Dépendance externe installée en phase dev : matplotlib (pour les figures).

## 3. Méthodologie
- Chaque run : moteur démarré, scénario joué sur l'attaquant (timestamps machine), EVE collecté après flush gracieux, classification par SID attendu.
- Vérité-terrain : SCN-001..004 = `attack`, SCN-005 = `benign` (contrôle négatif).
- Unité de classification = le run. TP/FN depuis les scénarios d'attaque, TN/FP depuis le bénin. Aucune métrique fabriquée : dénominateur indéfini → `NOT_AVAILABLE`.
- Latence de détection = 1er timestamp d'alerte attendue − début d'attaque (timestamps réels ; exclut synchronisation/SSH/collecte).

## 4. Scénarios
| Scénario | Vérité-terrain | SID attendu |
|---|---|---|
| SCN-001 | attack | 2000001 |
| SCN-002 | attack | 2000002 |
| SCN-003 | attack | 2000003 |
| SCN-004 | attack | 2000004 |
| SCN-005 | benign | None |

## 5. Résultats IDS
- Matrice de confusion (runs VALID) : TP=40 FP=0 FN=0 TN=10.
- Accuracy=1.0 · Precision=1.0 · Recall=1.0 · F1=1.0 · FPR=0.0 · FNR=0.0.
  - SCN-001: valid=10/10, det_rate=1.0, lat_ms(mean=105.7,sd=4.855,n=10,ci95=[102.227, 109.173])
  - SCN-002: valid=10/10, det_rate=1.0, lat_ms(mean=175.5,sd=19.386,n=10,ci95=[161.632, 189.368])
  - SCN-003: valid=10/10, det_rate=1.0, lat_ms(mean=310.6,sd=10.895,n=10,ci95=[302.806, 318.394])
  - SCN-004: valid=10/10, det_rate=1.0, lat_ms(mean=114.7,sd=10.307,n=10,ci95=[107.327, 122.073])
  - SCN-005: valid=10/10, det_rate=NOT_APPLICABLE, lat_ms(mean=None,sd=None,n=0,ci95=None)

## 6. Résultats IPS
- Matrice de confusion (runs VALID) : TP=40 FP=0 FN=0 TN=10.
- Accuracy=1.0 · Precision=1.0 · Recall=1.0 · F1=1.0 · FPR=0.0 · FNR=0.0.
  - SCN-001: valid=10/10, det_rate=1.0, lat_ms(mean=105.2,sd=4.849,n=10,ci95=[101.731, 108.669]), blocked=10/10 (rate=1.0)
  - SCN-002: valid=10/10, det_rate=1.0, lat_ms(mean=217.4,sd=25.163,n=10,ci95=[199.4, 235.4]), blocked=10/10 (rate=1.0)
  - SCN-003: valid=10/10, det_rate=1.0, lat_ms(mean=309.2,sd=11.351,n=10,ci95=[301.08, 317.32]), blocked=10/10 (rate=1.0)
  - SCN-004: valid=10/10, det_rate=1.0, lat_ms(mean=164.3,sd=16.76,n=10,ci95=[152.311, 176.289]), blocked=10/10 (rate=1.0)
  - SCN-005: valid=10/10, det_rate=NOT_APPLICABLE, lat_ms(mean=None,sd=None,n=0,ci95=None), blocked=0/10 (rate=0.0)

## 7. Métriques
TP/TN/FP/FN, Accuracy/Precision/Recall/F1/FPR/FNR, taux de détection, latence de détection, taux de blocage, latence de blocage, CPU/RAM, débit/volume capturé, pertes. Voir `tables/`.

## 8. Statistiques
Par métrique quantitative : n, moyenne, médiane, écart-type, min, max, IC95 (t de Student, scipy) et CV lorsque pertinent. Voir Tables 5 et 7.

## 9. Comparaison
- IDS : CPU moteur moyen=13.17%, débit capturé moyen=0.3272 Mbps.
- IPS : CPU moteur moyen=14.45%, débit capturé moyen=0.0 Mbps.
- Baseline (sans moteur) : pas de processus Suricata → CPU/RAM moteur `NOT_APPLICABLE` ; sert de référence de volume/débit de trafic.

## 10. Limites
- Les métriques reflètent le **jeu de signatures ARCHIVIRT Article-2** (4 signatures à seuil), pas la capacité de Suricata contre des attaques inconnues.
- SCN-002 : target-02 impose l'auth par clé publique ; le signal mesuré est le **motif de connexions** SSH répétées, non des essais de mot de passe.
- rockyou présent en **stub** (liste courte) sur l'attaquant.
- CPU/RAM baseline non comparables au moteur (aucun processus en baseline).
- Laboratoire actuellement non air-gappé (Internet présent) ; offline = phase 2.

## 11. Conclusions scientifiques
Dans les conditions expérimentales considérées, la méthodologie ARCHIVIRT produit une évaluation quantitative **reproductible** de l'efficacité IDS/IPS (détection, blocage, latence, impact système), avec traçabilité (provenance + données brutes par run).

## 12. Résultats réellement démontrés
- Qualification IDS reproductible (RUNS=10) des 5 scénarios, matrice de confusion et métriques dérivées calculées sur données réelles.
- Contrôle négatif : le trafic bénin ne déclenche aucune signature testée.
- Latence de détection mesurée depuis des timestamps réels.
- Blocage IPS inline **réel** (événements `action:blocked`/`drop` observés).

## 13. Résultats NON démontrés
- Efficacité contre des attaques hors du jeu de signatures défini.
- Snort 3 (absent/non installable offline) — aucune comparaison inter-moteurs.
- Air-gap/offline complet (reporté en phase 2).

## 14. Travaux futurs
- Offline Artifact Set + destroy/rebuild sans Internet (phase 2).
- Intégration Snort 3 pour comparaison inter-moteurs.
- Jeux de signatures élargis (ET open) et analyse ML/UEBA sur données brutes conservées.
