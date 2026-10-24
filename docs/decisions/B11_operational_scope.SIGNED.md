# Décision B11 : périmètre opérationnel d'ARCHIVIRT (SIGNÉE)
Date (UTC) : 2026-10-24T23:52:38Z. Déclaration : « je suis daccord avec toutes tes recommandations » — réponse du propriétaire du projet (yasnemanegre), 2026-10-24, approuvant : D-B1 option B limitée à Suricata IDS (extension IPS/Snort 3 à l'intégration de ces modes), les décisions M-6 du DECISION_M6.md §1, et le périmètre B11 complet par étapes.

**Périmètre cible : les deux moteurs (Suricata, Snort 3) dans les deux modes (IDS, IPS en ligne)**, conformément à l'objet d'ARCHIVIRT (« Virtual IDS/IPS Testing Labs »), intégrés par étapes. Chaque étape a son code, ses tests et une série d'acceptation autorisée sous le protocole inchangé 13 planifiés / ≥ 10 valides / ≤ 2 invalides.

| Étape | Combinaison | État au 2026-10-24 | Conditions de sortie |
|---|---|---|---|
| 1 | Suricata IDS | Campagne exécutable ; SCN-001 jamais accepté (B1) ; M-6 signé partiellement | V-1, D-TA-3, signature finale de M-6, série SCN-001 ACCEPTED |
| 2 | Suricata IPS en ligne | Fait pour l'Article 2 (250 fichiers bruts gelés) ; **refusé** par la campagne actuelle (`campaign_v1.sh:60`, IPS_MODE_REFUSED : pas de remise en état NFQUEUE/miroir) | Remise en état après IPS, réactivation du mode, amendement D-B1 pour l'IPS, série d'acceptation |
| 3 | Snort 3 IDS puis IPS | **Refusé** (`campaign_v1.sh:58`, collecte non intégrée) ; règles traduites testées en bac à sable 84/84 ; 2 règles de contrôle par mode | Collecte, validation et mesures, règles, qualification Q1/Q2, amendement D-B1, séries d'acceptation |

Inchangés : données gelées de l'Article 2 (545/545), critères `bf466291`, paramètres `30bf2ef8`.
