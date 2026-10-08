# ARCHIVIRT — Article 2 : audit scientifique

## Combien de runs / VALID / INVALID / PREREQUISITE_MISSING ?
- Total runs (schéma Article-2) : **115**
- VALID : **100** · INVALID : **15** · PREREQUISITE_MISSING : **0**
  - ids: {'VALID': 50} (n=50)
  - baseline: {'INVALID': 15} (n=15)
  - ips: {'VALID': 50} (n=50)
- INVALID (baseline, 15) = sans moteur donc sans EVE **par conception** ; exclus des statistiques de détection, utilisés uniquement pour la performance.

## Combien TP / TN / FP / FN ?
- IDS (runs VALID) : TP=40 TN=10 FP=0 FN=0
- IPS (runs VALID) : TP=40 TN=10 FP=0 FN=0
- Provenance : unité = run. Attaque (SCN-001..004) détectée via son SID attendu → TP, sinon FN. Bénin (SCN-005) → TN si aucune signature d'attaque, FP sinon. Baseline exclue de la matrice.

## Métriques disponibles
- IDS: Accuracy=1.0 Precision=1.0 Recall=1.0 F1=1.0 FPR=0.0 FNR=0.0
- IPS: Accuracy=1.0 Precision=1.0 Recall=1.0 F1=1.0 FPR=0.0 FNR=0.0
- Latence de détection (tous scénarios d'attaque), latence de blocage (IPS), taux de détection, taux de blocage, faux-blocage, CPU, RSS, paquets/octets/débit capturés (IDS/baseline), pertes.

## Métriques NON disponibles
- Débit/paquets **en IPS** sur les interfaces miroir : `NOT_APPLICABLE` (le trafic inline transite par ens4/ens5, non mirrorés vers ens6/ens7).
- CPU/RAM moteur en **baseline** : `NOT_APPLICABLE` (aucun processus moteur).
- Accuracy/Precision/... en baseline : `NOT_AVAILABLE` (pas de classification moteur).

## Les résultats IPS sont-ils réellement prouvés ?
- **Oui** : événements réels `action:blocked`/`drop` observés, blocage par scénario (runs bloqués) = {'SCN-001': 10, 'SCN-002': 10, 'SCN-003': 10, 'SCN-004': 10, 'SCN-005': 0}.
- Contrôle négatif SCN-005 : 0 run bloqué → faux-blocage = 0.
- La preuve repose sur les événements EVE réels, **pas** sur la présence des règles drop.

## Latence moyenne par scénario (ms)
- IDS:
  - SCN-001: mean=105.7 median=105.0 sd=4.855 min=100 max=117 n=10 ci95=[102.227, 109.173]
  - SCN-002: mean=175.5 median=169.5 sd=19.386 min=157 max=213 n=10 ci95=[161.632, 189.368]
  - SCN-003: mean=310.6 median=313.0 sd=10.895 min=293 max=325 n=10 ci95=[302.806, 318.394]
  - SCN-004: mean=114.7 median=116.0 sd=10.307 min=97 max=133 n=10 ci95=[107.327, 122.073]
- IPS:
  - SCN-001: mean=105.2 median=104.5 sd=4.849 min=98 max=116 n=10 ci95=[101.731, 108.669]
  - SCN-002: mean=217.4 median=221.5 sd=25.163 min=182 max=259 n=10 ci95=[199.4, 235.4]
  - SCN-003: mean=309.2 median=310.5 sd=11.351 min=289 max=325 n=10 ci95=[301.08, 317.32]
  - SCN-004: mean=164.3 median=168.0 sd=16.76 min=138 max=192 n=10 ci95=[152.311, 176.289]

## Impact IDS / IPS
- CPU moteur moyen : IDS=13.17% · IPS=14.45% (baseline : pas de processus moteur).
- RSS moyen : IDS=50.14 MB · IPS=44.31 MB.
- Interprétation prudente : ces valeurs caractérisent la configuration virtuelle ARCHIVIRT considérée, pas une performance universelle de Suricata.

## Limites
- Métriques = propriété du **jeu de signatures contrôlé** Article-2, pas de Suricata en général.
- SCN-002 = **SSH connection-rate attack pattern** (cible publickey-only ; pas de guessing de mots de passe).
- Cross-firing inter-signatures en IDS (documenté) ; sans FP car confiné aux runs d'attaque.
- Débit IPS non mesuré sur le chemin inline ; rockyou en stub ; lab non air-gappé.

## Résultats directement utilisables dans l'Article 2
- Matrice de confusion + Accuracy/Precision/Recall/F1/FPR/FNR (IDS et IPS), n=50 chacun.
- Latence de détection par scénario avec IC95 (n=10).
- Taux de blocage IPS (100% attaques, 0% bénin) avec latence de blocage.
- CPU/RAM moteur par scénario ; reproductibilité (CV) sur 10 répétitions.
- Toutes les valeurs sont traçables (provenance + données brutes par run).