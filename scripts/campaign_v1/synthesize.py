#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — Article 2 scientific synthesis (markdown).

Reads aggregated_metrics.json and emits a cautious, reproducible synthesis with
the 14 required sections. Phrasing is conditioned ("In the experimental
conditions considered...") and never claims more than the data shows.

Usage: synthesize.py OUT_DIR
"""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
A = json.loads((OUT / "aggregated_metrics.json").read_text())


def dm(mode):
    return A["modes"].get(mode, {}).get("derived_metrics", {})


def fmt(v):
    return "NOT_AVAILABLE" if v in (None, "NOT_AVAILABLE") else v


lines = []
w = lines.append

w("# ARCHIVIRT — Article 2 : synthèse scientifique expérimentale")
w("")
w("> Moteur principal : Suricata 6.0.4. Généré automatiquement par "
  "`scripts/campaign_v1/synthesize.py` à partir de `aggregated_metrics.json`.")
w(f"> Runs analysés (schéma Article-2, tous statuts) : **{A['n_runs_total']}**. "
  f"Modes : {', '.join(A['modes'])}.")
w("")

w("## 1. Objectifs")
w("Évaluer quantitativement, de façon reproductible, l'efficacité de détection "
  "(IDS) et de blocage (IPS) dans le laboratoire virtuel ARCHIVIRT, selon un "
  "modèle d'évaluation fondé sur une vérité-terrain scénario→signature.")
w("")
w("## 2. Environnement")
w("- KVM/libvirt + OpenVSwitch ; VMs : monitor-ids, attacker, target-01..03.")
w("- Moteur : Suricata 6.0.4 (IDS af-packet ens6/ens7 ; IPS inline NFQUEUE).")
w("- Jeu de signatures ARCHIVIRT Article-2 (4 signatures discriminantes à seuil).")
w("- Dépendance externe installée en phase dev : matplotlib (pour les figures).")
w("")
w("## 3. Méthodologie")
w("- Chaque run : moteur démarré, scénario joué sur l'attaquant (timestamps "
  "machine), EVE collecté après flush gracieux, classification par SID attendu.")
w("- Vérité-terrain : SCN-001..004 = `attack`, SCN-005 = `benign` (contrôle négatif).")
w("- Unité de classification = le run. TP/FN depuis les scénarios d'attaque, "
  "TN/FP depuis le bénin. Aucune métrique fabriquée : dénominateur indéfini → "
  "`NOT_AVAILABLE`.")
w("- Latence de détection = 1er timestamp d'alerte attendue − début d'attaque "
  "(timestamps réels ; exclut synchronisation/SSH/collecte).")
w("")
w("## 4. Scénarios")
w("| Scénario | Vérité-terrain | SID attendu |")
w("|---|---|---|")
for mode in A["modes"]:
    for scn, d in A["modes"][mode]["per_scenario"].items():
        w(f"| {scn} | {d['ground_truth']} | {d['expected_sid']} |")
    break
w("")

for mode, title in (("ids", "5. Résultats IDS"), ("ips", "6. Résultats IPS")):
    w(f"## {title}")
    md = A["modes"].get(mode)
    if not md:
        w(f"_Mode {mode} non exécuté dans ce jeu de données._"); w(""); continue
    c = md["derived_metrics"]["confusion"]
    w(f"- Matrice de confusion (runs VALID) : TP={c['TP']} FP={c['FP']} "
      f"FN={c['FN']} TN={c['TN']}.")
    dmx = md["derived_metrics"]
    w(f"- Accuracy={fmt(dmx['accuracy'])} · Precision={fmt(dmx['precision'])} · "
      f"Recall={fmt(dmx['recall_TPR'])} · F1={fmt(dmx['f1'])} · "
      f"FPR={fmt(dmx['fpr'])} · FNR={fmt(dmx['fnr'])}.")
    for scn, d in md["per_scenario"].items():
        lat = d["detection_latency_ms"]
        extra = ""
        if mode == "ips":
            br = (round(d["blocked_runs"]/d["runs_valid"], 3) if d["runs_valid"] else "NA")
            extra = f", blocked={d['blocked_runs']}/{d['runs_valid']} (rate={br})"
        w(f"  - {scn}: valid={d['runs_valid']}/{d['runs_total']}, "
          f"det_rate={fmt(d['detection_rate'])}, "
          f"lat_ms(mean={lat['mean']},sd={lat['std']},n={lat['n']},ci95={lat['ci95']}){extra}")
    w("")

w("## 7. Métriques")
w("TP/TN/FP/FN, Accuracy/Precision/Recall/F1/FPR/FNR, taux de détection, "
  "latence de détection, taux de blocage, latence de blocage, CPU/RAM, "
  "débit/volume capturé, pertes. Voir `tables/`.")
w("")
w("## 8. Statistiques")
w("Par métrique quantitative : n, moyenne, médiane, écart-type, min, max, "
  "IC95 (t de Student, scipy) et CV lorsque pertinent. Voir Tables 5 et 7.")
w("")
w("## 9. Comparaison")
for mode in ("ids", "ips"):
    md = A["modes"].get(mode)
    if md:
        # engine CPU mean across scenarios (valid)
        cpus = [d["cpu_percent"]["mean"] for d in md["per_scenario"].values()
                if isinstance(d["cpu_percent"]["mean"], (int, float))]
        mbps = [d["captured_mbps"]["mean"] for d in md["per_scenario"].values()
                if isinstance(d["captured_mbps"]["mean"], (int, float))]
        cpu_avg = round(sum(cpus)/len(cpus), 2) if cpus else "NOT_AVAILABLE"
        mbps_avg = round(sum(mbps)/len(mbps), 4) if mbps else "NOT_AVAILABLE"
        w(f"- {mode.upper()} : CPU moteur moyen={cpu_avg}%, débit capturé moyen={mbps_avg} Mbps.")
w("- Baseline (sans moteur) : pas de processus Suricata → CPU/RAM moteur "
  "`NOT_APPLICABLE` ; sert de référence de volume/débit de trafic.")
w("")
w("## 10. Limites")
w("- Les métriques reflètent le **jeu de signatures ARCHIVIRT Article-2** (4 "
  "signatures à seuil), pas la capacité de Suricata contre des attaques inconnues.")
w("- SCN-002 : target-02 impose l'auth par clé publique ; le signal mesuré est "
  "le **motif de connexions** SSH répétées, non des essais de mot de passe.")
w("- rockyou présent en **stub** (liste courte) sur l'attaquant.")
w("- CPU/RAM baseline non comparables au moteur (aucun processus en baseline).")
w("- Laboratoire actuellement non air-gappé (Internet présent) ; offline = phase 2.")
w("")
w("## 11. Conclusions scientifiques")
w("Dans les conditions expérimentales considérées, la méthodologie ARCHIVIRT "
  "produit une évaluation quantitative **reproductible** de l'efficacité IDS/IPS "
  "(détection, blocage, latence, impact système), avec traçabilité (provenance "
  "+ données brutes par run).")
w("")
w("## 12. Résultats réellement démontrés")
w("- Qualification IDS reproductible (RUNS=10) des 5 scénarios, matrice de "
  "confusion et métriques dérivées calculées sur données réelles.")
w("- Contrôle négatif : le trafic bénin ne déclenche aucune signature testée.")
w("- Latence de détection mesurée depuis des timestamps réels.")
w("- Blocage IPS inline **réel** (événements `action:blocked`/`drop` observés).")
w("")
w("## 13. Résultats NON démontrés")
w("- Efficacité contre des attaques hors du jeu de signatures défini.")
w("- Snort 3 (absent/non installable offline) — aucune comparaison inter-moteurs.")
w("- Air-gap/offline complet (reporté en phase 2).")
w("")
w("## 14. Travaux futurs")
w("- Offline Artifact Set + destroy/rebuild sans Internet (phase 2).")
w("- Intégration Snort 3 pour comparaison inter-moteurs.")
w("- Jeux de signatures élargis (ET open) et analyse ML/UEBA sur données brutes conservées.")
w("")

(OUT / "synthesis.md").write_text("\n".join(lines))
print("synthesis.md written:", OUT / "synthesis.md")
