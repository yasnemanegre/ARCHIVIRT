# M-6 FINAL : critères T-A du bras D0I (Diagnostic de capture instrumenté). Dossier de signature

**Statut : SIGNÉ (final) le 2026-10-25T00:50:24Z par le propriétaire du projet.** Copie signée de `DECISION_M6_FINAL.md` (sha `598a2a5687fe2738…`), non modifié. Base : M-6 partiel signé le 2026-10-24 (`ta_criteria.D0I.APPROVED_PARTIAL.json`, `768fd0be…`), inchangé.

## Ce que la signature finale ajoute
- **D-TA-3 = option A** (choisie par le propriétaire le 2026-10-25, sous condition de cohérence avec l'esprit d'ARCHIVIRT et de validité pour les tests futurs) :
  - **source principale** : statistiques par RX d'eve, prises dans l'événement `stats` émis **à la même seconde** que l'enregistrement final de `stats.log` (même relevé que le total de TA-b1) ;
  - **corroboration** : statistiques de sortie par RX de `suricata.log` (arrêt propre) ; mêmes threads RX, **pertes égales**, paquets **égaux ou supérieurs** (le journal est écrit plus tard, à l'arrêt) ;
  - tout le reste donne NOT_EVALUABLE : événement simultané absent, corroboration absente, désaccord sur les pertes, moins de paquets à la sortie, événements simultanés contradictoires.
- **Principe général pour les tests futurs** (Suricata IPS, Snort 3) : comparer des compteurs par RX et un total **issus du même relevé**, une source plus tardive ne servant qu'à corroborer dans le sens physiquement possible. Seule la lecture des fichiers propre à chaque moteur devra être ajoutée (amendement lors de l'intégration).
- TA-b1, TA-b2 et TA-s1 passent à APPROVED ; statut global `APPROVED`. Les verdicts T-A ne sont alors plus provisoires (code 0 si DEMONSTRATED).

## Fondement (V-1, 2026-10-25, `D0I-PREP-20261025T000931Z/V1/V1_RESULT.md`)
Dernier événement eve `stats` et dernier enregistrement `stats.log` : même seconde, même total (3/3 relevés). Format eve par RX (`RX#01-ens7`, `RX#02-ens7`, `capture.kernel_packets` et `kernel_drops`) conforme. Configuration déployée `f2252730`, provenance `ARCHIVIRT-P2-DIAG1-D0I`.

## Preuves logicielles
- Évaluateur r2 (`b2b9db6b…`) : r1 + D-TA-3 option A.
- Suite r2 **71/71**, dont 5 nouveaux cas (B10 à B14), N03 rendu plus strict, et 3 nouveaux mutants détectés.
- Suite r2 sur l'évaluateur r1 : N03, B10, B12 et B13 échouent, ce qui montre que les tests distinguent les deux règles.
- Critères candidats sur la série nominale synthétique : DEMONSTRATED, **non provisoire** (code 0).

## Inchangés
Critères d'arrêt `bf466291`, paramètres `30bf2ef8`, protocole 13/10/2, Article 2 (545/545), verdicts passés, D-B1 (option B, Suricata IDS). D0I reste un bras de **diagnostic** : il ne vaut pas acceptation de SCN-001 (B1).

## Signature
- Décisions approuvées telles que proposées : **oui**
- Déclaration : « ok. je signe M-6 final tel que proposé » — propriétaire du projet (yasnemanegre), 2026-10-25T00:50:24Z
- Fichier de critères signé : `ta_criteria.D0I.APPROVED.json`
