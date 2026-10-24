# Proposition d'amendement méthodologique — contrôle facultatif des arrêts forcés (`--engine-stop`)

**Statut : PROPOSITION, non approuvée.** Le comportement par défaut reste celui de r1 : le contrôle n'est **pas** activé et aucun drapeau n'est transmis par défaut. Ce document ne change ni le protocole (13/10/2), ni les critères `bf466291`, ni les paramètres `30bf2ef8`.

## 1. Problème observé
- **OBSERVED** (REVUE-B1-B2, test B1-03, réexécuté ici) : un essai dont le moteur a été arrêté par SIGKILL (`ARCHIVIRT_ENGINE=STOPPED_FORCED`), mais dont `stats.log` et `eve.json` sont complets et couvrent l'attaque, est évalué `engine_drops` = NOT_EXCEEDED. Il peut donc être VALID.
- **INFERRED** (mécanisme, RULES_AND_SOURCES R9 de REVUE) :
  - un SIGKILL supprime le relevé de statistiques final écrit à l'arrêt (présent dans 61/61 essais normaux, OBSERVED) ;
  - le vidage EVE n'est pas garanti (`stop.sh` l. 13–14, DOCUMENTED).
  - Les compteurs évalués peuvent alors provenir d'un relevé périodique sans être les compteurs finaux.

## 2. Règle actuellement documentée et ses limites
- **DOCUMENTED** :
  - validité = `validate_run` (attaque, EVE, détection) **et** critères d'arrêt VALID (`campaign_acceptance.py` l. 9–11, 28–31) ;
  - INVALID si un critère est NOT_EVALUABLE ; aucune valeur absente n'est convertie en résultat favorable (`archivirt_stopwatch_eval.py`, docstring) ;
  - `engine_drops` lit les lignes Total de `stats.log` (`bf466291`).
- **Limite** : **aucune** règle ne mentionne l'état d'arrêt du moteur (UNDEFINED).
  - PATCH-2r1 ne couvre l'arrêt forcé que si le dernier relevé est antérieur à la fin de l'attaque (test C10).
  - Il ne le couvre **pas** si un relevé périodique postérieur à l'attaque existe.
- **Conclusion** : les documents ne permettent pas de déterminer la règle. Une **décision formelle** est nécessaire (D-B1).

## 3. Règle candidate (option B)

> **Pour une série approuvée après l'adoption de cet amendement, en mode IDS uniquement**, le critère `engine_drops` d'un essai est NOT_EVALUABLE, ce qui rend l'essai INVALID en vertu de la règle existante, si `engine_stop.txt` de l'essai :
> - ne contient pas exactement une ligne `ARCHIVIRT_ENGINE=STOPPED_CLEAN` ;
> - ou contient une ligne `ARCHIVIRT_ENGINE=STOPPED_FORCED` ;
> - ou est absent, vide, illisible ou contradictoire.
>
> Un essai déjà NOT_EVALUABLE ou CONFIRMED pour une autre raison garde son verdict d'invalidité ; seul le motif peut changer.

- **Implémentation candidate** (inchangée depuis REVUE, empreintes vérifiées) : évaluateur `99ba0711…`, `p2_run_monitor.py` `787e1535…`, `campaign_v1.sh` `8a8c746b…`.
- **Contrôle actif seulement si `--engine-stop` est transmis.** Sans le drapeau, l'évaluateur est identique à r1 (OBSERVED : 61/61 blocs et codes de sortie).

## 4. Conséquences pour les futurs essais

| Situation | Sans amendement (r1) | Avec amendement (option B) |
|---|---|---|
| CLEAN, preuves complètes, pas de perte | VALID possible | VALID possible (inchangé) |
| CLEAN, pertes | INVALID (CONFIRMED) | INVALID (CONFIRMED, inchangé) |
| **FORCED, preuves complètes** | **VALID possible** | **INVALID** (NOT_EVALUABLE) |
| FORCED, preuves incomplètes ou non couvrantes | INVALID (NOT_EVALUABLE par 1r1/2r1) | INVALID (motif d'origine conservé) |
| `engine_stop.txt` absent, vide, illisible ou contradictoire (erreur de collecte de l'état d'arrêt) | sans effet | INVALID (NOT_EVALUABLE) |
| **Essai interrompu** (signal, `set -e`, abandon) | INVALID par `cleanup()` → `finalize --note` → `mark-invalid` (`campaign_v1.sh` l. 115–119, `p2_run_monitor.py` l. 134–135) | **Inchangé** : `cleanup()` ne transmet ni `--stats-log` ni `--engine-stop` ; l'essai reste INVALID par la note |
| Collecte des preuves de diagnostic incomplète (`ENGINE_EXTRA_STATUS` INCOMPLETE) | sans effet sur la validité | **sans effet** (hors du périmètre de cette règle ; lu seulement par l'analyse T-A) |

- **Coût attendu** : 0 arrêt forcé sur 52 essais P2-VAL2 (DOCUMENTED, `SERIE_P2_VAL2_20261021T2300Z.md` l. 114). Pour D0, ce nombre n'a pas été vérifié (UNKNOWN).
- **Budget 13/10/2** : chaque arrêt forcé consomme un essai non valide (au plus 2).

## 5. Périmètre
- **Mode IDS (AF_PACKET) uniquement**, c'est-à-dire le périmètre du critère `engine_drops` (`modes: ["ids"]`, `bf466291`). La campagne candidate n'ajoute le drapeau que pour `MODE == ids`.
- Mode IPS et Snort : hors périmètre (le critère n'y est pas applicable). Toute extension serait une décision séparée (D-B1-bis).

## 6. Preuves exigées pour conclure à un essai évaluable
- `engine_stop.txt`, écrit par `stop_engine | tee` (PATCH-5r1/5r2), **avant** `finalize` (ordre vérifié, B1-18) ;
- `stats.log` complet et couvrant (1r1 + 2r1) ;
- `eve.json` avec un relevé de stats cohérent (2r1).

## 7. Non-rétroactivité (obligatoire)
- **La règle ne doit jamais être appliquée aux 61 essais historiques (D0, P2-VAL2).** Aucun `engine_stop.txt` n'existe pour eux : appliquée, elle les rendrait **tous** NOT_EVALUABLE (OBSERVED, B1-16, 61/61).
- Leurs verdicts restent ceux enregistrés (61/61 inchangés).
- Le drapeau n'est transmis que par la campagne, pour les séries postérieures à l'amendement. L'évaluateur ne doit pas être relancé avec `--engine-stop` sur des données historiques.

## 8. Dépendances d'intégration
- **5r1 ou 5r2 doivent précéder l'option B.** OBSERVED : le diff de campagne de l'option B s'applique textuellement **sans** 5r1, car il ne touche que `fin_args`. Appliqué seul, il rendrait chaque essai IDS NOT_EVALUABLE, faute d'`engine_stop.txt`. L'ordre doit être imposé par la procédure.
- Les trois fichiers de l'option B vont ensemble : ne transmettre le drapeau que si l'évaluateur le connaît.

## 9. Décision à soumettre
> « Adopter, pour les séries futures en mode IDS, la règle §3 (option B), activée par la campagne. Non rétroactive. Effective à partir de la série <identifiant>. »

Ou, à défaut, l'option A : statu quo documenté (`engine_stop.txt` descriptif seulement).
