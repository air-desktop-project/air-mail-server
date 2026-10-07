# ARC (RFC 8617) — feuille de route

Rédigée le 2026-10-07, après avoir constaté qu'air-mail-server **n'implémente
pas ARC** : ni vérification, ni scellement, ni option. La seule chose qu'il en
fait est de noter au registre de réception si des en-têtes ARC étaient
*présents* — un booléen, `registre.rs:1421`, sans rien en conclure. RFC 8617
n'est pas dans le tableau des RFC du README, là où 8461, 8463 et 8601 le sont.

---

## Le problème qu'ARC résout

SPF et DKIM survivent mal au **transit**. Quand un message est réexpédié —
redirection d'adresse, liste de diffusion — l'intermédiaire casse les deux :

- **SPF** compare l'IP émettrice au domaine de l'enveloppe. L'intermédiaire
  émet depuis SA machine : l'échec est mécanique.
- **DKIM** signe des en-têtes et le corps. L'intermédiaire ajoute souvent une
  étiquette au `Subject`, un pied de page, ou réécrit le MIME : la signature ne
  vérifie plus.

DMARC exigeant qu'au moins l'un des deux passe **et** soit aligné, le receveur
final voit un `dmarc=fail` sur un message légitime, authentifié à son premier
saut. En `p=reject`, il le jette.

ARC fait consigner à chaque intermédiaire **ce qu'il a lui-même constaté** à
l'entrée, et le scelle. Trois en-têtes par saut, numérotés `i=1`, `i=2`… :

| En-tête | Ce qu'il porte |
|---|---|
| `ARC-Authentication-Results` | les résultats SPF/DKIM/DMARC tels que CE saut les a vus |
| `ARC-Message-Signature` | une signature du message, à la manière de DKIM |
| `ARC-Seal` | une signature de LA CHAÎNE, enchaînée aux instances précédentes |

Le receveur final valide la chaîne et obtient un `cv=` : `none`, `pass` ou
`fail`. Avec `cv=pass`, il peut lire dans l'instance `i=1` que SPF et DKIM
passaient AVANT le transit, et accepter malgré son propre `dmarc=fail`.

### Ce qu'ARC n'apporte pas, et qu'on oublie toujours

**AUCUNE AUTORITÉ.** Une chaîne valide prouve que personne ne l'a altérée —
pas que le scelleur est honnête. Honorer un ARC est une **décision de confiance
locale** envers l'intermédiaire qui a scellé. Sans liste de scelleurs de
confiance, la vérification ne sert à rien : c'est la décision d'exploitation,
et non la cryptographie, qui est le cœur du sujet.

---

## Phase 0 — mesurer avant de construire — **FAITE le 2026-10-07**

Aucun code. Trois gestes, dont le troisième décide de tout le reste.

### Ce qui a été fait

| Geste | Sur les deux serveurs |
|---|---|
| `--dmarc-quarantine-folder Junk` | un `p=quarantine` est MIS DE CÔTÉ au lieu d'être remis en boîte de réception |
| `--dmarc-report-dir .../rapports-dmarc` | les rapports agrégés se composent et se **déposent** |
| relevé du registre | le compte de départ, ci-dessous |

**`--dmarc-quarantine-folder` ÉTAIT DÉJÀ IMPLÉMENTÉ** : option analysée
(`ams-admin-options/src/lib.rs:1566`), portée par la configuration, câblée dans
la remise (`delivery.rs:1105`, `avec_quarantaine`), et éprouvée. La première
version de cette feuille de route le donnait à écrire — c'était faux, et vérifié
avant d'écrire une ligne de code. Il n'y avait qu'à le configurer.

La quarantaine **ne dépend pas de `--dmarc enforce`** : elle agit en `observe`,
ce qui est exactement ce qu'on veut ici — voir sans perdre.

Les rapports sont **déposés, pas remis** (`--dmarc-send` non posé) : composer un
rapport est une mesure, l'envoyer est un engagement envers les autres domaines.
C'est une décision à part.

### Le relevé de départ

Compté par `air-mail-admin registre cherche … | python3 docs/arc/mesure-arc.py` :

```
narro.ch          messages consignés 6   ARC 1   échec DMARC 0   ARC+échec 0
air-desktop.org   messages consignés 6   ARC 1   échec DMARC 0   ARC+échec 0
```

Les registres sont **jeunes** — posés les 2026-10-06 et 07 —, le relevé ne vaut
donc rien encore. L'unique message portant ARC est, dans les deux cas, celui
envoyé depuis Gmail pour éprouver la chaîne d'en-têtes.

### Comment relever la mesure

Depuis le Mac, dans ce dépôt. Le script lit l'entrée standard, les registres
vivent sur les serveurs :

```sh
# narro.ch
ssh onyx 'sudo air-mail-admin registre cherche \
  /var/lib/air-mail/air-mail.conf --limit 100000' \
  | python3 docs/arc/mesure-arc.py

# air-desktop.org
ssh -i ~/.ssh/id_ed25519_thierry_at_mbp-16i9 root@51.254.212.176 \
  'sudo -u air-mail air-mail-admin registre cherche \
   /var/lib/air-mail/air-mail.conf --limit 100000' \
  | python3 docs/arc/mesure-arc.py
```

**EN LECTURE SEULE** : `registre cherche` ne touche à rien, et le script ne fait
que compter.

### LA PORTE DE DÉCISION

**À relire dans un mois.** La colonne qui décide est `ARC + échec DMARC` : c'est
le courrier qu'ARC sauverait, et rien d'autre.

- proche de zéro → **ne pas construire**. Le chantier n'achèterait rien.
- non négligeable → les phases 1 à 3 valent leur prix, et le chiffre dit
  combien.

---

## Phase 1 — `ams-arc`, vérification seule, bibliothèque pure

Une crate **feuille** : ni entrée-sortie, ni horloge, ni réseau — C1, que
`scripts/check-etages.sh` vérifie. Même étage qu'`ams-dkim` et `ams-dmarc`.

Ce qu'elle fait :

- lire les trois en-têtes et reconstruire les instances `i=1..N` ;
- tenir les règles structurelles de RFC 8617 : numérotation **contiguë**, 50
  instances au plus, `cv=none` obligatoire en `i=1` et `cv=pass` ensuite ;
- valider l'`ARC-Message-Signature` — un DKIM déguisé — et l'`ARC-Seal`, qui
  signe la chaîne ;
- rendre un verdict : le `cv`, les instances, et **le domaine de chaque
  scelleur** — c'est lui dont la phase 3 aura besoin.

### Ce qui se réutilise d'`ams-dkim`, et c'est beaucoup

`crates/ams-dkim/src/` porte déjà `canonical` (relaxed/simple), `body`
(condensat du corps), `key` (RSA et Ed25519), `signature` et `tag` (analyse des
couples), `base64`. 2 501 lignes qui couvrent la cryptographie ; ARC n'ajoute
que la logique de chaîne.

### Les portes du dépôt à franchir

| Porte | Ce qu'elle exige |
|---|---|
| `check-couverture.sh` | **100 %** (C2) |
| `check-fuzz.sh` | une cible de fuzz — un analyseur d'en-têtes venus du réseau en exige une |
| `check-sans-c.sh` | cryptographie **Rust pure**, comme `ams-dkim` |
| `check-etages.sh` | la crate reste une feuille |
| README | RFC 8617 ajoutée au tableau des RFC |

**Livrable seul**, sans aucun changement de comportement du serveur.

---

## Phase 2 — `arc=` dans `Authentication-Results`

Câblage dans la boucle de réception, après SPF et DKIM. Le serveur **constate**
sans rien changer à ses décisions.

### Le risque principal, et il est documenté dans le code

L'en-tête `Authentication-Results` occupe une place **réservée à l'octet** :
`connection.rs:1037` réserve, `connection.rs:1725` écrit. Le commentaire
prévient — « *un octet de trop écraserait le premier en-tête du pair, un de
moins laisserait un trou au milieu du message* ». Ajouter `arc=` oblige à faire
grandir la réservation **et** à la garder exacte.

**C'est là que ça casse, pas dans la cryptographie.**

### Le second point

Le registre passe de `arc: bool` à un verdict. C'est un **changement de format
du registre**, qui est scellé et chaîné : la compatibilité de relecture doit
être traitée explicitement, sans quoi `registre verifie` refusera les fichiers
d'avant.

---

## Phase 3 — la confiance, et l'effet sur DMARC

Le cœur du sujet, et ce n'est pas de la cryptographie.

- une option **`--arc-trusted-sealer <domaine>`**, répétable. **Sans elle, ARC
  ne change rien** — ce doit être le défaut, puisqu'une chaîne valide ne prouve
  pas que le scelleur est honnête ;
- dans `ams-dmarc::evaluate` : un rattrapage **seulement si** DMARC échoue,
  `cv=pass`, le scelleur le plus externe est dans la liste, **et** l'instance
  `i=1` montre un passage aligné ;
- le rattrapage se **consigne** — registre et `Authentication-Results` —, sinon
  le serveur accepterait du courrier sans trace de pourquoi.

C'est à ce moment-là, et pas avant, que `--dmarc enforce` devient tenable sans
sacrifier le courrier réexpédié.

---

## Phase 4 — sceller en réexpédition — **probablement jamais**

N'a d'intérêt que si ces serveurs réexpédient le courrier d'autrui : liste de
diffusion, alias vers un domaine tiers. Ce n'est pas le cas : les alias
remettent en local, et la sortie passe par Resend.

Réutiliserait la clé DKIM, ou une `--arc-key`/`--arc-selector` dédiée. Au plan
pour la complétude, avec l'avis franc qu'il ne faut pas la faire.

---

## Ce que la phase 0 a appris sur la réécriture d'une configuration

Deux pièges rencontrés en modifiant celle d'onyx, qui valent pour **toute**
modification future. `config write` remplace le fichier ENTIER : il faut donc
reproduire tout le jeu d'options, et deux choses ne se voient pas dans un
`config show`.

1. **LE MOT DE PASSE DU RELAIS N'EST PAS AFFICHÉ.** Une candidate écrite avec un
   secret vide donne un `diff` parfaitement propre — et casserait l'émission en
   silence. Il se vérifie à part, par l'empreinte de ce que porte la
   configuration binaire.
2. **LE SECRET DE SCELLEMENT EST TIRÉ À NEUF SUR UN FICHIER NEUF.** Tous les
   jetons d'API en cours cesseraient de valoir. On écrit donc **sur une copie de
   la configuration vivante**, que `config write` reprend — il le dit :
   « *secret REPRIS du fichier existant* ».

La procédure sûre, et c'est celle qui a été suivie :

```
config show (vivante)            -> référence
cp vivante -> candidate           # pour que le scellement soit REPRIS
config write candidate …          # tout le jeu d'options, plus le nouveau
config show candidate | diff      # ne doit montrer QUE ce qu'on ajoute
empreinte du secret de relais     # identique des deux côtés
puis, seulement alors : bascule, redémarrage, et retour arrière si échec
```

Et la commande de référence du dépôt, `docs/migration/bascule.md` §0.4, **était
périmée** : onyx a gagné depuis SCRAM, appareils, délégations, brouillons,
registre et audit. Une commande de manuel vieillit sans prévenir — c'est
précisément ce que `repeter-la-configuration.sh` existe pour attraper, et il
n'attrape que ce que le manuel prétend, pas ce que la production porte.

---

## Résumé pour décider

Le chantier utile est **1 à 3**, et son déclencheur n'est pas ARC : c'est la
décision de passer DMARC en `enforce`. Tant que les deux serveurs sont en
`observe`, aucun courrier légitime n'est perdu, et ARC n'achète rien.

La phase 0 est faite. Elle rendra son chiffre dans un mois.
