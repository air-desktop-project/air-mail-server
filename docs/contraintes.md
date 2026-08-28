# Contraintes d'air-mail-server

Ce document est le **registre des contraintes imposées au projet**. Il n'est pas
une note d'intention : chaque entrée dit la règle, ce qu'elle interdit, et — le
plus important — **ce qui la fait respecter aujourd'hui**.

Quand la réponse à cette dernière question est « rien », c'est écrit en toutes
lettres. Une règle qui se croit outillée et ne l'est pas est pire qu'une règle
absente : l'absente, on la respecte à la main en le sachant ; celle qui ment donne
une assurance que personne ne vérifie.

Les contraintes ci-dessous ont été **imposées par l'auteur du projet le
2026-08-28**. Elles ne se négocient pas au fil de l'eau : les amender demande une
décision explicite, consignée ici.

---

## C1 — Aucune entrée-sortie dans les protocoles, **ni dans le serveur**

Les crates `ams-proto-*` transforment des octets en commandes et des réponses en
octets. Elles ne connaissent ni socket, ni fichier, ni horloge.

**Et la contrainte remonte d'un cran** : la session serveur elle-même
(`ams-session`) est une machine à états sans entrée-sortie. Elle reçoit des octets
et l'heure ; elle rend des octets à émettre et des actions à exécuter. Ce sont les
boucles (`ams-loop-*`) qui lisent, écrivent et attendent.

**Ce que ce choix achète, et pourquoi il est structurant** : c'est la seule
disposition où [C2](#c2--100 %-de-couverture-sur-les-protocoles) reste atteignable
au-dessus des codecs. Une machine à états se pilote pas à pas depuis un test ; une
boucle `async` ne se pilote pas — on l'attend.

**Ce qu'il coûte** : une boucle par moteur, écrite deux fois.

**Outillé par** : rien d'automatique. Aucun gate ne vérifie qu'une crate `ams-proto-*`
ou `ams-session` n'importe pas `std::net` ou `std::fs`. C'est faisable (un `grep`
sur les `use`) et ce n'est pas fait.

## C2 — 100 % de couverture sur les protocoles

Les crates de protocole et les machines à états sans I/O doivent être couvertes
**intégralement**.

**Ce qui est réellement mesuré, et ce qui ne l'est pas.** Le seuil porte sur les
**régions** et les **lignes**. Il ne porte **pas** sur les branches : sur Rust
stable, `llvm-cov` ne les instrumente pas, et le rapport affiche `0 / 0`. Écrire
« lignes et branches » alors que le compteur de branches reste vide serait
exactement l'affirmation invérifiée que ce document existe pour proscrire.

La mesure par régions couvre l'essentiel de ce qu'on attendait des branches :
chaque bras d'un conditionnel est une région distincte. Éprouvé — une sonde à
deux bras dont un seul était exercé a fait tomber le gate à 8/9 régions, quand le
compteur de lignes affichait encore 100 %. C'est donc la mesure par régions qui
attrape ce que la mesure par lignes laisse passer.

Le périmètre est celui de C1 — ce qui ne fait pas d'entrée-sortie. Les boucles
(`ams-loop-*`) et le stockage (`ams-store`) en sont **hors**, non par indulgence
mais parce qu'y atteindre 100 % exigerait de simuler des pannes du noyau, ce qui
mesure la simulation et non le code.

**Outillé par** : `scripts/check-couverture.sh`, exécuté en CI (`cargo llvm-cov`).
Le gate part de **zéro dette** — les crates concernées sont vides à ce jour — ce
qui est la seule circonstance où un seuil à 100 % peut être bloquant dès sa
naissance sans rien avoir à « résorber ».
Il **dit combien de régions il a mesurées** : un rapport à 100 % sur zéro région
n'est pas un succès, c'est un rapport vide, et il le déclare.

## C3 — Longueurs vérifiées, dépassement de tampon impossible

Toute longueur qui vient du réseau est vérifiée avant d'être employée. Un décodeur
qui lit un littéral IMAP `{4294967295}` ne doit ni allouer, ni indexer, ni boucler
sur cette valeur : il doit la **refuser**.

Conséquences déjà gravées dans le workspace :

- `clippy::arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`
  et `cast_lossless` sont en **`deny`**. Sur un serveur de courrier, une
  conversion qui tronque n'est pas une imprécision, c'est une faille.
- `unsafe_op_in_unsafe_fn` est en **`forbid`**.

**Outillé par** : les lints ci-dessus, qui font échouer la CI. Ce qu'ils ne
couvrent PAS : ils voient une conversion douteuse, pas une borne oubliée. Le fuzz
(`cargo-fuzz`) sur chaque décodeur est le contrôle qui manque, et il n'existe pas
encore.

## C4 — TLS 1.3 au minimum

Rien en dessous. Pas de TLS 1.2, pas de repli négocié, pas d'option de
compatibilité. Un client qui ne sait pas faire TLS 1.3 n'est pas servi.

**Point ouvert — le fournisseur cryptographique.** `rustls` est la seule
implémentation Rust sérieuse, et elle est **sans entrée-sortie par construction**,
donc alignée avec C1. Mais son fournisseur par défaut (`aws-lc-rs`) embarque du C ;
`ring` aussi. Seul `rustls-rustcrypto` est pur Rust — au prix d'être moins
éprouvé, et non certifié. Ce choix engage le portage vers Air, où une dépendance
C est un problème, et **il n'est pas tranché**.

**Outillé par** : rien. Aucune ligne de TLS n'est écrite.

## C5 — Le moteur d'entrées-sorties, par cible

| Cible | Moteur |
| --- | --- |
| Unix (Linux glibc, BSD, macOS) | **tokio** |
| `*-linux-air` | le moteur asynchrone d'Air — `air-async` sur `air-uring` (io_uring) |

Les deux moteurs existent réellement : `air-async` (exécuteur mono-thread) et
`air-uring` (réacteur io_uring safe) sont implémentés dans le dépôt `air`.

Par C1, **aucun trait ne les abstrait** : chaque moteur porte sa propre boucle,
qui pilote la même machine à états. Il n'y a donc pas de couche d'adaptation
asynchrone à maintenir, et la logique du serveur n'est écrite qu'une fois.

**Coût assumé de tokio** : ~25 crates transitives entrent dans un workspace qui
n'en comptait aucune, dont plusieurs à `unsafe` important (`mio`, `parking_lot`).
C'est le prix de la maturité et des audits publics ; il est payé les yeux ouverts.

**Outillé par** : rien. `ams-loop-air` n'est pas créée — une crate vide portant ce
nom laisserait croire qu'un portage est entamé.

## C6 — Aucune version ancienne de protocole

On ne sert pas ce qui affaiblit. Sont **exclus d'emblée**, et la liste est
ouverte :

- SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 (cf. C4) ;
- l'authentification en clair hors TLS — `AUTH PLAIN` / `AUTH LOGIN` sur une
  connexion non chiffrée, `USER`/`PASS` POP3 idem ;
- `APOP` (MD5, exige le mot de passe en clair côté serveur) ;
- `CRAM-MD5` ;
- IMAP4rev1 **en tant que cible** : la référence est la RFC 9051 (IMAP4rev2). La
  compatibilité rev1 sera examinée pour ce qu'elle coûte, jamais accordée par
  défaut ;
- le relais ouvert, sous toutes ses formes.

**Outillé par** : rien à ce jour — la liste est une décision, pas un contrôle.

## C7 — La sécurité prime sur la performance

Quand les deux s'opposent, c'est la sécurité qui tranche, et l'arbitrage est
consigné à l'endroit du code concerné. Cette règle n'est pas un slogan : elle
autorise explicitement à refuser une optimisation, et elle interdit d'en
introduire une dont la sûreté n'est pas démontrée.

**Outillé par** : rien d'automatique, et par nature — c'est un critère de revue.

## C8 — Détection de flooding et bannissement par source

Le serveur doit détecter :

1. les **tentatives de flooding** (débit de connexions ou de commandes par source) ;
2. les **trames invalides**, comptées **par source**.

Au-delà de *x* trames invalides par minute, la machine fautive n'est plus acceptée
pendant *y* heures. `x` et `y` sont des **paramètres de configuration**, pas des
constantes.

Par C1, cette logique est une machine à états sans entrée-sortie (`ams-guard`) :
elle reçoit `(source, événement, instant)` et rend un verdict. Elle est donc
couverte à 100 % par C2, ce qui est le bon régime pour un composant dont un faux
positif coupe du courrier légitime.

**Outillé par** : rien. `ams-guard` est vide.

## C9 — DKIM et DMARC

DKIM (RFC 6376) en signature et en vérification ; DMARC (RFC 7489) en évaluation
de politique.

**Point déduit, à confirmer : SPF (RFC 7208).** DMARC évalue l'alignement d'un
message sur SPF **et/ou** DKIM. Sans SPF, DMARC ne conclut que sur le courrier
aligné DKIM — ce qui écarte une part importante des expéditeurs légitimes et rend
la politique `p=reject` inapplicable. `ams-spf` est donc créée. Si l'intention
était de s'en passer, c'est ici qu'il faut le dire.

Ces trois crates sont **sans entrée-sortie** malgré leur besoin de DNS : une
résolution est une *action rendue* par la machine à états, exécutée par la boucle,
et dont le résultat lui est réinjecté. C'est ce qui les rend couvrables à 100 %
sans serveur DNS de test.

**Outillé par** : rien. Les trois crates sont vides.

## C10 — Le serveur ne s'exécute jamais avec les privilèges du superutilisateur

Jamais. Pas même le temps de se lier à un port, pas de `setuid` après coup, pas de
`CAP_NET_BIND_SERVICE`.

Les ports privilégiés (25, 465, 587, 110, 995, 143, 993, 80, 443) sont atteints
par une **règle de redirection du pare-feu** vers des ports non privilégiés, que
l'administrateur pose hors du serveur.

**Ce que cette contrainte simplifie** : il n'y a aucun code d'abandon de
privilèges à écrire, donc aucun à se tromper. Le chemin le plus sûr est celui qui
n'existe pas.

**Outillé par** : rien à ce jour. Un refus explicite de démarrer sous UID 0 est
trivial à écrire et **doit** l'être — sans quoi cette contrainte ne tient qu'à la
discipline de qui lance le service.

## C11 — La configuration est un fichier binaire Cap'n Proto

Pas de texte, pas de TOML, pas de YAML, pas de JSON. Le schéma `.capnp` est la
définition normative de ce qui est configurable, et le fichier de configuration en
est une instance binaire.

Précédent direct : Air emploie déjà `capnp` (crate **pur Rust**, zéro dépendance
transitive, aucune surface C) pour son artefact de configuration.

Conséquence : la configuration **n'est pas éditable à la main**. C'est ce qui rend
C12 obligatoire plutôt que confortable.

**Outillé par** : rien. `ams-config` est vide.

## C12 — Deux exécutables, aux noms distincts

| Binaire | Rôle |
| --- | --- |
| `air-mail-server` | le serveur |
| `air-mail-admin` | contrôle et configuration |

L'outil d'administration est le **seul** moyen de produire et de lire un fichier
de configuration (C11).

**Outillé par** : les deux crates existent et produisent les deux binaires. Aucune
des deux ne fait quoi que ce soit.

## C13 — Le courrier est stocké en fichiers bruts, disposition Maildir

Un fichier par message, contenu brut RFC 5322, atomicité par `rename()` de `tmp/`
vers `new/`, drapeaux portés par le nom du fichier. Aucun verrou.

**Conséquence connue et non résolue** : Maildir ne porte pas d'identifiant stable,
alors qu'IMAP exige des UID stables et croissants sous une `UIDVALIDITY` donnée.
Un index sera nécessaire — et il devra être **reconstructible depuis les
fichiers**, faute de quoi il devient une seconde source de vérité qui peut diverger
de la première. La forme de cet index n'est pas décidée.

**Outillé par** : rien. `ams-store` est vide.

---

## Ce que les contraintes ont changé dans le dépôt

`ams-rt` et `ams-rt-std` ont été **supprimées**. Elles offraient une abstraction
d'exécution — traits `Listener` / `Stream` / `Clock`, et une implémentation sur
`std::net` — que C1 et C5 rendent inutile : puisque chaque moteur porte sa propre
boucle et que la logique est une machine à états, il n'y a rien à abstraire.

C'étaient les deux seules crates implémentées et testées du dépôt. Les garder
aurait laissé dans l'arbre une couture que l'architecture retenue n'emprunte pas,
et une couture inutilisée finit par être utilisée.

## L'état réel, sans complaisance

À la date de ce document, **aucune contrainte fonctionnelle n'est implémentée**.
Le dépôt porte une structure, des lints, deux gates de CI et ce registre. C3 est
partiellement outillée (par les lints), C2 l'est par son gate — qui mesure zéro
région et le dit. Tout le reste est une décision écrite, pas un code vérifié.

C'est l'état normal d'un projet de trois commits. Ce qui ne serait pas normal
serait de l'écrire autrement.
