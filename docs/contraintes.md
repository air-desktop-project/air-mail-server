# Contraintes d'air-mail-server

Ce document est le **registre des contraintes imposées au projet**. Il n'est pas
une note d'intention : chaque entrée dit la règle, ce qu'elle interdit, et — le
plus important — **ce qui la fait respecter aujourd'hui**.

Quand la réponse à cette dernière question est « rien », c'est écrit en toutes
lettres. Une règle qui se croit outillée et ne l'est pas est pire qu'une règle
absente : l'absente, on la respecte à la main en le sachant ; celle qui ment donne
une assurance que personne ne vérifie.

Les contraintes ci-dessous ont été **imposées par l'auteur du projet** à partir
du 2026-08-28. Elles ne se négocient pas au fil de l'eau : les amender demande une
décision explicite, consignée ici.

**Les numéros sont en ajout seul.** Une contrainte nouvelle prend le numéro
suivant, jamais une place dans l'ordre thématique : c'est ce qui garantit qu'un
`C4` cité dans un commentaire de code ou un message de commit désignera toujours
la même chose.

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
Le gate est né à **zéro dette** — les crates concernées étaient vides — ce qui est
la seule circonstance où un seuil à 100 % peut être bloquant dès sa naissance sans
rien avoir à « résorber ». Il n'en a pas pris depuis : la première crate écrite
(`ams-mime`) est entrée à 100 %, sans dérogation.
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

**Outillé par** : les lints ci-dessus, qui font échouer la CI, et — depuis
`ams-mime` — l'absence d'allocation dans les décodeurs : ce qui n'alloue pas ne
peut pas allouer d'après un nombre venu du réseau. La crate est `#![no_std]`
**sans `alloc`**, ce qui rend la propriété structurelle et non disciplinaire.

**Et le fuzz existe** depuis le 2026-08-28 : `fuzz/`, crate `cargo-fuzz` **hors du
workspace**. La seconde toolchain que `cargo-fuzz` exige ne pouvait pas entrer
dans le workspace — deux LLVM produisent des profils de couverture mutuellement
illisibles, et le gate de C2 ne conclurait plus. Hors workspace, elle a son propre
`Cargo.lock`, n'entre ni dans la mesure ni dans le lock du produit, et rien de ce
qu'elle tire n'est livré.

Dix cibles éprouvant quarante-six propriétés, dont un **aller-retour** sur
l'encodeur de réponses, un **vocabulaire de sortie clos** sur la session, et
l'**indépendance au découpage** sur la phase de données : le même flux, lu d'un
seul tenant puis par tranches arbitraires, doit rendre le même verdict et les
mêmes octets. C'est exactement ce que la contrebande SMTP exploite quand ce n'est
pas le cas.

**Le fuzz a déjà payé six fois**, dont une en intégration continue, sur une
entrée qu'une campagne locale de deux millions d'exécutions avait manquée. `fuzz_ams_smtp_data` a trouvé, à sa première
campagne, une faute qui dépendait de l'endroit où la lecture avait été coupée — la
contrebande SMTP en miniature. Et `fuzz_ams_smtp_reply` avait trouvé, en soixante
secondes, un défaut réel : sous une borne de réponse inférieure à
l'enveloppe incompressible de six octets, un `saturating_sub` transformait « aucune
ligne ne tient » en « les lignes vides tiennent ». Corrigé, et l'entrée fautive est
versionnée en graine de non-régression.

La CI lance un smoke-fuzz borné à vingt secondes par cible. C'est un détecteur de
régression, **pas une campagne**, et `fuzz/README.md` le dit à l'endroit où
quelqu'un pourrait croire l'inverse.

Ce que cela ne couvre toujours PAS : les lints voient une conversion douteuse, pas
une borne oubliée ; et le fuzz ne voit que ce qu'il atteint.

## C4 — TLS 1.3 au minimum

Rien en dessous. Pas de TLS 1.2, pas de repli négocié, pas d'option de
compatibilité. Un client qui ne sait pas faire TLS 1.3 n'est pas servi.

**Le fournisseur cryptographique est `rustls-rustcrypto`** (décision du
2026-08-28) : pur Rust, sans une ligne de C. `rustls` est sans entrée-sortie par
construction — il traite des tampons, pas des sockets — donc naturellement aligné
avec C1.

Configuration exacte, et elle n'est pas négociable :

```toml
rustls            = { version = "0.23", default-features = false, features = ["std"] }
rustls-rustcrypto = { git = "https://github.com/RustCrypto/rustls-rustcrypto",
                      rev = "cb967bd6427865f72e5619326c16080cbfd98e53",
                      default-features = false, features = ["std"] }
```

`default-features = false` **est ce qui applique C4 et C6** : la feature `tls12`
est dans les défauts de `rustls-rustcrypto`, et la laisser active ferait entrer
TLS 1.2 par la porte de derrière.

### Ce qui a été mesuré, et non supposé

Vérifié le 2026-08-28 sur cette configuration exacte, par compilation et
exécution réelles :

- **Aucun C.** 74 crates compilées ; ni `ring`, ni `cc`, ni la moindre crate
  `*-sys`. Ces trois-là figurent bien au `Cargo.lock` — un lock enregistre les
  dépendances optionnelles même inactives — mais `cargo tree --target all -i ring`
  ne les trouve pas dans le graphe, et aucune ne passe par `rustc` à la
  compilation.
- **TLS 1.3 seulement.** Le fournisseur offre exactement trois suites :
  `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`,
  `TLS13_CHACHA20_POLY1305_SHA256`. **Aucune suite TLS 1.2**, C6 est donc tenue
  par la construction et pas seulement par une intention.
- Groupes d'échange de clés du fournisseur amont : X25519, secp256r1, secp384r1.
  `ams-tls` **préfixe** cette liste avec `X25519MLKEM768` ([C14](#c14--échange-de-clés-post-quantique-obligatoire)),
  qui devient donc le groupe préféré sans qu'aucun des trois autres disparaisse.

**Outillé par** : `ams-tls::provider()` et ses tests. Trois assertions y tiennent
C4 et C6 par la mesure, pas par l'intention : les suites offertes sont exactement
trois, **toutes de version TLS 1.3**, et le groupe hybride est en tête de liste.
Un jour où un défaut de `rustls-rustcrypto` ferait rentrer `tls12`, ces tests
échouent. Depuis le 2026-08-28, `crates/ams-loop-tokio/tests/starttls.rs` y
ajoute la preuve d'usage : une connexion SMTP réelle monte en **TLS 1.3** face à
un `openssl s_client`, sur la boucle du produit.

Ce qui reste non outillé : rien n'empêche un futur appelant de construire un
`ServerConfig` avec un autre fournisseur — la boucle reçoit celui qu'on lui
donne, et ne vérifie pas d'où il vient. C'est une revue, pas un gate.

### Les trois réserves, écrites plutôt que tues

1. **La version publiée sur crates.io est périmée.** `0.0.2-alpha`, publiée le
   2024-04-24 — plus de deux ans. Le dépôt amont, lui, est **vivant** (dernier
   push le 2026-08-27). D'où la dépendance `git` figée sur un SHA : c'est le seul
   moyen d'avoir la version maintenue, et le SHA est ce qui préserve la
   reproductibilité. Une dépendance `git` échappe en revanche à la couverture
   habituelle de `cargo audit` — à compenser par une revue à chaque changement de
   SHA.
2. **Ses auteurs la numérotent `0.0.2-alpha`.** C'est une déclaration de maturité,
   et elle vient d'eux. Le choix est fait les yeux ouverts : c'est le prix du pur
   Rust, seul `aws-lc-rs` et `ring` offrant l'alternative éprouvée — au prix du C,
   que le portage vers Air ne peut pas payer.
3. **Aucun échange de clés post-quantique.** Les trois groupes sont classiques ;
   il n'y a pas de `X25519MLKEM768`. Ce point était ouvert ; il a été **tranché le
   2026-08-28** et fait l'objet de [C14](#c14--échange-de-clés-post-quantique-obligatoire).
   La réserve est **levée le 2026-08-28** : le groupe est implémenté dans
   `ams-tls`, et le fournisseur le place en tête. La réserve garde sa place ici
   parce qu'elle décrit toujours `rustls-rustcrypto` seul — c'est nous qui
   comblons le manque, pas l'amont.

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

**Coût de tokio : MESURÉ, et bien moindre qu'annoncé.** Cette contrainte tablait
sur « ~25 crates transitives ». Le graphe de build réel, sur la cible Linux et
avec les seules features qui servent, en compte **douze, dont sept seulement à
l'exécution** : `bytes`, `errno`, `libc`, `mio`, `pin-project-lite`,
`signal-hook-registry`, `socket2`. Les cinq autres — `tokio-macros` et son
outillage proc-macro — compilent pour l'hôte et n'entrent dans aucun binaire
livré.

`default-features = false` fait toute la différence. L'estimation est corrigée ici
plutôt que laissée en place : un registre qui garde ses approximations après la
mesure vaut moins que pas de registre du tout.

**Outillé par** : `ams-loop-tokio` accepte des connexions sur un port et les
sert. Ses tests jouent des conversations SMTP entières **en mémoire**
(`tokio::io::duplex`) et de vraies connexions sur la boucle locale, sur un port
que le noyau choisit. `ams-loop-air` n'est toujours pas créée : une crate vide
portant ce nom laisserait croire qu'un portage est entamé.

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

**Outillé par** : pour TLS, deux `default-features = false` — sur
`rustls-rustcrypto` et sur `tokio-rustls` — retirent la feature `tls12` du
graphe, et un test de `ams-tls` vérifie que le fournisseur n'offre que trois
suites, **toutes en 1.3**.

Pour l'authentification, depuis le 2026-08-28 : `ams-sasl` ne connaît qu'un
mécanisme, `PLAIN`, et la session répond `504 Unrecognized authentication type`
à tout autre — `CRAM-MD5` et `LOGIN` compris, et c'est éprouvé. `AUTH` hors TLS
reste refusé par un `538` qui n'est réglable par rien. Le magasin refuse par
ailleurs toute empreinte qui n'est pas de l'`argon2id` aux paramètres du produit
(voir C11), ce qui ferme la porte à un fichier écrit par un outil plus ancien.

`CRAM-MD5` mérite sa phrase, parce que la raison de l'exclure n'est pas celle
qu'on croit : ce n'est pas seulement MD5, c'est que le mécanisme **oblige le
serveur à conserver le mot de passe en clair** pour calculer le condensat. Un
mécanisme qui interdit de stocker une empreinte aggrave la fuite qu'il prétend
éviter.

**`USER`/`PASS` hors chiffrement sont refusés depuis le 2026-08-29**, par la
session POP3 et sans réglage possible : le mot de passe y traverse le fil tel
quel. C'est le pendant exact du `538` d'`AUTH` en SMTP.

**`APOP` est refusé depuis le 2026-08-29**, et pour la même raison de fond que
`CRAM-MD5` : ce n'est pas MD5, c'est que le mécanisme **oblige le serveur à
conserver le mot de passe en clair** pour calculer le condensat. `ams-proto-pop3`
ne le reconnaît pas — il n'est même pas distingué d'un verbe inconnu, parce qu'un
pair à qui l'on apprendrait qu'il est « reconnu mais désactivé » réessaierait.

Le reste de la liste — IMAP4rev1, le relais ouvert — reste une décision : rien ne
l'empêche mécaniquement, sinon que le code qui l'appliquerait n'est pas écrit.

**Le piège vaut d'être nommé** : les défauts de `tokio-rustls` sont
`["logging", "tls12", "aws-lc-rs"]`. Les laisser ferait entrer TLS 1.2 **et** du
C dans la boucle sans qu'une seule ligne du dépôt le demande — deux contraintes
tombées par une valeur par défaut, et personne pour s'en apercevoir.

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

**Outillé par** : `ams-guard` pour la logique, et `ams-loop-tokio` pour le
câblage — le garde est consulté **avant la bannière**, puis à chaque commande.

**Qui compte comme « trame invalide » est décidé par la SESSION**, pas par la
boucle : `Turn::peer_fault`. La boucle ne peut pas le déduire d'un code de
réponse, puisque `502` sanctionne un verbe retiré par la RFC — une faute — comme
un `EXPN` qu'on décline, qui n'en est pas une. Le lui faire deviner y remettrait
du protocole.

**Un refus légitime n'est pas une faute** : boîte inconnue, relais refusé, trop de
destinataires. Un expéditeur qui se trompe d'adresse n'est pas un attaquant. Le
revers est nommé : une rafale de destinataires refusés est la signature d'une
récolte d'adresses, et cela mérite un compteur à soi, avec son propre seuil.
**Ce n'est pas fait.**

**On ne dit pas un mot à un banni** : pas même une bannière. Répondre confirmerait
qu'il y a un serveur ici, et le texte du refus lui apprendrait qu'il est banni
plutôt que hors service.

**Trois décisions qui ne se devinent pas**, et que le registre consigne parce
qu'elles ne se lisent pas dans le code seul :

1. **La clé est un préfixe, pas une adresse.** Bannir une IPv6 seule ne sert à
   rien — le plus petit bloc attribué est un `/64`, et le pair banni revient à
   l'adresse suivante. Longueur configurable : `/64` en IPv6, `/32` en IPv4.
2. **La table est bornée et fournie par l'appelant.** Une table qui grandit avec
   le nombre de sources est un épuisement de mémoire offert à qui dispose d'un
   `/64`.
3. **Une peine en cours n'est jamais évincée.** Le fuzz a montré qu'évincer « le
   bannissement qui expire le plus tôt » suffisait à s'en libérer en remplissant
   la table. Une table pleine de peines **cesse d'apprendre** plutôt que
   d'oublier : c'est une dégradation, pas un déni.

**Le revers assumé de la fenêtre fixe** : « x par minute » se compte sur une
fenêtre qui s'ouvre au premier événement d'une source. À cheval sur deux fenêtres,
un pair peut donc atteindre **le double** du seuil. C'est le prix d'un comptage
entièrement en entiers, éprouvable sans approximation ; un test le vérifie plutôt
que de le taire.

## C9 — DKIM et DMARC

DKIM (RFC 6376) en signature et en vérification ; DMARC (RFC 7489) en évaluation
de politique.

**SPF (RFC 7208) en fait partie** — déduit de DMARC, puis **confirmé le
2026-08-28**. DMARC évalue l'alignement d'un message sur SPF **et/ou** DKIM ; sans
SPF, il ne conclut que sur le courrier aligné DKIM, ce qui écarte une part
importante des expéditeurs légitimes et rend une politique `p=reject`
inapplicable.

Ces trois crates sont **sans entrée-sortie** malgré leur besoin de DNS : une
résolution est une *action rendue* par la machine à états, exécutée par la boucle,
et dont le résultat lui est réinjecté. C'est ce qui les rend couvrables à 100 %
sans serveur DNS de test.

**Outillé par** : SPF l'est entièrement, depuis le 2026-08-29. `ams-spf` lit un
enregistrement `v=spf1` — termes, qualificateurs, préfixes CIDR —, développe les
macros du §7, et **évalue une politique jusqu'au verdict** : `include`,
`redirect=`, `a`, `mx`, `ptr`, `exists`, avec les sept issues de la RFC. Couvert
à 100 % (C2) et fuzzé sur onze propriétés réparties en deux cibles, dont
l'indivisibilité de la validation et la terminaison de l'évaluation.

Ce qui n'est pas outillé : `ams-dkim` et `ams-dmarc` restent vides, et **SPF
n'est pas encore câblé dans la boucle SMTP** — la crate sait conclure, personne
ne l'interroge encore. Tant que ce câblage manque, C9 n'empêche aucune
usurpation : un verdict que personne ne demande ne protège rien.

### Ce que l'évaluation ne fait pas, et pourquoi c'est la bonne forme

Elle ne résout rien. `Evaluator::poll` rend soit un verdict, soit une
**question** — un nom, et ce qu'on veut en savoir — que l'appelant résout avant
de rendre la réponse. C'est ce qui rend la crate couvrable à 100 % sans serveur
DNS de test, et c'est surtout ce qui met **la limite des dix résolutions** (RFC
7208 §4.6.4) là où elle se vérifie. Cette limite n'est pas une commodité : sans
elle, un enregistrement hostile fait travailler le résolveur d'autrui, et un
message devient autant de requêtes payées par celui qui le reçoit. Elle est
éprouvée par une chaîne de onze `include`, et la **profondeur de la pile** l'est
séparément — car en desserrant les résolutions, c'est elle qui doit tenir.

Deux sous-limites appartiennent à l'appelant, parce que la question posée en
recouvre plusieurs : au plus dix enregistrements `MX`, au plus dix noms rendus
par une résolution inverse (§4.6.4). Elles sont écrites sur le type `Query` —
**un contrat qu'on ne peut pas vérifier doit au moins être lisible.**

## C10 — Le serveur ne s'exécute jamais avec les privilèges du superutilisateur

Jamais. Pas même le temps de se lier à un port, pas de `setuid` après coup, pas de
`CAP_NET_BIND_SERVICE`.

Les ports privilégiés (25, 465, 587, 110, 995, 143, 993, 80, 443) sont atteints
par une **règle de redirection du pare-feu** vers des ports non privilégiés, que
l'administrateur pose hors du serveur.

**Ce que cette contrainte simplifie** : il n'y a aucun code d'abandon de
privilèges à écrire, donc aucun à se tromper. Le chemin le plus sûr est celui qui
n'existe pas.

**Outillé par** : `ams_loop_tokio::refuse_root`, qui refuse de continuer sous UID
effectif 0. La **décision** (`is_root`) est séparée de l'appel système pour être
éprouvable sans être `root` ; l'appel, lui, ne l'est pas, et c'est l'une des
raisons pour lesquelles l'étage 3 est hors du périmètre de C2.

Et il n'y a **aucun** code d'abandon de privilèges dans le dépôt : ni `setuid`, ni
`capabilities`, ni séparation de privilèges. Ce n'est pas un manque, c'est ce que
la contrainte achète — on ne se trompe pas dans ce qu'on n'écrit pas.

## C11 — La configuration est un fichier binaire Cap'n Proto

Pas de texte, pas de TOML, pas de YAML, pas de JSON. Le schéma `.capnp` est la
définition normative de ce qui est configurable, et le fichier de configuration en
est une instance binaire.

Précédent direct : Air emploie déjà `capnp` (crate **pur Rust**, zéro dépendance
transitive, aucune surface C) pour son artefact de configuration.

Conséquence : la configuration **n'est pas éditable à la main**. C'est ce qui rend
C12 obligatoire plutôt que confortable.

**Outillé par** : `ams-config`. Le schéma `.capnp` est la définition normative ;
le code Rust qui en dérive est **généré et committé**, pour que le build et la CI
n'aient besoin d'aucun outil C++. Régénérer est une opération de mainteneur, rare
et hors CI (`crates/ams-config/regenerate.sh`).

**Et la conséquence est appliquée jusqu'au bout** : `air-mail-server` ne se règle
QUE par un fichier — il n'a aucune option de réglage, et `air-mail-admin config
write` est le seul moyen d'en produire un. Deux sources de configuration seraient
une de trop : c'est ainsi qu'un serveur finit par tourner autrement que ce que son
administrateur croit avoir demandé.

**Une dérogation, la première, et elle est nommée.** Le code dérivé du schéma est
GÉNÉRÉ : il porte un accesseur par champ et par sens, dont la plupart ne seront
jamais appelés. Exiger 100 % dessus (C2) reviendrait à écrire des tests qui
n'éprouvent aucune de nos décisions — et un test qui n'éprouve rien affaiblit la
mesure au lieu de la renforcer. Le gate exclut donc **un fichier**, pas une crate,
et l'annonce à chaque exécution : une dérogation qu'on ne voit plus est une
dérogation qui s'élargit. Le code écrit à la main d'`ams-config` reste à 100 %.

**`ams-config` alloue**, seule de l'étage 2 dans ce cas : construire un message
Cap'n Proto le demande. Ce n'est pas une entorse à C3, qui interdit d'allouer
d'après une longueur venue du RÉSEAU — ce qui est lu ici vient d'un fichier écrit
par l'administrateur. La lecture est en outre bornée par une limite de traversée
explicite, pour qu'un fichier corrompu ne fasse pas boucler le décodeur.

### La section TLS ne porte que des CHEMINS

Ajoutée le 2026-08-28. Deux champs, `certificateChainPath` et `privateKeyPath`,
et **pas le matériel lui-même** : une clé privée recopiée dans le fichier de
configuration hériterait des permissions de celui-ci, et le renouvellement
automatique d'un certificat — qui remplace un fichier — obligerait à réécrire la
configuration entière.

**Il n'y a pas de drapeau `enabled`, et c'est le point.** Le chiffrement est
offert si et seulement si les deux chemins sont renseignés. Un drapeau créerait
deux états faux : « activé sans certificat », qui ferait mentir la bannière, et
« certificat sans activation », qui donnerait le contraire à lire de ce qui se
passe. Un seul chemin sur deux est refusé — par `air-mail-admin` devant le
terminal, et de nouveau au chargement, parce qu'un fichier peut arriver
autrement.

Le serveur **refuse de démarrer si la clé privée est lisible par tout le monde** :
il suffirait d'un compte de service compromis pour repartir avec son identité,
sans laisser de trace. Le partage par GROUPE reste permis — c'est ainsi que les
certificats se partagent sur un système bien tenu, et punir cela punirait la
bonne pratique au lieu de la mauvaise.

### La relève verrouille la boîte, et le verrou est un `flock`

Écrit le 2026-08-29. La RFC 1939 §3 veut un accès exclusif pendant toute une
session POP3 : deux sessions qui effacent en même temps se marcheraient dessus,
et le second `QUIT` porterait sur des numéros qui ne désignent plus rien.

Un fichier témoin donnerait l'exclusion — mais il **survivrait à un arrêt
brutal**, et il faudrait alors décider au bout de combien de temps un verrou
devient « périmé ». Personne ne décide bien cela : trop court, on ouvre à deux ;
trop long, une boîte reste inaccessible après un simple redémarrage. `flock` est
relâché par le noyau à la mort du processus — il n'y a pas de verrou périmé, donc
pas de règle à se tromper.

Le fichier de verrou, lui, **reste en place** : l'effacer à la fin ouvrirait une
course où deux sessions verrouillent deux fichiers différents portant le même
nom.

### Un compte, une boîte — et la fin du fourre-tout

Écrit le 2026-08-29. Le nom du compte est **aussi le nom du répertoire de sa
boîte** (`<maildir>/<compte>/`), et ses adresses d'enveloppe sont une liste.

**Ce que cela change, et ce n'est pas mince** : accepter tout ce qui arrivait
dans un domaine hébergé faisait de ce serveur un fourre-tout —
`n.importe.qui@example.com` était accepté, écrit sur le disque, et jamais lu.
C'est ainsi qu'on remplit un disque avec du courrier que rien n'attend.
Désormais, une adresse qu'aucun compte ne déclare est refusée par un `550`.

`--hosted` ne sert donc plus à accepter : c'est la liste de ce que le serveur
déclare servir, confrontée aux adresses des comptes **une fois, au démarrage**.
Ce qui était une seconde règle d'acceptation est devenu une déclaration
contrôlée, ce qu'elle voulait dire depuis le début.

**Un seul champ pour l'identité et le répertoire**, et c'est une frontière de
sécurité : un login de `../../etc` ferait écrire hors de la racine. Le contrôle
(`ams_auth::check_login`) a lieu à l'écriture du magasin ET à sa lecture, parce
qu'un fichier peut arriver autrement que par notre outil.

**Un message, plusieurs boîtes** : un `RCPT` par destinataire, un seul `DATA`.
Le message est donc écrit dans chaque boîte, en parallèle. Un lien matériel
coûterait moins de place, mais suppose un même système de fichiers — ce que rien
ici ne garantit — et fait partager une inode entre des comptes qui n'ont rien à
partager. Le choix est fait dans ce sens et il coûte de la place.

Enfin, une limite honnête : les `rename` sont atomiques **un par un, pas
ensemble**. Un échec au milieu d'une remise à plusieurs laisse les premiers
remis, et le pair réessaiera — il recevra alors le message en double dans ces
boîtes-là. C'est le compromis de tout serveur sans file d'attente, et le doublon
est moins grave que la perte.

### Le magasin d'identifiants est UN AUTRE fichier

Décidé le 2026-08-28. Le chemin est nommé dans la configuration
(`accounts @11`), le contenu vit ailleurs, sous son propre schéma
(`ams-accounts.capnp`). Trois raisons, et chacune suffirait : les deux ne
changent pas au même rythme, ils ne méritent pas les mêmes permissions, et une
fuite de l'un n'est pas une fuite de l'autre.

**Argon2id, m = 19456 Kio, t = 2, p = 1** — la première des configurations
équivalentes de l'OWASP *Password Storage Cheat Sheet*. `Argon2id` et non
`Argon2i` ni `Argon2d` : c'est l'hybride, celui que la RFC 9106 §4 recommande
quand on ne sait rien de l'attaquant, ce qui est notre cas. Ces chiffres sont
écrits ici parce qu'on les changera un jour, et qu'il faudra alors savoir ce
qu'on remplace.

#### Le coût est le sujet, et il se retourne contre nous

Dix-neuf mébioctets par vérification, c'est ce qui rend une attaque par
dictionnaire coûteuse. C'est aussi une **amplification** : quelques octets sur le
fil deviennent 19 Mio chez nous. Deux cent cinquante-six connexions simultanées
réclameraient cinq gibioctets.

Le serveur borne donc à **quatre vérifications simultanées** (`ams-server`,
`VERIFICATIONS_SIMULTANEES`), sous `block_in_place` : le pire cas tient dans
76 Mio, les tentatives excédentaires attendent leur tour sur un fil bloquant, et
l'ordonnanceur asynchrone n'est jamais bloqué. C'est la contrainte C7 dans les
deux sens à la fois — la sécurité prime, et elle ne doit pas devenir le levier.

#### Trois contrôles au chargement, plutôt que trois surprises plus tard

1. **Un nom en double est refusé.** Deux empreintes pour un nom, c'est une
   question sans réponse ; le premier arrivé l'emporterait en silence, et
   l'administrateur croirait avoir changé un mot de passe.
2. **Une empreinte sous le plancher est refusée, en nommant le compte.** Une
   vérification Argon2 emploie les paramètres inscrits DANS l'empreinte — c'est
   ce qui permet de les faire évoluer sans invalider les comptes. C'est aussi ce
   qui rend ce contrôle indispensable : un compte haché en `m=8,t=1` serait
   vérifié en `m=8,t=1`, et le magasin paraîtrait sain.
3. **Un magasin lisible par tout le monde empêche le démarrage.** Ce ne sont que
   des empreintes, mais c'est un **dictionnaire de noms** offert à qui a un
   compte sur la machine, et le matériel d'une attaque hors ligne qu'aucun garde
   ne compte.

#### Ce qu'un refus ne dit pas

Un compte inconnu passe tout de même par une vérification, contre une empreinte
de personne (`ams_auth::DUMMY_HASH`). Sans elle, l'écart de temps entre « ce
compte n'existe pas » et « ce mot de passe est faux » rendrait le magasin
énumérable **sans en connaître un seul mot de passe**. Un test vérifie que cette
empreinte porte bien les paramètres du produit : le jour où ils changeront sans
qu'elle suive, l'écart reviendrait.

Le mot de passe, lui, ne passe **jamais** par la ligne de commande :
`air-mail-admin account add` le lit sur l'entrée standard. Ce que `ps` affiche,
tout le monde le lit.

## C12 — Deux exécutables, aux noms distincts

| Binaire | Rôle |
| --- | --- |
| `air-mail-server` | le serveur |
| `air-mail-admin` | contrôle et configuration |

L'outil d'administration est le **seul** moyen de produire et de lire un fichier
de configuration (C11).

**Outillé par** : les deux binaires existent et servent.

`air-mail-server` assemble les pièces et ne contient **aucune logique de
protocole** — pas même le `421` qui refuse une source trop pressée, qui vient de
la session. Il refuse le superutilisateur avant d'ouvrir un port, et écoute par
défaut sur `2525` : un port privilégié serait inatteignable sans les privilèges
que C10 interdit.

`air-mail-admin summary` relit une boîte. Ce n'est pas une commodité : c'est la
reconstruction de C13 exécutée à la demande, celle qui prouve que les fichiers
suffisent à retrouver ce que l'index dirait.

**Les commandes de configuration n'existent pas**, parce que le format de C11
n'existe pas. Le serveur se règle en attendant par sa ligne de commande — ce qui
n'enfreint pas C11, qui parle d'un FICHIER, mais ne la satisfait pas non plus.

## C13 — Le courrier est stocké en fichiers bruts, disposition Maildir

Un fichier par message, contenu brut RFC 5322, atomicité par `rename()` de `tmp/`
vers `new/`, drapeaux portés par le nom du fichier. Aucun verrou.

### L'index : Cap'n Proto, et reconstructible depuis les fichiers

Maildir ne porte pas d'identifiant stable, alors qu'IMAP exige des UID stables et
croissants sous une `UIDVALIDITY` donnée. Un **index binaire Cap'n Proto** — même
format que la configuration (C11) — porte les UID, les drapeaux et la
`UIDVALIDITY`.

**Les fichiers restent la seule source de vérité. L'index est reconstructible
depuis eux** (décision du 2026-08-28). Un index qui ne le serait pas deviendrait
une seconde source de vérité, qui peut diverger de la première sans que rien ne le
signale.

### Ce que « reconstructible » exige vraiment, et ce n'est pas évident

Reconstruire un index, ce n'est pas le recalculer *d'une manière ou d'une autre* :
c'est retrouver **exactement les mêmes UID**. Un UID déduit d'un ordre — la date
de modification, l'ordre de lecture du répertoire — n'est pas stable : il change
au premier fichier restauré depuis une sauvegarde, et le client resynchronise
toute la boîte.

**Donc l'UID vit dans le nom du fichier**, pas seulement dans l'index. La partie
unique d'un nom Maildir est opaque et libre — hors `:` et `/` — ce qui suffit à
l'y porter.

La propriété qui en découle est vérifiable, et c'est elle qu'il faudra défendre
par un test : **perdre l'index coûte un parcours de répertoire, jamais une
resynchronisation client**. La `UIDVALIDITY` n'a alors aucune raison de changer —
et c'est bien ce qu'on veut, car la changer force chaque client à retélécharger
l'intégralité de la boîte.

### Où vit le code, et pourquoi pas dans `ams-store`

La logique de reconstruction — d'une liste de noms de fichiers vers un index — est
la partie critique, et elle ne fait **aucune entrée-sortie**. Elle vit donc dans
`ams-index` (étage 2), avec le codec Cap'n Proto de l'index, et relève du 100 % de
[C2](#c2--100--de-couverture-sur-les-protocoles).

`ams-store` (étage 3) ne fait que fournir les noms et écrire les octets. Ce
découpage n'est pas une élégance : le gate de couverture travaille **par crate**,
donc une logique critique laissée dans une crate d'entrée-sortie serait, de fait,
non couverte.

L'index s'écrit comme un message se dépose — par `rename()` atomique. Un index
douteux **se reconstruit plutôt que se répare** : c'est peu cher, et cela évite
d'avoir à faire confiance à des octets dont on doute.

**Outillé par** : `ams-index` pour les noms, les drapeaux, la reconstruction et
la **réconciliation** de l'index avec les fichiers — sans entrée-sortie, couvert
à 100 %, et fuzzé sur l'aller-retour de l'UID ; `ams-config` pour le codec du
fichier ; et `ams-store` pour la boîte elle-même, dont les tests éprouvent les
trois propriétés qui comptent : l'`UIDVALIDITY` survit à une réouverture, un
index perdu la fait changer sans perdre un seul UID, et un index illisible se
comporte exactement comme un index absent.

**Ce qui est fait** : arrivée par `rename()` atomique, UID dans le nom (`,U=`),
adoption des messages déposés par un autre outil, nettoyage de `tmp/` même quand
une remise est abandonnée, et **deux `fsync`** — le fichier avant le `rename`, le
répertoire après. La seconde est celle qu'on oublie : un `rename` n'est durable
que lorsque le répertoire qui le porte l'est, et un serveur qui répond `250` sans
cela n'a pas pris la responsabilité du message, il l'a promise (RFC 5321 §6.1).

### La persistance de l'index, et pourquoi elle tient en deux nombres

Écrite le 2026-08-28, en Cap'n Proto comme cette contrainte le veut
(`ams-index.capnp`). Le fichier vit dans la racine de la boîte — ni `cur/`, ni
`new/`, ni `tmp/`, où tout outil Maildir le compterait comme un courrier
illisible.

**Il ne porte QUE ce que les noms de fichiers ne portent pas**, et ce refus est
la décision de conception. Un index Maildir classique recopie la liste des
messages pour éviter un parcours de répertoire ; celui-ci s'en abstient, parce
que recopier ce que les noms disent déjà créerait une **seconde source de
vérité**, capable de diverger de la première sans que rien ne le signale. L'UID,
les drapeaux et la taille sont dans les noms : ils y restent.

Restent deux nombres qu'aucun nom ne peut porter :

1. l'`UIDVALIDITY`, qui appartient à la BOÎTE et non à un message ;
2. le **filigrane** des UID, qui doit survivre à l'effacement du message portant
   le plus grand. Sans lui, effacer le dernier message ferait recommencer la
   numérotation — et un client verrait, sous un numéro qu'il croit connaître, un
   message qui n'est pas celui-là.

**Le filigrane est écrit EN AVANCE, par tranches de 256.** Le réécrire à chaque
remise coûterait deux `fsync` de plus par message ; ne l'écrire qu'à l'ouverture
laisserait le trou décrit ci-dessus. La réservation ferme ce trou pour un
`fsync` toutes les 256 remises, au prix de **trous dans la numérotation** après
un arrêt brutal — jusqu'à 255 UID sautés. La RFC 9051 §2.3.1.1 les autorise
explicitement : un trou ne coûte rien à personne, un UID réattribué coûte cher.

**Un index illisible est un index ABSENT, pas une panne.** Fichier manquant,
octet retourné, message tronqué : les trois mènent au même endroit — on
reconstruit depuis les fichiers, et l'`UIDVALIDITY` change. Refuser d'ouvrir la
boîte transformerait un octet retourné en indisponibilité, alors que tous les
messages sont là et que leurs UID le sont aussi.

Le prix de cette reconstruction est nommé : **tous les clients resynchronisent
la boîte entière**. C'est ce que l'`UIDVALIDITY` sert à dire, et c'est pourquoi
elle ne doit changer QUE là.

**Ce qui n'est pas fait non plus** : `ams-store` n'implémente pas le trait
`Delivery` de la boucle — l'adaptation appartient au binaire, qui connaît les
deux. Et elle **bloque** : `commit` fait deux `fsync`, donc l'adaptation devra
passer par `spawn_blocking`.

## C14 — Échange de clés post-quantique obligatoire

Le serveur **doit toujours offrir `X25519MLKEM768`** (point de code `0x11ec`), et
le préférer à tout autre groupe. `X25519` reste offert **en second**, pour les
pairs dont la pile TLS ne sait pas encore faire de post-quantique.

L'obligation porte sur le **serveur**, pas sur le client : ce groupe doit être
présent et préféré dans toute configuration ; aucune n'a le droit de le retirer.

### Le résidu accepté, et il est nommé

Un pair sans post-quantique obtient `X25519`, et cette connexion-là **n'est pas
protégée** contre « intercepter aujourd'hui, déchiffrer demain ». C'est le prix
de l'interopérabilité, il est payé les yeux ouverts, et il ne doit pas être
présenté autrement — notamment pas dans une documentation qui annoncerait « le
serveur est post-quantique » sans dire « quand le pair le veut bien ».

Décision du 2026-08-28, après avoir écarté l'option « seul groupe offert », qui
aurait fait échouer la poignée de main de tout pair sans PQ — y compris en SMTP
entrant, où le pair n'est pas de notre ressort.

### Ce qui a été écrit, parce que rien ne le fournissait

`rustls-rustcrypto` **n'a aucune trace de ML-KEM** : ni feature, ni une seule
occurrence dans son code (vérifié le 2026-08-28 sur le dépôt amont). Le seul
fournisseur `rustls` qui offre `X25519MLKEM768` est `aws-lc-rs`, qui embarque du
C — ce que [C4](#c4--tls-13-au-minimum) exclut.

La voie pure Rust existe, et elle a été vérifiée avant d'être décidée :

- `rustls` 0.23 **connaît déjà le point de code** — `X25519MLKEM768 => 0x11ec`
  dans `msgs/enums.rs` ;
- `rustls::crypto::SupportedKxGroup` et `ActiveKeyExchange` sont des traits
  **publics**, donc implémentables hors de la crate ;
- `ml-kem` 0.3.2 (RustCrypto) est pur Rust, `no_std`, sans dépendance C — et
  c'est **exactement la version qu'Air épingle**, qu'il a validée contre les
  vecteurs FIPS 203, mesurée en temps constant (dudect) et fuzzée en
  décapsulation ;
- `x25519-dalek` est déjà une dépendance de `rustls-rustcrypto`.

`ams-tls` porte donc une implémentation de `SupportedKxGroup` composant ces deux
primitives, **préfixée** aux `kx_groups` du fournisseur (`ams-tls::kx` et
`ams-tls::provider`, écrites le 2026-08-28).

### Ce que cela nous fait posséder — et ce n'est pas rien

Aucune primitive n'est inventée : ML-KEM-768 et X25519 viennent de crates
auditées. Mais **le combinateur hybride et son encodage sur le fil deviennent
notre code**, et c'est du code critique. Il ne suffit pas qu'il compile :

- l'ordre exact des octets (clé d'encapsulation, chiffré, et concaténation des
  deux secrets partagés) doit être **relevé dans la spécification**, jamais
  reconstitué de mémoire — deux moitiés interverties donnent un handshake qui
  échoue en interopérabilité et réussit contre soi-même ;
- des **vecteurs de test** et une **interopérabilité vérifiée contre une
  implémentation de référence** (OpenSSL 3.5+, `aws-lc-rs`) sont exigés avant que
  cette ligne quitte le statut « écrite » ;
- la crate étant sans entrée-sortie, elle relève du 100 % de
  [C2](#c2--100--de-couverture-sur-les-protocoles) — les deux branches, avec et
  sans PQ, sont à couvrir.

### La spécification a été lue, et elle avait un piège

La source est `draft-ietf-tls-ecdhe-mlkem`, **récupérée et lue le 2026-08-28**,
et non reconstituée. Son §3.1.3 dit que pour `X25519MLKEM768` le secret ML-KEM
vient **en premier** dans la concaténation — « pour des raisons historiques » —
alors que le même document met l'ECDH en premier pour `SecP256r1MLKEM768`. Deux
groupes du même brouillon, deux ordres opposés : c'est exactement le genre de
détail qu'une reconstitution de mémoire rend faux avec assurance.

Au passage, une leçon sur les sources : la RFC 9814 avait été citée de mémoire
comme étant ce hybride. Elle traite en réalité de SLH-DSA dans CMS. Une référence
plausible et fausse est pire qu'une référence absente.

### Interopérabilité : VÉRIFIÉE, avec sa date et ses limites

`crates/ams-tls/tests/interoperabilite.rs` monte un `ServerConfig` sur notre
fournisseur (TLS 1.3 seul, certificat P-256 auto-signé fabriqué à la volée) et
fait venir dessus un **`openssl s_client` réel** contraint à
`-groups X25519MLKEM768 -tls1_3`.

Résultat obtenu le **2026-08-28 contre OpenSSL 3.6.3** :

```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Negotiated TLS1.3 group: X25519MLKEM768
```

Ce que cette preuve vaut, exactement : la poignée de main ne se termine que si
les deux camps calculent **le même secret** — le MAC du message `Finished` en
dépend. Une inversion des deux moitiés du secret partagé passerait tous nos tests
internes (nous serions faux des deux côtés) et échouerait ici. C'est là toute la
raison d'être de ce test.

Ses limites, écrites plutôt que tues :

- **Ce n'est pas un gate de CI.** Les images GitHub livrent OpenSSL 3.0, qui
  ignore ce groupe. Le test se **saute bruyamment** — il annonce la version
  trouvée et pourquoi il ne conclut pas — au lieu de passer en silence, ce qui
  serait un vert mensonger. C'est donc une vérification **manuelle**, à rejouer
  sur une machine ayant OpenSSL 3.5+, et cette ligne dit sa date pour qu'on sache
  quand elle a été rejouée.
- **Pas encore de vecteurs FIPS 203 rejoués ici.** `ml-kem` les valide chez lui,
  et Air les a rejoués sur cette même version épinglée ; ce que nous n'avons pas,
  ce sont des vecteurs pour *le combinateur*, qu'aucune source normative ne
  publie encore.

**Outillé par** : `ams-tls` (couverte à 100 % au titre de C2, gate automatique),
ses tests unitaires — dont le refus d'un point X25519 d'ordre faible **des deux
côtés** (RFC 8446 §4.2.8.2) et la propagation d'une panne de la source d'aléa —
la cible de fuzzing `fuzz_ams_tls_kx`, et le test d'interopérabilité ci-dessus,
**manuel**.

Depuis le 2026-08-28, `ams-loop-tokio` conduit `STARTTLS` (RFC 3207) et
`crates/ams-loop-tokio/tests/starttls.rs` fait monter en chiffrement un vrai
`openssl s_client -starttls smtp` **sur la boucle elle-même**. Celui-là tourne en
intégration continue : il n'exige aucun groupe post-quantique, un OpenSSL 3.0 y
négocie `X25519`. Sur une machine récente, il négocie `X25519MLKEM768` — observé
le 2026-08-28 avec OpenSSL 3.6.3.

**Depuis le 2026-08-28, le serveur livré chiffre.** Le schéma porte une section
`Tls` ([C11](#c11--la-configuration-est-un-fichier-binaire-capn-proto)), et
`crates/ams-server/tests/chiffrement.rs` lance le **vrai exécutable** sur une
vraie configuration binaire, puis y envoie un `openssl s_client -starttls smtp`.
C'était la marche qui manquait : la boucle savait chiffrer depuis la veille, et
le serveur servait pourtant en clair. Seul un test qui monte tout l'assemblage
pouvait voir la différence — et son jumeau vérifie l'autre moitié, à savoir
qu'un serveur SANS certificat n'annonce pas `STARTTLS`.

Ce qui reste non outillé, et qui doit être su : **une paire dépareillée n'est pas
détectée au démarrage**. `rustls` documente que `with_single_cert` refuse une clé
qui ne correspond pas au certificat ; avec `rustls-rustcrypto`, la clé de
signature ne sait pas rendre sa clé publique et la comparaison est sautée en
silence. Mesuré, et consigné par un test qui échouera le jour où l'amont saura
faire. En attendant, un renouvellement qui remplace un seul des deux fichiers
donne un serveur qui démarre et dont toutes les poignées de main échouent.

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

Deux crates portent du code : **`ams-mime`** (le squelette d'un message) et
**`ams-proto-smtp`** (les commandes **et les réponses**). Aucun protocole n'est pour autant servi : il
manque l'encodage des réponses, la machine à états de session, et tout le reste.

Sont outillées : C2 (le gate mesure 6 400 régions, toutes couvertes), C8
(`ams-guard`, câblé), C10 (`refuse_root`, appelé avant tout le reste), C11 (`ams-config`, et le serveur
ne se règle QUE par un fichier), C12 (les deux binaires), C13 en grande partie
(`ams-index` et `ams-store`, hors persistance de l'index), C3 (les
lints, l'absence d'allocation dans les décodeurs, et le fuzz), C6 **en partie et
pour de bon** — les deux décodeurs refusent le CR et le LF isolés, et
`ams-proto-smtp` refuse en outre les routes sources, les verbes retirés par la
RFC 5321, et tout octet non imprimable dans une réponse ; et **`ams-session`
refuse `AUTH` hors chiffrement** — sans réglage pour le rétablir, et sans même
l'annoncer avant TLS.

**La contrebande SMTP est fermée** : la phase de données n'accepte que
`<CRLF>.<CRLF>`, refuse tout `CR` ou `LF` isolé, et le fuzz éprouve que le
découpage des lectures ne change rien au verdict.

C6 reste néanmoins **partielle** : rien n'exige encore TLS 1.3, C4 n'ayant pas de
code.

Tout le reste — TLS, post-quantique, DKIM, SPF, DMARC, flooding, configuration
binaire, stockage, non-root — est une décision écrite, pas un code vérifié.
