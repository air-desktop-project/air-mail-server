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

**Et il a coûté une crate de plus, le 2026-08-29.** SPF (C9) ne conclut rien sans
résoudre des noms. Deux chemins s'offraient : prendre une bibliothèque de
résolution toute faite, ou écrire le codec. C1 tranche — le DNS est un protocole,
et un protocole s'écrit ici sous forme de codec sans entrée-sortie, couvert à
100 % et fuzzé. Une bibliothèque de résolution aurait apporté son propre modèle
d'exécution, ses propres délais et ses propres caches, c'est-à-dire exactement ce
que l'étage 3 doit décider — et elle ne se porterait pas telle quelle sur Air.
`ams-dns` tient en quelques centaines de lignes parce qu'on n'écrit **qu'un
client stub** : ce serveur pose des questions, il n'en répond aucune.

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

**C'est fait depuis le 2026-08-29** : cet exemple-là n'est plus une intention.
`ams_proto_imap::CommandReader` refuse ce littéral avant de lire un seul octet,
et le fuzz l'éprouve sur onze millions d'entrées. Voir « IMAP » plus bas pour ce
que le découpage d'une commande demande de plus.

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

**SPF est câblé dans la boucle SMTP depuis le 2026-08-29.** La session rend la
main au `MAIL FROM:` sans répondre, la boucle résout, et la session compose la
réponse : `550 5.7.23` pour un `fail`, `451 4.4.3` pour une panne de résolution
(RFC 7372 §3.2), `250` pour tout le reste. Trois états se règlent dans le fichier
de configuration — ne rien vérifier, vérifier et retenir, vérifier et opposer —
et le défaut, quand des résolveurs apparaissent, est **de regarder** : une
politique mal écrite chez un partenaire refuse du courrier légitime, et il vaut
mieux le lire dans un journal que l'apprendre au téléphone.

**Le verdict est écrit dans le message depuis le 2026-08-29**, sous la forme
d'un en-tête `Received-SPF` (RFC 7208 §9.1) posé EN TÊTE, avant les en-têtes du
pair. Un verdict qu'on n'écrit pas ne sert à rien : le message accepté ne
porterait aucune trace de ce qu'on a vérifié, et ni le lecteur, ni un filtre en
aval, ni DMARC ne pourraient le savoir.

L'en-tête porte deux valeurs **que le pair choisit**, et il est écrit DANS le
message qu'on remet. Deux règles le ferment, et aucune n'est facultative : tout
octet hors de l'ASCII imprimable fait refuser l'en-tête entier — pas
d'échappement de secours, pas de remplacement — et les quatre octets qui ont un
sens syntaxique sont préfixés d'une contre-oblique. La borne des 998 octets par
ligne (RFC 5322 §2.1.1) est **vérifiée à l'écriture**, pas supposée : un en-tête
plus long est refusé, car coupé en aval il se lirait comme un en-tête entier
disant autre chose. Une cible de fuzz éprouve nommément qu'aucun saut de ligne
n'y est autre chose qu'un repli.

**DKIM est commencé depuis le 2026-08-29**, par ce qu'une signature COUVRE : la
grammaire des listes `tag=valeur` (§3.2), le champ `DKIM-Signature` (§3.5),
l'enregistrement de clé publique (§3.6.1) et la canonicalisation (§3.4), `simple`
et `relaxed`, en-têtes et corps. Couvert à 100 % (C2) et fuzzé sur sept
propriétés, dont l'indépendance au découpage — le corps se canonicalise en flux,
et le condensat ne doit pas dépendre de la taille des paquets que le pair choisit.

Les épreuves de la canonicalisation sont **les vecteurs de la RFC 6376 §3.4.5**,
et non des exemples écrits ici. Ce n'est pas de la coquetterie : une erreur d'un
octet dans une canonicalisation ne produit aucun symptôme visible, elle rend
simplement toutes les signatures invalides — ou en valide qui ne devraient pas
l'être. Une épreuve inventée ici passerait ses propres tests et échouerait contre
le reste du monde.

**La vérification est là depuis le 2026-08-29** : condensat du corps en flux,
condensat des en-têtes signés, et signature `rsa-sha256` ou `ed25519-sha256`
(RFC 8463). Le condensat du corps se compare AVANT la signature — c'est gratuit,
là où une exponentiation modulaire ne l'est pas — et deux bornes encadrent les
clés RSA : moins de 1024 bits se factorise (RFC 8301 §3.2), plus de 4096 bits est
du calcul offert à qui le publie.

### D'où viennent les vecteurs, et pourquoi pas d'ici

Une épreuve écrite avec le code qu'elle éprouve passe toujours. Les deux ancrages
de la vérification viennent donc d'ailleurs : **le `bh=` que la RFC 6376 annexe A
publie**, recalculé sur son propre message sans qu'une ligne de ce projet y
serve ; et **des signatures produites par OpenSSL**, sur un condensat fixe pour
la cryptographie seule, et sur un bloc d'en-têtes canonicalisé par une
implémentation Python écrite séparément pour la chaîne entière. Si notre
canonicalisation dérivait d'un octet, cette dernière signature ne vérifierait
plus.

### La cryptographie n'a coûté aucun paquet de plus

`rsa`, `sha2` et `ed25519-dalek` étaient DÉJÀ dans l'arbre, tirées par
`rustls-rustcrypto` (C4). Les déclarer en direct a ajouté trois arêtes au
`Cargo.lock` et zéro paquet — c'est vérifiable dans son diff. `rsa` est épinglée
sur la version candidate qu'amont épingle : en prendre une autre mettrait deux
implémentations de la même arithmétique dans le binaire, dont une seule serait
revue le jour d'un avis de sécurité.

`ams-dkim` alloue désormais — `rsa` ne peut pas faire autrement. C'est la
deuxième crate de l'étage 2 dans ce cas, après `ams-config`, et la différence
compte : ce qui est alloué ici vient d'un pair. Les deux bornes sur les clés sont
ce qui empêche ce pair de choisir combien.

**Le câblage est là depuis le 2026-08-29.** La boucle retient le bloc d'en-tête
pendant que le corps s'écoule, condense en flux, va chercher la clé sous
`<sélecteur>._domainkey.<domaine>`, et verse le verdict dans le résumé de la
connexion — que le serveur annonce à l'arrêt. Éprouvé de bout en bout, jusqu'au
binaire : un message signé par OpenSSL, une clé servie par un vrai résolveur sur
une socket locale, et « 1 signature vraie » au journal.

### Le verdict n'arrive qu'après le corps, et rien n'est écrit dans le message

SPF conclut au `MAIL FROM:` — avant que le message existe. DKIM signe le corps :
son verdict ne peut pas être connu avant le dernier octet. Un en-tête de résultat
se pose EN TÊTE ; l'écrire demanderait donc soit de garder tout le message, soit
de le récrire. Les deux méritent leur propre décision, et c'est DMARC qui la
portera — avec l'`Authentication-Results` (RFC 8601) qui rapportera les trois
méthodes ensemble. En attendant, le verdict va au seul endroit qui existe : le
compte que le serveur rend à l'arrêt.

### DKIM ne refuse aucun message, et c'est voulu

Une signature qui échoue ne dit pas qu'un message est faux : une liste de
diffusion qui ajoute un pied de page casse une signature parfaitement honnête.
RFC 7489 le pose — c'est DMARC qui rapproche un `pass` du domaine de l'en-tête
`From:`, et lui seul qui décide. Il n'y a donc **aucun réglage** à écrire ici :
la vérification a lieu dès qu'un résolveur est configuré, et n'oppose rien.

### Deux bornes contre l'amplification

Chaque signature coûte **une résolution DNS et une exponentiation modulaire**. Un
message qui en porterait cent ferait travailler la machine cent fois pour un seul
envoi : **cinq au plus sont vérifiées**. Et le bloc d'en-tête, qui doit être
retenu en entier pour condenser les champs que `h=` nomme, est borné à 256 Kio —
au-delà, on renonce à vérifier plutôt que de laisser un pair choisir combien de
mémoire il occupe. On ne vérifie pas non plus ce qu'on refuse : dépenser une clé
et une exponentiation pour un message qu'on jette offrirait de faire travailler
la machine sans rien livrer.

**La signature à l'émission est écrite depuis le 2026-08-29.** `Signer` compose
le champ, le relit avec le même analyseur que le vérificateur, condense ce qu'il
vient d'écrire, et le signe. Cette relecture est le seul endroit où l'on vérifie
que ce qu'on écrit est ce qu'on croit écrire — et c'est elle qui refuse une
signature qui ne couvrirait pas `from`.

Deux choses ne s'écrivent pas, et les deux sont des décisions : **`l=`**, parce
que la borne de corps laisse ajouter ce qu'on veut après les `n` premiers octets
(§8.2) ; et **l'heure**, qui vient de l'appelant parce que cette crate n'a pas
d'horloge (C1).

### Personne n'appelle encore le signataire, et c'est dit

Le relais entrant est refusé explicitement (`RelayDenied`), et une signature n'a
de sens qu'à l'émission. Le signataire est donc écrit, couvert et fuzzé, mais
**aucun chemin ne l'emprunte** — il attend qu'un message sorte d'ici. C9 demande
« DKIM en signature et en vérification » : la première moitié existe, la seconde
tourne.

Depuis le 2026-08-29, ce serveur SAIT ÉMETTRE : le client SMTP sortant est écrit
et éprouvé (voir plus bas). Ce qui manque au signataire n'est donc plus le
transport, mais un message à signer — c'est-à-dire une soumission, ou l'envoi des
rapports.

**DMARC est commencé depuis le 2026-08-29** : la grammaire de l'enregistrement
`_dmarc` (§6.3), l'alignement (§3.1) et le verdict (§6.6.2). Couvert à 100 % (C2)
et fuzzé sur six propriétés, dont la symétrie de l'alignement et le fait que le
mode strict est plus étroit que le relâché — l'inverse ferait qu'un domaine qui
durcit sa politique laisserait passer davantage.

### Ce que DMARC ajoute, et pourquoi il fallait les deux autres d'abord

SPF autorise un domaine d'ENVELOPPE ; DKIM en fait signer un autre. Ni l'un ni
l'autre ne parle du `From:` — la seule ligne que l'humain lira. Un message peut
donc passer les deux sans que rien ne dise quoi que ce soit de son auteur
affiché : il suffit d'émettre depuis un domaine qu'on détient, de le signer, et
d'écrire ce qu'on veut dans le `From:`.

### Le domaine organisationnel est DEMANDÉ, pas deviné

L'alignement relâché compare des domaines organisationnels, et il n'existe
aucune règle syntaxique pour les trouver : il faut la liste des suffixes
publics. Une implémentation naïve — « les deux dernières étiquettes » — ferait
aligner `attaquant.co.uk` avec `victime.co.uk`. La crate demande donc la réponse
par un trait, et n'en fournit aucune implémentation : **celui qui répond doit
savoir ce qu'il répond.** C'est le même partage que pour les questions DNS de
SPF, et pour la même raison.

**Le câblage est là depuis le 2026-08-29**, et il a demandé les trois choses qui
manquaient. Le domaine du `From:` : `ams_mime::author_domain` le lit, en
traversant les commentaires et en REFUSANT un champ qui porte plusieurs auteurs
(§6.6.1) — avec deux auteurs, il y a deux politiques et rien pour dire laquelle
s'applique. La liste des suffixes publics : un fichier nommé dans la
configuration. Et un endroit où refuser : le point final du `DATA`, où le verdict
arrive enfin.

C'EST LE SEUL ENDROIT DU SERVEUR OÙ UN MESSAGE EST REFUSÉ POUR CE QU'IL PRÉTEND
ÊTRE. SPF refuse une enveloppe, le garde refuse un débit, la session refuse une
syntaxe. La réponse le nomme — `550 5.7.1 … (DMARC)`, et non le `554` générique :
le pair n'a rien à corriger chez lui, et l'envoyer chercher la faute au mauvais
endroit ne sert personne. Éprouvé jusqu'au binaire : un message dont le `From:`
dit `banque.test` et dont rien ne s'aligne reçoit son 550 et n'est pas remis ;
le message aligné qui suit passe.

### La quarantaine n'est pas encore un endroit

`p=quarantine` demande de traiter le message comme suspect. Ce serveur n'a pas de
dossier pour cela : il le REMET, et consigne la demande. Le refuser serait faire
plus que ce que le domaine a demandé ; le taire serait faire moins que ce qu'on
sait.

### Les rapports agrégés, depuis le 2026-08-29

Sans rapports, un domaine durcit sa politique à l'aveugle : il découvre ses
propres prestataires oubliés en même temps que ses correspondants découvrent que
son courrier ne passe plus. C'est la raison pour laquelle tant de domaines
restent à `p=none` pour toujours. Les rapports agrégés (§7.2) sont maintenant
**comptés, composés, nommés, compressés et déposés**.

Un rapport est un DÉNOMBREMENT, jamais une copie : on n'y met aucun message,
seulement combien il en est venu de telle adresse et ce qu'on en a conclu. Deux
messages qui se ressemblent — même source, même conclusion, mêmes identifiants —
ne font qu'une ligne, et c'est ce qui garantit qu'un rapport ne dit jamais rien
d'un message en particulier.

ON RAPPORTE CE QU'ON A FAIT, JAMAIS CE QUI ÉTAIT DEMANDÉ. Un message que
`p=quarantine` visait et que ce serveur a remis se rapporte `none`, parce que
c'est la vérité. Écrire `quarantine` ferait croire à un domaine qu'il est protégé
là où il ne l'est pas, et c'est le seul mensonge qu'un rapport ne peut pas se
permettre.

### SANS LE CONTRÔLE DE §7.1, DMARC EST UN AMPLIFICATEUR

Un enregistrement DMARC est public, et personne ne vérifie qui le publie pour son
propre domaine. Rien n'empêche donc quiconque d'écrire, sous un domaine qu'il
détient, `rua=mailto:victime@banque.test`, puis d'émettre en masse du courrier
prétendant venir de là : chaque receveur du monde qui applique DMARC compose
alors un rapport et l'envoie — à la victime. Le coût est payé par des tiers de
bonne foi, et le volume est multiplié par le nombre de receveurs. Une attaque par
réflexion, montée avec un seul enregistrement DNS.

La parade tient en une phrase : *quand la destination n'est pas dans le domaine
qui l'a demandée, c'est à la DESTINATION de dire qu'elle accepte*. Elle le fait
en publiant `<domaine-demandeur>._report._dmarc.<sa-zone>` — un nom que
l'attaquant ne peut pas écrire, puisqu'il est chez la victime. Ce serveur le
vérifie une fois par période et par domaine, et **une panne de résolution ne vaut
pas un consentement**.

La comparaison se fait sur les domaines eux-mêmes, pas sur leurs domaines
organisationnels : se tromper dans le sens strict coûte une interrogation DNS ;
se tromper dans l'autre autorise un envoi que personne n'a accepté.

### La remise des rapports, depuis le 2026-08-29

Les rapports sont désormais **composés, déposés, puis remis** — et les deux
derniers gestes sont séparés par un dossier. Ce n'est pas une commodité : c'est
ce qui fait qu'un rapport composé survit à un redémarrage, à une panne de réseau,
à un serveur d'en face qui ne répond pas ce jour-là.

CE QUI EST REMIS EST RETIRÉ, ET CE QU'ON REFUSE AUSSI. Un `5yz` retire le
rapport : insister remplirait le dossier de messages que personne ne veut, et
harcèlerait un serveur qui a dit non. Un refus temporaire, lui, laisse le fichier
en place — c'est tout l'intérêt de l'avoir écrit sur un disque. Et **un rapport
de plus de sept jours s'efface** : sans cette borne, un domaine injoignable ferait
croître le dossier sans fin, et l'on réessaierait des années durant d'envoyer le
compte d'une journée que plus personne ne peut exploiter.

REMETTRE NE SE DÉCIDE PAS À LA PLACE DE CELUI QUI EXPLOITE LA MACHINE. Le défaut
dépose et n'envoie rien ; `--dmarc-send` remet. Émettre du courrier vers des
tiers en son nom est une décision, et elle se prend une fois, explicitement.

Le message qui porte un rapport est un `multipart/mixed` : un texte d'explication
et le XML gzippé en base64. Il est composé par `ams-mime`, qui a gagné pour
l'occasion **un troisième base64** — celui-ci replie en `CRLF` seul, là où celui
de DKIM replie en `CRLF` suivi d'une espace, parce qu'un corps MIME n'est pas un
en-tête et que l'espace de continuation ferait partie des données. Trois usages,
trois règles de pliage, trois analyseurs : les partager ferait qu'un jour, en
corrigeant l'un, on casserait les deux autres.

Le texte d'explication est **en anglais**, et c'est délibéré : ce message part
vers des systèmes et des opérateurs du monde entier, dont la seule langue commune
est celle-là — et le composeur n'admet que de l'ASCII, ce qui exclut d'écrire un
français correct.

### Les rapports d'échec, depuis le 2026-08-29

`ruf=` est servi (RFC 6591, sur RFC 5965), et c'est la partie de DMARC qu'il faut
approcher avec le plus de précautions.

UN RAPPORT AGRÉGÉ EST UN DÉNOMBREMENT ; UN RAPPORT D'ÉCHEC PORTE LE COURRIER DE
QUELQU'UN. Le premier ne dit rien d'un message en particulier ; le second dit
tout d'un message précis — d'où il vient, ce qu'il prétendait être, ce qu'on en a
fait — et il part chez le domaine qu'on rapporte, c'est-à-dire, quand cela
compte, **chez celui qui usurpe**. Ce qu'on y met, on le lui donne. C'est une des
raisons pour lesquelles tant de receveurs n'en envoient aucun.

Trois décisions découlent de là, et elles sont prises dans le code plutôt que
laissées à un réglage.

**On ne recopie pas le corps.** La partie jointe est un `text/rfc822-headers`
(RFC 6522 §4), pas un `message/rfc822`. Le corps d'un message est ce qu'une
personne a écrit ; il n'apprend rien sur une authentification.

**ON NE RECOPIE MÊME PAS TOUS LES EN-TÊTES.** `ams_mime::EXPOSES` est une liste
BLANCHE, et le reste tombe : ce qui reste sert à comprendre un échec
d'authentification — ce que le message prétendait être, et les traces de ce qu'on
a vérifié — ce qui tombe parle de tiers (`To`, `Cc`) ou de nos machines (chaque
`Received` décrit un chemin interne que personne n'a demandé à publier). Une
liste noire aurait été plus douce et se serait trompée : le jour où un en-tête
nouveau porte une donnée personnelle, une liste noire le laisse passer, une liste
blanche l'arrête sans qu'on ait rien à faire. Le champ `Original-Rcpt-To` de la
RFC 6591 §3.2 n'est pas écrit non plus : dire à celui qui usurpe QUI a reçu son
message serait lui livrer ce qu'il cherchait.

Le `Subject:`, lui, y est. Le rapport part chez le domaine du `From:` : si le
message est légitime et mal configuré, ce sujet est le sien ; s'il est usurpé, ce
sujet est celui de l'attaquant. Dans les deux cas il n'appartient pas à celui qui
a reçu le message — et il est ce qui permet à un domaine de reconnaître son
propre flux.

**SANS PLAFOND, UNE USURPATION EN MASSE DEVIENT UN DÉLUGE.** Un rapport d'échec
part par message : quelqu'un qui usurpe un domaine cent mille fois nous ferait
écrire cent mille messages à ce domaine, qui n'a rien demandé de tel et qui en
subirait les conséquences à notre place (RFC 6591 §5). Cent par période et par
domaine : assez pour comprendre un flux mal configuré, trop peu pour nuire.

`fo=` dit quand un rapport est dû, et son défaut est le plus étroit : sans lui,
un domaine n'en reçoit que si RIEN n'a réussi. Les quatre demandes se cumulent
(`fo=1:d:s`), et `d` comme `s` regardent le mécanisme lui-même, alignement mis à
part — une signature fausse sur un message par ailleurs aligné se rapporte, et
c'est tout leur intérêt. Une valeur qu'on ne comprend pas fait ÉCARTER
l'enregistrement : un domaine qui demande autre chose que `0`, `1`, `d` ou `s` ne
demande pas « ce qui était prévu par défaut ».

Et, comme pour les agrégés, une destination externe doit avoir consenti (§7.1)
avant de recevoir quoi que ce soit. Le défaut, enfin, n'en compose aucun :
`--dmarc-failure-reports` le demande.

## IMAP : le découpage, depuis le 2026-08-29

IMAP N'EST PAS UN PROTOCOLE DE LIGNES, et c'est ce qui le rend délicat. SMTP et
POP3 se lisent ligne par ligne : un `CRLF`, une commande. IMAP non — une commande
peut porter un LITTÉRAL, `{42}` suivi d'un `CRLF` puis de quarante-deux octets
bruts qui peuvent contenir tout ce qu'on veut, `CRLF` compris, et la commande
continue après. Chercher le premier `CRLF` pour découper cela, c'est offrir à un
client de faire lire n'importe quoi comme une commande.

Ce découpage est donc la première chose écrite, avant tout vocabulaire d'argument
— un serveur IMAP qui découpe mal est un serveur qu'on fait lire ce qu'on veut,
**avant toute authentification**.

### Deux formes de littéral, et une seule est sûre par construction

`{42}` est synchronisant : le client attend un `+` du serveur, qui peut donc
refuser avant de rien lire. `{42+}` (RFC 7888) ne l'est pas — les octets suivent
immédiatement, et le serveur n'a aucun moyen de dire non. C'est pourquoi la
RFC 9051 §6.3.11 les borne à quatre kibioctets, et pourquoi **cette borne-là
n'est pas la nôtre à choisir** : toutes les autres bornes de ce module sont
décidées ici, et les noms de champ ne prétendent pas le contraire — la RFC 9051
n'en donne qu'une, les 8192 octets d'une ligne (§4).

### L'accolade se cherche en dehors des guillemets

`a001 LOGIN "toto{5}" x` ne porte aucun littéral : l'accolade y est dans une
chaîne. La chercher sans suivre les guillemets — et sans traiter le guillemet
échappé — laisserait le client choisir où l'on découpe.

### LE TAG EST RECOPIÉ DANS LA RÉPONSE

IMAP entrelace les commandes ; c'est le tag qui dit à quelle commande une réponse
répond, et le serveur le recopie verbatim (§7). Un `CRLF` dedans écrirait une
réponse entière de la main du client ; un `*` en ferait une réponse non
sollicitée ; un `+` une demande de continuation, à laquelle le client répondrait
par des octets que le serveur lirait comme une commande. Ce ne sont pas des cas
particuliers : ce sont les trois formes que prend une réponse IMAP. La grammaire
de la RFC les exclut déjà du tag, et ce module l'applique à la lettre plutôt que
de faire confiance.

Le tag est aussi borné à trente-deux octets — il est recopié, donc un tag de deux
kibioctets ferait une réponse de deux kibioctets pour un client qui n'a rien
demandé de tel.

### Les arguments, sous leurs trois écritures

Un argument IMAP est un atome, une chaîne ou un littéral, et le client choisit. Un
serveur qui n'en lit que deux refuse du courrier légitime ; un serveur qui les
confond laisse le client décider de ce qu'il lit. La valeur ne se rend pas par
emprunt — `"a\"b"` vaut trois octets là où la source en porte cinq — et s'écrit
donc dans le tampon de l'appelant.

Un détail trouvé par un test avant que le fuzz n'ait à le chercher : **une faute
arrête la lecture**. Aucune des trois écritures ne sait où reprendre après ce
qu'elle n'a pas compris, et rendre la faute sans avancer faisait un itérateur qui
la répétait sans fin — un appelant qui collectait n'en voyait jamais la fin.

### La session, depuis le 2026-08-29

Quatre états (§3), et c'est l'état qui décide de tout. `SELECT` avant
authentification est une commande parfaitement FORMÉE : c'est l'état qui la
refuse, pas la grammaire.

UN MOT DE PASSE NE TRAVERSE PAS UNE CONNEXION EN CLAIR. `LOGIN` et `AUTHENTICATE
PLAIN` sont tous deux refusés hors chiffrement, avec le `[PRIVACYREQUIRED]` que
la RFC 9051 prévoit — annoncer `LOGINDISABLED` sans refuser laisserait un client
mal écrit envoyer le mot de passe quand même.

De cet invariant découle une simplification qui se lit dans le code : on ne peut
pas être authentifié sans être chiffré, donc `STARTTLS` n'a pas à vérifier
l'état. Une comparaison de plus serait une garde qu'aucune entrée ne peut faire
céder — et le fuzz éprouve l'invariant lui-même, sur des suites de commandes
arbitraires.

`STARTTLS` efface tout ce qui précède (§6.2.1) : ce qui a été dit en clair a pu
être dit par quelqu'un d'autre.

QUAND LE TAG EST ILLISIBLE, LA RÉPONSE EST NON SOLLICITÉE. Une réponse conclut la
commande que son tag désigne ; si le tag lui-même est irrecevable, il n'y a rien à
désigner — et le recopier pour le dire serait précisément l'injection que sa
validation ferme.

### Ce qui n'y est pas

**Les boîtes.** `SELECT`, `LIST`, `FETCH` et les autres sont reconnus, leur état
est vérifié, et la session répond `NO [UNAVAILABLE]` — `NO` et non `BAD`, parce
que la commande est correcte et permise et que c'est ce serveur qui ne la sert
pas. Les servir demande un magasin qui porte des UID stables et des marques
persistantes, ce que Maildir ne fait pas seul et ce à quoi `ams-index` existe.
`APPEND` demandera en plus un chemin qui écoule au fil de l'eau, comme le `DATA`
de SMTP : la borne d'un littéral est de soixante-quatre kibioctets, ce qui suffit
à un nom de boîte ou à une recherche, et pas à un message.

### La boucle, depuis le 2026-08-29

Le port 143 écoute (`--listen-imap`). Le pilote ne sait du protocole que trois
choses : qu'une commande ne se découpe pas au premier `CRLF`, qu'une réponse
s'écrit telle quelle, et que la session lui dit quoi faire ensuite.

LE TAMPON GRANDIT, ET IL EST BORNÉ PAR LA GRAMMAIRE. Les pilotes SMTP et POP3
lisent dans un tampon de taille fixe : une ligne y tient ou n'y tient pas. La
longueur d'une commande IMAP, elle, n'est connue qu'en la lisant. Ce qui empêche
le tampon de croître sans fin n'est donc pas une taille choisie dans le pilote,
mais les bornes du découpage — refusées **avant** que le moindre octet ne soit
lu. C'est la raison pour laquelle la borne d'un littéral est passée d'un
mébioctet à soixante-quatre kibioctets : ce que la grammaire admet, une connexion
doit pouvoir le retenir.

UNE COMMANDE INDÉCODABLE FERME LA CONNEXION. Quand la syntaxe est fautive, on ne
sait plus où la commande se termine ; reprendre la lecture laisserait le client
choisir ce qu'on lira comme une commande. Un tag illisible, lui, ne ferme rien :
la commande était lisible, c'est son tag qui ne l'était pas.

Après `STARTTLS`, le tampon est vidé lui aussi : ce qui restait à lire a été
envoyé en clair, donc peut-être par quelqu'un d'autre, et le traiter après la
poignée de main reviendrait à lui faire confiance.

Éprouvé jusqu'au binaire : bannière avec `LOGINDISABLED`, `LOGIN` refusé en
clair, `STARTTLS`, capacités qui deviennent `AUTH=PLAIN`, `LOGIN` par littéral
synchronisant avec sa demande de continuation, `LOGOUT`.

## Les boîtes IMAP, depuis le 2026-08-29

`SELECT`, `EXAMINE`, `CLOSE`, `UNSELECT`, `LIST`, `STATUS`, `FETCH` et `UID
FETCH` servent maintenant la boîte du compte. Une par compte, nommée `INBOX` — le
nom que la RFC 9051 §5.1 réserve pour cela.

AUCUN CHEMIN N'EST CONSTRUIT À PARTIR D'UN NOM DE BOÎTE. Le nom vient du client.
`INBOX` est comparé à une constante, et la boîte qu'il désigne est celle que la
table des comptes a déjà ouverte au démarrage. Un nom qui n'est pas `INBOX`
n'ouvre rien : il ne devient jamais un morceau de chemin, et il n'y a donc aucune
traversée de répertoire à empêcher.

UN MESSAGE NE PASSE JAMAIS PAR LA SESSION (C1, C3). `FETCH` peut demander dix
mégaoctets ; les retenir pour les écrire ensuite donnerait au client le droit de
choisir combien de mémoire le serveur consomme. La session rend un *intervalle* —
« le message 3, de l'octet 0 à l'octet 4 812 » — et le pilote l'écoule par
tranches, en lisant par la boîte ouverte. ON A ANNONCÉ UNE LONGUEUR, ET ON LA
TIENT : si le magasin s'arrête plus tôt, le manque est comblé plutôt que de
désynchroniser un client qui compte les octets qu'on lui a promis.

LE COÛT D'UN `FETCH` EST BORNÉ DES DEUX CÔTÉS. Un ensemble de séquences ne rend
pas plus de `max_sequence_items` intervalles, une liste pas plus de
`max_fetch_items` éléments, et la boîte a un nombre fini de messages : le produit
que le client peut faire faire au serveur est donc borné avant toute lecture. La
lecture, elle, appartient à la BOÎTE OUVERTE et non au magasin — la demander au
magasin l'obligerait à retrouver le message à chaque tranche de quelques
kibioctets, c'est-à-dire à relire le répertoire, et un `FETCH 1:* BODY[]` sur dix
mille messages y deviendrait quadratique à la demande du client.

LA CONCLUSION ÉTIQUETÉE EST LE DERNIER MORCEAU. §7 veut que les réponses non
sollicitées précèdent la conclusion de leur commande. La rendre d'avance
obligeait le pilote à la retenir et à l'écrire après les données — un ordre
qu'aucun type ne lui rappelait. Il l'a inversé, et **c'est l'essai contre le vrai
binaire qui l'a montré**, pas les tests : ceux-ci lisaient les octets dans le
bon ordre parce qu'ils les lisaient tous d'un coup.

DEUX LECTURES D'UN MÊME ENSEMBLE DOIVENT S'ACCORDER. `contains` répond « ce
message est-il demandé ? » (chemin `UID FETCH`), `ranges` énumère lesquels le
sont (chemin de l'émission). Se contredire rendrait un message à qui ne l'a pas
demandé. Une cible de fuzz les confronte : quinze millions d'entrées, aucune
divergence. Les surprises de la §9 y sont — `*` vaut le dernier message, un
intervalle n'est pas ordonné (`25:*` sur trois messages vaut `3:25`), et sur une
boîte vide `1:*` ne rend rien plutôt que le message zéro.

IMAP NE VERROUILLE PAS, PARCE QU'IL N'ÉCRIT PAS. POP3 prend le verrou exclusif de
la boîte : il efface, et la RFC 1939 §3 le lui demande. Une session IMAP dure des
heures ; le même verrou interdirait toute relève POP3 pendant ces heures, et
s'interdirait à lui-même — `STATUS INBOX` sur une boîte déjà sélectionnée se
heurtait à son propre verrou et répondait qu'elle n'existe pas, ce que l'essai
contre le binaire a montré aussi. IMAP relève donc sans verrouiller, ce pour quoi
Maildir est fait : un message est un fichier qui ne change plus une fois déposé.
Ce qu'on accepte en échange est un message effacé en cours de session — cas qu'il
fallait tenir de toute façon, puisque rien n'empêchait sa disparition entre
l'annonce de sa taille et son écriture.

`[READ-WRITE]` EST UNE PROMESSE, ET C'EST LE MAGASIN QUI LA TIENT. Tant que rien
ne s'écrit — ni `STORE`, ni `APPEND`, ni `EXPUNGE` — `SELECT` répond
`[READ-ONLY]`, avec `PERMANENTFLAGS ()`. Une session qui affirmerait la
modifiabilité qu'elle ne peut pas connaître ferait une promesse que le client ne
verrait démentie qu'en essayant.

Ce qui n'est toujours pas servi : une PARTIE désignée — `BODY[1]`, `BODY[1.MIME]`.

Éprouvé jusqu'au binaire, contre un vrai Maildir rempli par SMTP : `LIST`,
`SELECT INBOX` et ses sept réponses, `STATUS` sur la boîte sélectionnée,
`FETCH 1:* (UID FLAGS RFC822.SIZE INTERNALDATE)`, `FETCH 1 BODY.PEEK[]` dont les
octets sont ceux du fichier, `BODY.PEEK[HEADER]`, `UID FETCH 2 BODY.PEEK[TEXT]
<4.6>`, `CLOSE`, et un `FETCH` refusé une fois la boîte refermée.

## `STORE` : écrire dans un Maildir, depuis le 2026-08-29

Dans un Maildir, LES DRAPEAUX VIVENT DANS LE NOM DU FICHIER : les écrire, c'est
renommer. Trois questions qu'aucun protocole ne tranche, et qui se tranchent ici.

ON N'ÉCRIT PAS CE QU'ON CROIT SAVOIR, ON ÉCRIT CE QU'ON VIENT DE LIRE. Les
drapeaux sont relus dans le nom du fichier à l'instant du renommage, et non dans
l'instantané pris à l'ouverture. Deux `+FLAGS` concurrents se composent alors, au
lieu que le second efface ce que le premier venait de poser. Un `FLAGS` nu écrase
— mais c'est ce que le client a demandé : `+`/`-` fusionnent, `FLAGS` remplace.

LE NOM QU'ON LIT DOIT ÊTRE CELUI QUI EXISTE. Quand le renommage échoue, le
message a bougé : on le retrouve par son UID — le seul identifiant qui survive à
un changement de drapeaux — et l'on recommence, trois fois au plus. Trois échecs
de suite ne sont plus une course, c'est un autre programme qui remue la boîte, et
insister ne ferait que l'accompagner.

**Le piège n'était pas là où on l'attendait.** C'est le raccourci « rien à
écrire » qui mordait : il concluait à partir d'un nom disparu, et répondait `OK`
sans avoir rien écrit. Un `STORE` qui ment sur ce qu'il a fait est pire qu'un
`STORE` qui échoue. Le raccourci vérifie maintenant que le fichier est là, et le
défaut a été trouvé en renommant un message sous les pieds du binaire — aucun
test unitaire ne l'aurait vu, faute de système de fichiers.

`P` N'EST PAS DANS LE VOCABULAIRE D'IMAP, DONC IMAP NE PEUT PAS LE RETIRER.
Maildir a six lettres, IMAP cinq drapeaux, et `P` (*passed*) n'a pas
d'équivalent. Un `FLAGS (\Seen)` demande « exactement `\Seen` » dans le
vocabulaire du client, qui ne sait pas dire `P` : le lui faire effacer serait lui
prêter une intention qu'il ne pouvait pas former.

UN DRAPEAU INCONNU EST REFUSÉ : un client à qui l'on répond `OK` croit son
étiquette posée, et ne la reverra jamais.

UNE SEULE VÉRITÉ SUR CE QUI S'ÉCRIT. La boîte énumère les drapeaux qu'elle sait
faire survivre ; `PERMANENTFLAGS` les cite, `SELECT` répond `[READ-ONLY]` quand
il n'y en a aucun, et `STORE` refuse ce qui n'y figure pas. Une seconde méthode
« est-elle modifiable ? » aurait fini par ne plus dire la même chose.

CE QUI SE PERD, ET CE QUI NE SE PERD PAS. Deux sessions qui marquent le même
message ne s'effacent pas l'une l'autre — vérifié sur le binaire, deux connexions
IMAP simultanées, `+FLAGS (\Seen)` d'un côté et `+FLAGS (\Flagged)` de l'autre :
le fichier porte les deux lettres. En revanche une session ne VOIT pas ce qu'une
autre vient de poser : son instantané fixe les rangs et les noms pour toute la
sélection, et le relire à chaque `FETCH` coûterait un parcours de répertoire par
commande. Elle le verra à la prochaine sélection. C'est une limite, elle est dite,
et elle ne fait perdre aucune marque — seulement du retard à en rendre compte.

`STORE` emprunte la machine d'émission de `FETCH` : §6.4.6 veut qu'un `STORE` non
silencieux rende une réponse `FETCH` par message modifié — mêmes réponses, même
ordre, même ensemble. Les écrire deux fois aurait fait deux codes qui divergent.
Et l'implicite `\Seen` d'un `BODY[…]` sans `PEEK` (§6.4.5) est devenu un `STORE`
comme un autre, ce qui a retiré une méthode au lieu d'en ajouter une.

Éprouvé jusqu'au binaire, contre un vrai Maildir : les trois verbes, `.SILENT`,
`UID STORE`, le refus de `\Deleted`, la survie des drapeaux d'une session à
l'autre, la lecture du corps après renommage, un message renommé sous nos pieds
(deux fois, avec et sans changement à écrire), et un message effacé pendant la
commande — qui ne la fait pas échouer.

## `EXPUNGE` : effacer pour de bon, depuis le 2026-08-29

`\Deleted` n'est plus refusé, parce que quelque chose l'honore enfin. `EXPUNGE`
efface les messages qui le portent, `UID EXPUNGE` s'en tient à l'ensemble qu'on
lui nomme (§6.4.9), et `CLOSE` efface en refermant (§6.4.2) — là où `UNSELECT`
referme sans rien effacer, ce pour quoi il existe.

CHAQUE `* n EXPUNGE` RENUMÉROTE CE QUI SUIT (§7.5.1). Effacer les messages 1 et 3
d'une boîte de trois ne s'annonce pas « 1 puis 3 » mais « 1 puis 2 » : après le
premier, l'ancien troisième est devenu le deuxième. Un serveur qui annoncerait
les rangs d'origine ferait effacer au client un message qu'il voulait garder.

ON N'EFFACE PAS SUR UNE CROYANCE PÉRIMÉE. La session demande d'effacer ce que son
instantané dit marqué ; le magasin relit les lettres dans le nom du fichier à
l'instant d'effacer, et REFUSE si la marque n'y est plus. Le refus ne s'annonce
pas : annoncer un effacement qui n'a pas eu lieu ferait perdre au client le fil
des numéros. La dissymétrie est voulue — un courrier perdu ne se retrouve pas,
un courrier qui survit une session de trop s'efface au prochain `EXPUNGE`.

`NotFound` NE VEUT PAS DIRE « DÉJÀ PARTI ». Dans un Maildir, un message
introuvable sous son nom a le plus souvent changé de nom : quelqu'un a écrit ses
drapeaux. **Le prendre pour une disparition faisait oublier de la boîte un
message bien vivant** — et pire, le déclarait « effacé » sur la foi de lettres
lues dans un nom qui n'existait plus. On le retrouve par son UID, et l'on
recommence, trois fois au plus. Trouvé sur le binaire, en retirant une marque
sous ses pieds ; les tests unitaires ne pouvaient pas le voir, faute de système
de fichiers.

UNE BOUCLE QUI N'AVANCE PAS REMPLIT LA MÉMOIRE (C3, C7). L'effacement n'avance
pas le rang courant : ce qui suivait descend à sa place, et il faut l'examiner à
son tour. Le tour ne se termine donc que parce que la boîte rétrécit — ce que la
session ne peut pas vérifier. Elle ne compte pas dessus : elle n'efface jamais
plus de messages que la boîte n'en portait, et `CLOSE` porte la même borne. Ce
n'est pas de la prudence abstraite : un itérateur qui ne consommait pas son
entrée a déjà tué cette machine, 6 Gio en quelques secondes. La cible
`fuzz_ams_session_imap` en fait désormais une propriété — l'émission doit
CONCLURE, et une boîte d'épreuve qui rétrécit vraiment lui donne de quoi tourner.

Éprouvé jusqu'au binaire, contre un vrai Maildir : la renumérotation (les
fichiers 1 et 3 partent, les UID 2 et 4 restent), un `UID EXPUNGE` qui ne touche
que son ensemble, une marque retirée sous nos pieds qui fait survivre le message,
un message effacé par ailleurs qui s'annonce quand même effacé, `CLOSE` qui
efface sans rien annoncer, et `EXAMINE` puis `EXPUNGE` qui répond
`NO [CANNOT] Mailbox is read-only`.

## `SEARCH` : un arbre sans allocation, depuis le 2026-08-29

IMAP4rev2 A REMPLACÉ `* SEARCH` PAR `* ESEARCH` (§7.3.4). La réponse
`* SEARCH 2 4 5 6 7` de rev1 a disparu ; rev2 rend
`* ESEARCH (TAG "a001") ALL 2,4:7`, où les résultats sont un ENSEMBLE et non une
liste. Ce serveur n'annonce que `IMAP4rev2` : rendre l'ancienne forme à un client
qui a lu l'annonce serait le tromper.

ON COMPRIME EN AVANÇANT, SANS RIEN RETENIR. Savoir si le résultat suivant
prolonge le précédent tient dans deux entiers — la plage ouverte. Tout retenir
pour comprimer à la fin demanderait une mémoire que le client choisirait.

C'EST LA SEULE RÉPONSE QUI NE TIENNE PAS FORCÉMENT DANS UN MORCEAU. Une ligne
`ESEARCH` peut dépasser le tampon : elle se découpe, et le découpage ne change
pas ce que le client lit — éprouvé sur toutes les tailles de un à soixante-quatre
octets. Chaque morceau s'écrit d'un seul geste : composé dans un tampon fixe par
des routines qui ne peuvent pas échouer, puis poussé une fois. Découvrir le
manque de place au milieu d'une plage laisserait un résultat à moitié écrit, que
le client lirait comme un résultat faux. Et un tampon qui suffit à l'en-tête sans
suffire à la première plage le DIT, au lieu de rendre indéfiniment du vide — ce
qui serait une boucle sans fin chez l'appelant, née d'un tampon chez nous.

UN ARBRE SANS ALLOCATION, ET SANS CYCLE POSSIBLE (C1, C3). `NOT`, `OR` et les
parenthèses font de `SEARCH` une expression. Les nœuds vivent dans un tableau de
soixante-quatre places et se désignent par leur indice — et **un nœud ne
référence que des indices strictement inférieurs**, parce qu'un enfant est rangé
avant son parent. Ce n'est pas une convention qu'on espère tenir : c'est la seule
façon dont le tableau se remplit, et elle rend le cycle impossible. L'évaluation
descend donc toujours, et se termine sans compteur de tours. L'imbrication est
bornée à huit : sans quoi `NOT NOT NOT …` ferait descendre l'analyseur aussi
profond que le client le demande, et la pile n'est pas extensible.

Deux gardes inatteignables ont été retirées plutôt que couvertes : l'accès au
tableau de nœuds est devenu un PARCOURS TOTAL — soixante-quatre comparaisons
bornées, comme « vingt chiffres majorent tout `u64` » ailleurs — et l'indice des
nœuds est un `u16`, ce qui a fait disparaître une conversion qui ne pouvait pas
échouer.

CE QUI EST CHERCHÉ, ET CE QUI EST REFUSÉ. Tout ce qui se décide avec ce que la
boîte sait déjà : `ALL`, les cinq drapeaux et leurs formes `UN…`, `LARGER`,
`SMALLER`, `BEFORE`/`ON`/`SINCE`, `UID <ensemble>`, un ensemble de rangs, et
leurs combinaisons. RIEN qui demande de lire le message — `BODY`, `TEXT`,
`SUBJECT`, `FROM`, `HEADER` sont reconnus et REFUSÉS, parce qu'un
`SEARCH SUBJECT "facture"` répondant « aucun résultat » serait un mensonge exact.
Le jeu de caractères se lit et se refuse de même : chercher dans un encodage
qu'on ignore ferait rendre n'importe quoi, et `NO [BADCHARSET]` est le code que
la RFC prévoit.

Éprouvé jusqu'au binaire, contre un vrai Maildir : `ALL`, `LARGER`, `SMALLER`,
`UNSEEN`/`SEEN`, `NOT`, `OR`, les parenthèses, les trois formes de date, `UID
SEARCH`, la compression (`1,3:4` et `1:2,4`), une recherche sans résultat qui
omet `ALL`, trente-quatre messages dont un sur deux marqué — seize plages sur UNE
ligne — et les deux refus.

## `COPY` : tout ou rien, depuis le 2026-08-29

`COPY` et `UID COPY` copient dans la boîte nommée. `INBOX` est la seule qui
existe, donc la seule destination possible ; toute autre reçoit `NO [TRYCREATE]`,
le code qui apprend au client qu'un `CREATE` suivi du même `COPY` marcherait.

§6.4.7 : UN `COPY` N'EST PAS PARTIELLEMENT RÉUSSI. « If the server can't copy all
the messages, it should restore the destination mailbox to its state before the
COPY and return a tagged error. » Ce qui a été copié avant l'échec est donc
défait. Défaire ne demande rien à retenir : les UID attribués se suivent, donc ce
qu'il faut retirer est une plage — et l'on ne retire QUE cette plage, dont
personne d'autre ne détient les UID.

`COPYUID` DIT OÙ, OU NE DIT RIEN. L'ensemble de destination tient toujours en une
plage, puisque les UID sont attribués en croissant. Celui de source est ce que le
client a désigné, trous compris : sa longueur est choisie par le client. On
l'accumule dans un tampon borné, et s'il déborde on OMET `COPYUID` entièrement —
un ensemble tronqué désignerait d'autres messages que ceux qu'on a copiés, ce qui
est pire que de ne rien dire. C'est un `SHOULD` de la RFC, et un `SHOULD` tenu à
moitié ne vaut rien.

COPIER, C'EST DÉPOSER UN MESSAGE NEUF, avec la danse que Maildir impose et que la
remise SMTP connaît déjà : écrire dans `tmp/`, synchroniser, renommer. Les
drapeaux d'origine sont préservés en UN SEUL renommage — déposer puis renommer
laisserait la copie visible sans eux, et un client qui regarderait à cet instant
la croirait non lue. La date d'arrivée est celle de la copie : la reculer
demanderait une dépendance pour un `utimensat`, et §6.4.7 n'en fait qu'un
souhait. C'est dit ici plutôt que tu.

CE QU'ON PARCOURT NE DOIT PAS GRANDIR SOUS NOS PIEDS. Copier dans la boîte
ouverte l'agrandit ; relire le nombre de messages à chaque tour ferait de
`COPY 1:* INBOX` une boucle que le client n'aurait qu'à demander. Le nombre est
arrêté d'avance, comme pour `EXPUNGE`.

Éprouvé jusqu'au binaire, contre un vrai Maildir : `COPYUID` avec la validité de
la destination, des copies dont l'empreinte SHA-256 est celle de l'original, les
drapeaux préservés (`:2,FS` recopié, et le message sans drapeau resté dans
`new/`), `NO [TRYCREATE]` pour une boîte inconnue, et surtout **un message rendu
illisible en cours de commande** : la copie du précédent a bien été défaite, et
aucun UID neuf n'est resté.

## `MOVE` : copier puis retirer, depuis le 2026-08-29

§6.4.8 IMPOSE L'ORDRE DES RÉPONSES : d'abord `* OK [COPYUID …]`, non sollicité,
qui dit où les messages sont allés ; puis les `* n EXPUNGE` ; enfin la
conclusion. Le premier voyage comme réponse du tour et les autres comme morceaux
d'émission — c'est exactement l'ordre où l'appelant les écrit, sans qu'il ait
rien à se rappeler. Un premier essai les avait mis dans l'autre sens, et c'est
l'aide de test qui mentait : elle ajoutait la réponse du tour à la FIN, là où la
boucle l'écrit en tête. Corrigée, elle dit maintenant ce que le fil dit.

ON RETIRE PAR UID, MÊME QUAND LE CLIENT A DÉSIGNÉ DES RANGS. Retirer renumérote :
un ensemble de rangs cesserait de désigner ce qu'il désignait dès le premier
retrait. Les sources sont traduites en UID pendant la copie, et si cette
traduction ne tient pas dans ce qu'on sait nommer, le déplacement est REFUSÉ et
les copies défaites — retirer au hasard serait perdre du courrier.

RETIRER N'EST PAS EFFACER. `EXPUNGE` relit la marque `\Deleted` dans le nom du
fichier avant d'effacer ; `MOVE` n'a aucune marque à relire, puisqu'il retire un
message qu'il vient de copier sur ordre exprès. Le magasin porte donc deux
opérations distinctes, et le dit : les confondre ferait ou bien un `MOVE` qui ne
déplace rien, ou bien un `EXPUNGE` qui efface ce qu'on ne lui a pas demandé.

SI LA LIGNE `COPYUID` NE TIENT PAS, ELLE EST OMISE, et le déplacement a lieu
quand même. C'est un `SHOULD` ; échouer là laisserait les copies faites et les
retraits à faire, ce qui est bien pire que de ne pas dire où les messages sont
allés.

`si_selectionne` a disparu : plus aucune commande n'y menait, toutes les
commandes de boîte étant servies. Une fonction que rien n'appelle est une
affirmation que rien ne vérifie.

Éprouvé jusqu'au binaire, contre un vrai Maildir : le `COPYUID` non sollicité
avant deux `* 1 EXPUNGE` — le second vaut « 1 » parce que le premier a
renuméroté —, les UID d'origine disparus et les copies présentes, les drapeaux
préservés, `NO [TRYCREATE]` pour une destination inconnue, et **un message rendu
illisible en cours de commande** : rien n'a été retiré, et aucune copie n'est
restée.

## `APPEND` : un message qui ne séjourne nulle part, depuis le 2026-08-29

C'EST LA SEULE COMMANDE DONT UN ARGUMENT EST UN MESSAGE. Toutes les autres
tiennent dans ce qu'une connexion peut retenir ; celle-ci porte ce que le client
veut, et la retenir lui donnerait le droit de choisir combien de mémoire le
serveur consomme. Elle se lit en deux temps : la grammaire lit ce qui précède le
littéral, et le message s'écoule vers le magasin au fil de l'eau — exactement
comme le `DATA` de SMTP, et par la même danse Maildir.

`APPEND` NE PASSE DONC PAS PAR LE DÉCOUPAGE ORDINAIRE (C1, C3). Le pilote
reconnaît sa première ligne AVANT de découper, parce que découper voudrait dire
accumuler. Ce qui n'est pas de cette forme — un `APPEND` sans littéral, ou dont
le nom de boîte EST un littéral, ce qui est légal — retombe sur le chemin
ordinaire, qui le refuse en le disant : écouler ce littéral-là écrirait un nom de
boîte dans le courrier.

ON REFUSE AVANT D'INVITER. Un littéral synchronisant attend une invitation ; la
donner puis refuser ferait attendre le serveur pour des octets que le client
n'enverra jamais. **Le défaut a existé** : un test d'intégration a mis cinq
minutes au lieu d'une seconde, et c'est ce délai qui l'a montré. Une boîte
inconnue, une session non authentifiée, un message plus gros que la borne se
disent maintenant sans qu'un octet n'ait été lu. Un littéral NON synchronisant,
lui, part sans prévenir : ses octets arrivent quoi qu'on réponde, on les lit et
on les jette.

DEUX BORNES, ET CE NE SONT PAS LES MÊMES. `max_literal_octets` dit ce qu'une
connexion RETIENT ; `max_append_octets` dit ce qu'un MESSAGE pèse, et le serveur
lui donne la borne SMTP — un message qu'on refuserait de recevoir par un chemin
n'a pas de raison de passer par l'autre.

RIEN N'EST VISIBLE TANT QUE LE DÉPÔT N'EST PAS VALIDÉ, et un message tronqué ne
se dépose pas : si le pair raccroche au milieu, le dépôt est abandonné. Valider
ce qu'on a reçu déposerait du courrier que personne n'a envoyé.

LA DATE DEMANDÉE EST HONORÉE. §6.3.12 permet au client de donner la date-heure du
message ; `std::fs::File::set_times` la pose sur le fichier encore dans `tmp/`,
avant le renommage — donc avant que quiconque puisse le voir, et sans dépendance.
`INTERNALDATE` la relit à l'identique : lire ce qu'on écrit est la moindre des
cohérences, et c'est éprouvé dans les deux sens.

MESURÉ SUR LE BINAIRE, puisque c'est la question que cette commande pose : un
dépôt de neuf mébioctets ne coûte RIEN en mémoire résidente — quatre-vingts
dépôts laissent le serveur à 51,7 Mio, et la centaine de kibioctets qui s'ajoute
au fil des connexions est de la rétention d'allocateur, pas une fuite. Le message
ne séjourne nulle part : ni dans la session, ni dans le tampon du pilote.

## `CREATE` : là où un nom de client devient un chemin, depuis le 2026-08-29

Ce dépôt pouvait écrire en toutes lettres qu'AUCUN CHEMIN N'ÉTAIT CONSTRUIT À
PARTIR D'UN NOM DE BOÎTE : `INBOX` se comparait à une constante. `CREATE` met fin
à cette tranquillité, et la remplace par des règles qu'on peut lire.

ON REFUSE, ON NE TRANSFORME PAS. La RFC autorise beaucoup plus que ce serveur
n'accepte : de l'UTF-8, des points, des caractères qu'un système de fichiers lit
mal. Un nom qu'on ne saurait pas transcrire sans risque est refusé, jamais
adapté — rendre au client un nom qui n'est pas celui qu'il a demandé lui ferait
chercher longtemps, et transformer, c'est ouvrir la porte à ce qu'on ne voit pas.
Les règles tiennent en un endroit, `ams-proto-imap` : non vide et borné, découpé
sur `/` sans composant vide, profondeur bornée, AUCUN POINT — ce qui ferme `..` —
et de l'ASCII imprimable sans `\`, `%`, `*`, `"` ni `:`. L'espace est admis :
« Sent Messages » est un nom de dossier des plus ordinaires.

LA RÈGLE EST VÉRIFIÉE DEUX FOIS, par la session puis par le magasin. Non par
défiance de la première, mais parce que c'est le magasin qui touche le système de
fichiers : une vérification faite ailleurs est une vérification qu'on ne voit pas
en lisant l'endroit qui en dépend, et celle-ci survivra à un appelant qui
l'oublierait.

UN SEUL NIVEAU DE RÉPERTOIRES SUR LE DISQUE. `Archives/2026` devient
`.Archives.2026` dans la racine du compte, à la façon de Maildir++ : le chemin
n'a donc jamais plus d'un morceau venu du client. `fuzz_ams_imap_fetch` en fait
une propriété, vérifiée sur la TRANSCRIPTION elle-même — pas de séparateur, pas
de `..`, pas d'octet de contrôle — sur des noms arbitraires.

ON N'OUVRE QUE CE QUI EXISTE. `Maildir::open` crée l'arborescence qu'on lui
nomme : l'appeler sans regarder ferait de chaque `SELECT` sur une faute de frappe
une boîte de plus. Seul `CREATE` crée.

CRÉER `A/B/C` CRÉE AUSSI `A` ET `A/B` (§6.3.4) : en Maildir++ les parents sont
des répertoires frères, et les omettre ferait montrer par `LIST` une fille sans
sa mère.

LES NOMS SE CITENT DANS LES RÉPONSES, toujours plutôt que seulement quand c'est
nécessaire : ne citer que les noms qui en ont besoin demanderait une condition de
plus, qu'il faudrait avoir juste à chaque endroit.

Un cache borné par ce qui existe : ouvrir un Maildir relit son index et le
réécrit ; le refaire à chaque `LIST` coûterait un parcours de répertoire par
commande. Le cache ne grandit que d'une entrée par dossier RÉELLEMENT créé — un
client ne peut donc pas le faire enfler en nommant des boîtes au hasard.

Éprouvé jusqu'au binaire : `CREATE Archives`, puis `Archives/2026/Janvier` qui
crée bien ses deux parents, `"Sent Messages"` avec son espace, `LIST` qui les
rend tous cités, `STATUS` et `SELECT` qui les ouvrent, un `APPEND` dans un
dossier — et six noms dangereux (`../autrecompte`, `a/../../etc`, `Sent.2026`,
`/absolu`, un `%`) refusés sans qu'aucun répertoire n'apparaisse hors de la
racine du compte.

## `DELETE` : ce qui s'en va et ce qui reste, depuis le 2026-08-29

§6.3.5 : UNE BOÎTE QUI A DES FILLES NE DISPARAÎT PAS. Son courrier s'en va, son
NOM demeure, et il se marque `\Noselect`. Effacer le nom romprait la hiérarchie :
ses filles existeraient sans que personne puisse les atteindre.

SUR LE DISQUE, CELA SE DIT SANS MARQUEUR. Le répertoire reste, ses trois
sous-répertoires Maildir s'en vont : un nom sans `cur/` est `\Noselect`, et il le
reste tant qu'un `CREATE` ne le refait pas — ce que §6.3.4 autorise expressément.
C'est la même règle qui empêche `Maildir::open` de ressusciter une boîte effacée,
puisqu'il recrée ce qui manque : on n'ouvre que ce qui a un `cur/`.

L'INDEX PART AVEC LE COURRIER, et une boîte recréée reçoit une `UIDVALIDITY`
neuve. Le piège est la résolution de l'horloge : effacer puis recréer dans la
même seconde rendait la MÊME validité avec des UID repartis de un, et un client
qui a gardé ses UID aurait montré à son porteur des messages qui ne sont pas ceux
qu'il désigne — ce que §5.3.1 interdit précisément. `fresh_uid_validity` porte
donc un compteur : deux appels ne rendent jamais la même valeur, et l'horloge ne
sert qu'à faire avancer plus vite.

`INBOX` NE S'EFFACE PAS : c'est le seul endroit où le courrier arrive, et un
client qui la perdrait ne recevrait plus rien. La session le dit, le magasin le
redit — c'est lui qui ferait disparaître des fichiers.

ON NE GARDE PAS OUVERTE UNE BOÎTE QU'ON VIENT D'EFFACER. La session en tient un
instantané, des chemins, un état : tout cela désigne ce qui n'est plus. Le client
se retrouve authentifié sans sélection.

Éprouvé jusqu'au binaire : une boîte sans fille dont le répertoire disparaît, une
boîte avec fille dont le nom demeure marqué `\Noselect` — sa fille restant
ouvrable —, un `SELECT` sur le nom vidé refusé, un `CREATE` qui le rend ouvrable
de nouveau, `INBOX` refusée, et une boîte effacée puis recréée dans la même
seconde dont la validité a bien changé.

## `RENAME` : deux règles qu'on manque facilement, depuis le 2026-08-29

§6.3.6 : LES FILLES SUIVENT. Renommer `Vieux` renomme aussi `Vieux/2026` : les
laisser derrière ferait des boîtes dont le chemin ne mène plus nulle part. On
rassemble d'abord tout ce qui bouge, on vérifie que RIEN n'est déjà pris, puis on
renomme — et si l'un échoue, on défait les précédents. Un renommage à moitié
réussi laisserait la mère sous un nom et ses filles sous l'autre, ce qu'aucun
client ne saurait démêler.

§6.3.6 : RENOMMER `INBOX` LA VIDE SANS LA FAIRE DISPARAÎTRE. Son courrier s'en va
vers le nouveau nom ; elle reste. Les messages se déplacent par `rename` dans le
même système de fichiers : ils ne passent jamais par la mémoire, et n'existent à
aucun instant en deux exemplaires.

ET SON INDEX RESTE. C'est le détail qui coûte cher si on le manque — et je l'ai
manqué d'abord : l'index porte le prochain UID à servir, et la validité d'`INBOX`
NE CHANGE PAS en la renommant. Le retirer ferait repartir les UID de un après un
redémarrage, sous la même validité, c'est-à-dire réattribuer des numéros déjà
donnés — ce que §2.3.1.1 interdit. Un index qui compte des messages partis n'est
pas un problème : le parcours dit ce qui EST, l'index seulement ce qui A ÉTÉ, et
`reconcile` les confronte dans cet ordre.

Le même essai a montré un second défaut, plus ancien : `UIDNEXT` se calculait sur
l'INSTANTANÉ — le dernier message plus un — et redescendait donc dès qu'un
message était effacé. §2.3.1.1 veut qu'il ne recule jamais ; il se demande
désormais au compteur du Maildir, qui est le seul à le savoir.

Éprouvé jusqu'au binaire : `Vieux` et ses deux filles renommés d'un coup,
`INBOX` renommée dont les deux messages se retrouvent dans la destination pendant
qu'elle reste ouvrable et vide, son compteur d'UID intact, et `UIDNEXT` qui ne
recule pas après un effacement total.

## `ENVELOPE` : le message dit de lui-même, depuis le 2026-08-29

Un client qui affiche une liste de messages ne veut pas les messages : il veut
dix champs par message. `ENVELOPE` (§7.5.2) les lui donne sans qu'il ait à lire
quoi que ce soit.

**ON NE DÉCODE RIEN.** L'enveloppe porte le TEXTE DE L'EN-TÊTE, tel quel : un
`Subject:` en mots encodés (`=?utf-8?B?…?=`) se recopie encodé, et c'est au
client de le lire. Décoder ici lui rendrait autre chose que ce que le message
porte, et lui ôterait le moyen de le vérifier. Ce qui s'en va est la SYNTAXE de
la RFC 5322, pas le texte : les guillemets d'un nom cité et ses échappements, les
commentaires — traversés, jamais recopiés —, et les routes source, que la RFC
5322 a retirées et qu'`adl` rend donc toujours `NIL`. Les défauts de §7.5.2 sont
tenus : un `Sender:` ou un `Reply-To:` absent — ou vide — prend la valeur de
`From:`.

**UNE CHAÎNE NE PORTE PAS DE FIN DE LIGNE**, et c'est la propriété qui compte. Le
pliage disparaît partout, y compris à l'intérieur d'un nom cité — le cas qu'on
oublie, et celui que le fuzz a trouvé alors que les essais unitaires, écrits
pourtant en visant le pliage, ne l'avaient pas vu. Une chaîne IMAP qui porterait un `CR` ou un `LF`
ferait lire au client la fin de la réponse au milieu d'un nom, puis la suite du
dialogue comme du protocole : ce n'est pas une laideur d'affichage, c'est une
désynchronisation. Le pli s'EFFACE au lieu de devenir un blanc — celui qui suit
un `CRLF` appartient déjà à la chaîne, et le compter deux fois écarterait les
deux mots d'un espace de trop. Un nom qui n'est qu'un pli ne vaut rien : `NIL`,
et non `""`. Le contrôle qui précède l'écriture doit dire ce que la plume écrira,
sans quoi il ouvrirait des guillemets que rien ne viendrait remplir.

D'où la cible `fuzz_ams_mime_envelope` : ce qui part sur le fil est bien formé —
dix champs, parenthèses équilibrées, aucune fin de ligne dans une chaîne, et un
tampon trop court le dit au lieu d'écrire une enveloppe à moitié. 2 468 400
exécutions après le correctif, sans panne.

**L'ENVELOPPE NE SÉJOURNE PAS DANS LA SESSION** (C1), comme aucun message n'y
séjourne : elle se compose dans le tampon de l'appelant et s'écoule par morceaux.
Un défaut latent est tombé en l'écrivant : `FETCH 1 (BODY[] UID)` émettait
`BODY[] {100}` puis ` UID 1`, PUIS les cent octets — les données d'un élément
arrivaient après l'élément suivant, et aucun client n'aurait pu les recoller. La
session compte désormais les éléments déjà écrits et reprend où elle s'était
arrêtée, au lieu de rouvrir la ligne à chaque morceau.

Là où la composition échoue — en-tête illisible, enveloppe plus grande que son
tampon —, le serveur rend `(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)` plutôt que
rien : une enveloppe vide est une réponse, une enveloppe absente couperait la
réponse au milieu d'un élément.

Éprouvé jusqu'au binaire, sur un message déposé par `APPEND` portant un nom cité
à virgule, un groupe, un commentaire, un `Reply-To:` et un sujet en mots encodés :
le sujet reste encodé, `"Dupont, Jean"` survit, `Sender` reprend `From`, le groupe
s'ouvre et se referme, le commentaire tombe, et `In-Reply-To` est `NIL` quand
`Message-Id` est rendu verbatim.

## `BODYSTRUCTURE` : l'arbre du message, depuis le 2026-08-30

Un client qui affiche une liste de pièces jointes ne veut pas les pièces
jointes : il veut leur nom, leur type et leur taille, pour chaque partie et pour
chaque partie emboîtée. C'est ce que `BODYSTRUCTURE` (§7.5.2) lui donne.

**LE MESSAGE NE SÉJOURNE PAS, LA DESCRIPTION SEULE RESTE** (C1, C3). Une
enveloppe se lit dans l'en-tête ; une structure se lit dans TOUT le message,
parce que ce sont les frontières de la RFC 2046 qui la dessinent et qu'elles sont
semées d'un bout à l'autre. Retenir le message pour les trouver reviendrait à
réserver ce que l'expéditeur a choisi d'écrire — exactement ce que C3 interdit.
Le balayeur se fait donc POUSSER les octets, par morceaux, et ne retient qu'un
état borné : au plus soixante-quatre parties, huit niveaux d'emboîtement, une
arène d'en-têtes de seize kibioctets et une fenêtre de lecture de soixante-quatre.
Un message d'un gibioctet et un message de mille octets coûtent la même mémoire.

**LE DÉCOUPAGE NE CHANGE PAS LE RÉSULTAT**, et c'est la propriété que
`fuzz_ams_mime_structure` éprouve. Les morceaux ont la taille du tampon de celui
qui lit — une taille que le message ne choisit pas, et que rien ne garantit
stable. Une frontière tombant à cheval sur deux morceaux ne doit pas se voir.
C'est la même propriété que pour la phase de données de SMTP, et pour la même
raison : deux lecteurs qui découpent différemment doivent conclure pareil, faute
de quoi ce qu'un client voit dépend de la mémoire du serveur. 540 822 exécutions,
sans panne.

**RIEN DE CE QUI DÉBORDE NE FAIT ÉCHOUER.** Une structure absente couperait la
réponse au milieu d'un élément, ce qui est pire qu'une structure incomplète : au
delà des bornes, on décrit ce qu'on a pu voir, dans une forme que la grammaire
admet toujours. Un `multipart` qu'on n'a pas su ouvrir — sans frontière, ou sans
place pour l'emboîter — est décrit en `application/octet-stream`, ce que MIME
prescrit pour une entité qu'on ne sait pas interpréter (RFC 2049 §2) et ce qu'un
client ne lira pas de travers : un type `MULTIPART` suivi d'une taille n'existe
pas dans la grammaire de §7.5.2. Un `multipart` sans fille reçoit un corps vide,
que §7.5.2 exige (`1*body`).

Trois détails que l'on manque, et que l'écriture a coûtés :

- **Le `CRLF` qui précède une frontière lui appartient** (RFC 2046 §5.1.1) : il
  quitte donc la TAILLE du corps. Mais il ne quitte pas son nombre de LIGNES —
  ce qu'il terminait reste une ligne, simplement une ligne sans fin. Retrancher
  les deux faisait disparaître la dernière ligne de chaque partie.
- **Une ligne d'en-tête n'est pas dans le corps qu'elle ouvre**, mais elle est
  dans celui de tout ce qui la contient. C'est ce qui fait qu'un `message/rfc822`
  compte les lignes du message entier, en-tête compris, comme §7.5.2 le veut.
- **Les parties ouvertes sont exactement ce qui contient la ligne** : une fille
  est créée après ce qui la porte, donc son rang est plus grand. L'ordre de la
  table dit l'emboîtement, et il n'y a aucune chaîne de parents à remonter sans
  se tromper.

Éprouvé jusqu'au binaire, sur un message déposé par `APPEND` portant un
`multipart/mixed` de trois parties dont un `multipart/alternative` de deux, une
pièce jointe en base64 avec son `Content-Id` et un nom de fichier à apostrophe,
et un `message/rfc822` : les tailles, les lignes, les paramètres, la disposition,
l'enveloppe du message porté et sa structure sont toutes rendues, et exactes.

## `BODY[1]` : rendre une partie, et rien qu'elle, depuis le 2026-08-30

Dire la structure ne suffisait pas : un client qui voulait une pièce jointe
téléchargeait tout le message. `BODY[1]`, `BODY[1.2]`, `BODY[1.MIME]`,
`BODY[3.HEADER]` et `BODY[3.TEXT]` rendent maintenant la partie désignée.

**LE BALAYEUR SAVAIT OÙ SONT LES FRONTIÈRES ; IL LUI MANQUAIT DE DIRE OÙ CHAQUE
PARTIE COMMENCE.** Chaque partie retient désormais le rang de son premier octet
d'en-tête — ce qui donne `BODY[1.MIME]` sans relire le message une seconde fois.
Deux erreurs de découpe sont tombées en l'écrivant, et **aucune n'était visible
dans la structure** : c'est en servant les octets qu'elles se voient.

- **Une partie commence APRÈS sa frontière, jamais avant.** Le rang qu'on avait
  sous la main était celui où s'arrête ce qui PRÉCÈDE, `CRLF` de frontière
  déduit : deux octets et une ligne trop tôt.
- **La dernière frontière d'un `multipart` ne le ferme pas.** Son contenu, c'est
  ce que son propre parent délimite : son délimiteur de fin et l'épilogue qui le
  suit en font partie. Le clore sur lui-même rendait un `BODY[1]` amputé de sa
  dernière frontière — une entité que le client n'aurait pas su relire.

**UN `message/rfc822` NE COMPTE PAS POUR UN NIVEAU** (§6.4.5) : `3.1` est la
première partie du message qu'il porte, et non une partie de lui. `HEADER` et
`TEXT` ne veulent rien dire ailleurs que sur un message encapsulé — c'est SON
en-tête et SON corps qu'ils désignent, pas ceux de la partie qui le porte.

**CE QUI N'EXISTE PAS N'EST PAS UNE FAUTE.** `BODY[9]` sur un message qui n'a pas
neuf parties vaut `NIL`, ce que §6.4.5 admet : un client qui demande une partie
vue dans une structure devenue périmée ne fait rien de mal, et faire échouer sa
commande entière le punirait de rien. En revanche `BODY[0]` ou `BODY[1..2]` sont
des fautes de syntaxe — les confondre ferait chercher au client une erreur là où
il n'y en a pas, ou l'inverse.

**UN INTERVALLE DE PARTIE PART DROIT DANS UNE LECTURE DE FICHIER**, et le chemin
qui le désigne vient du réseau. C3 : le fuzz éprouve donc qu'il ne sort jamais du
message. 317 620 exécutions, sans panne.

**DEUX CORPS DANS UNE MÊME COMMANDE S'ÉCOULENT ENFIN L'UN APRÈS L'AUTRE.**
C'était refusé — « en rendre deux demanderait d'entrelacer deux intervalles de
fichier dans une même réponse ». Depuis que la session compte les éléments déjà
écrits, elle reprend où elle s'était arrêtée : le refus n'avait plus de raison, et
il est retiré. C'est aussi ce qui rend vérifiable la règle qui veut que la portée
de la partie SUIVANTE se redemande au magasin — sans quoi la seconde recevrait
l'intervalle de la première.

Éprouvé jusqu'au binaire, sur un message à trois niveaux : `[1.1]` et `[1.2]` des
deux formes d'un `multipart/alternative`, `[2]` de la pièce jointe, `[2.MIME]` de
ses lignes d'en-tête, `[3.HEADER]`, `[3.TEXT]` et `[3.1]` du message encapsulé,
`[9]` qui vaut `NIL` sans empêcher l'`UID` qui suit, une demande partielle sur une
partie, et deux parties dans une même commande.

Ce qui n'est toujours pas servi : `IDLE`, `NAMESPACE`, `ENABLE`, `SUBSCRIBE` et
`BINARY[…]`.

## `HEADER.FIELDS` : quelques champs, depuis le 2026-08-30

`BODY[HEADER.FIELDS (FROM SUBJECT)]` est ce qu'un client demande pour peupler une
liste de messages sans tout télécharger. `.NOT` fait l'inverse, et les deux valent
aussi sur une partie qui encapsule un message.

**LES CHAMPS SORTENT TELS QU'ILS SONT ÉCRITS** : pliage, ordre du message,
doublons. Un client qui vérifie une signature DKIM sur ce qu'il a reçu condense
les octets du message, pas une version remise au propre. Et **la ligne vide est
toujours là**, même quand aucun champ ne correspond — un client qui recevrait
zéro octet ne saurait pas distinguer « aucun champ » de « pas de réponse ».

**LE DÉCOUPAGE DES ÉLÉMENTS RESPECTE LES CROCHETS**, et c'est ce qui manquait
d'abord : `BODY[HEADER.FIELDS (FROM TO)]` porte des blancs à l'intérieur d'un
élément, et couper dessus rendait deux morceaux dont aucun n'était lisible. C'est
exactement ce qui faisait refuser `HEADER.FIELDS` comme « non servi ».

**LES NOMS VOYAGENT À CÔTÉ DES ÉLÉMENTS.** Un élément de `FETCH` est retenu dans
un tableau de taille fixe ; y loger une liste de noms ferait porter à CHACUN des
soixante-quatre la place que le plus gourmand demanderait. Ils vivent donc dans
une réserve bornée, un intervalle par élément — et ce qu'on accepte doit tenir
dans ce qui le retient : au-delà, la commande est refusée par `NO [LIMIT]` plutôt
que servie amputée de ses derniers noms.

**UN CHOIX N'EST PAS UN INTERVALLE DU MESSAGE**, c'est une sélection : il ne peut
pas s'écouler comme un `BODY[]`, qui se lit dans le fichier. Le magasin le
compose, en annonce la longueur — le littéral `{n}` l'exige avant le premier
octet — puis le sert par morceaux. C'est pourquoi le trait porte deux méthodes et
non une : on ne peut pas commencer à écrire sans savoir combien il y en aura.

**UN NOM CITÉ EST RECEVABLE, ET ON NE LE SERT PAS.** `header-fld-name` est un
`astring` : `"From"` et un littéral annoncé sont licites. On ne sait pas les
déciter, et rendre le nom tel quel donnerait un choix qui ne désigne pas ce que le
client a demandé. C'est donc un REFUS de service, et non une faute — les
confondre ferait chercher au client une erreur là où il n'y en a pas, ou
l'inverse.

Éprouvé jusqu'au binaire, sur un message à pièce jointe et message encapsulé :
deux champs rendus dans l'ordre du message et non dans celui de la demande, le
choix inverse, `[2.HEADER.FIELDS]` qui rend le sujet du message porté sans son
`X-Interne`, `[1.HEADER.FIELDS]` qui vaut `NIL` sur une partie qui n'encapsule
rien, un choix mêlé à `UID` et `FLAGS`, et une demande partielle.

## Chercher DANS les messages, depuis le 2026-08-30

`SUBJECT`, `FROM`, `TO`, `CC`, `BCC`, `HEADER`, `BODY`, `TEXT` étaient refusés, et
LE REFUS ÉTAIT LE BON CHOIX tant qu'on ne savait pas décoder : un `SEARCH SUBJECT
"facture"` qui répondrait « aucun résultat » sur un message intitulé
`=?utf-8?B?ZmFjdHVyZQ==?=` serait un mensonge exact — et un mensonge qu'aucun
client ne peut détecter. Ce qui a changé, c'est qu'on sait décoder.

**ON CHERCHE DANS LE TEXTE, PAS DANS LES OCTETS.** C'est l'inverse de ce que rend
une `ENVELOPE`, et ce n'est pas une contradiction : rendre et chercher ne
demandent pas la même chose. L'un doit rendre ce que le message PORTE — le client
doit pouvoir le vérifier —, l'autre doit trouver ce qu'il VEUT DIRE.

Il a donc fallu deux décodeurs, tous deux dans `ams-mime`, sans allocation :

- **Les mots encodés** (RFC 2047), `B` et `Q`, avec `us-ascii`, `utf-8` et
  `iso-8859-1` — cette dernière se convertit sans table. Le blanc entre deux mots
  encodés disparaît (§6.2) : il ne sert qu'à les séparer, et le garder couperait
  en deux un texte que l'expéditeur a dû découper pour tenir dans une ligne. Un
  mot mal formé est du texte ordinaire (§6.3), et non une erreur.
- **Les encodages de transfert** (RFC 2045 §6) : base64 et quoted-printable,
  coupures molles comprises. Un mot coupé en deux par un `=` de fin de ligne se
  retrouve entier — l'oublier ferait apparaître des fins de ligne au milieu des
  mots, et manquer ce qu'on cherche.

`decoded_max` majore ce que le décodage occupera SANS LIRE L'ENTRÉE, parce que le
décodage GRANDIT : quatre caractères de base64 rendent trois octets
`iso-8859-1`, qui font six octets d'UTF-8. C'est la propriété que
`fuzz_ams_mime_decode` éprouve — 1 835 632 exécutions, sans panne — avec celle
qu'un encodage inconnu est l'identité.

**TROIS CHOSES NE SE FONT PAS, ET SE DISENT** : un jeu de caractères qu'on ne
sait pas convertir laisse son mot encodé tel quel — mieux vaut ne pas trouver que
de trouver autre chose ; la casse ne se replie que pour l'ASCII, faute des tables
qu'il faudrait ; et l'on ne cherche que dans du TEXTE, au plus un mébioctet par
partie — une pièce jointe binaire ne se cherche pas par son texte, et parcourir
vingt mébioctets coûterait à ce serveur ce qu'un client peut demander autant de
fois qu'il veut.

**NI LA GRAMMAIRE NI LA SESSION NE LISENT LE MESSAGE** (C1). Le nœud dit QUOI
chercher et OÙ ; celui qui a le message dit si ça s'y trouve. `Search::matches`
prend donc une fermeture — et une fermeture DYNAMIQUE : générique, elle serait
recopiée une fois par appelant, et chaque copie porterait des chemins que
personne n'emprunte. Le gate de couverture l'a montré avant qu'on l'écrive :
quinze régions apparues d'un coup dans une crate qu'on n'avait pas touchée.

Éprouvé jusqu'au binaire, sur deux messages : un sujet en base64 trouvé par son
texte, un sujet en `iso-8859-1` avec son `_` valant espace, un corps en
quoted-printable dont un mot est coupé par une coupure molle, une pièce jointe
base64 qui ne se trouve PAS par son contenu encodé, et la forme encodée du sujet
qui ne se trouve pas non plus — puisqu'on cherche le texte.

## Le signeur DKIM a un appelant, depuis le 2026-08-30

C9 demande « DKIM en signature ET en vérification ». La vérification tournait
depuis longtemps ; le signataire, lui, existait, était couvert à 100 %, comparé à
OpenSSL — et **n'était appelé par personne**. C'était la dette la plus visible du
produit : une fonctionnalité écrite qui ne servait à rien.

**CE QU'ON ÉMET PART SIGNÉ**, dès qu'une clé est nommée. Ce que ce serveur émet,
ce sont ses rapports DMARC — et c'est précisément ce qui devait être signé en
premier : un rapport arrive chez un domaine qui, par définition, se méfie de ce
qui n'est pas authentifié.

**PAS DE DRAPEAU** (C8, comme partout ici) : on signe si et seulement si un
sélecteur ET une clé sont nommés. Un sélecteur sans clé ne veut dire ni « signe »
ni « ne signe pas », et `air-mail-admin` le refuse devant l'opérateur — c'est le
seul moment où le lui dire coûte une seconde plutôt qu'une astreinte.

**LA CLÉ SE LIT AU DÉMARRAGE**, jamais à la première émission : un serveur qui
découvrirait alors qu'elle est illisible aurait déjà annoncé qu'il signe. Ce qui
ne peut pas marcher doit refuser de démarrer. Et une clé lisible par tout le
monde l'empêche, comme celle de TLS et pour la même raison — qui la vole signe en
notre nom, et rien ne le distingue de nous. Le partage par groupe reste permis.

**L'AVEUGLEMENT, PARCE QU'ON SIGNE À LA DEMANDE.** `Signer::sign` scellait sans
aveuglement, ce que la crate elle-même déconseille à un serveur : qui l'observe
obtient autant de mesures qu'il veut. `Signer::sign_with` a donc été écrit — même
champ, même signature, l'aveuglement ne protège que LA CLÉ —, et la signature
sort de la boucle asynchrone : une exponentiation RSA privée et une lecture
d'`/dev/urandom` sont bloquantes, et n'ont rien à faire dans un fil que d'autres
partagent.

**LA CLÉ N'APPARAÎT JAMAIS DANS UNE TRACE.** `SigningKey` n'a délibérément pas de
`Debug` ; le signataire de la boucle en a un, écrit à la main, qui montre le
sélecteur et rien d'autre. Une clé privée qui figure dans un journal n'est plus
une clé privée.

**UN MESSAGE QU'ON NE SAIT PAS SIGNER PART QUAND MÊME.** Il vaut mieux un rapport
non signé qu'un rapport qui n'arrive pas : le destinataire n'en a pas moins
besoin, et rien dans DMARC n'exige que nos propres rapports le soient. Le serveur
dit au démarrage s'il signe, plutôt que de laisser le découvrir chez le
destinataire.

Il a fallu, pour cela, apprendre à lire une clé : `SigningKey::from_pem` lit le
PKCS#8 (`BEGIN PRIVATE KEY`, RSA ou Ed25519) et le PKCS#1 (`BEGIN RSA PRIVATE
KEY`). **C'EST L'ÉTIQUETTE QUI DIT LE FORMAT, ET NON UNE DEVINETTE** : essayer
l'un puis l'autre marcherait aussi, et masquerait une clé abîmée derrière un
second essai qui échoue pour une autre raison.

## Le gate de couverture arrondissait vers le haut, depuis le 2026-08-29

`check-couverture` comparait un POURCENTAGE ARRONDI à son seuil. Sur deux
décimales, 23 580 régions couvertes sur 23 581 s'écrivent « 100,00 % » : le gate
a dit OK alors qu'il manquait une région, et c'est en écrivant `STORE` que
l'écart s'est vu. Il compare maintenant des COMPTES, et le rapport arrondit vers
le bas — un rapport qui affiche la perfection alors qu'il manque une région ment
poliment, et c'est ce chiffre-là qu'on lit avant de conclure.

La région manquante était une garde inatteignable de plus : `(Some(b'('),
Some(b')')) if liste.len() >= 2`, alors qu'un octet ne peut pas être à la fois
`(` et `)`.

## Le client SMTP sortant, depuis le 2026-08-29

Jusqu'ici, tout venait à ce serveur : des pairs frappaient, il répondait. Émettre
inverse la relation, et avec elle toutes les questions de confiance — **le
serveur qu'on joint est désigné par le destinataire**, c'est-à-dire par quiconque
publie un `MX`, et ce qu'il répond est une entrée hostile comme une autre.

Les trois étages y sont, comme partout (C1). L'étage 1 lit les réponses
(`ams-proto-smtp`) et point-farcit les corps ; l'étage 2 tient la session cliente
(`ams-session`) ; l'étage 3 résout, se connecte, chiffre et conduit
(`ams-loop-tokio`). Rien de tout cela ne partage une ligne avec le côté serveur :
lire une réponse n'est pas en écrire une, et les faire dériver d'un même code
ferait qu'un jour, en corrigeant l'un, on casserait l'autre.

### TROIS REFUS QUI SE RESSEMBLENT ET QUI NE SONT PAS LE MÊME

`4yz` : réessayer plus tard a un sens, et jeter ici perd du courrier qui serait
passé. `5yz` : réessayer n'en a aucun, et insister revient à harceler un serveur
qui a dit non. Le **`MX` nul** (RFC 7505) : le domaine déclare à l'avance ne
recevoir aucun courrier, et le confondre avec une panne ferait réessayer des
jours durant ce qu'il a explicitement fermé. Un serveur injoignable, lui, n'est
aucun des trois : c'est une panne, donc temporaire.

### LE CHIFFREMENT SORTANT N'AUTHENTIFIE PERSONNE, ET C'EST ÉCRIT

Le `MX` vient d'un DNS **non validé** (pas de DNSSEC, cf. plus haut). Un tiers
capable de détourner cette résolution peut aussi bien présenter un certificat
parfaitement valide pour le nom qu'il vient de fabriquer : **vérifier le
certificat contre le nom `MX` ne prouverait rien de plus que de ne pas le
vérifier**, puisque la chaîne de confiance s'arrête un cran plus tôt.

Ce qu'il faudrait pour authentifier vraiment, ce sont DANE (RFC 7672, qui demande
DNSSEC) ou MTA-STS (RFC 8461, qui demande HTTPS et une politique publiée). Aucun
des deux n'est ici, et les nommer vaut mieux que de laisser croire à une
protection qui n'existe pas.

Ce que le chiffrement apporte est réel et limité : on passe d'un espion passif à
un attaquant actif. Lire le courrier de tout le monde sur un lien devient
impossible ; il faut s'insérer dans chaque connexion, ce qui se voit et ce qui
coûte. C'est la thèse de la RFC 7435, et c'est aussi pourquoi elle ne doit
**jamais** être présentée comme une authentification.

**Le repli, lui, n'est pas opportuniste.** Un serveur qui annonce `STARTTLS` puis
refuse — la commande ou la poignée de main — ne nous fera pas parler en clair :
c'est exactement le levier d'une attaque par déclassement. Et TLS 1.3 reste le
plancher (C6), fût-ce au prix de quelques remises manquées.

### Ce qui n'a pas encore d'appelant

Le client est écrit, couvert à 100 %, fuzzé et **éprouvé contre notre propre
serveur** — deux moitiés qui ne partagent aucun code, mises face à face. Son
premier appelant est arrivé le même jour : la remise des rapports DMARC.

Il n'y a toujours pas de **file d'attente générale** : `send` remet, ou dit
pourquoi il n'a pas pu. Le dossier des rapports en tient lieu pour eux seuls — il
sait différer et abandonner, ce qui suffit à des messages qu'on peut perdre sans
que personne n'en souffre. Une vraie file demanderait des avis de non-remise et
une politique de reprise, deux décisions qui ne se prennent pas en passant, et
qu'un serveur qui n'accepte pas de soumission n'a pas encore à prendre.

### DNSSEC n'est pas validé, et c'est écrit partout

Le résolveur est cru sur parole. Un `pass` ne vaut donc que ce que vaut le chemin
jusqu'à lui, et c'est pourquoi le résolveur doit être **local, ou joint par un
lien de confiance**. Trois endroits le disent plutôt qu'un : le schéma de
configuration, l'aide d'`air-mail-admin`, et une ligne au démarrage du serveur.
Une lacune qu'on nomme est une lacune ; une lacune qu'on tait est un mensonge.

Deux défenses accompagnent tout de même chaque question, et elles ne coûtent
rien : **un identifiant tiré de `/dev/urandom`** — pas un compteur, pas une
horloge — et **un port source neuf** par question, une socket étant ouverte pour
chacune. Trente-deux bits à deviner valent mieux que seize pour qui voudrait
répondre à notre place. Le fichier d'aléa s'ouvre au démarrage : un serveur qui
découvrirait à la première connexion qu'il n'a pas d'aléa n'aurait plus que de
mauvaises options.

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

**Trois protocoles sont servis, par un vrai binaire, contre de vrais fichiers** :
SMTP en réception (avec `STARTTLS`, `AUTH PLAIN`, SPF, DKIM, DMARC et remise
Maildir), SMTP à l'émission (rapports DMARC), POP3, et IMAP — `SELECT`,
`EXAMINE`, `CLOSE`, `UNSELECT`, `LIST`, `STATUS`, `FETCH`, `STORE`, `EXPUNGE`,
`SEARCH`, `COPY`, `MOVE`, `APPEND`, `CREATE`, `DELETE`, `RENAME` et leurs formes
`UID`. Chacun a été éprouvé de bout en bout contre le binaire, et pas
seulement en tests.

**HTTP n'est pas servi** : `ams-proto-http` est un emplacement réservé, et son
en-tête le dit.

Sont outillées : C1 (les trois étages, et la couverture qui n'est exigible que
parce qu'ils sont séparés), C2 (le gate mesure 23 578 régions sur 16 crates,
toutes couvertes — et il compare désormais des comptes, non un pourcentage
arrondi), C3 (les lints, l'absence d'allocation dans les décodeurs, et 28 cibles
de fuzz dont la CI vérifie qu'elle les lance toutes), C4 (`ams-tls` n'offre que
TLS 1.3), C6 (les décodeurs refusent le CR et le LF isolés ; `AUTH`, `USER`/`PASS`
et `LOGIN` sont refusés hors chiffrement, sans réglage pour le rétablir), C8
(`ams-guard`, câblé sur les trois services), C9 (DKIM vérifié, SPF et DMARC
évalués, rapports agrégés et d'échec composés et émis), C10 (`refuse_root`,
appelé avant tout le reste), C11 (le serveur ne se règle QUE par un fichier
Cap'n Proto), C12 (les deux binaires aux noms distincts), C13 (Maildir, index
persistant, et lecture sans verrou côté IMAP), C14 (`X25519MLKEM768` en tête).

**La contrebande SMTP est fermée** : la phase de données n'accepte que
`<CRLF>.<CRLF>`, refuse tout `CR` ou `LF` isolé, et le fuzz éprouve que le
découpage des lectures ne change rien au verdict.

Ce qui manque, et qu'aucune phrase ne doit laisser croire acquis : `IDLE`,
`NAMESPACE`, `ENABLE`, `SUBSCRIBE` et `BINARY[…]` ; la file de réémission
des messages sortants ; et toute interface HTTP.
