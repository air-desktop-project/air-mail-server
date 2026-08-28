# air-mail-server

Serveur de courrier écrit en Rust : **SMTP**, **POP3**, **IMAP** et **HTTP**.

> ## État : squelette
>
> Ce dépôt compile, il est linté, et il porte quatre gates de CI. Il **ne sert
> aucun protocole**.
>
> **`air-mail-server` tourne.** Il écoute sur un port, reçoit du courrier en
> clair pour les domaines qu'on lui nomme, le dépose dans une boîte Maildir, et
> refuse les sources qui abusent.
>
> **Il chiffre** : nommez-lui un certificat et une clé, il annonce `STARTTLS` et
> monte en TLS 1.3, échange de clés post-quantique en tête. Sans certificat, il
> sert en clair — et ne l'annonce pas, faute de quoi il mentirait. Les deux
> moitiés de cette phrase sont éprouvées sur l'exécutable lui-même, face à un
> vrai OpenSSL.
>
> **Il authentifie** : `AUTH PLAIN` sous TLS, contre des empreintes Argon2id
> rangées dans un fichier séparé qu'`air-mail-admin` écrit. Sans comptes, il ne
> l'annonce pas.
>
> **Une boîte par compte** : seules les adresses qu'un compte déclare sont
> acceptées, et chacune mène à `<maildir>/<compte>/`. Sans comptes, le serveur
> n'accepte de courrier pour personne — ce n'est plus un fourre-tout.
>
> Onze crates portent du code ; les autres sont des emplacements réservés qui le
> disent dans leur documentation.
>
> Ce que ce dépôt affirme, il le tient. Rien de plus n'est promis ici.

## Les contraintes

Le projet est gouverné par un **registre de contraintes** :
[`docs/contraintes.md`](docs/contraintes.md). Chaque entrée dit la règle, ce
qu'elle interdit, et — le plus important — **ce qui la fait respecter
aujourd'hui**. Quand la réponse est « rien », c'est écrit.

En résumé, et sans rien promettre : aucune entrée-sortie dans les protocoles *ni
dans le serveur*, 100 % de couverture sur tout ce qui décide, TLS 1.3 sans repli
et **`X25519MLKEM768` toujours offert et préféré**, aucune version ancienne de
protocole, jamais de privilèges superutilisateur, configuration binaire Cap'n
Proto, stockage Maildir, DKIM/SPF/DMARC, et détection de flooding avec
bannissement par source.

La cryptographie est **pure Rust, sans une ligne de C** : `rustls` sur
`rustls-rustcrypto`, et un échange de clés hybride que le projet devra écrire
lui-même — aucun fournisseur pur Rust ne l'offre.

## Le découpage

Trois étages, et la frontière entre le deuxième et le troisième est la seule qui
compte.

### Étage 1 — grammaires, sans entrée-sortie

Des octets vers des commandes, et retour. Aucune socket, aucun fichier, aucune
horloge.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-mime` | RFC 5322 et MIME — le socle des quatre protocoles | **squelette du message : ligne, pliage, champs** |
| `ams-proto-smtp` | RFC 5321 | **commandes, réponses, phase de données** |
| `ams-sasl` | RFC 4422/4616 : `PLAIN` et son base64 | **implémenté** |
| `ams-proto-pop3` | RFC 1939 | **commandes et réponses** |
| `ams-proto-imap` | RFC 9051 (IMAP4rev2) | vide |
| `ams-proto-http` | RFC 9110 / 9112 | vide |

### Étage 2 — décisions, sans entrée-sortie

Des machines à états. Elles reçoivent des octets **et l'heure** ; elles rendent
des octets **et des actions**. Elles n'attendent jamais.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-session` | les sessions serveur | **SMTP et POP3 : sessions entières** |
| `ams-guard` | flooding et bannissement par source | **implémenté** |
| `ams-auth` | le magasin d'identifiants, vérification Argon2id | **implémenté** |
| `ams-tls` | TLS 1.3 uniquement, échange de clés post-quantique | **implémenté** |
| `ams-dkim` | RFC 6376 | vide |
| `ams-spf` | RFC 7208 | vide |
| `ams-dmarc` | RFC 7489 | vide |
| `ams-config` | les trois formats binaires : configuration, comptes, index | **implémenté** |
| `ams-index` | noms Maildir, drapeaux, reconstruction, `UIDVALIDITY` | **implémenté** |

### Étage 3 — exécution

Les seules crates qui lisent, écrivent et attendent. Elles ne décident de rien.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-loop-tokio` | la boucle Unix, sur tokio | **connexions + `STARTTLS`** |
| `ams-store` | Maildir : les fichiers, seule source de vérité | **implémenté** |
| `ams-server` | le binaire `air-mail-server` | **il tourne** |
| `ams-admin` | le binaire `air-mail-admin` | **`summary`** |

**Quatorze crates portent du code.** `ams-mime` : le squelette d'un message — la
ligne, le pliage, la séparation en-tête/corps, le découpage en champs. Les champs
structurés, les adresses, les dates et MIME restent à écrire.
`ams-proto-smtp` : les commandes, l'encodage des réponses multilignes, et **la
phase de données** — `<CRLF>.<CRLF>`, le point échappé, et le refus de tout `CR`
ou `LF` isolé. `BDAT`/`CHUNKING`, l'échappement à l'émission et la validation
complète d'une adresse IPv6 restent à écrire.

`ams-proto-pop3` : les commandes de la RFC 1939 et leurs réponses. `APOP`
n'existe pas ici — MD5, et surtout l'obligation de garder le mot de passe **en
clair** côté serveur pour calculer le condensat : un mécanisme qui interdit de
stocker une empreinte aggrave la fuite qu'il prétend éviter (C6). Le doublement
du point d'une réponse multiligne vit à **un seul endroit** : l'écrire deux fois,
c'est se donner deux occasions de l'écrire différemment, et un point non doublé
termine le message au milieu. La boucle et la relève depuis les boîtes restent à écrire.

`ams-sasl` : le mécanisme `PLAIN` et le base64 **strict** qui le transporte —
décodage seul, sans allocation. Strict veut dire : une seule écriture par
valeur. `Zg==` et `Zh==` décodent tous deux vers `f` ; accepter le second
donnerait plusieurs formes pour un même identifiant, de quoi passer à côté d'un
filtre ou d'un comptage. `LOGIN` et `CRAM-MD5` ne sont pas servis, et la crate
dit pourquoi plutôt que de se taire.

`ams-auth` : les comptes — un nom, une empreinte, des adresses — et la
vérification **Argon2id** (m = 19456 Kio, t = 2,
p = 1 — la configuration OWASP). Un compte inconnu coûte le même temps qu'un
compte connu, parce qu'il est comparé à une empreinte de personne : sans cela,
l'écart de temps rendrait le magasin énumérable sans en connaître un seul mot de
passe. Une empreinte sous le plancher du produit est refusée **au chargement**,
en nommant le compte — une vérification emploie les paramètres inscrits dans
l'empreinte, si bien qu'un compte haché faiblement serait vérifié faiblement.

`ams-session` : **deux** sessions. La session POP3 d'abord — les trois états de
la RFC 1939, `USER`/`PASS` refusés hors chiffrement, les réponses multilignes et
le doublement du point. L'état UPDATE, celui qui efface, n'est atteint que par un
`QUIT` venu de TRANSACTION : une coupure réseau ne perd donc jamais de courrier.
La boîte **sort de la session** le temps d'une commande, ce qui rend l'état
structurel — une commande de relève reçoit la boîte en argument, donc elle ne
peut pas être appelée sans.

Et la session SMTP entière — bannière, `EHLO`, annonce des
extensions, séquencement `MAIL`/`RCPT`/`DATA`, `STARTTLS`, refus d'`AUTH` hors
chiffrement, **la phase de données et l'échange SASL** — défi, base64, format de
`PLAIN`, annulation par `*`. Elle n'authentifie personne pour autant : elle
demande à la politique, qui refuse par défaut.

`ams-loop-tokio` : la boucle d'acceptation et le pilote d'une connexion, sur
tokio. Elle lit, elle écrit, elle ne décide de rien — pas même le `421` qui refuse
une source trop pressée, qui vient de la session. Ses tests jouent des
conversations en mémoire **et** de vraies connexions sur la boucle locale.

Elle conduit `STARTTLS` (RFC 3207) : la poignée de main, puis **le même pilote
rejoué au-dessus du flux chiffré**, la session remise à zéro. Ce qu'un pair envoie
derrière son `STARTTLS` n'est jamais exécuté — c'est la faille de 2011, et le
tampon n'est pas vidé en silence : le pair reçoit un `421` au lieu de son `220`.
Le fournisseur cryptographique, lui, ne vient jamais d'ici : l'appelant apporte
celui de `ams-tls`. De l'échange SASL, elle ne sait qu'une chose : après un
défi, la ligne suivante va à la session plutôt qu'à la grammaire des commandes.

`ams-guard` : la détection de flooding et le bannissement par source (C8), dans
une table **bornée** que l'appelant fournit — et dont une peine en cours n'est
jamais évincée. La clé est un **préfixe**, pas une adresse : bannir une IPv6 seule
ne sert à rien. Le garde est consulté avant la bannière, puis à chaque commande ;
**on ne dit pas un mot à un banni**.

`ams-tls` : le fournisseur cryptographique — pur Rust, **trois suites, toutes
TLS 1.3**, aucune ligne de C — et l'échange de clés hybride `X25519MLKEM768`
(C14), que `rustls-rustcrypto` ne fournit pas. C'est la seule crate du dépôt qui
porte de la **cryptographie composée** : les primitives viennent de `ml-kem` et
`x25519-dalek`, mais l'ordre des octets sur le fil est notre code. Il a été relevé
dans `draft-ietf-tls-ecdhe-mlkem` §3.1.3 — où le secret ML-KEM vient en premier,
à l'inverse de l'autre groupe du même brouillon — et **vérifié contre un
`openssl s_client` réel**, seule preuve possible que les deux camps calculent le
même secret. La boucle s'en sert pour `STARTTLS`, et le serveur pour de bon.

`ams-index` : les noms Maildir, les drapeaux, et la **reconstruction** — un
repliement sur les noms, sans table donc sans allocation. C'est là que vit la
raison d'être du `,U=` dans un nom de fichier.

Et ce que les noms **ne peuvent pas** porter : l'`UIDVALIDITY` de la boîte, et le
filigrane des UID. L'index persisté ne contient que ces deux nombres, et rien
d'autre — recopier ce que les noms disent déjà créerait une seconde source de
vérité, capable de diverger de la première sans que rien ne le signale. Le
perdre ne perd aucun message ni aucun UID : cela oblige seulement à changer
l'`UIDVALIDITY`, c'est-à-dire à demander aux clients de resynchroniser.

`ams-store` : la boîte Maildir. Arrivée par `rename()` atomique, **deux `fsync`**
— le fichier avant, le répertoire après —, adoption des messages déposés par
d'autres outils, et nettoyage de `tmp/` même quand une remise est abandonnée.
L'index s'écrit avec la même discipline, et son filigrane est **réservé par
tranches de 256** : un `fsync` toutes les 256 remises au lieu d'un par message,
au prix de trous dans la numérotation après un arrêt brutal. La RFC 9051 les
autorise ; un UID réattribué, lui, montrerait à un client un message pour un
autre.

`ams-config` : les **trois** schémas Cap'n Proto et leurs codecs — la
configuration, les comptes, l'index d'une boîte. Le code dérivé est **généré et
committé** : le build et la CI n'ont besoin d'aucun outil C++.

`ams-server` et `ams-admin` : les deux binaires de C12. Le premier assemble les
pièces et ne contient **aucune logique de protocole** — seulement le fil. Il lit
la section TLS de sa configuration, charge le certificat et la clé, et n'annonce
`STARTTLS` que s'il les a. Il **refuse de démarrer sur une clé privée lisible par
tout le monde** ; le partage par groupe, lui, reste permis. Le
second sait relire une boîte, ce qui est la reconstruction de C13 exécutée à la
demande.

Toutes les autres crates sont vides, et chacune le déclare dans sa documentation.

### Pourquoi les étages 1 et 2 ne font aucune entrée-sortie

Une machine à états se pilote pas à pas depuis un test : on lui donne des octets,
on lui donne une heure, on regarde ce qu'elle rend. **Une boucle asynchrone ne se
pilote pas — on l'attend.** C'est la seule disposition où le 100 % de couverture
reste atteignable au-dessus des codecs, et c'est aussi ce qui rend les décodeurs
fuzzables sans ouvrir un port.

L'étage 3 est hors de ce périmètre de couverture, non par indulgence, mais parce
qu'y atteindre 100 % exigerait de simuler les pannes du noyau — et l'on mesurerait
alors la fidélité de la simulation, pas la justesse du code.

### Aucune abstraction d'exécution

Il n'y a **pas** de trait qui abstrairait tokio et le moteur d'Air. Chaque moteur
porte sa propre boucle, qui pilote la **même** machine à états : rien à adapter,
rien à maintenir entre les deux, et la logique du serveur n'est écrite qu'une
fois.

## Portage vers Air

Ce projet appartient au même projet qu'[Air](https://github.com/air-desktop-project/air).
Il n'en dépend **pas** aujourd'hui.

Sur la cible `*-linux-air`, la boucle d'entrées-sorties sera adossée au moteur
asynchrone d'Air — `air-async` (exécuteur mono-thread) au-dessus de `air-uring`
(réacteur io_uring). Les deux existent réellement dans le dépôt `air`.

Cette boucle **n'est pas créée** : une crate vide portant ce nom laisserait croire
qu'un portage est entamé. Aucune date, aucun engagement de calendrier.

## Lancer

La configuration est un fichier **binaire** : elle n'est pas éditable à la main,
et `air-mail-admin` est le seul moyen d'en produire une. Le serveur, lui, n'a
aucune option de réglage — deux sources de configuration seraient une de trop.

```sh
cargo build --release

# 1. Produire la configuration.
./target/release/air-mail-admin config write air-mail.conf \
    --listen 127.0.0.1:2525 \
    --maildir ./maildir \
    --domain mail.example.com \
    --hosted example.com

# 2. La relire, pour vérifier ce qu'elle dit.
./target/release/air-mail-admin config show air-mail.conf

# 3. Servir.
./target/release/air-mail-server --config air-mail.conf

# Et regarder la boîte.
./target/release/air-mail-admin summary ./maildir
```

Le port par défaut **n'est pas 25** : le serveur refuse de s'exécuter en
superutilisateur (C10), et les ports privilégiés s'atteignent par une règle de
redirection du pare-feu.

Sans `--hosted`, il n'accepte de courrier pour personne — un serveur qui
accepterait tout serait un relais ouvert.

### Chiffrer

```sh
./target/release/air-mail-admin config write air-mail.conf \
    --domain mail.example.com --hosted example.com \
    --tls-cert /etc/ams/chaine.pem \
    --tls-key  /etc/ams/cle.pem
```

**Les deux options vont ensemble, ou aucune** : l'une sans l'autre ne veut dire
ni « chiffre » ni « ne chiffre pas », et elle est refusée devant le terminal
plutôt qu'au démarrage. Avec elles, le serveur annonce `STARTTLS` et monte en
TLS 1.3 (`X25519MLKEM768` préféré) ; sans elles, il sert en clair **et ne
l'annonce pas**.

Le serveur **refuse de démarrer si la clé est lisible par tout le monde** —
`chmod o-r` la répare. Le partage par groupe (`0640`, groupe `ssl-cert`) reste
permis : c'est la bonne pratique, pas la mauvaise.

Une mise en garde, mesurée et non supposée : **une paire dépareillée n'est pas
détectée au démarrage**. Le fournisseur pur Rust ne sait pas comparer la clé au
certificat, si bien qu'un renouvellement qui ne remplace qu'un des deux fichiers
donne un serveur qui démarre et dont toutes les poignées de main échouent.

### Des comptes, des boîtes

```sh
printf %s "$MDP" | ./target/release/air-mail-admin account add comptes.bin \
    --login jean --address jean@example.com --address j.dupont@example.com
./target/release/air-mail-admin account list comptes.bin
```

**Le nom du compte est le nom de sa boîte** — `<maildir>/jean/{cur,new,tmp}`. Un
seul champ plutôt que deux : un identifiant et un répertoire qu'on peut faire
diverger finissent par diverger. C'est une frontière de sécurité, et le nom est
donc contrôlé (ni `.`, ni `..`, sans `/`, sans point en tête) à l'écriture comme
à la lecture.

**Seules les adresses déclarées sont acceptées.** `--hosted` ne sert plus à
accepter : c'est la liste de ce que le serveur annonce servir, et elle est
confrontée aux adresses des comptes **au démarrage**. Une adresse dans un domaine
non annoncé est presque toujours une faute de frappe, et le serveur refuse de
démarrer en le disant.

Un compte **sans adresse** est licite : il se connecte, il envoie, il ne reçoit
rien. Et `postmaster` est un compte comme un autre — le serveur avertit au
démarrage si personne ne le reçoit, parce que la RFC 5321 §4.5.1 l'exige.

### Authentifier

```sh
# Le mot de passe se lit sur l'ENTRÉE STANDARD, jamais sur la ligne de commande :
# ce que `ps` affiche, tout le monde le lit.
printf %s "$MDP" | ./target/release/air-mail-admin account add comptes.bin --login jean
./target/release/air-mail-admin account list comptes.bin      # les noms, jamais les empreintes

./target/release/air-mail-admin config write air-mail.conf \
    --domain mail.example.com --hosted example.com \
    --tls-cert /etc/ams/chaine.pem --tls-key /etc/ams/cle.pem \
    --accounts comptes.bin
```

Le magasin sert **deux choses** qu'il faut distinguer : le *routage* — quelles
adresses existent, et vers quelle boîte — qui ne demande aucun chiffrement ; et
l'*authentification*, qui n'est annoncée que sous TLS. Un serveur de courrier
entrant en clair a donc des comptes sans avoir d'`AUTH`.

Le magasin est un **autre fichier**, écrit en `0600` : les comptes et la
configuration ne changent pas au même rythme, ne méritent pas les mêmes
permissions, et une fuite de l'un n'est pas une fuite de l'autre. Le serveur
refuse de démarrer s'il est lisible par tout le monde — ce ne sont que des
empreintes, mais c'est un dictionnaire de noms à essayer.

`--accounts` sans `--tls-cert` est refusé : `AUTH` n'est **jamais** annoncé hors
chiffrement, et ce refus n'est pas réglable.

## Construire

La toolchain est épinglée dans `rust-toolchain.toml` (**Rust 1.98.0**, stable).
`rustup` la sélectionne tout seul dans ce répertoire.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Le pin est une **version exacte**, pas le canal `stable` : un canal roulant
désigne une version différente toutes les six semaines, et deux mesures prises à
deux mois d'écart ne sont alors plus comparables.

## Vérification

La CI (`.github/workflows/ci.yml`) tourne sur chaque PR et sur `main`, en quatre
jobs indépendants : la vérification du code (les quatre commandes ci-dessus, sous
`-D warnings` et `--locked`), le gate **DCO**, le gate de **couverture**, et un
**smoke-fuzz**.

### Fuzzing (C3)

`fuzz/` est une crate `cargo-fuzz` **hors du workspace** : elle exige un nightly,
que le pin exact du workspace n'admet pas — deux LLVM produisent des profils de
couverture mutuellement illisibles. Dix cibles, quarante-six propriétés, dont un
**aller-retour** sur l'encodeur de réponses, un **vocabulaire de sortie clos** sur
la session, et l'**indépendance au découpage** sur la phase de données — celle qui
vise directement la contrebande SMTP. **Six défauts réels** trouvés et
corrigés, dont deux dans le garde. Voir
[`fuzz/README.md`](fuzz/README.md).

La CI en lance un smoke borné à vingt secondes par cible : un détecteur de
régression, **pas une campagne**.

### Couverture (C2)

`scripts/check-couverture.sh` exige **100 %** sur les treize crates des étages 1
et 2. Le seuil porte sur les **régions** et les **lignes** — pas sur les branches,
que `llvm-cov` n'instrumente pas sur Rust stable et dont le compteur reste à
`0 / 0`. Les régions font le travail attendu : chaque bras d'un conditionnel en
est une.

Le gate mesure aujourd'hui **6 891 régions** et **4 044 lignes**, toutes
couvertes. **Une seule dérogation, et elle est annoncée à chaque exécution** : le
code *généré* du schéma Cap'n Proto en est exclu — il porte un accesseur par champ
et par sens, dont la plupart ne seront jamais appelés, et les couvrir n'éprouverait
aucune de nos décisions. L'exclusion nomme **un fichier**, pas une crate. `ams-loop-tokio` en est **hors** : elle lit, écrit et attend, et y
atteindre 100 % exigerait de simuler les pannes du noyau — on mesurerait alors la
fidélité de la simulation. Il naissait à zéro dette et n'en a pas pris.

```sh
./scripts/check-couverture.sh
./scripts/check-couverture.sh --seuil 95   # pour un diagnostic local
```

### DCO

`scripts/check-dco.sh` examine les commits que la branche **ajoute** (`base..HEAD`,
jamais tout l'historique) et fait échouer sur :

- un commit sans `Signed-off-by:` — le DCO n'est pas certifié (`git commit -s`) ;
- une attribution de paternité à un outil (`Co-Authored-By: Claude …`,
  `Claude-Session:`, « Generated with … », une URL de session). Un outil ne
  co-signe pas, pas plus qu'un compilateur ; seule la signature de l'auteur humain
  fait foi.

Il **signale sans faire échouer** un `Signed-off-by` qui ne nomme pas l'auteur
(légitime pour un patch relayé) et un commit sans signature cryptographique.

Ce qu'il ne peut **pas** faire : dire si une signature est *valide*. `git`
distingue « non signé » de « signé mais invérifiable ici », et un runner de CI n'a
le trousseau de personne — il constate qu'une signature existe, jamais qu'elle est
bonne. La vérification effective relève de la protection de branche GitHub
(`required_signatures`), qui n'est **pas** activée sur ce dépôt à ce jour.

Le script tourne aussi en local :

```sh
./scripts/check-dco.sh            # base : origin/main
./scripts/check-dco.sh main       # ou une base explicite
```

## Dépendances

**Deux dépendances externes** : `tokio` pour la boucle d'entrées-sorties (C5), et
`capnp` pour la configuration binaire (C11) — cette dernière **pure Rust, sans
aucune dépendance transitive**, et compatible `no_std`.
Le graphe de build réel, sur Linux et avec les seules features qui servent, compte
**douze crates transitives, dont sept seulement à l'exécution** — `bytes`,
`errno`, `libc`, `mio`, `pin-project-lite`, `signal-hook-registry`, `socket2`.
Les cinq autres (`tokio-macros` et son outillage proc-macro) compilent pour l'hôte
et n'entrent dans aucun binaire. Le
registre tablait sur vingt-cinq ; `default-features = false` fait toute la
différence, et l'estimation y a été corrigée.

`libc` est déclarée en direct bien que tokio la tire déjà : `refuse_root` (C10)
appelle `geteuid` elle-même, et une dépendance qu'on utilise se déclare.

Les crates des étages 1 et 2 n'en ont **aucune** : elles sont `#![no_std]` sans
`alloc`.

## Licence

[MPL-2.0](LICENSE).
