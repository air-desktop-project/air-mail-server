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
> Ce qu'il ne fait pas : **ni TLS ni authentification** — ni `STARTTLS` ni `AUTH`
> ne sont annoncés, parce que rien ne sait les conduire. Et **une seule boîte pour
> tout le monde** : répartir par destinataire demande un modèle de comptes qui
> n'existe pas.
>
> Neuf crates portent du code ; les autres sont des emplacements réservés qui le
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
| `ams-proto-pop3` | RFC 1939 | vide |
| `ams-proto-imap` | RFC 9051 (IMAP4rev2) | vide |
| `ams-proto-http` | RFC 9110 / 9112 | vide |

### Étage 2 — décisions, sans entrée-sortie

Des machines à états. Elles reçoivent des octets **et l'heure** ; elles rendent
des octets **et des actions**. Elles n'attendent jamais.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-session` | les sessions serveur | **SMTP : session entière** |
| `ams-guard` | flooding et bannissement par source | **implémenté** |
| `ams-tls` | TLS 1.3 uniquement | vide |
| `ams-dkim` | RFC 6376 | vide |
| `ams-spf` | RFC 7208 | vide |
| `ams-dmarc` | RFC 7489 | vide |
| `ams-config` | schéma Cap'n Proto de la configuration | **implémenté** |
| `ams-index` | noms Maildir, drapeaux, reconstruction | **implémenté** |

### Étage 3 — exécution

Les seules crates qui lisent, écrivent et attendent. Elles ne décident de rien.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-loop-tokio` | la boucle Unix, sur tokio | **une connexion, de bout en bout** |
| `ams-store` | Maildir : les fichiers, seule source de vérité | **implémenté** |
| `ams-server` | le binaire `air-mail-server` | **il tourne** |
| `ams-admin` | le binaire `air-mail-admin` | **`summary`** |

**Dix crates portent du code.** `ams-mime` : le squelette d'un message — la
ligne, le pliage, la séparation en-tête/corps, le découpage en champs. Les champs
structurés, les adresses, les dates et MIME restent à écrire.
`ams-proto-smtp` : les commandes, l'encodage des réponses multilignes, et **la
phase de données** — `<CRLF>.<CRLF>`, le point échappé, et le refus de tout `CR`
ou `LF` isolé. `BDAT`/`CHUNKING`, l'échappement à l'émission et la validation
complète d'une adresse IPv6 restent à écrire.

`ams-session` : la session SMTP entière — bannière, `EHLO`, annonce des
extensions, séquencement `MAIL`/`RCPT`/`DATA`, `STARTTLS`, refus d'`AUTH` hors
chiffrement, et phase de données. **L'échange SASL et la boucle d'entrées-sorties
restent à écrire.**

`ams-loop-tokio` : la boucle d'acceptation et le pilote d'une connexion, sur
tokio. Elle lit, elle écrit, elle ne décide de rien — pas même le `421` qui refuse
une source trop pressée, qui vient de la session. Ses tests jouent des
conversations en mémoire **et** de vraies connexions sur la boucle locale. TLS et
SASL restent à écrire.

`ams-guard` : la détection de flooding et le bannissement par source (C8), dans
une table **bornée** que l'appelant fournit — et dont une peine en cours n'est
jamais évincée. La clé est un **préfixe**, pas une adresse : bannir une IPv6 seule
ne sert à rien. Le garde est consulté avant la bannière, puis à chaque commande ;
**on ne dit pas un mot à un banni**.

`ams-index` : les noms Maildir, les drapeaux, et la **reconstruction** — un
repliement sur les noms, sans table donc sans allocation. C'est là que vit la
raison d'être du `,U=` dans un nom de fichier.

`ams-store` : la boîte Maildir. Arrivée par `rename()` atomique, **deux `fsync`**
— le fichier avant, le répertoire après —, adoption des messages déposés par
d'autres outils, et nettoyage de `tmp/` même quand une remise est abandonnée.

`ams-config` : le schéma Cap'n Proto, et son codec. Le code dérivé est **généré
et committé** — le build et la CI n'ont besoin d'aucun outil C++.

`ams-server` et `ams-admin` : les deux binaires de C12. Le premier assemble les
pièces et ne contient **aucune logique de protocole** — seulement le fil. Le
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
