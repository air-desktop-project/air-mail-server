# air-mail-server

Serveur de courrier écrit en Rust : **SMTP**, **POP3**, **IMAP** et **HTTP**.

> ## État : squelette
>
> Ce dépôt compile, il est linté, et il porte trois gates de CI. Il **ne sert
> aucun protocole** : toutes les crates fonctionnelles sont des emplacements
> réservés qui le disent dans leur propre documentation.
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

| Crate | Périmètre |
| --- | --- |
| `ams-mime` | RFC 5322 et MIME — le socle des quatre protocoles |
| `ams-proto-smtp` | RFC 5321 |
| `ams-proto-pop3` | RFC 1939 |
| `ams-proto-imap` | RFC 9051 (IMAP4rev2) |
| `ams-proto-http` | RFC 9110 / 9112 |

### Étage 2 — décisions, sans entrée-sortie

Des machines à états. Elles reçoivent des octets **et l'heure** ; elles rendent
des octets **et des actions**. Elles n'attendent jamais.

| Crate | Périmètre |
| --- | --- |
| `ams-session` | les sessions serveur |
| `ams-guard` | flooding et bannissement par source |
| `ams-tls` | TLS 1.3 uniquement |
| `ams-dkim` | RFC 6376 |
| `ams-spf` | RFC 7208 |
| `ams-dmarc` | RFC 7489 |
| `ams-config` | schéma Cap'n Proto de la configuration |
| `ams-index` | index Maildir : codec et reconstruction |

### Étage 3 — exécution

Les seules crates qui lisent, écrivent et attendent. Elles ne décident de rien.

| Crate | Périmètre |
| --- | --- |
| `ams-loop-tokio` | la boucle Unix, sur tokio |
| `ams-store` | Maildir : les fichiers, seule source de vérité |
| `ams-server` | le binaire `air-mail-server` |
| `ams-admin` | le binaire `air-mail-admin` |

**Aucune crate n'est implémentée.** Chacune le déclare dans sa documentation.

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

La CI (`.github/workflows/ci.yml`) tourne sur chaque PR et sur `main`, en trois
jobs indépendants : la vérification du code (les quatre commandes ci-dessus, sous
`-D warnings` et `--locked`), le gate **DCO**, et le gate de **couverture**.

### Couverture (C2)

`scripts/check-couverture.sh` exige **100 %** sur les treize crates des étages 1
et 2. Le seuil porte sur les **régions** et les **lignes** — pas sur les branches,
que `llvm-cov` n'instrumente pas sur Rust stable et dont le compteur reste à
`0 / 0`. Les régions font le travail attendu : chaque bras d'un conditionnel en
est une.

À ce jour le gate **ne mesure rien** — les treize crates sont vides — et il le dit
au lieu d'annoncer 100 %. Un pourcentage sur un ensemble vide n'est pas une
mesure.

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

**Aucune dépendance externe**, et c'est délibéré. Le premier crate tiers qui
entrera dans ce workspace mérite d'être discuté pour lui-même, plutôt que d'entrer
par habitude dans un squelette.

## Licence

[MPL-2.0](LICENSE).
