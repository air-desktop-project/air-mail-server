# air-mail-server

Serveur de courrier écrit en Rust : **SMTP**, **POP3**, **IMAP** et **HTTP**.

> ## État : squelette
>
> Ce dépôt vient d'être créé. Il compile, il est linté, il a deux tests — et il
> **ne sert aucun protocole**. Les crates `ams-proto-*` et `ams-store` sont des
> emplacements réservés qui le disent dans leur propre documentation. La seule
> chose implémentée est la couture d'exécution décrite plus bas.
>
> Ce que ce dépôt affirme, il le tient. Rien de plus n'est promis ici.

## Ce qui existe aujourd'hui

| Crate | Rôle | État |
| --- | --- | --- |
| `ams-rt` | Traits d'exécution : `Listener`, `Stream`, `Clock` | Défini |
| `ams-rt-std` | Ces traits sur `std::net` / `std::time` | Implémenté, testé |
| `ams-proto-smtp` | Grammaire SMTP (RFC 5321/5322) | Vide |
| `ams-proto-pop3` | Grammaire POP3 (RFC 1939) | Vide |
| `ams-proto-imap` | Grammaire IMAP (RFC 9051) | Vide |
| `ams-proto-http` | Grammaire HTTP/1.1 (RFC 9110/9112) | Vide |
| `ams-store` | Boîtes, messages, drapeaux, UID | Vide |
| `ams-server` | Binaire d'assemblage | Annonce sa version |

## Le découpage, et pourquoi il est celui-là

**Les crates `ams-proto-*` ne font aucune entrée-sortie.** Elles transforment des
octets en commandes et des réponses en octets ; elles ne connaissent ni socket, ni
fichier, ni horloge.

Deux raisons, et elles se renforcent :

1. **Ce qui n'ouvre pas de port se vérifie exhaustivement.** Un littéral IMAP
   `{1024}` annonce une longueur venue du réseau. Ce chemin-là se teste et se
   fuzze sur un tableau d'octets en mémoire, pas sur une connexion.
2. **Ce qui ne fait pas d'entrée-sortie n'a rien à porter** le jour où
   l'environnement change.

**`ams-rt` est la couture.** Elle décrit ce que le serveur attend de son
environnement — accepter une connexion, lire et écrire des octets, lire l'heure.
`ams-rt-std` en donne aujourd'hui la seule implémentation.

## Portage vers Air

Ce projet appartient au même projet qu'[Air](https://github.com/air-desktop-project/air),
et vise à s'y adosser un jour. Il n'en dépend **pas** aujourd'hui : ni crate, ni
build, ni toolchain communs — `air-mail-server` compile sur Rust stable et n'a
aucune dépendance externe.

Le portage consistera à écrire une seconde implémentation d'`ams-rt` adossée au
stack Air, aux côtés d'`ams-rt-std`. C'est pour rendre cela possible sans
réécriture que les traits sont exprimés en `&[u8]` plutôt qu'en
`std::io::Read`/`Write`, et que les crates de protocole sont `#![no_std]` dès
maintenant : `std::io` n'existe pas sur la cible Air.

Aucune date, aucun engagement de calendrier : c'est une direction, pas un plan.

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

## Dépendances

**Aucune dépendance externe**, et c'est délibéré. Le premier crate tiers qui
entrera dans ce workspace mérite d'être discuté pour lui-même, plutôt que d'entrer
par habitude dans un squelette.

## Licence

[MPL-2.0](LICENSE).
