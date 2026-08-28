# Fuzzing d'air-mail-server

Crate `cargo-fuzz` **hors du workspace**, et pas par commodité.

`cargo-fuzz` exige un nightly ; le workspace est épinglé sur **stable 1.98.0 en
version exacte**. Deux toolchains dans un même workspace, ce sont deux LLVM — et
les profils de couverture que l'un écrit, l'autre ne sait pas les relire. Le gate
de [C2](../docs/contraintes.md) ne pourrait plus conclure.

La séparation résout cela sans compromis : cette crate a son propre `Cargo.lock`,
n'entre ni dans la mesure de couverture ni dans le lock du produit, et rien de ce
qu'elle tire n'est jamais livré. Le nightly employé ici est **roulant**, ce qui est
acceptable *ici seulement* : rien n'en sort qui doive s'accorder avec autre chose.

## Ce qu'on fuzze, et pourquoi

Un message est **la** donnée externe d'un serveur de courrier : n'importe qui peut
en composer un et l'envoyer. Une panique dans un décodeur y est un déni de service
offert à qui sait écrire quinze octets.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_mime_parse` | `seeds/mime` | le découpage d'un message — la grammaire |
| `fuzz_ams_mime_limits` | `seeds/mime` | le même, avec des **bornes arbitraires** |
| `fuzz_ams_smtp_command` | `seeds/smtp` | le décodage d'une commande — la grammaire |
| `fuzz_ams_smtp_limits` | `seeds/smtp` | le même, avec des **bornes arbitraires** |
| `fuzz_ams_smtp_reply` | `seeds/smtp-reply` | l'encodage d'une réponse — **aller-retour** |

Les variantes « bornes » existent parce que les bornes de C3 viennent de la
configuration (C8), donc d'un administrateur : un zéro, un `usize::MAX`, ou toute
valeur entre les deux. Une borne absurde doit produire un refus, jamais un
débordement.

Une ligne de commande SMTP est ce qu'un serveur lit **avant toute
authentification** : la surface la plus exposée du produit.

Les harnais sont **purs** — aucune entrée-sortie, conformément à ce que les crates
fuzzées s'interdisent (C1).

## Les propriétés

Vérifiées à chaque itération **acceptée**. Chaque grammaire a son fichier
d'invariants — `invariants.rs` pour MIME, `invariants_smtp.rs` pour SMTP —
**partagé** par ses deux cibles : celles-ci ne diffèrent que par la provenance des
bornes, jamais par ce qu'elles exigent.

### MIME (sept)

1. **Le découpage ne perd ni n'invente rien** : l'entrée est exactement l'en-tête,
   puis le CRLF vide, puis le corps. La plus forte, et la moins chère.
2. **Aucun CR ni LF isolé n'a survécu dans l'en-tête.** C'est la propriété qui
   ferme la contrebande SMTP : un octet de fin de ligne ambigu qui passerait
   permettrait au serveur suivant de découper autrement, et de voir un message que
   celui-ci n'a pas vu.
3. Les bornes annoncées sont tenues — taille d'en-tête, longueur de ligne.
4. Un nom de champ accepté est non vide et dans `ftext` (`%d33-126`).
5. Déplier ne peut que **retirer** des octets.
6. Un morceau déplié ne contient plus de fin de ligne.
7. La comparaison de nom est réflexive.

### SMTP — commandes (huit)

1. La ligne est bornée et se termine par CRLF.
2. **Aucun CR ni LF isolé n'a survécu** — même propriété, même raison.
3. **Les deux côtés de l'enveloppe n'admettent jamais la valeur de l'autre** :
   `<>` ne vient que d'un `MAIL`, `<Postmaster>` que d'un `RCPT`. Les confondre
   ferait accepter un message qui ne va nulle part, ou un avis de non-remise qui
   en provoquerait un autre.
4. `HELO` n'admet pas de littéral d'adresse (RFC 5321 §4.1.1.1).
5. Le mécanisme SASL est conforme à la RFC 4422 §3.1 (1 à 20, majuscules).
6. **Aucune route source ne passe** — une partie locale ne commence jamais par `@`.
7. La distinction domaine / littéral tient aux octets : un littéral porte ses
   crochets, un domaine n'en a pas et ne porte pas de `@`.
8. Une valeur de paramètre présente n'est jamais vide et ne porte ni `=` ni espace.

### SMTP — réponses (sept), dont un ALLER-RETOUR

Cette cible ne se contente pas de vérifier l'absence de panique : elle
**ré-analyse la sortie de l'encodeur** et exige d'y retrouver, à l'octet près, ce
qui y était entré. Un encodeur qui perdrait, tronquerait ou fusionnerait une ligne
échoue ici — et c'est la seule propriété qui les attrape toutes.

1. La taille annoncée par `encoded_len` est celle qui est écrite. C'est le contrat
   sur lequel l'écriture se dispense de toute vérification : s'il ment, on indexe
   hors du tampon.
2. La sortie se termine par CRLF.
3. **Aller-retour** : le découpage rend exactement les lignes entrées.
4. Le séparateur dit si la réponse continue — tiret partout sauf sur la dernière
   ligne. Un tiret final ferait attendre le pair indéfiniment ; une espace au
   milieu lui ferait lire la suite comme une autre réponse.
5. Le texte est celui qui est entré, à l'octet près.
6. **Aucun CR ni LF n'a survécu dans un texte** — l'injection de réponse.
7. Chaque ligne respecte sa borne, CRLF compris.

## Lancement

**Nommez la cible de compilation.** cargo-fuzz 0.13.1 choisissait
`x86_64-unknown-linux-gnu` par défaut, 0.13.2 choisit musl — dont la libc statique
est incompatible avec le sanitizer. Sans `--target`, la commande dépend de la
version de l'outil installée sur la machine.

```sh
# Campagne (Ctrl-C pour arrêter)
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu fuzz_ams_mime_parse
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu fuzz_ams_smtp_command

# Bornée, en partant du corpus versionné. Le `mkdir` n'est pas superflu :
# libFuzzer REFUSE DE DÉMARRER si le premier répertoire de corpus n'existe pas,
# et cargo-fuzz ne le crée que lorsqu'on ne lui en nomme aucun.
mkdir -p corpus/fuzz_ams_smtp_command
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu fuzz_ams_smtp_command \
  corpus/fuzz_ams_smtp_command seeds/smtp -- -max_total_time=30
```

`corpus/` et `artifacts/` ne sont **pas** versionnés : ils sont propres à une
machine et à une campagne. `seeds/` l'est, rangé **par grammaire** — des entrées
qui la franchissent, pour qu'une campagne courte ne passe pas son temps à la
redécouvrir.

## Ce que la CI en fait, et ce qu'elle n'en fait pas

La CI lance un **smoke-fuzz borné** de quelques secondes par cible. C'est un
détecteur de régression, **pas une campagne** : quelques secondes depuis un corpus
neuf n'explorent pas ce que des heures explorent. Une vraie campagne se lance à la
main, et l'absence de plantage en CI ne prouve rien de plus que ce qu'elle a
couvert.

## Ce que le fuzz a trouvé

**`fuzz_ams_smtp_reply`, en soixante secondes, à sa première campagne.**
`encoded_len` calculait la place disponible pour le texte d'une ligne par
`max_reply_octets.saturating_sub(6)` — six étant l'enveloppe incompressible
(code, séparateur, CRLF). Sous une borne inférieure à six, la saturation
transformait « aucune ligne ne tient » en « les lignes vides tiennent », et
l'encodeur émettait six octets sous une borne de trois.

L'habitude qui a produit ce défaut est ailleurs la bonne : préférer
`saturating_*` à `checked_*` évite une branche que rien ne pourrait exercer, et
que le 100 % de C2 compterait à jamais découverte. Elle ne vaut que **là où
l'échec est vraiment impossible** — et ici il ne l'était pas, puisque la borne
vient de la configuration, donc d'un administrateur.

L'entrée fautive est versionnée en graine de non-régression
(`seeds/smtp-reply/borne-inferieure-a-l-enveloppe`).

## Résultats

| Date | Cible | Exécutions | Plantages |
| --- | --- | --- | --- |
| 2026-08-28 | `fuzz_ams_mime_parse` | 2 780 381 (46 s) | 0 |
| 2026-08-28 | `fuzz_ams_mime_limits` | 2 046 935 (46 s) | 0 |
| 2026-08-28 | `fuzz_ams_smtp_command` | 10 668 888 (46 s) | 0 |
| 2026-08-28 | `fuzz_ams_smtp_limits` | 4 423 315 (46 s) | 0 |
| 2026-08-28 | `fuzz_ams_smtp_reply` | 3 226 422 (91 s) | **1, corrigé** |
