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
| `fuzz_ams_session_smtp` | `seeds/session` | la session — **vocabulaire de sortie clos** |
| `fuzz_ams_smtp_data` | `seeds/smtp-data` | la phase de données — **indépendance au découpage** |
| `fuzz_ams_guard` | `seeds/guard` | le garde — **une peine ne s'évince pas** |
| `fuzz_ams_index_name` | `seeds/index` | les noms Maildir — **aller-retour de l'UID** |
| `fuzz_ams_config` | `seeds/config` | les trois formats binaires : configuration, comptes, index |
| `fuzz_ams_tls_kx` | `seeds/tls` | la part de clé TLS du pair — **les deux rôles** |
| `fuzz_ams_sasl` | `seeds/sasl` | la réponse SASL — **décodage canonique** |
| `fuzz_ams_pop3` | `seeds/pop3` | la ligne POP3 — **et le doublement du point** |
| `fuzz_ams_session_pop3` | `seeds/pop3-session` | la session POP3 — **vocabulaire clos, états tenus** |

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

### Session SMTP (cinq), dont un VOCABULAIRE CLOS

Un pair hostile choisit l'ordre des commandes, leur contenu, et le moment où il
s'arrête. Cette cible lui donne cette liberté, plus les événements que la boucle
peut intercaler : poignée de main TLS, verdict SASL, verdict de message.

1. **Toute réponse appartient à une liste finie, connue d'avance.** La session ne
   compose ses réponses qu'avec des textes constants et son propre domaine ; si
   elle reprenait un seul octet venu du pair, la réponse sortirait de la liste.

   C'est plus fort que « aucun CR n'a survécu » : cela interdit l'écho *tout
   court*, donc aussi la fuite d'un nom de boîte dans un message d'erreur — le
   genre de détail qui transforme un serveur en annuaire.
2. **`AUTH` n'est jamais engagé hors chiffrement** — le refus emblématique de C6,
   éprouvé plutôt qu'affirmé.
3. `STARTTLS` n'est jamais proposé sur une session déjà chiffrée.
4. Chaque action s'accompagne du code qui lui correspond : `354` pour les données,
   `221` pour la fermeture, `334` pour le défi SASL, `220` pour TLS.
5. Après la poignée de main, ni l'identification ni l'authentification n'ont
   survécu (RFC 3207 §4.2).

### Phase de données SMTP (six), dont l'INDÉPENDANCE AU DÉCOUPAGE

La contrebande SMTP ne tient pas à un débordement : elle tient à ce que deux
lecteurs ne coupent pas le même flux au même endroit. C'est donc cela qu'il faut
éprouver, et pas seulement l'absence de panique.

Cette cible lit chaque flux **deux fois** : d'un seul tenant, puis par tranches
arbitraires — dont des tranches d'un octet, qui coupent au milieu d'un `CRLF` ou
d'un terminateur.

1. **Les deux lectures rendent le même verdict et les mêmes octets.** Un décodeur
   qui conclurait autrement sur `\r\n.\r` suivi de `\n` que sur `\r\n.\r\n` d'un
   coup échoue ici. C'est exactement la divergence dont vit l'attaque.
2. **L'invariante de progrès** : sur une entrée non vide, le récepteur consomme au
   moins un octet ou conclut. Sans elle, un pair enfermerait la boucle avec trois
   octets.
3. Le récepteur ne consomme jamais plus qu'on ne lui a donné.
4. **Aucun CR ni LF isolé n'a survécu** dans ce qui a été accepté.
5. Le message n'est jamais plus long que ce qui a été lu.
6. Les bornes de ligne et de message sont tenues.

### Garde anti-flooding (trois), dont l'INÉVINÇABILITÉ D'UNE PEINE

La table du garde est bornée — c'est ce qui l'empêche d'être un épuisement de
mémoire. Mais une table bornée doit oublier, et **ce qu'elle oublie est
précisément ce qu'un attaquant veut choisir**.

1. **Un banni le reste tant que sa peine court**, quel que soit le flot d'autres
   sources qui martèle la table. C'est l'attaque évidente : inonder pour se faire
   oublier.
2. **Un bannissement rendu n'est jamais déjà échu.** Un verdict qui se contredit
   au moment où il est prononcé ne vaut rien.
3. La table ne déborde jamais de sa capacité.

### Noms Maildir (six), dont l'ALLER-RETOUR DE L'UID

L'UID d'un message vit dans son nom de fichier : c'est ce qui rend l'index
reconstructible (C13). Si un nom composé ne se relisait pas à l'identique, l'UID
changerait au prochain parcours — et un UID qui change force à incrémenter
l'`UIDVALIDITY`, ce qui fait **retélécharger la boîte entière à tous les
clients**. Un défaut ici ne se voit pas quand il se produit : il se voit quand
mille boîtes se resynchronisent.

1. **Composer puis relire rend l'identique** — UID, taille, drapeaux.
2. **Recomposer depuis ce qui a été relu rend les mêmes octets.**
3. Un nom accepté ne porte jamais de `/` : la traversée de répertoire est fermée
   avant le système de fichiers.
4. Un UID lu n'est jamais nul (RFC 9051 §2.3.1.1).
5. Le repliement compte chaque nom une fois et une seule.
6. Le prochain UID est strictement au-dessus de tous ceux qui existent — sauf
   quand la boîte est épuisée, auquel cas elle le déclare.

### Session POP3 (cinq, dont DEUX INVARIANTS D'ÉTAT)

1. Rien ne panique, et le tampon de mille octets suffit toujours.
2. **Le vocabulaire de sortie est CLOS** : `+OK` ou `-ERR`, un seul `CRLF`, et
   rien qui vienne du pair. Un serveur qui renverrait ce qu'on lui envoie
   offrirait un moyen d'écrire dans le dialogue.
3. **Aucune session ne s'ouvre sans le bon mot de passe.**
4. **`USER`/`PASS` n'aboutissent jamais hors chiffrement** (C6) : une ouverture
   demandée sans TLS serait la faille.
5. **`CommitAndClose` n'est jamais rendu sans boîte ouverte.** L'état UPDATE
   n'est atteint que depuis TRANSACTION : c'est ce qui empêche une coupure
   réseau d'effacer du courrier.

### POP3 (quatre, dont le DOUBLEMENT DU POINT)

1. N'importe quels octets, avec n'importe quelles bornes, rendent une erreur ou
   une commande — jamais une panique.
2. **Une commande acceptée a son `CRLF` à la fin et n'en porte pas ailleurs.**
   C'est le contrebandage, dans un autre protocole : deux lecteurs qui ne
   s'accordent pas sur ce qui termine une ligne découpent le même flux en deux
   séries de commandes différentes.
3. **Ce qui est écrit fait exactement la taille annoncée**, et `encode` refuse
   tout ce que `encoded_len` refuse — les deux ne peuvent pas diverger.
4. **Toute ligne de corps commençant par un point en porte deux**, et aucune
   ligne doublée n'est le terminateur. Sans cela, le message finirait au milieu,
   et ce qui suit serait lu comme des commandes.

### Réponse SASL (quatre, dont une CANONICITÉ)

Ces octets-là arrivent d'un inconnu — chiffrés, oui, mais le chiffrement
n'authentifie personne. C'est la dernière grammaire que le serveur lit avant de
savoir à qui il parle.

1. N'importe quels octets rendent une erreur ou des identifiants, jamais une
   panique.
2. **Ce qui est décodé tient dans ce que `decoded_len` annonce** (C3) : la
   sortie est bornée par l'entrée, et jamais l'inverse.
3. **Deux chaînes base64 distinctes ne rendent jamais les mêmes octets.** C'est
   la propriété qui empêche un même identifiant de s'écrire de plusieurs façons,
   et donc de passer à côté d'un filtre ou d'un comptage qui compare les formes
   encodées. Le fuzzer la vérifie en changeant un caractère et en exigeant que
   la sortie change — ou que l'entrée soit refusée.
4. Les trois champs de `PLAIN`, remis bout à bout avec leurs deux séparateurs,
   recouvrent exactement ce qui a été lu.

La cible replie une partie de ses octets sur l'alphabet base64 : muter au hasard
produirait surtout des refus, et le décodeur lui-même ne serait jamais atteint.

### Échange de clés TLS (une, et elle se suffit)

La part `key_share` est lue **avant même le certificat** : c'est la première chose
qu'un inconnu fait entrer dans le processus, et la seule surface de `ams-tls`
atteignable sans avoir rien prouvé. La cible joue les **deux rôles** — serveur qui
reçoit la part du client, client qui reçoit celle du serveur —, le second au prix
d'une génération de clé par exécution.

1. N'importe quels octets rendent une erreur ou un secret, **jamais une panique**.

Il n'y a qu'une propriété, et c'est normal : un aller-retour n'a pas de sens ici
(les deux parts sont aléatoires par construction) et un secret partagé ne
s'inspecte pas — `SharedSecret` n'implémente délibérément pas `Debug`. Ce que la
cible éprouve, ce sont les **découpages de longueur** et les primitives qui les
suivent. La preuve que les deux camps calculent *le même* secret ne peut pas venir
d'un fuzzer : elle vient du test d'interopérabilité contre OpenSSL.

### Les trois formats binaires (sept)

Une configuration est écrite par l'administrateur, pas par un pair : ce n'est pas
une entrée hostile au sens de C3. Mais un disque vieillit, une copie s'interrompt,
un octet se retourne — et **un serveur qui panique en lisant sa propre
configuration ne démarre pas, et ne dit pas pourquoi**.

1. Lire n'importe quoi ne panique jamais.
2. **Ce qu'`air-mail-admin` écrit, `air-mail-server` le relit à l'identique.** Un
   écart y serait un serveur réglé autrement que ce que l'administrateur croit
   avoir demandé.
3. Réécrire ce qui a été relu rend les mêmes octets.
4. Corrompre un octet rend une erreur, jamais une panique.
5. **Le magasin de comptes fait l'aller-retour, lui aussi** — avec l'empreinte
   de personne, qui a les vrais paramètres du produit et franchit donc son
   contrôle de plancher, là où un vrai hachage coûterait des secondes par
   exécution.
6. **Tout magasin que le décodeur accepte a des noms uniques.** Les noms de la
   graine sont libres — vides, en double, quelconques : ce sont exactement les
   cas que le décodeur refuse, et les lier dans l'entrée cacherait ces refus au
   lieu de les éprouver.
7. **L'index fait l'aller-retour**, et n'importe quels octets le laissent rendre
   une erreur plutôt qu'une panique. Le stockage traite une erreur comme une
   ABSENCE d'index — il reconstruit — mais une panique, elle, ne se rattrape
   pas : elle empêche la boîte de s'ouvrir alors que tous les messages sont là.

## LE PIÈGE DE LA SÉPARATION, et il a déjà mordu

Cette crate est **hors du workspace** (voir `Cargo.toml`, qui dit pourquoi). La
conséquence se paie un jour ou l'autre : `cargo build --workspace`,
`cargo test --workspace` et `cargo clippy --workspace` **ne la compilent pas**.
Un champ ajouté à une structure publique — `Configuration`, par exemple — la
casse sans qu'aucun gate local ne le dise. C'est l'intégration continue qui l'a
attrapé, trois minutes plus tard, et c'est trois minutes de trop.

Avant de pousser une modification d'API, une seule commande suffit :

```sh
cd fuzz && cargo +nightly fuzz build --target x86_64-unknown-linux-gnu
```

**Et il faut en LIRE le code de retour.** Passer cette commande dans un tube —
`… | tail -1` — rend le code de `tail`, qui réussit toujours. C'est ainsi qu'un
échec de compilation est passé inaperçu jusqu'à l'intégration continue, alors
même que la commande avait été lancée.

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

**`fuzz_ams_index_name`, deux fois — et la seconde EN INTÉGRATION CONTINUE.**

La première : `compose` acceptait une partie unique vide — ou commençant par une
virgule — et produisait un nom que `parse` refusait.

La seconde : une partie unique portant DÉJÀ un champ `U=` ou `S=`. Le nôtre s'y
ajoutait, et un champ mal formé de l'appelant (`,U=0`) rendait illisible un nom
dont notre part était parfaite. Ces deux champs appartiennent au composeur, et
sont désormais refusés à l'entrée.

**`fuzz_ams_tls_kx`, dès sa toute première exécution — et pas une panique.**

LeakSanitizer, qui tourne avec le fuzzer, a signalé une **fuite mémoire sans
borne** : `ams_tls::provider()` obtenait le `&'static` exigé par `kx_groups` en
faisant `Box::leak`, sous couvert d'un commentaire disant « un fournisseur se
construit une fois au démarrage ». C'était une consigne d'usage, pas une garantie
— et rien dans la signature ne l'imposait à l'appelant. Appelée par connexion,
comme une boucle serveur pourrait légitimement le faire, la fonction perdait de la
mémoire à chaque fois.

Le groupe hybride est désormais un `static`, construit **à la compilation**. La
question n'est pas déplacée, elle est supprimée : aucune allocation, aucun verrou,
et une durée de vie qui est une propriété du code au lieu d'une promesse écrite
en commentaire. C'est le rappel qu'un fuzzer ne cherche pas que des paniques.

**Le smoke-fuzz de vingt secondes a trouvé ce qu'une campagne locale de deux
millions d'exécutions avait manqué.** Ce n'est pas de la chance : les deux
partent de corpus différents, et c'est précisément pourquoi la CI en lance un.
Les graines ont été enrichies depuis le corpus accumulé.

Dans les deux cas : un composeur qui fabrique de l'illisible n'en est pas un, et le
défaut ne se serait vu qu'au parcours suivant : l'UID redevenu introuvable, la
boîte à renuméroter, l'`UIDVALIDITY` à changer, et tous les clients à
resynchroniser.

**`fuzz_ams_guard`, deux fois, à sa première campagne.**

1. **Une peine pouvait être évincée.** La règle d'éviction sacrifiait, quand la
   table était pleine de bannissements, celui qui expirait le plus tôt — « puisque
   sa perte coûte le moins ». Il suffisait donc de remplir la table pour se
   libérer. La règle est devenue : **une peine en cours n'est jamais candidate à
   l'éviction**, et une table pleine de peines cesse d'apprendre plutôt que
   d'oublier. Entre oublier un attaquant prouvé et ne pas commencer à compter un
   inconnu, c'est l'oubli qui coûte le plus cher.
2. **Une peine de durée nulle était prononcée quand même**, sous la forme
   `Banned { until: maintenant }` — que l'interrogation suivante démentait
   aussitôt. Une configuration à zéro dit « ne bannis pas » : l'événement est
   désormais freiné, sans plus.

Une troisième défaillance venait de la cible elle-même : elle comparait des
ADRESSES là où le garde compare des PRÉFIXES. Sous un `/0`, deux adresses
différentes sont la même source, et le garde avait raison de la recompter.

**`fuzz_ams_smtp_data`, à sa première campagne, sur le flux `\rF\n`.** Sous une
borne de ligne étroite, la lecture d'un seul tenant rendait « CR isolé » et la
lecture hachée « ligne trop longue » : le `CR` retenu en fin de lecture était
compté AVANT d'être confirmé comme moitié d'un `CRLF`, alors que le même `CR` lu
d'un trait était refusé avant tout comptage.

Les deux lectures refusaient, donc rien ne passait — mais **la faute rendue
dépendait de l'endroit où la lecture avait été coupée**, et c'est la contrebande
SMTP en miniature. La règle est désormais unique : un `CR` n'est compté qu'une
fois confirmé. L'entrée fautive est versionnée
(`seeds/smtp-data/cr-compte-avant-confirmation`).

Une seconde entrée a fait échouer la cible sans que le code soit en cause : la
dernière ligne d'un flux TRONQUÉ n'a pas encore son `CRLF`, et lui appliquer la
borne « CRLF compris » accusait un octet licite. L'assertion a été corrigée, et
l'entrée gardée (`seeds/smtp-data/ligne-inachevee`) : une cible qui se trompe est
aussi une régression à empêcher.

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
| 2026-08-28 | `fuzz_ams_session_smtp` | 1 296 868 (91 s) | 0 |
| 2026-08-28 | `fuzz_ams_smtp_data` | 4 629 514 (121 s) | **1, corrigé** |
| 2026-08-28 | `fuzz_ams_guard` | 2 721 501 (151 s) | **2, corrigés** |
| 2026-08-28 | `fuzz_ams_index_name` | 2 015 974 (181 s) | **2, corrigés** |
| 2026-08-28 | `fuzz_ams_config` | 573 580 (91 s) | 0 |
| 2026-08-28 | `fuzz_ams_tls_kx` | 47 296 (121 s) | **1 fuite, corrigée** |
| 2026-08-28 | `fuzz_ams_sasl` | 4 786 307 (61 s) | 0 |
| 2026-08-29 | `fuzz_ams_pop3` | 11 871 878 (91 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_pop3` | 1 179 107 (91 s) | 0 |
| 2026-08-28 | `fuzz_ams_session_smtp` (SASL) | 521 646 (91 s) | 0 |

Le débit de `fuzz_ams_tls_kx` est trois ordres de grandeur sous les autres : une
génération de clé ML-KEM et deux X25519 par exécution, ce que rien n'accélérera.
Ce n'est pas un défaut du harnais, c'est le coût de la cible — et la raison de
lancer cette campagne-là plus longtemps que les autres.
