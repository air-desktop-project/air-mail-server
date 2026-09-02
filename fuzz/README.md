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

## UNE PROPRIÉTÉ MAL DITE N'EN TROUVE PAS : ELLE EN INVENTE

`fuzz_ams_session_imap` affirmait « non authentifié OU chiffré ». C'est faux :
`LOGOUT` mène à l'état `Logout`, qui n'est ni l'un ni l'autre — et qui ne donne
accès à rien. La cible est donc tombée sur un `LOGOUT` en clair, sans qu'il y eût
quoi que ce soit à corriger dans la session.

Ce qu'il fallait exclure, ce sont **les états qui donnent accès au courrier** :
`Authenticated` et `Selected`. C'est la quatrième fois qu'une campagne trouve une
propriété fausse plutôt qu'un défaut, et cela vaut d'être écrit : une cible qui
échoue commence par mettre en cause ce qu'elle affirme.

**La cinquième, le 2026-09-01, sur `fuzz_ams_mime_bounce`.** La cible exigeait
que le délimiteur de parties ne figure QUE là où le composeur le pose : cinq
fois, une pour l'en-tête et quatre aux bornes des trois parties. Le fuzz a rendu
quinze, en une seconde, avec un délimiteur d'UN SEUL caractère — qui se retrouve
alors dans `Content-Type`, dans `Return-Path`, dans n'importe quel mot qu'on
écrit.

Le code avait raison, et la propriété était trop large. Ce que `write_bounce`
garantit est plus étroit : le délimiteur est absent des DEUX parties LIBRES — le
texte et les en-têtes du message perdu —, c'est-à-dire des seules dont le contenu
ne vient pas de nous. C'est éprouvé là où cela se prouve, dans les essais
unitaires, et la cible a été réécrite autour de trois propriétés qui, elles,
tiennent : tout ce qui sort est ÉMETTABLE (pas un `CR` ni un `LF` isolé), le
chemin de retour est NUL, et **aucune valeur ne peut ajouter un champ de
statut** — celle qui vise vraiment le diagnostic du pair, où un `Action:
delivered` glissé ferait croire à une remise qui n'a pas eu lieu.

La même leçon que les quatre précédentes : la propriété qu'on a envie d'écrire
est souvent plus forte que celle qu'on tient.

**La sixième, le 2026-09-02, sur `fuzz_ams_dane`.** La cible exigeait que deux
certificats DIFFÉRENTS ne puissent pas satisfaire le même JEU de `TLSA` par un
`DANE-EE(3)`. Le fuzz a trouvé le contre-exemple évident une fois qu'on le voit :
un jeu qui porte DEUX `3 0 0`, un par certificat. Les deux sont alors satisfaits
à bon droit — c'est même ainsi qu'un domaine renouvelle, en publiant l'ancien et
le nouveau en même temps.

La propriété vraie se pose **par enregistrement** : un même `TLSA` à sélecteur
`0` ne désigne qu'un certificat, puisque sa donnée EST ce certificat ou son
empreinte. Le sélecteur `1`, lui, porte sur la clef, et deux certificats peuvent
légitimement partager la leur.

Trois de ces six fois portaient sur le même malentendu — confondre ce qu'un JEU
garantit avec ce qu'un de ses ÉLÉMENTS garantit.

**La septième, le 2026-09-02, sur `fuzz_ams_authres`.** La cible comptait les
`;` de l'en-tête composé et exigeait qu'il y en eût autant que de résultats
donnés en entrée. C'est vrai du champ NU ; c'est faux de sa forme REMBOURRÉE, qui
occupe une place fixe réservée en tête du message et **abandonne les signatures
DKIM qui n'y tiennent pas**. Leur nombre ne se déduit donc pas de l'entrée.

La propriété a été restreinte au champ nu, où rien n'est abandonné. Les cinq
autres — rien ne panique, rien n'est écrit au-delà, tout ce qui sort est
émettable, il n'y a qu'UN champ, et le rembourrage occupe EXACTEMENT la place —
valent pour les deux formes, et ce sont elles qui portent le sujet : cet en-tête
est le seul que ce serveur écrive en tête du message d'un pair, et tout ce qui y
entre vient d'en face.

## `scripts/check-fuzz.sh` — le contrôle se lance chez soi

Cette crate vit hors du workspace : **`cargo build --workspace` ne la touche
pas**. Une cible qui cesse de compiler ne se voit donc ni au build, ni aux tests,
ni au clippy — seulement en intégration continue, après un `push`. C'est arrivé
deux fois, les deux fois en changeant un trait que les cibles implémentent ; la
première, la cible ne compilait plus depuis deux commits sans que rien ne le
dise.

    scripts/check-fuzz.sh            # la liste, et la compilation des 63 cibles
    scripts/check-fuzz.sh --smoke    # et vingt secondes chacune
    AMS_FUZZ_SECONDES=300 scripts/check-fuzz.sh --smoke   # une vraie campagne

Le script porte la liste des cibles et de leurs graines, et **la CI l'appelle**
plutôt que d'en tenir une seconde : un contrôle qu'on ne peut pas rejouer chez
soi est un contrôle qu'on découvre en CI. La liste est confrontée aux `[[bin]]`
de `Cargo.toml`, et l'écart échoue — une cible qu'on oublie d'y inscrire ne
serait jamais lancée, et le gate resterait vert en ne l'ayant pas examinée. Un
rapport vert qui n'a rien examiné est un mensonge poli.

Elle est confrontée AUSSI au tableau de ce fichier, plus bas : une cible que
rien ne décrit est une cible que personne ne sait lire.

## `seeds/` S'ÉCRIT À LA MAIN ; `corpus/` EST À LIBFUZZER

Une graine porte un NOM qui dit ce qu'elle vise — `mime-bounce/refus`,
`session/contrebande`, `queue/nom-tordu` — et tient en quelques lignes qu'un
lecteur ouvre et comprend. C'est ce qui fait d'un répertoire de graines une
documentation de ce que la cible cherche, et non un tas d'octets.

Les trouvailles de libFuzzer, elles, vont dans `corpus/`, que git ignore. Il les
nomme par le SHA-1 de leur contenu, et **il écrit dans le PREMIER répertoire de
corpus qu'on lui donne**. D'où le piège, quand on lance une seule cible à la
main :

    cargo +nightly fuzz run <cible> seeds/<graines>                 # ← NON
    cargo +nightly fuzz run <cible> corpus/<cible> seeds/<graines>  # ← ainsi

La première forme déverse des centaines de fichiers DANS les graines, et un
`git add -A` les emporte. C'est arrivé : 656 fichiers dans un commit, retirés
juste avant la poussée, et six autres, plus anciens, qui y dormaient depuis
longtemps — dont les trois seules « graines » de `fuzz_ams_session_smtp`, qui
n'en avait donc aucune d'écrite.

`check-fuzz.sh` refuse désormais toute graine nommée comme une trouvaille, et
le dit avec la ligne de commande à employer. Le contrôle est en tête du script,
avant la compilation : il ne coûte rien, et il tombe avant qu'on ait attendu.

## UN ITÉRATEUR QUI N'AVANCE PAS TUE LA MACHINE

`Args`, l'itérateur d'arguments IMAP, rendait sa faute **sans consommer d'octet**
: il la répétait donc sans fin, et un appelant qui collecte remplissait la
mémoire. Le noyau a tué le binaire de test à 6,1 Gio, sur une machine qui en a
7,6. Trouvé par un test — avant que le fuzz n'ait à le faire, faute d'y avoir
pensé.

`fuzz_ams_imap` porte maintenant la propriété : **un itérateur rend au plus
autant d'éléments que son entrée a d'octets**, ce qui n'est pas un plafond
choisi mais la structure même (un argument occupe au moins un octet). Le drainage
est borné par `take`, si bien que la propriété échoue en un tour au lieu
d'allouer : réintroduire le défaut la fait tomber en une seconde, sur une entrée
de trois octets — vérifié.

Les quatorze autres itérateurs du dépôt ont été relus : tous avancent avant de
rendre leur faute.

## Ce qu'on fuzze, et pourquoi

Un message est **la** donnée externe d'un serveur de courrier : n'importe qui peut
en composer un et l'envoyer. Une panique dans un décodeur y est un déni de service
offert à qui sait écrire quinze octets.

**Le message** — RFC 5322 et MIME, la donnée que n'importe qui peut composer.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_mime_parse` | `seeds/mime` | le découpage d'un message — la grammaire |
| `fuzz_ams_mime_limits` | `seeds/mime` | le même, avec des **bornes arbitraires** |
| `fuzz_ams_mime_decode` | `seeds/mime-decode` | défaire un mot encodé — **`decoded_max` majore sans lire l'entrée**, et un encodage inconnu est l'identité |
| `fuzz_ams_mime_digest` | `seeds/mime-digest` | le résumé d'un message — **rien au-delà des deux tampons fixes**, et aucune fin de ligne dans ce qu'on rend |
| `fuzz_ams_mime_envelope` | `seeds/mime-envelope` | l'`ENVELOPE` d'un en-tête quelconque — **ce qui part sur le fil est bien formé** : dix champs, parenthèses équilibrées, et **aucune fin de ligne dans une chaîne** |
| `fuzz_ams_mime_structure` | `seeds/mime-structure` | la `BODYSTRUCTURE` d'un message quelconque — **le découpage ne change pas le résultat**, ce qui part sur le fil est bien formé, et **une partie désignée ne sort jamais du message** |
| `fuzz_ams_mime_compose` | `seeds/mime-compose` | les messages de rapport — **la pièce jointe se relit, la liste blanche tient** |
| `fuzz_ams_mime_bounce` | `seeds/mime-bounce` | le rapport de non-remise — **aucune valeur n'ajoute un champ de statut**, et le chemin de retour est nul |
| `fuzz_ams_authres` | `seeds/authres` | l'en-tête `Authentication-Results` — **il n'y a qu'UN champ**, tout ce qui sort est émettable, et le rembourrage occupe exactement la place réservée |

**SMTP** — ce qu'un serveur lit avant toute authentification.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_smtp_command` | `seeds/smtp` | le décodage d'une commande — la grammaire |
| `fuzz_ams_smtp_limits` | `seeds/smtp` | le même, avec des **bornes arbitraires** |
| `fuzz_ams_smtp_reply` | `seeds/smtp-reply` | l'encodage d'une réponse — **aller-retour** |
| `fuzz_ams_smtp_data` | `seeds/smtp-data` | la phase de données — **indépendance au découpage** |
| `fuzz_ams_smtp_chunk` | `seeds/smtp-chunk` | les morceaux de `BDAT` — **on ne consomme jamais plus que ce qui est annoncé**, et le découpage ne change rien |
| `fuzz_ams_smtp_literal` | `seeds/smtp-literal` | le littéral d'adresse d'un `EHLO` — **notre verdict est celui de `core::net`**, pour IPv4 comme pour IPv6 |
| `fuzz_ams_smtp_client` | `seeds/smtp-client` | réponses lues et corps émis — **le message ne se termine pas tout seul** |
| `fuzz_ams_session_smtp` | `seeds/session` | la session — **vocabulaire de sortie clos** |
| `fuzz_ams_queue` | `seeds/queue` | la file de réémission — **un nom écrit se relit et ne sort pas du répertoire**, une enveloppe ne s'invente pas de destinataire |

**POP3 et IMAP** — les deux façons de relever son courrier.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_pop3` | `seeds/pop3` | la ligne POP3 — **et le doublement du point** |
| `fuzz_ams_session_pop3` | `seeds/pop3-session` | la session POP3 — **vocabulaire clos, états tenus** |
| `fuzz_ams_imap` | `seeds/imap` | découpage d'une commande IMAP — **le client ne choisit pas où l'on coupe**, et l'itérateur d'arguments s'arrête |
| `fuzz_ams_imap_fetch` | `seeds/imap-fetch` | ce qu'un `FETCH`, un `STORE`, un `SEARCH` et un `APPEND` désignent — **les deux lectures d'un ensemble s'accordent**, un drapeau accepté se réécrit, une recherche décide sans boucler, et **ce qu'un `APPEND` annonce, on peut le tenir** ; **un nom de boîte accepté ne sort pas de sa racine** |
| `fuzz_ams_session_imap` | `seeds/imap-session` | la session IMAP — **jamais authentifié sans chiffrement**, un intervalle de `FETCH` ne déborde pas du message, et **une émission conclut** |

**L'authentification du courrier** — qui a le droit d'écrire sous ce nom.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_spf` | `seeds/spf` | l'enregistrement SPF — **validation d'un seul tenant** |
| `fuzz_ams_spf_eval` | `seeds/spf-eval` | l'évaluation SPF, réponses DNS comprises — **elle conclut** |
| `fuzz_ams_spf_header` | `seeds/spf-header` | l'en-tête `Received-SPF` — **aucune injection de ligne** |
| `fuzz_ams_dkim` | `seeds/dkim` | signature, clé et canonicalisation — **le découpage ne change rien** |
| `fuzz_ams_dmarc` | `seeds/dmarc` | politique et alignement — **l'alignement est symétrique** |
| `fuzz_ams_dmarc_report` | `seeds/dmarc-report` | destinations et rapport agrégé — **le rapport ne s'injecte pas** |
| `fuzz_ams_dns` | `seeds/dns` | la réponse d'un résolveur — **la compression ne boucle pas** |

**Le transport chiffré** — à qui l'on parle, et sous quelle garantie.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_tls_kx` | `seeds/tls` | la part de clé TLS du pair — **les deux rôles** |
| `fuzz_ams_tls_quic` | `seeds/tls-quic` | le pont entre `rustls::quic` et notre protection — **le pont chiffre comme la crate en dessous** |
| `fuzz_ams_dane` | `seeds/dane` | ce qu'un `TLSA` autorise — **un jeu non authentifié n'engage jamais**, et un inutilisable ne satisfait rien |
| `fuzz_ams_mtasts` | `seeds/mtasts` | une politique MTA-STS — **le joker couvre exactement une étiquette**, et ce qu'elle permet vient de ses `mx` |
| `fuzz_ams_tlsrpt` | `seeds/tlsrpt` | un rapport TLS et ses destinations — **jamais plus que la borne**, et **un domaine ne s'autorise pas lui-même** |

**HTTP, HTTP/2 et HTTP/3** — la façade d'administration.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_http_head` | `seeds/http-head` | la liste de champs d'une requête — **aucune valeur ne porte de `CR`, de `LF` ni de `NUL`**, et le nombre de champs est borné |
| `fuzz_ams_http_response` | `seeds/http-response` | la réponse lue par le client — **la contrebande dans l'autre sens** : aucun `CR` ni `LF` isolé, et **`Content-Length` et `Transfer-Encoding` ne coexistent jamais** |
| `fuzz_ams_h2_frame` | `seeds/h2-frame` | le cadrage HTTP/2 — **un cadre rendu entier tient dans ce qu'on a lu**, et se réécrit à l'identique |
| `fuzz_ams_h2_hpack` | `seeds/h2-hpack` | les primitives HPACK — **une chaîne décodée ne déborde pas**, et Huffman est déterministe |
| `fuzz_ams_h2_connection` | `seeds/h2-connection` | la machine de connexion HTTP/2 — **une faute fatale arrête tout**, et les fenêtres restent dans leurs bornes |
| `fuzz_ams_h3_frame` | `seeds/h3-frame` | le cadrage HTTP/3 — **les types qu'HTTP/2 employait ne passent jamais** (§11.2.1) |
| `fuzz_ams_h3_connection` | `seeds/h3-connection` | la machine de connexion HTTP/3 — **aucune trame avant les réglages**, un seul flux critique de chaque sorte, et un `GOAWAY` ne remonte pas |
| `fuzz_ams_h3_driver` | `seeds/h3-driver` | le conducteur HTTP/3 sur des octets — **chaque appel rend la main**, et une faute est définitive |

**QUIC** — le transport sous HTTP/3.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_quic_varint` | `seeds/quic-varint` | les entiers de §16 — **une écriture longue se lit comme la courte** |
| `fuzz_ams_quic_packet` | `seeds/quic-packet` | les en-têtes de paquet de §17 — **un identifiant tient dans ses vingt octets** |
| `fuzz_ams_quic_crypto` | `seeds/quic-crypto` | la protection des paquets — **deux numéros donnent deux nonces**, et ce qu'on abîme ne se déchiffre pas |
| `fuzz_ams_quic_emit` | `seeds/quic-emit` | la fabrication d'un paquet protégé — **ce que `payload_capacity` promet, `seal_packet` le tient** |
| `fuzz_ams_quic_receive` | `seeds/quic-receive` | l'ouverture d'un paquet — **ce qui ne s'authentifie pas se jette, et ne ferme rien** |
| `fuzz_ams_quic_routing` | `seeds/quic-routing` | le tri des datagrammes (§5.2) — **un datagramme trop petit n'ouvre jamais de connexion**, et on ne lui répond pas |
| `fuzz_ams_quic_handshake` | `seeds/quic-handshake` | les flux `CRYPTO` de §4 — **les trois flux sont étanches**, et rien ne recule |
| `fuzz_ams_quic_stream` | `seeds/quic-stream` | un flux et son réassemblage — **ce qui est livré est ce qui a été envoyé, dans l'ordre** |
| `fuzz_ams_quic_streams` | `seeds/quic-streams` | la collection de flux — **la table ne déborde jamais**, et un refus ne consomme rien |
| `fuzz_ams_quic_connection` | `seeds/quic-connection` | la machine d'état d'une connexion — **le crédit ne dépasse jamais trois fois ce qu'on a reçu**, et un état ne remonte pas la pente |
| `fuzz_ams_quic_sent` | `seeds/quic-sent` | le suivi des paquets émis (RFC 9002 §6) — **les octets en vol ne mentent pas**, et rien n'est perdu deux fois |

**L'API REST** — ce qu'un jeton ouvre, et rien de plus.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_api_route` | `seeds/api-route` | ce qu'une requête désigne — **aucun segment n'est `.`, `..` ou vide**, et la lecture ne donne jamais l'écriture |
| `fuzz_ams_api_token` | `seeds/api-token` | les jetons porteurs — **rien ne se vérifie sans avoir été scellé avec la bonne clé**, et un jeton n'ouvre jamais plus que sa portée |
| `fuzz_ams_api_json` | `seeds/api-json` | les représentations JSON — **ce qu'on écrit se relit**, aucune clé répétée, et toute troncature se refuse |
| `fuzz_ams_session_http` | `seeds/session-http` | la session HTTP — **le compte servi est celui du jeton**, jamais celui que le chemin nomme, et rien ne sort en clair |
| `fuzz_ams_session_render` | `seeds/session-render` | ce que l'API rend — **rien n'échappe à l'échappement**, et l'`uidvalidity` est toujours là dès qu'un UID l'est |

**Les briques communes** — ce que plusieurs protocoles partagent.

| Cible | Graines | Ce qu'elle éprouve |
| --- | --- | --- |
| `fuzz_ams_guard` | `seeds/guard` | le garde — **une peine ne s'évince pas** |
| `fuzz_ams_index_name` | `seeds/index` | les noms Maildir — **aller-retour de l'UID** |
| `fuzz_ams_config` | `seeds/config` | les trois formats binaires : configuration, comptes, index |
| `fuzz_ams_sasl` | `seeds/sasl` | la réponse SASL — **décodage canonique** |

**Ce tableau est vérifié, et non tenu à la main** : `check-fuzz.sh` confronte ses
lignes à la liste des cibles, et l'écart échoue. Une cible ajoutée sans y être
décrite serait une cible que personne ne sait lire — et un tableau qui décrit la
moitié des cibles laisse croire qu'il n'y en a que la moitié. C'est arrivé : il
en nommait vingt-neuf sur soixante et une.

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

### Enregistrement SPF (quatre, dont l'INDIVISIBILITÉ)

Ces octets-là viennent du DNS, c'est-à-dire d'un domaine que **l'expéditeur
choisit**. Un serveur qui panique en lisant l'enregistrement d'autrui offre son
arrêt à qui sait publier un TXT.

1. Rien ne panique, quelles que soient les bornes — zéro compris.
2. **Un enregistrement accepté se reparcourt en entier sans jamais échouer**, et
   rend toujours les mêmes termes. Un parcours qui dépendrait de ce qu'on lui
   demande appliquerait une politique différente selon le pair.
3. **Les bornes sont tenues** : ni plus de termes ni plus d'octets que ce qu'on
   a permis.
4. **Un mécanisme qui résout ne répond jamais seul**, et il dit exactement ce
   qu'il lui faut. Lui faire dire `false` le ferait passer pour « ne correspond
   pas », ce qui est une réponse — et il n'en a pas encore.

### Évaluation SPF (sept, dont LA TERMINAISON)

La cible voisine éprouve la LECTURE d'un enregistrement ; celle-ci éprouve ce
qui vient après, et qui est plus exposé. Une évaluation enchaîne des politiques
que **l'expéditeur choisit** — les siennes, celles des domaines qu'il inclut — et
des réponses DNS qu'il peut, en partie, fabriquer. Tout, ici, vient d'ailleurs :
le harnais sert donc des réponses arbitraires, y compris d'un genre qui ne
répond pas à la question posée.

1. Rien ne panique, quelles que soient les bornes et les réponses.
2. **ELLE CONCLUT.** Un évaluateur qui tourne sans fin est un déni de service
   offert à qui publie un `redirect=` circulaire. La borne n'est pas une
   supposition : elle se déduit des dix résolutions (RFC 7208 §4.6.4).
3. **Le nombre de questions ne dépasse pas la borne** : une question de départ,
   puis une par résolution permise, et pas une de plus.
4. **Un verdict est définitif** : rappeler `poll` après la fin rend le même, et
   une réponse tardive ne rouvre rien.
5. **Une question porte un nom interrogeable** — au plus 255 octets, la longueur
   d'un nom de domaine. Un nom tronqué en désignerait un AUTRE.
6. **Une panne de résolution vaut `temperror`**, jamais un refus : dire `fail` à
   la place ferait jeter un message qui serait passé cinq minutes plus tard.
7. Les bornes de l'évaluation sont fuzzées elles aussi — zéro compris.

### DMARC (sept, dont LA SYMÉTRIE DE L'ALIGNEMENT)

L'enregistrement vient du DNS, c'est-à-dire d'un domaine que **l'expéditeur
choisit** — celui de son propre `From:`. Les domaines comparés viennent, eux, de
SPF et de DKIM : ce sont des noms qu'un pair a écrits.

1. Rien ne panique, quels que soient les octets.
2. **Un enregistrement accepté commence par `v=DMARC1` et porte un `p=`** — les
   deux choses sans lesquelles la RFC 7489 §6.6.3 l'écarte.
3. **L'ALIGNEMENT EST RÉFLEXIF ET SYMÉTRIQUE.** Un domaine s'aligne avec
   lui-même, et l'ordre des deux ne change rien : une comparaison qui dépendrait
   de l'ordre ferait passer un message dans un sens et pas dans l'autre.
4. **Le mode strict est plus étroit que le relâché** : ce que `s` aligne, `r`
   l'aligne aussi. L'inverse ferait qu'un domaine qui durcit sa politique
   laisserait passer davantage.
5. **Une réussite exige un mécanisme aligné** — il doit être possible de dire
   lequel — et un `From:` vide n'aligne rien.
6. **Le pourcentage tient dans ses bornes**, de zéro à cent.
7. **UN MESSAGE PARFAITEMENT ALIGNÉ NE VAUT JAMAIS UN RAPPORT D'ÉCHEC**, quelle
   que soit la valeur de `fo=`. Un domaine qui recevrait un rapport pour un
   message que rien n'accuse cesserait de les lire.

### Rapports DMARC (cinq, dont LE NOM QUI NE DEVIENT PAS UN CHEMIN)

Deux surfaces, et les deux viennent d'ailleurs. La liste `rua=` est publiée par
**le domaine qu'on rapporte** — c'est-à-dire, quand ça compte, par celui qui
usurpe. Le contenu du rapport, lui, porte le `header_from` et les adresses
d'enveloppe : **ce que le pair a dicté**.

1. Rien ne panique, quels que soient les octets.
2. **Ce qui sort du décodage `%XX` est de l'ASCII imprimable**, toujours : c'est
   ce qui empêche un `%0D%0A` d'écrire des en-têtes dans le message qu'on
   enverra à cette adresse.
3. **Un rapport composé ne porte aucune balise qu'on n'a pas écrite.** On compte
   les ouvrantes : un `<record>` injecté se verrait immédiatement.
4. **UN NOM DE FICHIER NE PEUT PAS DEVENIR UN CHEMIN** — ni barre oblique, ni
   `..`. Ce nom est écrit chez autrui, à partir d'un domaine choisi par celui
   qu'on rapporte.
5. **Le nom interrogé pour vérifier une destination est toujours dans la zone de
   cette destination.** C'est tout ce qui empêche l'attaquant de se donner le
   droit d'être rapporté à quelqu'un d'autre.

### Découpage IMAP (cinq, dont L'INDÉPENDANCE À LA FRAGMENTATION)

Une commande IMAP peut porter un littéral — `{42}` puis quarante-deux octets
bruts, `CRLF` compris — et continuer après. **C'est avant toute
authentification que cette surface est exposée.**

1. Rien ne panique, quels que soient les octets.
2. **Une commande complète tient dans ce qu'on a donné** : la longueur rendue ne
   dépasse jamais le tampon, et elle se termine par un `CRLF`.
3. **LE DÉCOUPAGE NE DÉPEND PAS DE L'ARRIVÉE DES OCTETS.** Sans cela, un client
   choisirait où l'on coupe rien qu'en fragmentant ses paquets. Les deux
   lecteurs sont conduits jusqu'à leur terme avant d'être comparés : une demande
   de continuation est un ÉVÉNEMENT, pas un état — c'est la cible qui l'a appris
   à sa première campagne, et la propriété a été corrigée, pas le code.
4. **Un tag accepté est recopiable dans une réponse** : il ne porte aucun octet
   qui pourrait en écrire une seconde.
5. **Une réponse encodée tient sur une ligne**, et une seule.

### Session IMAP (cinq, dont L'INVARIANT QUI PORTE TOUT LE RESTE)

La grammaire découpe, la session décide. Ce qu'on éprouve ici n'est pas la
syntaxe mais **ce que l'état autorise**, et ce que la session écrit en retour.

1. Rien ne panique, quelle que soit la suite de commandes.
2. **ON NE PEUT PAS ÊTRE AUTHENTIFIÉ SANS ÊTRE CHIFFRÉ.** C'est l'invariant qui
   porte tout le reste : un mot de passe ne traverse pas une connexion en clair,
   et aucune suite de commandes ne doit pouvoir contourner cela.
3. **Toute réponse est faite de lignes complètes**, sans quoi le client
   recollerait deux réponses en une.
4. **UNE RÉPONSE ÉTIQUETÉE NE REPREND QUE LE TAG QU'ON A REÇU.** Le tag est
   recopié : s'il en sortait un que le client n'a pas envoyé, ce serait qu'on
   l'a fabriqué — ou pire, qu'on a recopié autre chose.
5. **Après `LOGOUT`, la session ne répond plus.**

### Les messages de rapport (six, dont LA LISTE BLANCHE)

L'adresse du destinataire d'un rapport est publiée par le domaine qu'on
rapporte ; le nom du fichier joint se compose à partir de ce même domaine. **Un
message qu'on compose soi-même et qu'on remet soi-même est le dernier endroit où
une injection passerait inaperçue.**

1. Rien ne panique, quels que soient les octets.
2. **Un message composé n'a que les en-têtes qu'on a écrits** — on les compte,
   DANS LE BLOC D'EN-TÊTE seulement : un corps `text/plain` a le droit de
   contenir « From: », c'est du texte.
3. **Le délimiteur figure exactement trois fois** : deux ouvertures, une clôture.
   Un `multipart` qui se découpe ailleurs se lit autrement que ce qu'on a écrit.
4. **LA PIÈCE JOINTE SE RELIT**, à l'octet près. Le décodeur base64 est écrit
   dans la cible, séparé de l'encodeur : réencoder avec le code qu'on éprouve
   prouverait seulement qu'il est d'accord avec lui-même.
5. **Une date s'écrit toujours**, et tient dans ce qu'elle annonce.
6. **LA LISTE BLANCHE TIENT** : dans un rapport d'échec, la partie qui recopie le
   message rapporté ne porte que des champs dont le nom figure dans `EXPOSES`.
   C'est la propriété qui protège le tiers dont on rapporte le courrier, et c'est
   celle qui compte le plus ici. Elle est vérifiée sur des blocs d'en-tête
   arbitraires, ce qu'aucun test écrit à la main ne couvrirait.

### Le côté ÉMETTEUR de SMTP (cinq, dont LA CONTREBANDE PAR L'AUTRE BOUT)

Jusqu'ici, tout venait à ce serveur. Émettre inverse la relation : **le serveur
auquel on remet est désigné par le destinataire**, et ses réponses décident de ce
qu'on fait du message.

1. Rien ne panique, quels que soient les octets.
2. **Une réponse délimitée se relit** : si `reply_len` rend une longueur,
   `Reply::parse` accepte exactement ces octets-là, et toutes ses lignes portent
   le même code.
3. **`Done` EST TERMINAL** : une session qui a conclu ne repart pas. Sans cela,
   un pair bavard pourrait faire remettre deux fois le même message.
4. **UN CORPS FARCI NE PEUT PAS SE TERMINER TOUT SEUL** : la seule ligne au point
   est celle qu'on écrit à la fin. C'est la contrebande SMTP, et c'est la
   propriété qui compte le plus ici.
5. **Le farcissage ne dépend pas du découpage.**

### DKIM (sept, dont L'INDÉPENDANCE AU DÉCOUPAGE)

Trois surfaces, toutes fournies par autrui : le champ `DKIM-Signature` d'un
message, l'enregistrement de clé publique lu dans le DNS, et **le corps du
message** — ce qu'un pair envoie de plus gros.

1. Rien ne panique, quels que soient les octets et le découpage.
2. **LE DÉCOUPAGE NE CHANGE RIEN.** La canonicalisation du corps est une machine
   en flux : le pair choisit la taille de ses paquets, et le condensat ne doit
   pas en dépendre. Une fin de ligne coupée en deux est le cas qui casse les
   implémentations naïves — la cible éprouve le découpage donné, celui d'un seul
   tenant, et celui d'un octet par octet.
3. **`relaxed` tient ses promesses** : aucune tabulation ne survit, aucune suite
   de deux espaces, aucun blanc avant une fin de ligne, aucun pliage.
4. **Le corps canonicalisé finit par une fin de ligne**, sauf le corps vide en
   `relaxed` — et cette exception-là est dans la RFC.
5. **La borne `l=` coupe, elle ne réécrit pas** : ce qui sort sous une borne est
   un préfixe exact de ce qui sort sans elle.
6. **Une signature acceptée est cohérente** : `v=1`, un algorithme admis — jamais
   `rsa-sha1` —, `from` couvert, `i=` sous `d=`, `x=` après `t=`.
7. **Une clé acceptée n'est pas révoquée**, et deux lectures rendent la même
   chose.
8. **Le base64 n'admet qu'une écriture par valeur** : ce qui se décode a une
   longueur multiple de quatre, remplissage compris.
9. **Retirer le `b=` ne touche à rien d'autre.** `bh=` commence par les mêmes
   deux octets que `b=` suivi de `h` : un analyseur qui chercherait « b= » sans
   regarder les limites d'étiquette effacerait le condensat du corps, et TOUTES
   les signatures échoueraient sans qu'aucun message ne dise pourquoi.

10. **CE QU'ON SIGNE SE RELIT.** Le champ que le signataire écrit est un
    `DKIM-Signature` valide — ou bien il refuse d'écrire. Aucune ligne n'y
    dépasse ce qu'une ligne peut porter, et aucun saut de ligne n'y est autre
    chose qu'un repli. On signe en Ed25519 : une signature RSA par exécution
    ferait tomber le débit de trois ordres de grandeur, et ce qu'on éprouve ici
    est l'ÉCRITURE, que l'algorithme ne change pas.

**Ce que cette cible ne fuzze pas, et pourquoi.** La vérification RSA elle-même :
une exponentiation modulaire par exécution ferait tomber le débit de trois ordres
de grandeur, et ce qu'on éprouverait alors serait l'arithmétique de `rsa` — une
crate qui a ses propres épreuves, et que ce projet ne saurait pas mieux fuzzer
que ses auteurs. Ce qui est à nous, ici, c'est ce qui ENTRE dans la
cryptographie : la canonicalisation, le base64, et le retrait du `b=`.

### En-tête `Received-SPF` (cinq, dont L'INJECTION DE LIGNE)

Cet en-tête porte deux valeurs que **le pair choisit** — son expéditeur
d'enveloppe et son `HELO` — et il est écrit DANS LE MESSAGE QU'ON REMET. Un
`CR LF` recopié tel quel, et le pair écrit les en-têtes qu'il veut : un
`Authentication-Results` fabriqué, un destinataire de plus, un faux
`Received-SPF: pass` sous le nôtre.

1. Rien ne panique, quelle que soit la taille du tampon — zéro comprise.
2. **AUCUN SAUT DE LIGNE QUI NE SOIT UN REPLI.** Tout `CR` est suivi d'un `LF` ;
   tout `LF` est précédé d'un `CR` et suivi d'une espace, sauf celui qui termine
   l'en-tête. C'est la propriété qui ferme l'injection.
3. **Aucune ligne ne dépasse 998 octets** (RFC 5322 §2.1.1).
4. **La forme est tenue** : le nom du champ, puis l'un des sept mots de la RFC
   7208 §2.6, puis un `CRLF` final.
5. **Une valeur non imprimable fait TOUJOURS refuser** — et pour cette
   raison-là, jamais une autre.

### Réponse DNS (cinq, dont LA COMPRESSION)

Ces octets arrivent par UDP, d'une adresse qu'on n'a pas authentifiée, avec une
charge que n'importe qui sur le chemin peut fabriquer. **C'est la surface la plus
exposée du serveur après SMTP lui-même** : elle s'atteint sans ouvrir de
connexion, en devinant un port et un identifiant.

1. Rien ne panique — et surtout **rien ne boucle**. Un nom peut se poursuivre par
   un pointeur vers un autre nom du message ; un message hostile fabrique un
   cycle en quarante octets, et un décodeur naïf y tourne indéfiniment. La parade
   est structurelle — chaque pointeur vise strictement plus bas — et c'est le
   temps d'exécution qui l'éprouve ici.
2. **Un message accepté se parcourt entièrement** : la validation est d'un seul
   tenant, et l'itérateur rend ce que l'en-tête annonce, ni plus ni moins.
3. **Un nom lu tient dans 255 octets.** Plus long, il ne désigne rien
   d'interrogeable ; tronqué, il désignerait AUTRE CHOSE.
4. **Deux lectures rendent la même chose** : rien ne dépend de l'ordre dans
   lequel on interroge un enregistrement.
5. **Une question qu'on encode n'est jamais prise pour une réponse.** Sans ce
   refus, un pair injecterait ses questions dans le flot des réponses attendues.

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

## CETTE CRATE EST HORS DU WORKSPACE, ET ÇA SE PAIE À CHAQUE FOIS

`cargo fmt --all`, `cargo clippy --workspace` et `cargo test --workspace` lancés
à la racine **ne la voient pas**. Trois fois déjà, une API changée l'a laissée
cassée sans qu'aucune commande locale ne le dise ; une quatrième, c'est le
`cargo fmt -- --check` de la CI qui a échoué sur un `use` trop long.

Après toute modification qui la touche — la sienne, ou celle d'une crate qu'elle
consomme :

```sh
cd fuzz
cargo fmt                       # elle a son propre formatage à faire
cargo +nightly fuzz build       # ET ON EN LIT LE CODE DE RETOUR
```

**La leçon n'est pas « lancer la commande », c'est « en lire le code de
retour »** : `cargo +nightly fuzz build | tail -1` rend celui de `tail`, qui
réussit toujours.

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

**`fuzz_ams_dkim`, une seconde fois — et celle-là était une injection d'en-tête.**

Le signataire écrivait dans son champ le domaine et le sélecteur qu'on lui
donnait, tels quels. La cible lui a donné un domaine fait de deux points et de
sauts de ligne : le champ produit portait donc un `CRLF` suivi d'autre chose,
c'est-à-dire **la fin de l'en-tête et le début d'un autre**. Qui contrôlerait la
configuration d'un signataire pourrait ainsi écrire les en-têtes qu'il veut dans
le courrier signé.

L'assertion qui l'a trouvée ne cherchait pourtant pas cela : elle vérifiait
seulement que le champ écrit se relit avec le domaine qu'on avait demandé. Il se
relisait avec un domaine RACCOURCI — la grammaire des étiquettes retire les
blancs de tête et de queue — et c'est ce décalage d'un octet qui a dénoncé le
reste.

Le signataire refuse désormais tout ce qui n'est pas un octet de valeur
d'étiquette dans `d=`, `s=` et `i=`, et tout ce qui n'est pas `ftext` dans les
noms de `h=`.

**`fuzz_ams_dkim`, dès sa première exécution — et ce n'était pas un défaut du
code, c'était un contrat qui n'était écrit nulle part.**

La canonicalisation `relaxed` d'un en-tête promet qu'aucun pliage ne survit. La
cible lui a donné un NOM DE CHAMP contenant un `CRLF` — et le `CRLF` est ressorti,
puisque le nom n'est que mis en minuscules.

Aucun message ne peut porter un tel nom : le bloc d'en-tête est validé bien
avant, et un nom de champ y est `%d33-57 / %d59-126` (RFC 5322 §3.6.8). Mais rien
ne le DISAIT, et une fonction publique qui suppose sans le dire est une fonction
qu'on appellera un jour autrement. La précondition est donc écrite sur la
fonction — avec la raison pour laquelle rien ne la vérifie à l'exécution : ce
qu'elle rend est une entrée de condensat, jamais un en-tête qu'on émet, et un nom
absurde y donne un condensat absurde, donc une vérification qui échoue. La cible,
elle, ramène désormais son nom à ce qu'un nom peut être.

**La leçon n'est pas « le fuzz a trouvé un bogue », c'est « le fuzz a trouvé une
supposition ».** C'est le genre de trouvaille qui ne vaut rien tant qu'on ne
l'écrit pas.

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

**`fuzz_ams_dmarc_report`, en trois minutes, à sa première campagne.** Le nom
d'un rapport n'admettait que des lettres, des chiffres, un tiret, un point et un
souligné — ce qui laissait passer `a..b`, et donc un `..` dans un nom de fichier
écrit chez autrui. Rien n'était exploitable : sans barre oblique, `..` ne
remonte nulle part, et la barre oblique était déjà refusée.

Le correctif n'en est pas moins réel. `a..b` **n'est pas un domaine** — une
étiquette DNS ne peut pas être vide — et laisser entrer ce qui n'est pas un
domaine en se reposant sur l'absence d'un second octet est exactement le
raisonnement qui finit par céder, le jour où quelqu'un ajoute une jointure de
chemin ailleurs. Chaque étiquette doit désormais porter quelque chose.

**`fuzz_ams_smtp_client`, en quelques secondes, à sa première campagne.** Le
texte d'une réponse pouvait porter un `CR` ou un `LF` isolé : `250 a\nb\r\n`
passait. Ce qui suivait le saut de ligne était du texte pour nous, et une ligne
pour tout ce qui lirait ce texte ensuite — un journal, un rapport, un message de
non-remise. **C'est la contrebande SMTP prise par l'autre bout**, et c'est
exactement la faute que ce dépôt ferme partout ailleurs.

Le correctif refuse tout octet de contrôle dans le texte d'une réponse, la
tabulation exceptée (RFC 5321 §4.2 la prévoit). Les octets HAUTS, eux, passent :
des serveurs en émettent dans leur bannière, et refuser une remise pour un accent
coûterait du courrier sans rien protéger — on ne les interprète jamais.

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
| 2026-08-29 | `fuzz_ams_spf` | 1 886 802 (91 s) | 0 |
| 2026-08-29 | `fuzz_ams_spf` (après `resolve`) | 2 224 920 (91 s) | 0 |
| 2026-08-29 | `fuzz_ams_spf_eval` | 5 799 279 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_dns` | 14 395 679 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_spf_header` | 7 478 784 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_dkim` | 3 255 821 (181 s) | **1, contrat corrigé** |
| 2026-08-29 | `fuzz_ams_dkim` (avec la vérification) | 2 921 202 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_dkim` (avec la signature) | 707 978 (181 s) | **1, corrigée** |
| 2026-08-29 | `fuzz_ams_dmarc` | 10 092 643 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_config` (avec DMARC) | 187 544 (61 s) | 0 |
| 2026-08-29 | `fuzz_ams_dmarc_report` | (avant correctif) | **1, corrigé** |
| 2026-08-29 | `fuzz_ams_dmarc_report` | 1 625 597 (221 s) | 0 |
| 2026-08-29 | `fuzz_ams_config` (avec les rapports) | 222 412 (71 s) | 0 |
| 2026-08-29 | `fuzz_ams_smtp_client` | (avant correctif) | **1, corrigé** |
| 2026-08-29 | `fuzz_ams_smtp_client` | 8 247 626 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_mime_compose` | 1 434 635 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_config` (avec la remise) | 267 065 (71 s) | 0 |
| 2026-08-29 | `fuzz_ams_mime_compose` (avec les échecs) | 1 925 299 (201 s) | 0 |
| 2026-08-29 | `fuzz_ams_dmarc` (avec `fo=`) | 8 851 543 (151 s) | 0 |
| 2026-08-29 | `fuzz_ams_config` (avec les échecs) | 215 062 (71 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap` | 11 944 609 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap` (avec les arguments) | 7 738 126 (151 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_imap` | 3 058 685 (221 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap_fetch` | 15 261 189 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_imap` (avec les boîtes) | 3 292 791 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap_fetch` (avec `STORE`) | 7 303 754 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_imap` (avec `STORE`) | 1 993 276 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap` (arrêt de l'itérateur) | 5 072 564 (121 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_imap` (avec `EXPUNGE`) | 2 188 197 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap_fetch` (avec `SEARCH`) | 9 490 143 (201 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_imap` (avec `COPY`) | 2 993 293 (181 s) | 0 |
| 2026-08-30 | `fuzz_ams_mime_structure` (parties désignées) | 317 620 (241 s) | 0 |
| 2026-08-30 | `fuzz_ams_mime_structure` | 540 822 (241 s) | 0 |
| 2026-08-29 | `fuzz_ams_mime_envelope` | (première campagne) | **1, corrigé** |
| 2026-08-29 | `fuzz_ams_mime_envelope` | 2 468 400 (301 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_imap` (avec `MOVE`) | 2 907 842 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap_fetch` (avec `APPEND`) | 5 960 657 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_imap_fetch` (noms de boîtes) | 5 427 497 (181 s) | 0 |
| 2026-08-29 | `fuzz_ams_config` (avec l'écoute IMAP) | 208 794 (71 s) | 0 |
| 2026-08-29 | `fuzz_ams_config` (avec SPF) | 193 256 (61 s) | 0 |
| 2026-08-29 | `fuzz_ams_session_smtp` (avec SPF) | 381 710 (61 s) | 0 |
| 2026-08-28 | `fuzz_ams_session_smtp` (SASL) | 521 646 (91 s) | 0 |

Le débit de `fuzz_ams_tls_kx` est trois ordres de grandeur sous les autres : une
génération de clé ML-KEM et deux X25519 par exécution, ce que rien n'accélérera.
Ce n'est pas un défaut du harnais, c'est le coût de la cible — et la raison de
lancer cette campagne-là plus longtemps que les autres.
