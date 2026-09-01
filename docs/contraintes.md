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

**Outillé par** : `scripts/check-etages.sh`, exécuté en CI avant même `clippy` —
il ne compile rien, dure une seconde, et dit ce que la compilation ne dira jamais.

Il refuse `std::net`, `std::fs`, `std::io`, `std::process`, `std::thread`,
`std::time::Instant`, `std::time::SystemTime` et toute dépendance à `tokio`, dans
les crates du périmètre. **`std::time::Duration` n'y est pas** : c'est un type, pas
une horloge. `Instant` et `SystemTime`, eux, rendent deux réponses différentes au
même appel — ce qu'une machine à états ne doit pas faire. C'est la distinction qui
compte, et non le nom du module.

**LA LISTE DES CRATES N'Y EST PAS ÉCRITE** : elle est lue dans
`check-couverture.sh`, qui en a besoin pour la même raison — le périmètre de C2
EST celui de C1. Deux listes auraient fini par différer, et une crate serait sortie
de l'une sans sortir de l'autre : couverte à 100 % et libre de faire des
entrées-sorties, ou l'inverse. Si l'extraction ne rend rien, le script ÉCHOUE
plutôt que de conclure — un contrôle qui n'a rien examiné n'est pas un contrôle qui
passe.

**Et il a été éprouvé en le faisant échouer** : un `use std::fs::File` glissé dans
un codec, puis une dépendance `tokio` déclarée sans être employée. Les deux sont
vus. Un gate qu'on n'a jamais vu refuser est un gate dont on ne sait rien.

*(Cette entrée disait « rien d'automatique […] c'est faisable et ce n'est pas
fait » depuis l'ouverture du registre.)*

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

### La quatrième réserve : aucune suite ne savait chiffrer un paquet QUIC

Constaté le 2026-08-31, en cherchant à monter HTTP/3.

`rustls` sait conduire la poignée de main TLS 1.3 de QUIC, mais **seulement pour
les suites dont le fournisseur déclare savoir chiffrer un PAQUET QUIC** — ce qui
n'est pas la même chose que chiffrer un enregistrement TLS. §5 de RFC 9001
définit une protection de paquet distincte : un AEAD dont le nonce dérive du
numéro de paquet, et un masquage d'en-tête qui n'existe pas en TLS.

Les trois suites de `rustls-rustcrypto` portaient `quic: None`.
`rustls::quic::ServerConnection` refusait donc de se construire, avec le message
« at least one ciphersuite must support QUIC ». **HTTP/3 était bloqué avant sa
première ligne.**

La réserve est **levée le 2026-08-31**, par `crates/ams-tls/src/quic.rs` :

- `provider_quic()` rend le fournisseur ordinaire dont chaque suite porte en plus
  un algorithme QUIC. Les suites que ce module ne sait pas conduire sont
  **écartées** plutôt que laissées sans QUIC : les laisser passer les ferait
  échouer APRÈS la poignée de main, au premier paquet — un symptôme très loin de
  sa cause.
- Les trois traits de `rustls::quic` (`Algorithm`, `PacketKey`,
  `HeaderProtectionKey`) sont branchés sur **`ams-quic-crypto`**, vérifié contre
  les vecteurs de l'annexe A de RFC 9001. Rien n'est réimplémenté : une seconde
  implémentation de la même chose finit par diverger sur le cas que personne n'a
  éprouvé, et celle-ci n'aurait pas eu de vecteurs.
- Les suites capables de QUIC sont des **constantes de compilation**, pas des
  objets fuités à l'exécution. La première version employait `Box::leak` une fois
  par appel ; c'est `LeakSanitizer`, sous `cargo fuzz`, qui a compté les octets
  perdus. Un serveur n'appelle `provider_quic()` qu'au démarrage — mais une
  fonction publique ne choisit pas ses appelants.
- `ALPN_H3` et `alpn_h3()` annoncent `h3`, et rien d'autre. Même règle que `h2`
  sur TCP : annoncer un protocole qu'on refuse de servir est pire que de ne pas
  l'annoncer.

**Ce qui est mesuré, et non supposé** : `rustls` et `ams-quic-crypto` dérivent
les MÊMES clés initiales. L'essai `rustls_et_nous_derivons_les_memes_clefs_initiales`
fait chiffrer le même paquet par les deux chemins et compare les octets. Aucun
essai d'`ams-quic-crypto` ne pouvait l'établir : là-bas, notre dérivation
dialogue avec elle-même. La cible de fuzz `fuzz_ams_tls_quic` étend la même
comparaison à tout ce qui n'est pas dans l'annexe.

**Ce qui reste à faire** : le fournisseur est capable de QUIC, ce n'est pas la
même chose que servir HTTP/3. Le pont de poignée de main, le tri des datagrammes,
l'émission d'un paquet protégé, la détection de perte et le conducteur de
connexion ont suivi le 2026-08-31 (voir ci-dessous) ; restent l'écoute UDP
elle-même, les flux, puis le conducteur HTTP/3.

### La poignée de main, et pourquoi elle occupe deux crates

Écrit le 2026-08-31. §4 de RFC 9001 décrit comment TLS et QUIC se parlent. Deux
crates s'en partagent le travail, et le partage n'est pas décoratif :

- **`ams-quic::handshake`** tient les RÈGLES : trois flux `CRYPTO` (un par
  niveau, `0-RTT` excepté), le réassemblage hors d'ordre, et les quatre refus que
  §4.1.3, §8.3 et §7.5 nomment. **Elle n'alloue pas** — comme le reste
  d'`ams-quic`, elle tient les décalages et laisse les octets à l'appelant.
- **`ams-quic-tls`** conduit `rustls::quic::ServerConnection` d'après ces règles,
  possède les trois fenêtres de quatre kibioctets, et traduit chaque refus en
  code de fermeture.

Pourquoi pas dans `ams-tls` ? Parce que son manifeste dit « TLS 1.3 :
établissement et chiffrement d'enregistrements », et qu'une machine de connexion
QUIC n'est pas cela. RFC 9001 est elle-même un document séparé de RFC 8446 et de
RFC 9000, pour la même raison.

#### Les quatre refus, et leurs codes

| Ce qui arrive | Où c'est écrit | Ce qu'on ferme avec |
| --- | --- | --- |
| Une trame `CRYPTO` dans un paquet `0-RTT` | §8.3 | `PROTOCOL_VIOLATION` |
| Du NEUF à un niveau déjà dépassé | §4.1.3 | `PROTOCOL_VIOLATION` |
| Des clés plus hautes, des octets non lus plus bas | §4.1.3 | `PROTOCOL_VIOLATION` |
| Plus de `CRYPTO` hors d'ordre qu'on n'en retient | §7.5 de RFC 9000 | `CRYPTO_BUFFER_EXCEEDED` |

Le dernier **n'est pas une faute interne**, contrairement à la fenêtre trop
courte d'un flux ordinaire : il n'y a pas de contrôle de flux sur `CRYPTO`, donc
rien n'avait annoncé de limite au pair — mais la RFC lui a quand même donné un
code, parce que la borne devait bien exister quelque part. La nôtre est de
**4096 octets par niveau**, le plancher que §7.5 impose.

#### Ce que le vrai client a trouvé, et qu'un faux n'aurait pas vu

L'essai monte un `rustls::quic::ClientConnection` en face, avec une autorité et
un certificat produits par `openssl`. Il a fait tomber deux choses :

1. **Lire et écrire n'avancent pas ensemble.** La première version installait le
   même niveau des deux côtés à chaque changement de clés. Or le serveur reçoit
   ses clés de `1-RTT` en même temps qu'il envoie son `Finished`, tandis que le
   `Finished` DU CLIENT arrive encore en `Handshake` : passer la lecture en
   `1-RTT` à ce moment-là faisait refuser, comme « du neuf à un niveau déjà
   dépassé », la seule chose qui termine la poignée de main. Un essai avec
   soi-même aurait fait la même faute des deux côtés.
2. **Un certificat auto-signé n'est pas un certificat serveur.** `openssl req
   -x509` produit `CA:TRUE`, et webpki refuse `CaUsedAsEndEntity` — à raison,
   puisqu'une autorité peut signer n'importe quel nom. Le matériel d'essai monte
   donc une autorité, puis une paire qu'elle signe.

Une troisième subtilité est consignée sans être corrigée, parce qu'elle ne nous
concerne pas : `write_hs` coupe le vol avant le premier message à chiffrer, **ce
qui ne se produit que s'il reste quelque chose à émettre en clair devant**. Côté
serveur, c'est toujours le cas — le `ServerHello` précède tout. Côté client, non :
son `Finished` est seul dans la file, et `write_hs` le rend dans le même appel
que les clés de `Handshake`, alors qu'il appartient au niveau `Handshake`. C'est
la raison pour laquelle `ams-quic-tls` n'offre pas de côté client : la règle
simple qui suffit ici ne suffirait pas là.

### Le tri des datagrammes, et pourquoi il ne tient pas de table

Écrit le 2026-08-31, dans `ams-quic::routing`. **C'est le tout premier code que
touche un octet venu du réseau**, et il le touche avant que quoi que ce soit soit
authentifié : les clés d'un `Initial` se dérivent d'un identifiant que le paquet
porte en clair (§5.2 de RFC 9001), donc tout le monde peut en fabriquer un.
Chacune de ses décisions doit être sûre pour un menteur.

Il **ne tient pas de carte** des identifiants. Associer un identifiant à une
connexion demande une structure qui grandit et rétrécit, et `ams-quic` n'alloue
pas — mais surtout, une carte n'est pas une décision : c'est du rangement. Ce qui
est une décision, c'est ce qu'on fait d'un datagramme SELON ce que la carte
répond. On lit donc d'abord ce que le datagramme dit de lui-même (`Incoming::read`),
l'appelant interroge sa carte, puis `Incoming::route` tranche. Le même partage que
`Recv`, qui tient les décalages et laisse les octets.

#### Les règles, et l'ordre dans lequel elles se posent

L'ordre n'est pas libre. §5.2.2 : « Packets with a supported version, or no
Version field, are matched to a connection using the connection ID. » **La version
se juge donc AVANT la carte** — l'inverse ferait remettre à une connexion en cours
un paquet d'une version qu'elle ne parle pas. Et le `Retry` se juge avant tout le
reste : c'est le seul paquet dont la seule présence est déjà une faute côté
serveur, et le laisser filer jusqu'à la carte lui donnerait une chance d'être
remis à quelqu'un.

| Ce qui arrive | Où c'est écrit | Ce qu'on en fait |
| --- | --- | --- |
| Une négociation de version | §6.1 | jeter — un serveur les émet, il n'en reçoit pas |
| Un `Retry` | §17.2.5 | jeter — idem |
| Une version qu'on ne sert pas, ≥ 1200 octets | §5.2.2 | négocier |
| Une version qu'on ne sert pas, < 1200 octets | §5.2.2 | jeter — répondre ferait un amplificateur |
| Un identifiant connu | §5.2 | à sa connexion |
| Un `Initial` ≥ 1200 octets | §14.1 | une connexion neuve |
| Un `Initial` < 1200 octets | §14.1 | jeter |
| Un `Handshake` sans connexion | §5.2.2 | jeter |
| Un `0-RTT` sans connexion | §5.2.2 | jeter |
| Un en-tête court inconnu | §5.2.2 | jeter |

Le plancher de 1200 octets **est la garde d'amplification au plus tôt**. §8.1
borne ce qu'on renvoie à trois fois ce qu'on a reçu ; §14.1 fixe le plancher de
ce « reçu ». Sans lui, un attaquant obtiendrait trois fois un tout petit
datagramme, autant de fois qu'il veut. La garde elle-même vit dans
`ams_quic::Connection` (`send_budget`, `amplification_limited`), écrite plus tôt.

**Ce qu'on jette est nommé.** Le résultat est le même — rien ne part —, mais un
compteur par raison est la seule façon de distinguer, en exploitation, un réseau
qui perd des paquets d'un balayage de port, et un client mal réglé d'une attaque.
Un unique compteur « jetés » ne dirait rien de tout cela. En revanche, ce qu'on
**ne sait pas lire** n'a qu'un seul refus, délibérément : distinguer un bit fixe
absent d'une troncature apprendrait, à qui balaie le port, ce que nous savons
lire.

#### Deux décisions qui ne sont pas des réglages

- **Les identifiants qu'on distribue font huit octets**, et c'est une constante.
  §5.1 : leur longueur n'est pas sur le fil dans un en-tête court, donc un serveur
  ne peut lire ces paquets-là que s'il sait d'avance combien d'octets il a
  distribués. Une longueur qui varierait d'une connexion à l'autre rendrait ses
  propres paquets illisibles. Huit, c'est-à-dire soixante-quatre bits : §8.1
  ouvre la validation implicite d'adresse à partir de « at least 64 bits of
  entropy », et prendre plus court la fermerait.
- **Un paquet de négociation de version n'a pas de type**, et `Incoming::kind`
  rend `None` pour lui. §17.2.1 : la version zéro n'est pas une version, et les
  bits de type ne veulent alors rien dire. Leur donner une valeur laisserait un
  `match` prendre une décision sur des bits qui ne décrivent rien.

Une limite est écrite plutôt que tue : un en-tête qu'on ne sait pas lire se jette,
même quand il aurait mérité une négociation. §6.1 demande d'échouer en renvoyant
les deux identifiants du paquet reçu, et on ne peut pas les renvoyer si on ne sait
pas les lire — une version future dont les identifiants dépasseraient vingt octets
tomberait là.

### L'émission d'un paquet, et pourquoi son ordre est l'inverse de la lecture

Écrit le 2026-08-31, dans `ams-quic::emit`. **Une faute d'émission ne se voit
jamais chez nous** : elle se voit chez le pair, sous la forme d'un paquet
illisible, à un moment et pour une raison qui n'ont plus rien à voir avec
l'endroit où la faute a été commise. C'est ce qui rend ce module plus délicat que
son symétrique.

L'ordre est celui de `open_packet`, à l'envers :

1. écrire l'en-tête en clair, la longueur du numéro dans son premier octet ;
2. écrire le numéro tronqué (§17.1) ;
3. chiffrer la charge, **l'en-tête entier servant de données associées** ;
4. **alors seulement**, masquer l'en-tête.

La quatrième vient en dernier parce que le masque se calcule sur un échantillon
du CHIFFRÉ (§5.4.2 de RFC 9001). Masquer avant de chiffrer prendrait
l'échantillon dans du clair, et le pair — qui masque après avoir reçu —
n'obtiendrait pas le même.

#### Trois choses que le type rend impossibles

- **Pas de `0-RTT`.** `Plan` n'a pas de variante pour lui. Nous ne l'offrons pas
  (C6) : des données précoces ne sont pas protégées contre le rejeu (§17.2.3), et
  une requête rejouée est une requête traitée deux fois. Un champ « veut-on du
  `0-RTT` ? » finirait par être basculé ; une variante absente ne se bascule pas.
- **Pas de `Retry` ni de négociation de version.** Ceux-là ne portent ni numéro
  ni charge chiffrée : rien de ce module ne les concerne. Les faire entrer dans
  le même `Plan` obligerait chaque étape à écarter deux cas qui ne lui
  ressemblent pas — et une étape qui écarte est une étape qu'on peut oublier
  d'écrire.
- **Pas de champ sans effet.** Un jeton n'existe que dans un `Initial`, un
  identifiant de source que dans un en-tête long, une phase de clé que dans un
  en-tête court. Une structure unique laisserait renseigner un jeton pour un
  paquet `1-RTT` : **un réglage sans effet est pire qu'un réglage absent**, parce
  qu'on croit l'avoir posé.

#### Le plancher de charge, et d'où vient son nombre

§5.4.2 : l'échantillon de protection d'en-tête se prend seize octets, quatre
octets après le début du numéro — **comme si le numéro faisait toujours quatre
octets**, puisque le pair qui démasque ne connaît pas encore sa longueur réelle.
Il faut donc que le numéro, la charge et le tag atteignent ensemble vingt octets,
soit « at least 3 bytes of frames […] if the packet number is encoded on a single
byte, or 2 bytes for a 2-byte packet number encoding ».

La condition est écrite en toutes lettres dans le code plutôt que réduite à
`charge >= 3` : l'égalité ne tient que parce que le tag fait justement seize
octets, ce qui est vrai des suites de §5.4.2 et de nulle part ailleurs.

#### Ce que la couverture a fait retirer

Une seconde vérification de §5.4.2 « sur le paquet fini » avait été écrite par
prudence. Elle disait `numero_a + 4 + 16 <= total` — or `total` vaut
`numero_a + numero + charge + 16`, donc c'était mot pour mot la condition déjà
posée. **Une garde qui répète une garde n'ajoute rien : elle ajoute une branche
que rien ne peut emprunter.**

Le reste des gardes inatteignables a été remplacé par des `expect` qui DISENT
pourquoi elles ne peuvent pas se déclencher, plutôt que par des `?` que nul essai
n'emprunte. Le partage est net : `disposer` vérifie tout ce qui est vérifiable —
le numéro, l'échantillon, la borne d'un datagramme — et tout ce qui suit est
infaillible par construction, y compris l'écriture de l'en-tête, qui reçoit une
tranche de la taille exacte.

### Le conducteur de connexion, et ce que trois essais ont trouvé

Écrit le 2026-08-31, dans `ams-quic-tls::Connection`. **Toutes les pièces
existaient ; aucune ne savait ce qu'il fallait faire ensuite.** Ce qui se décide
là, et nulle part ailleurs : quelles trames vont dans quel paquet et à quel
niveau, combien on a le droit d'émettre, et quand se réveiller.

La portée est la poignée de main : `CRYPTO`, `ACK`, `PADDING`, `PING`,
`HANDSHAKE_DONE` et `CONNECTION_CLOSE`. **Pas de flux.** Une trame qu'on ne sait
pas encore traiter est ignorée plutôt que refusée — la refuser fermerait des
connexions qu'on servira demain, et §12.4 ne condamne que ce qu'on ne sait pas
LIRE.

#### Trois défauts trouvés par les essais

1. **Un drapeau emprunté à une autre question.** Le verrou « a-t-on déjà pris
   acte de la fin de la poignée de main ? » se servait de « l'adresse est-elle
   validée ? ». Or §8.1 la valide dès le premier paquet `Handshake` reçu,
   c'est-à-dire AVANT la fin de la poignée de main : le verrou était déjà fermé
   quand on en avait besoin, et rien de ce qu'il gardait ne se faisait — ni la
   vérification de l'ALPN, ni la lecture des paramètres du pair, ni le
   `HANDSHAKE_DONE`. **Un drapeau emprunté à une autre question finit toujours
   par répondre à celle-là.**
2. **`State::s_eteint()` couvre `Closing`.** La garde de `poll_transmit` s'en
   servait, ce qui empêchait la fermeture elle-même de partir. §10.2.2 ne fait
   taire qu'en `Draining` : en `Closing`, il reste précisément une chose à dire.
3. **Les acquittements comptaient dans la fenêtre de congestion.** §2 de RFC 9002
   l'interdit : « Packets that contain only ACK frames do not count toward
   congestion control limits. » Un serveur qui n'a plus que des acquittements à
   envoyer voyait sa fenêtre se remplir d'octets que personne n'acquitterait
   jamais — puisqu'un acquittement ne s'acquitte pas — et **finissait par se
   taire tout seul**. C'est un essai de tampon étroit qui l'a fait voir.

#### Ce que la retransmission fait, et ce qu'elle ne fait pas

Quand un paquet se perd, on ramène le curseur d'émission du flux `CRYPTO` au
décalage qu'il portait : tout ce qui suit repart. C'est parfois plus que
nécessaire — des octets déjà reçus repartent —, et c'est sans conséquence : le
pair les reconnaît comme des doublons (§7.5 de RFC 9000), et une poignée de main
tient dans quelques kibioctets. Tenir la liste exacte des trous demanderait un
ensemble d'intervalles de plus, pour économiser des octets sur un échange qui
n'a lieu qu'une fois par connexion.

#### Ce que l'essai principal prouve, et ce qu'il ne prouve pas

Une poignée de main QUIC complète aboutit, en vrais paquets, contre un
`rustls::quic::ClientConnection`. Elle aboutit **aussi lorsqu'un datagramme se
perd en chemin** — c'est l'essai qui compte le plus, puisque QUIC n'a pas de
retransmission automatique.

La moitié TLS du client ne partage rien avec nous : c'est elle qui refuserait un
`ServerHello` mal placé ou une transcription incomplète. **Sa moitié QUIC, en
revanche, est notre code** : cet essai ne prouve donc pas l'interopérabilité,
mais que le conducteur assemble correctement des pièces déjà éprouvées
séparément. L'interopérabilité demandera un client tiers.

Et il a fallu instrumenter deux fois pour trouver que la faute était dans le
client d'essai, non dans le serveur : la première fois parce qu'il n'installait
pas ses clés entre deux datagrammes, la seconde parce qu'une substitution de
texte avait échoué en silence et laissé l'ancienne version en place. **Le
symptôme désignait le serveur ; la cause était ailleurs, deux fois.**

### Les flux câblés au conducteur, et quatre manques que les essais ont montrés

Écrit le 2026-08-31. `ams-quic-tls::Connection` sert désormais `STREAM`,
`RESET_STREAM`, `STOP_SENDING`, `MAX_DATA`, `MAX_STREAM_DATA` et `MAX_STREAMS`,
émet des octets d'application, et offre à l'appelant `open_stream`, `write`,
`finish`, `read` et `read_reset`.

Les flux ne se bâtissent **qu'à la fin de la poignée de main** : §4.1 et §4.6 se
règlent sur des paramètres que §7.4 ne laisse croire qu'authentifiés. Les bâtir
plus tôt réglerait la connexion sur des limites que le pair n'a jamais annoncées,
et `Reason::PasEncoreDeFlux` dit à l'application qu'elle a parlé trop tôt plutôt
que de la laisser croire ses octets partis.

Ce qu'on annonce est ce qu'on tient : seize kibioctets par flux, quatre fois cela
pour la connexion, et les plafonds de la table. **La fenêtre par flux domine tout
le coût d'un flux** — l'état tient en trois kibioctets —, et elle ne s'alloue
qu'au premier octet reçu : un pair qui ouvre trente-deux flux sans rien y écrire
ne doit pas nous faire réserver un demi-mébioctet.

#### §12.4 n'était pas appliqué du tout

Une trame de flux dans un paquet de poignée de main était ignorée en silence.
« An endpoint MUST treat receipt of a frame in a packet type that is not
permitted as a connection error of type PROTOCOL_VIOLATION. » Ce n'est pas une
formalité : **sans ce contrôle, la trame atteignait une collection qui n'existe
pas encore**. Et l'ignorer ne valait pas mieux, le pair croyant avoir dit quelque
chose.

Le même contrôle porte §19.20 : un serveur qui reçoit un `HANDSHAKE_DONE` doit
fermer, puisque c'est lui qui l'émet. En recevoir un veut dire que le pair se
croit serveur, et rien de ce qui suivrait n'aurait le sens qu'on lui prêterait.

#### La fenêtre se rouvrait sur ce qui arrive, et non sur ce qui est lu

§4.1 : « A receiver … extends the limit as data is consumed. » L'asseoir sur
l'arrivée la laissait grande ouverte même si l'application ne lisait rien — et
**le crédit de connexion ne bornait plus la mémoire qu'un pair peut nous faire
retenir**, ce pour quoi il existe. `Streams` compte donc ce qui est consommé, et
y ajoute ce qu'un flux rendu n'avait pas livré : ces octets-là ne seront jamais
lus, et ne pas les compter perdrait leur crédit pour toujours.

#### Rien ne rendait jamais les places

Trente-deux flux, et plus jamais un de plus : la table se serait remplie de flux
morts, et le pair aurait vu ses ouvertures refusées **sans avoir rien fait de
mal**. La récolte passe donc à chaque datagramme reçu et avant chaque émission —
ce qui met le `MAX_STREAMS` dans le paquet courant plutôt que dans le suivant.

#### Le `FIN` chevauche les derniers octets

§19.8 le pose sur la trame qui porte la fin. L'attendre coûtait un paquet de plus
par flux, et un aller-retour de plus pour l'acquitter. Un détail de bande
passante, trouvé parce qu'un essai attendait l'acquittement d'un flux qui ne
venait jamais dans le tour prévu.

#### Et un défaut du CLIENT D'ESSAI, pour la troisième fois de suite

Il bourrait tout datagramme à 1200 octets, alors que §14.1 ne l'exige que pour
ceux qui portent un `Initial`. **Un en-tête court n'a pas de champ de longueur**
(§17.3) : sa charge va jusqu'au bout du datagramme, et les zéros entraient donc
dans le chiffré. Les paquets ne s'authentifiaient plus, et **aucun acquittement
applicatif n'était jamais parvenu au serveur** — ce qui se voyait comme un
conducteur qui ne terminait pas ses flux.

Le symptôme désignait le conducteur ; la faute était dans l'essai. C'est la
troisième fois, et les trois fois le symptôme a désigné le serveur.

#### Sept gardes inatteignables de plus

Toutes signalées par la couverture, dont une redondance introduite dans
`rang_ouvert` en écrivant cette tranche même. Elle est remplacée par
`Streams::can_send`, qui distingue « ce flux n'émet pas » de « son crédit est
nul » — deux choses que confondre aurait fait refuser un flux simplement bloqué.

### Les flux de requête d'HTTP/3

Écrit le 2026-09-01. **Une requête fait désormais l'aller-retour** : des champs
comprimés par QPACK arrivent, une application décide, et une réponse repart
comprimée.

#### `Service` : ce que le conducteur ne décide pas

`ams-h3` sait découper un flux en trames, décomprimer une section de champs et
réécrire une réponse. **Il ne sait pas ce qu'une requête veut dire**, et n'a ni
compte, ni jeton, ni magasin. L'étage qui assemble branchera `ams-session::http`
derrière cette interface, exactement comme il le fait pour HTTP/2.

Le corps arrive entier : §4.1 fait qu'une requête est complète quand le client a
fini d'écrire, et le conducteur n'appelle le service qu'à ce moment. **Une
requête tronquée n'atteint donc jamais le service**, qui n'a pas à s'en défendre.

#### Ce qui ne passe pas par le tampon

Les octets d'une trame vont directement dans leur bac — la section de champs, le
corps, ou rien pour une trame inconnue (§9). Un corps de soixante kibioctets n'a
rien à faire dans un tampon de quatre-vingts octets, et l'y faire transiter
n'apporterait qu'une recopie.

Les deux bacs sont bornés : la section de champs au
`SETTINGS_MAX_FIELD_SECTION_SIZE` qu'on annonce, le corps à soixante-quatre
kibioctets. **Au-delà, c'est `H3_EXCESSIVE_LOAD`** — §8.1 nomme exactement cela,
« the endpoint detected that its peer is exhibiting a behavior that might be
generating excessive load », et le pair le SAIT puisque nos réglages le lui ont
dit.

Ce serveur n'est d'ailleurs pas un dépôt : son API administre des boîtes, et ce
qui entre par une requête tient en quelques kibioctets. Un message de courrier
entre par SMTP, où il s'écoule sans être retenu.

#### Une réponse sans corps n'a pas de trame `DATA`

Une trame de zéro octet ne dit rien de plus que son absence, et coûte deux octets
à chaque réponse qui n'a rien à porter.

#### Trois codes que j'avais devinés, et que la grammaire savait

Un flux qui se termine sans section d'en-têtes rend `H3_REQUEST_INCOMPLETE` et
non `H3_FRAME_UNEXPECTED` : il n'y a pas eu de requête du tout. Un champ de
réponse que §4.2 interdit rend `H3_INTERNAL_ERROR` : **c'est notre service qui a
demandé l'impossible**, et l'imputer au pair rendrait son journal mensonger. Et
un flux de poussée venant d'un client rend `H3_ID_ERROR` : c'est l'emploi du
flux qui est faux, non sa création.

Les trois fois, l'essai que j'écrivais supposait un code, et les trois fois la
grammaire — écrite plus tôt, contre la RFC — avait raison.

#### Une cible de fuzz sur des octets, et non sur des types

`fuzz_ams_h3_connection` éprouve la machine d'état sur une suite de TYPES de
trames donnée à la main. `fuzz_ams_h3_driver` lui donne **des octets**, avec leur
découpage : c'est là qu'un tampon mal borné ou un pas qui n'avance pas se
verraient — non comme une réponse fausse, mais comme une boucle qui ne rend
jamais la main.

En l'ajoutant, j'ai d'abord écrasé la cible existante en réemployant son nom.
Elle a été restaurée depuis git, et la nouvelle porte le sien.

### L'écoute HTTP/3 du serveur (`listenH3`)

Écrite le 2026-09-01. Le serveur ouvre une socket UDP à côté de son port TCP, avec
les mêmes certificats, la même session, la même API et le même videur.

#### Une adresse à part, et non le même port qu'HTTP/2

HTTP/3 se découvre par `Alt-Svc` et se sert conventionnellement sur le même
numéro de port, en UDP. On pourrait donc l'ouvrir dès que `listenHttp` l'est.
**Ce serait ouvrir un port derrière un pare-feu que l'exploitant n'a pas
ouvert** — et une surprise sur un port est un incident. Le schéma porte donc
`listenH3`, et le code Cap'n Proto a été régénéré pour lui.

Les mêmes conditions que pour HTTP/2 s'appliquent : sans certificat ni secret de
scellement, ce port ne s'ouvre pas. QUIC chiffre toujours (§5 de RFC 9001) — il
n'y a même pas de mode en clair à refuser, seulement une configuration
incomplète.

#### La même session et la même API, ou rien

Un jeton scellé par HTTP/2 doit ouvrir HTTP/3, et une ressource servie d'un côté
doit être la même de l'autre. Les monter deux fois donnerait **deux clés de
scellement**, donc des jetons qui ne s'ouvriraient pas d'un côté à l'autre.
`listenH3` sans `listenHttp` n'est donc pas servi, et le serveur le dit plutôt
que de le laisser découvrir à la première requête.

La configuration TLS d'HTTP/3 n'est pas celle d'HTTP/2 : elle porte l'ALPN `h3`
seul, dont §3.1 de RFC 9114 fait la condition de la connexion.

#### Une course dans les essais, que ce travail a révélée

`lancer` rend la main dès l'annonce de l'écoute SMTP, écrite juste après le
`bind` — **donc avant que l'API, HTTP/3 et le reste ne se montent**. Lire le
journal à cet instant, c'est le lire au hasard de l'ordonnancement : l'essai passe
la plupart du temps et échoue sous charge sans rien apprendre.

Le nouvel essai a échoué tout de suite, et `attendre_le_journal` le rend stable.
**Les essais existants qui lisaient le journal de la même façon portaient la même
course** : ils passaient pour la même raison que celui-ci passait deux fois sur
trois. Ils ont été repris — deux lectures immédiates remplacées par l'attente, et
une attente écrite à la main qui refaisait l'aide.

Pour vérifier que l'attente n'a pas rendu ces essais complaisants, le message du
serveur a été changé volontairement : l'essai a échoué, **et il a mis les cinq
secondes de son délai à le faire**. Un essai qui attend sans jamais échouer ne
vaut pas mieux qu'un essai qui lit trop tôt.

`chiffrement.rs` ne lit le journal que dans sa propre attente de démarrage et dans
ses messages d'échec : il n'y avait rien à y reprendre.

### HTTP/3 branché sur l'écoute (`ams-loop-tokio::h3`)

Écrit le 2026-09-01. **Une requête HTTP/3 traverse désormais toute la chaîne sur
une vraie socket UDP** : QUIC, TLS, ALPN `h3`, flux de contrôle, réglages, QPACK,
session, jeton, API, et la réponse qui revient comprimée.

C'est ici, et nulle part ailleurs, que les étages se touchent. `ams-h3` conduit
HTTP/3 sans connaître QUIC autrement que par son interface `Transport` ;
`ams-quic-tls` conduit une connexion sans savoir ce qu'un octet veut dire ;
`ams-session::http` décide des requêtes sans rien émettre. **Aucun des trois ne
connaît les deux autres.**

Deux pièces, et rien de plus. Un pont — `Pont<'a>(&'a mut Connection)` — qui vit
ici parce que ni le trait ni `Connection` ne nous appartiennent, et que la règle
de l'orphelin interdit de les marier chez un tiers. Et un service qui reprend
**exactement** l'enchaînement d'HTTP/2 : `session.request`, puis selon `Next`
soit `api.authenticate` et `on_credentials`, soit `api.serve`. Une seconde façon
de décider ferait diverger les deux versions du protocole sur des règles qui
n'ont rien à voir avec le transport.

#### La couture ne disait pas QUI parle, et C8 l'exige

`Application` recevait une connexion et un flux, mais pas l'adresse du pair — que
l'écoute tenait pourtant. Or le videur range ses comptes par source, et **un refus
d'identifiants doit compter contre l'adresse qui l'a tenté**. Sans cela, HTTP/3
aurait servi sans aucune protection contre les essais répétés, là où HTTP/2 en a
une depuis toujours.

Ce n'était pas contournable dans l'adaptateur : l'information n'existait pas de ce
côté de la frontière. Les trois rendez-vous portent maintenant la `Source`, et
elle se pose **à chaque requête** — un service sert plusieurs connexions, et la
retenir à la construction ferait compter tous les refus contre la première adresse
qui a parlé.

#### Ce que l'essai de bout en bout a coûté à écrire, et pourquoi c'est bien

Trois refus successifs de la session, chacun juste :

- `/health` n'existe pas : les routes de cette API commencent par `/v1`.
- **L'index 22 de la table statique de QPACK vaut `:scheme: http`**, et non
  `https` — c'est 23. Ce serveur ne sert rien en clair (C4), et il l'a dit.
- Un corps sans `content-type` est refusé : §8.3 de RFC 9110 fait que sans lui la
  session ne sait pas ce qu'elle lit, et elle refuse plutôt que de deviner.

Les trois fois, le refus est arrivé **comprimé par QPACK, sur une vraie socket**,
avec son « problem detail » de RFC 9457 lisible dans le corps. Un essai qui aurait
passé du premier coup aurait prouvé moins que ces trois échecs.

La requête d'essai est composée à la main, préfixes de §5.1 de RFC 7541 compris :
la bâtir avec notre propre encodeur ne prouverait rien du fil — si l'ordre des
champs était faux des deux côtés, l'essai passerait quand même.

### Le conducteur HTTP/3 : l'ouverture de connexion (`ams-h3`)

Écrit le 2026-09-01. Un crate d'étage 2, sans entrée-sortie, dans le périmètre de
couverture. **Toutes les pièces existaient** — `ams-proto-h3` lit une tête de
flux, une trame, des réglages ; son module `qpack` lit et écrit une section de
champs ; `ams-session::http` décide déjà des requêtes pour HTTP/2. Aucune ne
savait quel flux ouvrir en premier, ce qu'il faut y écrire, ni à quoi rattacher
les octets qui arrivent.

Cette tranche fait l'ouverture : le flux de contrôle et ses `SETTINGS` (§6.2.1),
la lecture des têtes de flux unidirectionnels (§6.2), et les trames de contrôle
(§7.2). Les flux de requête viendront ensuite.

#### `Transport` : ce que HTTP/3 demande à QUIC, et rien de plus

Quatre choses : ouvrir un flux unidirectionnel, lire, écrire, savoir où en est la
réception. **Tout le reste — les clés, les numéros, la congestion, les
retransmissions — ne regarde pas HTTP/3**, et le lui laisser voir donnerait à un
conducteur d'étage supérieur les moyens de défaire ce que l'étage du dessous a
décidé.

Le pont vers `ams-quic-tls::Connection` vit à l'étage qui les assemble, et non
ici : c'est une pièce de montage, elle demande une vraie connexion pour être
éprouvée, et `ams-h3` ne connaît donc pas `ams-quic-tls` du tout.

Cela rend aussi les essais d'HTTP/3 indépendants de TLS : ils ne demandent ni
certificat ni poignée de main, et chacun dit une chose sur HTTP/3 plutôt que sur
TLS. **C'est une conséquence, et non le motif.**

#### Ce que la couverture a trouvé : un tampon trop petit d'un en-tête

`TAMPON_OCTETS_MAX` valait soixante-quatre, comme la charge de contrôle la plus
grande qu'on accepte. **Un `SETTINGS` de cette taille exacte remplissait donc le
tampon sans jamais tenir son en-tête**, et le flux de contrôle se figeait pour
toujours — sans erreur, sans trace, et sans que le pair ait rien fait de mal.

Rien ne l'aurait montré : aucun essai n'atteignait cette branche, et c'est la
couverture qui l'a signalée. Le tampon vaut désormais la charge PLUS l'en-tête le
plus long de §7.1, et un essai envoie une trame à la borne exacte — avec des
entiers de §16 écrits sur huit octets, puisque §16 n'impose pas la forme la plus
courte et qu'un pair conforme a le droit de le faire.

#### Un type de flux inconnu n'est pas une faute de connexion

§6.2 : « The recipient MUST NOT consider unknown stream types to be a connection
error of any kind. » On abandonne CE flux et rien d'autre — c'est ce qui laisse
une extension ouvrir les siens sans casser les pairs qui ne la connaissent pas.

**Mais on le CONSOMME**, plutôt que de l'ignorer : les octets non lus ne
rouvriraient jamais la fenêtre du flux (§4.1 de RFC 9000), et le pair finirait
bloqué sans comprendre pourquoi.

**Les flux QPACK, eux, ne se jettent plus.** Ils l'ont été tant que rien ne les
lisait ; leurs instructions sont désormais lues et jugées, et ce qu'on refuse se
dit. Voir « Une table dynamique QPACK de zéro octet » plus bas.

Une trame inconnue se saute de même **sans passer par le tampon** (§9) : elle peut
faire des mébioctets, et l'y mettre donnerait au pair le moyen de choisir combien
nous retenons.

#### Un générique multiplie les régions à couvrir

`on_established` est générique sur le transport, et chaque type qui le traverse
en fait recopier le code. Deux faux transports dans les essais demandaient donc
d'éprouver deux fois chaque branche pour n'en montrer aucune de plus. Il n'y en a
qu'un, avec un drapeau pour ce qu'il refuse.

### La couture applicative (`ams-loop-tokio::quic::Application`)

Écrite le 2026-09-01. C'est le point où une application reçoit les octets d'un
flux — **et c'est tout ce qu'elle reçoit** : l'écoute sait ouvrir un paquet,
compter un crédit et retransmettre ; elle ne sait pas ce qu'un octet veut dire,
et n'a pas à le savoir. Le même partage qu'entre `ams-session::http` et
`ams-loop-tokio::http`, et pour la même raison — ce qui décide et ce qui exécute
ne se vérifient pas de la même façon.

Trois rendez-vous, et pas un de plus :

- `on_established` — **le premier instant où l'on peut ouvrir un flux**, §7.4 ne
  laissant croire les limites du pair qu'authentifiées. HTTP/3 y ouvrira ses
  trois unidirectionnels, que le client attend sans les avoir demandés. Dit une
  fois et une seule : les rouvrir à chaque datagramme épuiserait le plafond de
  §4.6 en quelques tours.
- `on_readable` — appelé tant qu'il reste de quoi lire, **et borné à soixante-
  quatre appels par tour** (C3) : une application qui prendrait un octet à la
  fois ferait autrement tourner la boucle pendant que les autres connexions
  attendent.
- `on_closed` — ce qu'on tenait pour cette connexion ne sert plus.

L'écoute relit la table des flux à chaque tour plutôt que de tenir une file des
flux devenus lisibles. Cette file demanderait d'être juste à l'arrivée d'un
octet, à la lecture d'un autre et à l'annulation d'un flux, et un oubli s'y
verrait comme un flux qui se fige sans raison. **Trente-deux entrées se relisent
pour moins cher qu'une erreur.**

`SansApplication` n'est pas un bouchon : un serveur QUIC sans application sert
quand même la poignée de main, les acquittements et le contrôle de flux, ce qui
est exactement ce qu'il faut pour éprouver le transport seul.

#### Ce qu'un essai d'écho a prouvé, et deux fautes qu'il a montrées

`crates/ams-loop-tokio/tests/quic.rs` fait maintenant l'aller-retour complet : le
client ouvre un flux, écrit une requête, et reçoit la réponse d'une application
qui n'a jamais touché à une socket.

Le monter a montré deux fautes dans le client d'essai, toutes deux dans la
composition d'un datagramme :

**Le client rendait `false` et abandonnait le datagramme avant d'y poser ce
qu'il avait à dire.** Une requête seule, sans acquittement à joindre, ne partait
donc jamais.

**Et §17.3, pour la troisième fois.** Un en-tête court n'ayant pas de champ de
longueur, sa charge va jusqu'au bout du datagramme : **un paquet `1-RTT` est
toujours le dernier**, et il ne peut y en avoir qu'un. L'acquittement applicatif
et les trames de l'essai vont donc dans le MÊME paquet. La première version en
posait deux, et le premier était jeté sans un mot — ce qui se voyait comme un
serveur qui ne fermait pas sur une faute qu'on venait de lui envoyer.

Cette faute-là était **intermittente** : elle dépendait de la présence d'un
acquittement à joindre au même tour. Un essai qui passe quatre fois sur six ne
passe pas.

### Un flux sur la vraie socket, et son contrôle négatif

Écrit le 2026-08-31. `crates/ams-loop-tokio/tests/quic.rs` fait désormais ouvrir
au client un flux bidirectionnel, y écrire et le terminer — sur la pile réseau du
système.

**Ce que cet essai prouve** : §12.4, §4.1 et §4.6 sont servis de bout en bout, la
trame arrive au bon niveau, le crédit est compté, le flux est rangé dans sa part
de table. **Ce qu'il ne prouve pas** : qu'une application reçoive ces octets.
L'écoute n'a pas encore de couture applicative, et c'est le conducteur HTTP/3 qui
l'apportera ; l'inventer avant de connaître ses besoins reviendrait à deviner.

#### Un essai qui ne peut pas échouer ne prouve rien

« La connexion est restée ouverte » ne dirait rien d'une écoute qui jetterait
toutes les trames de flux en silence. Un second essai fait donc dépasser au
client le plafond de §4.6, et vérifie que le serveur le lui DIT plutôt que de
jeter. Sans ce contrôle négatif, le premier essai aurait été décoratif.

Il a d'ailleurs corrigé une attente fausse : `QuicStats::closed` ne compte pas
les connexions qu'on ferme, mais celles qui ont fini d'attendre. §10.2 garde une
connexion en fermeture trois PTO durant, pour redire son `CONNECTION_CLOSE` au
pair qui n'aurait pas entendu.

#### Le même défaut de bourrage, dans le second client d'essai

Il bourrait lui aussi tout datagramme à 1200 octets. Il n'échouait pas visiblement
tant que l'essai s'arrêtait à la poignée de main — les paquets à en-tête long ont
un champ de longueur —, mais aucun acquittement applicatif ne pouvait lui
parvenir. Corrigé de la même façon que l'autre, et pour la même raison (§17.3).

### La collection de flux, et ce que le fuzz a trouvé

Écrite le 2026-08-31, dans `ams-quic::streams`. **Toutes les machines par flux
existaient** — `Send` (§3.1), `Recv` (§3.2), `Flow` (§4.1), `Concurrences`
(§4.6) — et aucune ne savait à quel flux une trame s'adresse, avec quelle limite
il s'ouvre, ni quand sa place se libère. C'est le même vide qu'avant le
conducteur de connexion, et le module ne comble que celui-là.

#### Elle ne garde pas les octets

`Recv::on_stream` demandait déjà sa fenêtre en argument ; la collection se
contente de la lui passer, et rend en échange un rang de table stable par lequel
l'appelant retrouve ses tampons. **C'est ce qui garde `ams-quic` sans allocation
et sa taille bornée** : un flux y coûte quelques centaines d'octets d'état, et
non la taille de sa fenêtre.

La mesure qui a tranché : un flux pèse 3 184 octets d'état, dont 3 072 pour les
deux jeux d'intervalles de réassemblage. Ramener ceux-ci de 64 à 8 intervalles
les ferait tomber à 496 — mais `HOLES_MAX` porte déjà son argument, et il est
juste : soixante-quatre intervalles couvrent les vingt-huit paquets qu'un pair
peut avoir en vol sur un flux avec une fenêtre de 32 kibioctets. **Et surtout, la
fenêtre que l'appelant doit tenir domine tout le reste** : économiser 2,7 Ko
d'état devant 32 Ko de fenêtre ne valait pas la tolérance au désordre qu'on y
perdait.

#### Un plafond par famille, et non un seul pour la table

§4.6 compte quatre familles : deux sens d'ouverture, deux directionnalités. Si
les quatre puisaient dans le même crédit, **le pair pourrait remplir la table
avec une seule famille et rendre les trois autres inutilisables — sans jamais
dépasser aucune limite qu'on lui a annoncée**. Chaque famille a donc sa part de
table, et la somme des parts est la table entière. Le débordement devient
impossible par construction, et non gardé par un test qu'aucun essai
n'atteindrait.

Le plafond annoncé vaut « ce qu'on a rendu, plus une part ». Les deux termes
comptent : un pair qui nous avait annoncé peu nous laisse de la place dès le
départ, et chaque flux rendu en libère une de plus. §4.6 compte les flux ouverts
depuis toujours et jamais les vivants — sans ce compte, une connexion n'aurait
droit qu'à huit flux par famille pour toute sa vie, et une page HTTP/3 en demande
davantage.

**Une place libre n'est pas une promesse.** Tant que le `MAX_STREAMS` n'est pas
parti, le pair ne sait rien du crédit qu'une place rendue vient d'ouvrir : rendre
la place et relever le plafond sont donc deux gestes, `oublier` et
`set_max_streams`, et `grant_streams` propose entre les deux. Les confondre
accepterait des flux que le pair n'a pas le droit d'ouvrir.

#### Ce que le fuzz a trouvé, et par sa conséquence

`fuzz_ams_quic_streams` a fait tomber une propriété qui ne parlait pas de la
faute : **le rang d'un flux vivant avait bougé**. La cause était ailleurs — §19.8
exige de refuser une trame qui parle d'un flux à nous que nous n'avons pas
ouvert, et la collection l'ouvrait à la place du pair. Le jour où `open` prenait
ce rang, il en existait alors deux du même numéro, donc deux contrôles de flux
pour un seul flux, qui divergeaient en silence.

§2.1 donne à chaque côté ses propres numéros, et celui qui ouvre est le seul à
choisir quand. Un pair qui parle d'un numéro à nous ne prend pas de l'avance : il
désigne quelque chose dont nous n'avons aucune idée. D'où `Reason::StreamNotCreated`,
qui porte le `STREAM_STATE_ERROR` de §19.8.

**La faute ne s'est pas vue là où elle était commise**, et c'est le troisième
défaut de suite trouvé de cette façon : c'est la propriété d'ensemble qui l'a
révélée, longtemps après le geste fautif.

#### Trois défauts trouvés en relisant, avant toute compilation

`oublier` relevait le plafond que `grant_streams` était censé proposer ; `on_sent`
consommait le crédit de connexion avant de vérifier que le flux existe, laissant
un refus dépenser pour des octets jamais émis ; et deux gardes de `read` et
`credit` étaient inatteignables, `slot` ne rendant jamais que le rang d'un flux
vivant. Quatre autres gardes inatteignables ont été retirées ensuite, chacune
signalée par la couverture.

### L'écoute UDP (`ams-loop-tokio::quic`)

Écrite le 2026-08-31. C'est la troisième étape pour QUIC : les grammaires
décident sans entrée-sortie, `ams-quic-tls::Connection` conduit une connexion
sans savoir d'où viennent ses octets, et **ce module ne fait que tenir la socket
et la carte**. Le même partage que pour HTTP/2, où `ams-session::http` décide et
`ams-loop-tokio::http` exécute.

Depuis le 2026-08-31, `crates/ams-loop-tokio/tests/quic.rs` mène **une poignée
de main QUIC complète sur une vraie socket UDP de bouclage**, avec un certificat
fabriqué par `openssl` et un client bâti sur `rustls::quic::ClientConnection`.

#### Une seule tâche, et non une par connexion

Un serveur QUIC n'a qu'une socket : tout arrive au même endroit. Distribuer les
datagrammes à mille tâches demanderait mille files et mille réveils pour ce
qu'une boucle fait sans partage — et le partage est précisément ce qui coûte.
La conséquence assumée : une connexion lente retarde les autres. C'est
acceptable tant que le traitement d'un datagramme est borné, ce que la grammaire
garantit (C3).

#### Ce que l'écoute décide, et ce qu'elle ne décide pas

Elle décide de quatre choses, et de rien d'autre :

- **à qui appartient ce datagramme**, par la carte des identifiants que nous
  avons distribués (§5.2) ;
- **quand se réveiller**, par le plus proche des délais que les connexions
  annoncent — et `core::future::pending()` quand il n'y en a aucun, pour qu'un
  serveur au repos ne se réveille jamais pour rien ;
- **vers quelle adresse** partent les octets qu'une connexion produit ;
- **quand oublier** ce qui s'est éteint.

Tout le reste — les clés, les numéros, la fenêtre, les retransmissions — est
déjà décidé ailleurs, et l'écoute n'en sait rien.

#### Trois refus délibérés

**Une erreur de lecture n'arrête pas l'écoute.** Sur UDP, un `ECONNREFUSED`
remonte d'un datagramme précédent qu'un pair a rejeté : arrêter là fermerait le
service au premier pair discourtois.

**Une erreur d'émission ne ferme pas la connexion.** Le pair peut être
momentanément injoignable ; §13.3 prévoit déjà la retransmission de ce qui n'est
pas acquitté. Fermer sur un échec d'envoi transformerait une gêne passagère en
perte définitive.

**Un `Initial` au-delà de la capacité est jeté en silence.** §5.2.2 l'autorise,
et une réponse serait exactement l'amplification qu'on refuse d'offrir.

**La migration n'est pas suivie** (§9) : un datagramme reçu d'une autre adresse
est traité, mais les réponses continuent de partir vers l'adresse connue. Suivre
un changement d'adresse sans le valider (§8.2) donnerait un moyen simple de
rediriger un flot vers un tiers.

#### Ce que cet essai éprouve, et que les autres ne pouvaient pas

Les essais du conducteur passent les datagrammes de main en main dans le même
processus. Ici ils traversent la pile du système, ce qui met à l'épreuve les
quatre décisions ci-dessus — dont la carte : **l'essai vérifie que le client
finit par adresser ses paquets à l'identifiant que le serveur lui a donné**, et
non à celui qu'il avait choisi au départ. Si la carte rangeait mal, la poignée de
main s'arrêterait au deuxième aller-retour.

Le second essai écrit du bruit sur le port — un datagramme quelconque, un
`Initial` trop court, du texte HTTP — et vérifie qu'aucun n'ouvre de connexion et
qu'aucun n'arrête l'écoute. Le port est ouvert au monde ; c'est la première
chose qu'il faut prouver.

Deux ajouts au périmètre ont été nécessaires, et tous deux sont couverts :
`Incoming::source()`, parce que §7.2 fait choisir à chacun l'identifiant que
l'autre emploie — l'adresse de retour se LIT, elle ne se déduit pas ; et
`Connection::close_with(u64, u64)`, parce que `Error::close_code()` rend un code
qui n'est pas toujours un code de transport : §4.8 de la RFC 9001 loge les
alertes TLS dans une plage à part, et §20 garde les deux espaces distincts
exprès.

### La détection de perte, et ce que deux essais ont trouvé

Écrit le 2026-08-31, dans `ams-quic::sent`. QUIC n'a pas de retransmission
automatique : un paquet perdu est perdu, et c'est à l'émetteur de s'en
apercevoir. **Sans ce module, une poignée de main ne finit pas** dès qu'un seul
datagramme se perd.

Les trois pièces qui l'entourent existaient déjà : `Rtt` mesure le trajet (§5),
`Congestion` borne le débit (§7), `Received` fabrique les `ACK` que l'on ENVOIE
(§13.2 de RFC 9000). Manquait celle qui se souvient de ce qu'on a envoyé.

Il ne retient qu'un numéro, une date, une taille et deux drapeaux. **Retenir
aussi les trames doublerait la mémoire d'une connexion** et ferait de ce module
le propriétaire de données qu'il ne relit jamais. Quand il déclare un paquet
perdu, il en rend le NUMÉRO ; c'est l'appelant, qui a composé les trames, qui
sait ce qu'il faut recomposer.

Un objet par espace de numérotation (§12.3) : un seul pour les trois compterait
des seuils de réordonnancement entre des numéros qui n'ont rien à voir.

#### Deux défauts trouvés par les essais, et non par la relecture

1. **Un paquet émis à l'origine de l'horloge était perdu d'avance.** §A.10 pose
   `lost_send_time = now - loss_delay` ; la première version saturait cette
   soustraction à zéro, ce qui rendait `parti_a <= 0` vrai pour tout paquet émis
   à l'instant zéro. Une horloge monotone commence près de zéro : ce sont les
   tout premiers paquets d'une connexion — ceux de la poignée de main — qui
   auraient été retransmis pour rien. `checked_sub` dit ce que la RFC dit :
   quand l'horloge n'a pas atteint le délai, rien n'a pu être émis si tôt.
2. **Un même numéro de paquet était accepté deux fois.** §12.3 de RFC 9000 :
   « A QUIC endpoint MUST NOT reuse a packet number within the same packet
   number space. » Rien n'obligeait ce module à le vérifier — c'est l'appelant
   qui numérote. Mais deux entrées pour un même numéro font compter deux fois
   les mêmes octets à l'acquittement, et la comptabilité des octets en vol
   dérive **sans que rien ne le dise** : cela se verrait dans un débit qui
   s'écroule, et nulle part ailleurs. C'est la cible de fuzz qui l'a montré, en
   soumettant deux fois le même numéro.

#### Les bornes, et pourquoi elles ne se valent pas

- **256 paquets retenus par espace.** Refuser d'émettre au-delà ne perd rien :
  cela plafonne le débit, exactement comme le fait déjà le contrôleur de
  congestion. C'est l'inverse d'une borne en réception, où ce qu'on ne retient
  pas est perdu pour de bon.
- **32 intervalles lus dans un `ACK`** — le nombre qu'on écrit soi-même. Un pair
  qui en envoie davantage décrit un réseau plus troué que tout ce qu'on sait
  tenir ; le refuser vaut mieux que de lire à moitié un acquittement, ce qui
  ferait déclarer perdus des paquets qui ne le sont pas.

#### Ce que le seuil temporel doit à un détail d'écriture

§6.1.2 : `9/8 × max(smoothed_rtt, latest_rtt)`, jamais moins que la granularité
de l'horloge. Le multiplicateur est porté **en huitièmes, en entiers** : un
flottant introduirait un arrondi là où la RFC parle d'une fraction exacte. Et le
plancher n'est pas décoratif — un seuil plus fin que ce qu'on sait mesurer
déclarerait perdu ce qui vient d'arriver.

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

**Le relais fermé n'est plus seulement une décision, depuis le 2026-09-01.** Il
l'était par défaut d'implémentation : `accepts_recipient` refusait toute adresse
qui n'était pas celle d'un compte, si bien qu'aucun message ne pouvait sortir. Un
relais fermé faute de savoir émettre n'est pas un relais fermé — c'est un serveur
qui ne sait pas émettre, et le jour où il l'apprend la protection disparaît sans
que personne l'ait décidé.

La file de réémission sortante est ce jour-là. Trois règles la tiennent, et elles
sont écrites AVANT le code qui émet :

1. **On ne relaie que pour un compte AUTHENTIFIÉ**, et l'authentification n'est
   annoncée que sous chiffrement. Un pair anonyme continue de recevoir un `550`.
2. **L'émission s'ouvre SUR DEMANDE**, et le défaut est éteint. Émettre du
   courrier vers des tiers ne se décide pas à la place de qui exploite la
   machine — la même règle que pour les rapports DMARC.
3. **Le rapport de non-remise se remet LOCALEMENT.** Puisque le chemin de retour
   est toujours l'adresse d'un de nos comptes, ce serveur n'envoie jamais de
   rebond à un inconnu. C'est ce qui le tient hors de la rétro-diffusion : émettre
   un rebond vers une adresse qu'un tiers a écrite dans un `MAIL FROM:` usurpé
   ferait de nous l'instrument de son envoi.

**Où les deux conditions se rejoignent** : `Policy::accepts_recipient` reçoit un
second argument, `submitter`, que la SESSION renseigne — elle seule a conduit
l'`AUTH`. La politique, elle, est partagée par toutes les connexions et n'a aucun
état propre à l'une d'elles ; le lui faire déduire d'autre chose serait la façon
d'ouvrir un relais sans s'en apercevoir. Le `&&` avec le drapeau de configuration
est écrit à UN SEUL endroit, dans `BoitesConnues`.

**Les deux portes de soumission appliquent la même règle**, et c'est délibéré :
SMTP authentifié et `/v1/submissions` mènent tous deux à la même file. N'en
ouvrir qu'une ferait deux règles pour un même geste, et l'utilisateur
découvrirait laquelle relaie en essayant.

**Quatre décisions de la file elle-même**, consignées parce qu'elles ne se lisent
pas dans le code seul :

1. **L'état de la reprise tient dans le NOM du fichier** —
   `<prochain>!<dépôt>!<essais>!<identifiant>.eml`. Un index séparé serait un
   second endroit à tenir cohérent avec le premier, et une panne au mauvais
   moment les ferait diverger. Un `rename()` fait passer d'un état à l'autre en
   une opération que le système de fichiers rend atomique.
2. **L'enveloppe est un fichier voisin, nommé par le SEUL identifiant.** Les
   en-têtes ne disent pas à qui remettre — `To:` peut nommer une liste, `Bcc:` a
   disparu à la composition —, et c'est `MAIL FROM:` et `RCPT TO:` qui décident.
   Le nom de l'enveloppe ne change jamais, si bien qu'une reprise n'a JAMAIS deux
   renommages à réussir ensemble.
3. **La péremption se juge APRÈS l'essai, à un seul endroit.** Un message qui a
   dormi pendant une panne du serveur a droit à un dernier essai, plutôt qu'à un
   rapport écrit sans avoir rien tenté. Et le dernier essai tombe SUR l'échéance :
   renoncer dès que l'attente la dépasserait raccourcirait en silence les cinq
   jours que §4.5.4.1 de RFC 5321 demande.
4. **Un envoi par destinataire, et non par domaine.** `RelayOutcome::Delivered`
   COMPTE les destinataires refusés ; il ne les NOMME pas. Grouper rendrait donc
   un rapport qui devrait deviner qui a échoué, et un rapport qui devine se trompe
   sur l'adresse d'un tiers. Le coût — une transaction par destinataire — se paie
   en connexions ; l'autre se paierait en rapports faux.

**Et un rapport qui ne se compose pas se compose SANS les en-têtes d'origine.**
Ce sont les seules valeurs du rapport qui ne viennent pas de nous, donc les seules
qui puissent le faire refuser ; renoncer alors ferait disparaître le message en
silence, ce que cette file existe pour empêcher. Le cas s'est produit pendant
l'écriture : un tiret cadratin dans le texte français du rapport, que le composeur
refuse à juste titre, effaçait le message sans que son expéditeur l'apprenne. Le
repli est là, et l'échec se journalise.

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
2. les **trames invalides**, comptées **par source** ;
3. les **destinataires refusés définitivement**, comptés **par source** — la
   signature d'une récolte d'adresses.

Au-delà de *x* trames invalides par minute, la machine fautive n'est plus acceptée
pendant *y* heures. `x` et `y` sont des **paramètres de configuration**, pas des
constantes.

**Et ils se règlent, depuis le 2026-09-01.** Jusque-là `air-mail-admin config
write` posait `Thresholds::DEFAULT` sans jamais le dire : la contrainte était
vraie dans le format et fausse en pratique, puisque personne ne pouvait écrire
autre chose que le défaut. Huit options les portent désormais —
`--connections-per-minute`, `--commands-per-minute`,
`--invalid-frames-per-minute`, `--refused-recipients-per-minute`,
`--ban-seconds`, `--ipv4-prefix-bits`, `--ipv6-prefix-bits` et
`--tracked-sources` —, et un test les fait traverser la ligne de commande,
l'encodage et la relecture pour qu'aucune ne puisse redevenir une constante par
inadvertance.

**Le refus est devant le terminal, pas au démarrage** — la même discipline que
les paires TLS et DKIM. L'outil refuse un zéro qui ne veut rien dire (aucune
connexion par minute ne sert personne ; aucune commande ne laisse même pas dire
`QUIT` ; une table de zéro source ne retient rien donc ne reproche rien) et un
préfixe hors bornes. `ams-guard`, lui, continue de **raboter** ce qui dépasse :
c'est ce qu'une bibliothèque doit faire d'une entrée qu'elle ne choisit pas, mais
un `/48` tapé pour de l'IPv4 et compté comme un `/32` serait une configuration
qui dit autre chose que ce qui a été demandé.

**Trois zéros restent licites, et ils ne veulent pas dire la même chose** — c'est
le seul endroit du projet où deux options voisines donnent à zéro des sens
opposés, et c'est pourquoi l'aide, le README et deux tests le disent :
`--refused-recipients-per-minute 0` ÉTEINT le comptage (voir plus bas),
`--invalid-frames-per-minute 0` bannit au PREMIER écart, et `--ban-seconds 0`
fait ajourner au lieu de bannir. `config write` avertit sur les deux derniers
plutôt que de les taire.

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
**C'est fait le 2026-09-01**, et quatre décisions le tiennent :

1. **Un refus reste hors de `peer_fault`.** La session pose un SECOND signal,
   `Turn::refused_recipient`, et la boucle en tire un troisième événement. Les
   deux ne se confondent pas : `x` trames invalides par minute et `z`
   destinataires refusés par minute sont deux seuils, avec deux justifications.
   Quand les deux signaux sont levés, c'est la faute qui l'emporte — elle est
   plus grave, et un pair ne doit pas diluer une faute en la maquillant en refus.
2. **Seul un refus DÉFINITIF compte.** `550` boîte inconnue et `550` relais
   refusé apprennent au pair que l'adresse n'existe pas ici ; `450` dit que NOUS
   ne pouvons pas en ce moment, et n'apprend rien sur l'adresse. Compter un
   temporaire punirait un pair pour nos propres embarras, et un expéditeur
   légitime qui réessaie — ce que la RFC lui demande — serait banni pour cela.
3. **Zéro éteint le compteur, et c'est ce qui rend le champ ajoutable.** Le
   schéma Cap'n Proto gagne `refusedRecipientsPerMinute @7`, et un fichier de
   configuration écrit avant que le champ n'existe décode zéro (§ C11). Zéro
   devait donc signifier « comme avant », c'est-à-dire *aucun comptage* — et non
   « tolérance nulle », qui bannirait au premier refus toute installation
   existante à la première mise à jour. Le serveur l'ANNONCE au démarrage et
   `air-mail-admin config show` le dit aussi : un compteur éteint en silence
   serait pire qu'absent.
4. **Le défaut est généreux : 50 par minute et par source.** Un faux positif
   diffère du courrier légitime d'un serveur entier ; un faux négatif laisse
   partir une liste d'adresses valides. Une passerelle qui relaie pour un site
   peut légitimement se tromper plusieurs fois par minute ; personne n'a besoin
   d'essayer cinquante adresses inconnues à la minute.

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

Ce qui n'était alors pas servi — une PARTIE désignée, `BODY[1]` et
`BODY[1.MIME]` — l'est depuis.

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

Ce qui n'était alors pas servi — `IDLE`, `SUBSCRIBE` — l'est depuis.

## Les mots-clefs, depuis le 2026-08-30

**CINQ, ET L'ENSEMBLE EST FERMÉ.** §2.3.2 n'oblige aucun serveur à servir un
mot-clef ; §E.15 en recommande cinq. Ce serveur sert ceux-là, et refuse le reste.

Le refus est la partie qui compte. Un serveur qui accepte un mot-clef qu'il ne
sait pas faire survivre répond `OK` à un client qui pose une étiquette, et cette
étiquette ne se reverra jamais. C'est le même raisonnement que pour un drapeau
système inconnu — et c'est aussi pourquoi `PERMANENTFLAGS` n'annonce pas `\*` :
`\*` promet qu'on accepte tout mot-clef nouveau, et cette promesse-là ne se
tient pas.

**MAILDIR LES PORTE DANS LE NOM DU FICHIER**, en minuscules, ce qui les fait
survivre comme les autres drapeaux — par un `rename()`, sans verrou et sans
réécrire le message. La correspondance des cinq lettres est écrite dans le code,
une fois pour toutes : la convention répandue la met dans un fichier annexe, qui
ne servirait ici qu'à rendre variable ce qui ne l'est pas, donc à la rendre
fausse le jour où il manque. Les minuscules suivent les majuscules dans l'ordre
ASCII, si bien que la règle d'ordre du format tient sans rien changer.

**`$NonJunk` N'EST PAS L'INVERSE DE `$Junk`** : les deux peuvent manquer, et cela
veut dire « personne n'a tranché ». Les traiter comme un seul drapeau perdrait
cette troisième réponse, qui est la plus fréquente.

Avec eux, **toute la grammaire de §9 est servie** : chaque commande, chaque
option de retour, chaque `search-key`, chaque `status-att`, chaque `fetch-att`.
Cette affirmation-là a été fausse deux fois avant d'être vraie, et ce qui l'a
rendue vraie n'est pas une liste de plus : c'est la confrontation à l'ABNF, mot
par mot.

**CE QUI RESTE, CE SONT DES `SHOULD`, ET ILS SE NOMMENT AUSSI.** §6.2.2 recommande
d'offrir un mécanisme SASL qui ne transporte pas le mot de passe en clair —
SCRAM-SHA-256, GSSAPI, EXTERNAL ; ce serveur n'offre que `PLAIN`, et seulement
sous chiffrement. Les attributs de SPECIAL-USE — `\Drafts`, `\Sent`, `\Trash` —
ne sont pas rendus non plus : ils désignent des boîtes que le serveur DÉSIGNE, et
celui-ci n'en désigne aucune. Un `SHOULD` qu'on ne tient pas se dit ; ne pas le
dire est la seule faute.

## `SENTBEFORE` : la date écrite, depuis le 2026-08-30

**CE N'EST PAS LA MÊME DATE.** `BEFORE` compare la date d'ARRIVÉE, `SENTBEFORE`
celle que le message porte dans son champ `Date:` (§6.4.4). Un message écrit
lundi et reçu vendredi répond à l'une et pas à l'autre.

§6.4.4 dit « disregarding time and timezone », et c'est ce qui rend la lecture
simple : on ne lit qu'un JOUR. Cela écarte toute la zoologie des fuseaux
obsolètes de RFC 5322 §4.3, qu'il faudrait sinon interpréter pour un résultat
qu'on jetterait.

**LE LECTEUR DE LA RECHERCHE EST DEVENU UN TRAIT.** Il y a maintenant deux
questions — « ce champ porte-t-il ce texte ? » et « quel jour ce message a-t-il
été écrit ? » —, et une fermeture n'en porte qu'une ; deux fermetures feraient
deux paramètres que chaque appelant devrait accorder. Ce n'est pas non plus une
fonction générique : elle serait recopiée pour chaque magasin, et chaque copie
porterait des chemins qu'aucun appelant n'emprunte (C2).

**UN JOUR HORS DU MOIS N'EST PAS UNE DATE** : `31 Feb` se lirait sinon comme le
3 mars. **Un message sans `Date:` lisible ne correspond à aucun critère
`SENT…`** : on ne compare pas ce qui n'est pas là, et tenir l'absence pour
l'époque le ferait répondre à tous les `SENTBEFORE`.

Le fuzz éprouve que ce qu'on lit se réécrit et se relit pareil : on repasse par
l'écriture, qui est l'inverse, plutôt que par une table de correspondance.

## Les options de rev2, depuis le 2026-08-30

**`STATUS` REND CE QUI EST DEMANDÉ** (§7.3.3), dans l'ordre demandé, et compte
`UNSEEN`, `DELETED` et `SIZE` en parcourant la boîte — mais SEULEMENT si on les
demande : les trois autres sont des propriétés que la boîte connaît sans
regarder ses messages, et un client qui surveille répète cette commande.
`RECENT` est refusé plutôt que rendu à zéro : rev2 l'a retiré avec le drapeau
qu'il comptait, et zéro ferait croire à une boîte sans arrivée.

**`LIST … RETURN (STATUS (…))`** est la seule forme de §6.3.9 qui emboîte des
parenthèses. La lecture compte donc les niveaux au lieu de chercher la première
fermante — qui refermerait le `STATUS` et laisserait la liste ouverte.

**`SEARCH RETURN (…)`** demande un parcours de plus : `MIN`, `MAX` et `COUNT`
s'écrivent AVANT la liste et ne peuvent pas s'écrire avant d'être connus. Ce
n'est pas cher — c'est le même parcours, sur une boîte déjà relevée.

**`$` SE RETIENT EN UID, JAMAIS EN RANGS.** §6.4.4.1 exige qu'un message effacé
sorte du résultat retenu, et — si l'on retenait des rangs — qu'on les décale à
chaque `EXPUNGE`. Un UID ne se décale pas : le message effacé cesse de
correspondre, et la règle est tenue par la NATURE de ce qu'on retient plutôt que
par un code qu'il faudrait penser à écrire. C'est le même choix que pour
l'`IDLE`, et pour la même raison.

Ce qui déborde est abandonné, pas tronqué : quatre cents UID espacés ne se
comprimant en aucune plage dépassent ce qu'une session retient, et le marqueur
ne désigne alors rien. Un ensemble tronqué désignerait d'autres messages que
ceux qu'on a trouvés.

**`* OK [CLOSED]` EST UNE FRONTIÈRE, PAS UNE POLITESSE** (§7.1) : tout ce qui la
précède parle de la boîte fermée, tout ce qui la suit parle de la nouvelle. Elle
paraît aussi quand la nouvelle sélection échoue — §6.3.2 ferme l'ancienne dans
ce cas-là aussi, et se taire laisserait le client croire qu'il la tient encore.

**UNE RÉPONSE CAUSÉE PAR UNE COMMANDE `UID` PORTE L'UID** (§6.4.9), la note de la
RFC nommant `UID FETCH` et `UID STORE`. Le commentaire qui justifiait l'absence
— « le client sait déjà de quel UID il parle » — était un raisonnement, pas une
lecture ; la RFC dit le contraire.

## `SUBSCRIBE` : les abonnements, depuis le 2026-08-30

**LE MÊME MOT NE DIT PAS LA MÊME CHOSE AUX DEUX PLACES.** `LIST (SUBSCRIBED)`
filtre ; `LIST … RETURN (SUBSCRIBED)` renseigne. La grammaire les sépare
(`ams-proto-imap/src/list.rs`), et la session ne les confond pas : le filtre
écarte, le renseignement marque.

**UNE OPTION QU'ON NE SERT PAS SE REFUSE.** `RECURSIVEMATCH`, `REMOTE`,
`RETURN (STATUS …)` : la lecture échoue plutôt que d'ignorer. Ignorer une option
de sélection rendrait une liste plus longue que ce qui a été demandé, et le client
la croirait filtrée — c'est-à-dire un mensonge silencieux, celui que ce projet
refuse partout ailleurs.

**ON VALIDE À L'ABONNEMENT, PAS APRÈS.** §6.3.7 laisse le choix de vérifier que
la boîte existe : on vérifie. Ce qui suit, en revanche, n'est pas un choix — la
même section INTERDIT de retirer de soi-même un abonnement dont la boîte a
disparu depuis. L'abonnement survit donc, et `LIST (SUBSCRIBED)` le rend marqué
`\NonExistent` (§6.3.9.6). C'est le seul endroit du serveur où l'on nomme une
boîte qui n'existe pas, et c'est le client qui l'a nommée avant nous.

**UN FICHIER DE TEXTE, ET C'EST COHÉRENT AVEC C11.** La configuration est binaire
parce qu'elle a un SCHÉMA — des champs, des types, une compatibilité à tenir. Une
liste d'abonnements n'en a pas : c'est une suite de noms, et un nom de boîte est
déjà de l'ASCII imprimable sans `LF`. Une ligne par nom ne peut pas être ambiguë.
Le fichier se réécrit à côté puis se renomme, pour qu'un `LIST` concurrent ne
lise jamais une liste à moitié écrite ; un verrou de processus ordonne les
écrivains de ce serveur, et le cache se relit sur la date du fichier — un `stat`
par question, aucune lecture tant que rien n'a changé.

**PLUSIEURS MOTIFS EN UNE FOIS**, ce que §9 admet, avec la règle qui va avec :
une boîte qui répond à deux motifs ne se rend qu'une fois. Et un motif VIDE
demande le séparateur de hiérarchie, pas une boîte.

## `IDLE` : l'attente, depuis le 2026-08-30

**C'est la seule commande où le serveur parle sans qu'on lui demande**, et c'est
ce qui la rend particulière à tenir : `+ idling` ouvre l'attente, et la conclusion
étiquetée ne vient qu'après le `DONE`. Le pilote attend alors deux choses à la
fois — la ligne du client et le changement de la boîte — par un `tokio::select!`
dont la lecture est annulable sans perte.

**SEULE LA CROISSANCE SE DIT.** Un `* n EXPUNGE` renumérote (§7.5.1) tous les
rangs qui suivent, et un client qui idle les a retenus. §6.3.13 n'oblige à rien
envoyer : se taire est correct, mentir sur les rangs ne l'est pas. La règle est
tenue par le magasin, pas par une convention : il n'ajoute qu'à la fin, et
seulement si le nouveau relevé COMMENCE par l'ancien, UID pour UID.

**DEUX `stat` PLUTÔT QU'UN PARCOURS.** La question se pose toutes les cinq
secondes, pour chaque session ouverte. Les dates de `new/` et `cur/` y répondent
sans lire le répertoire, et c'est la réponse dans l'immense majorité des cas.
`inotify` réveillerait plus vite, au prix d'une dépendance et d'un descripteur de
surveillance par session.

**ON RACCROCHE EN LE DISANT** : au bout de trente minutes (RFC 2177),
`* BYE Idle timeout`. Abandonner sans un mot laisserait le client croire qu'il
idle encore.

Éprouvé jusqu'au binaire : un message déposé dans `new/` pendant l'attente
ressort en `* 2 EXISTS`, et ne se redit pas au regard suivant.

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

## Trois petites choses que la RFC exige, depuis le 2026-08-30

**`\HasChildren` ET `\HasNoChildren`** : §7.3.1 veut que TOUT `LIST` porte l'un
des deux. Sans eux, un client qui affiche une arborescence doit interroger chaque
boîte pour savoir s'il faut dessiner un triangle d'ouverture — une commande par
boîte, là où une seule suffit. Le magasin les calcule dans la liste qu'il tient
déjà : rouvrir le système de fichiers pour la même question coûterait un parcours
de répertoire PAR BOÎTE listée.

Et le `LIST` que rend `SELECT` les porte aussi. **En omettre un ferait dire au
serveur deux choses différentes de la même boîte**, selon la question qu'on lui
pose — exactement le genre d'incohérence qu'un client n'a aucun moyen de
détecter.

**`NAMESPACE`** (§6.3.10) dit où les boîtes vivent. Un seul espace ici, et les
deux autres valent `NIL` : `NIL` n'est pas « je ne sais pas », c'est « il n'y en a
pas ». Un client qui lirait une liste vide chercherait encore.

**`ENABLE` N'ACTIVE RIEN, ET LE DIT.** Aucune extension de ce serveur ne se
négocie : tout ce qu'il sait faire, il le fait. La réponse liste ce qui a été
activé — rien —, ce que la grammaire admet (`enable-data = "ENABLED"
*(SP capability)`). Se taire laisserait le client se demander si la commande a été
comprise. **L'ÉTAT COMPTE** : §6.3.1 la réserve à l'état authentifié, AVANT toute
sélection, parce qu'une extension activée en cours de session changerait ce que
des réponses déjà en vol signifient.

## `BINARY` : ce que les octets veulent dire, depuis le 2026-08-30

`BODY[1]` rend les octets du message ; `BINARY[1]` rend ce qu'ils VEULENT DIRE,
transfert-décodé. `BINARY.SIZE[1]` en donne la taille décodée — celle du fichier
ne s'en déduit pas, puisque le pliage, les blancs et les coupures molles ne
rendent aucun octet, et c'est pourquoi le trait porte deux méthodes : un littéral
s'annonce avant ses octets.

**C'EST LA SEULE COMMANDE D'IMAP QUI ÉCHOUE POUR CE QU'UN MESSAGE PORTE.** Un
encodage qu'on ne sait pas défaire vaut `NO [UNKNOWN-CTE]` (§6.4.5) : rendre les
octets encodés en les faisant passer pour le contenu tromperait le client sans
qu'il puisse s'en apercevoir. Les données déjà émises restent sur le fil — le
`NO` lui dit de ne pas s'y fier.

**UN LITTÉRAL8, ET NON UN LITTÉRAL** : `~{n}` plutôt que `{n}`. `BINARY` rend des
octets quelconques, `NUL` compris, ce qu'un littéral ordinaire n'a pas le droit
de porter (§4.3). Le tilde le dit au client avant qu'il lise.

**UNE PIÈCE JOINTE DÉCODÉE NE TIENT PAS EN MÉMOIRE**, et redécoder depuis le
début à chaque morceau serait quadratique. `decode_chunk` s'arrête donc là où IL
N'Y A RIEN À RETENIR — un groupe complet de base64, un octet qui n'ouvre pas
d'échappement — et dit combien d'octets BRUTS il a lus. La session porte ce rang
d'un morceau à l'autre, comme elle porte le décalage d'un corps. Reprendre au
milieu d'un groupe demanderait de retenir les bits en cours, donc un état que
l'appelant finirait par perdre.

**LA DEMANDE PARTIELLE PORTE SUR LE CONTENU DÉCODÉ.** `BINARY[1]<100.50>` ne se
sert pas par un déplacement dans le fichier : le rang décodé et le rang brut ne
sont pas proportionnels. Il faut DÉCODER CE QU'ON JETTE, et l'étape d'écoulement
porte donc deux compteurs — où reprendre, et ce qu'il reste à jeter.

**LE DERNIER GROUPE DE BASE64 EST PARTIEL**, et le manquer coûte la fin de chaque
pièce jointe : `YQ==` porte deux caractères pour un octet, `YWI=` trois pour
deux. Seul l'appelant sait où le contenu s'arrête — le décodeur le lui demande
donc, plutôt que de le deviner. Le défaut a été trouvé par l'épreuve de reprise,
qui rendait « la facture de mars et d'avr » au lieu de « d'avril ».

Deux gardes qu'aucune entrée ne pouvait faire céder ont disparu au passage : les
écritures du décodeur passent par `zip` — la place a été vérifiée juste avant —,
et l'écoulement BOUCLE au lieu de se rappeler, ce qui faisait dépendre la pile de
ce qu'un message porte.

Éprouvé jusqu'au binaire : une pièce jointe de deux mille quarante-huit octets
portant tous les octets possibles, `NUL` compris, rendue IDENTIQUE à travers
plusieurs fenêtres de décodage ; un corps en quoted-printable dont la coupure
molle a disparu ; une demande partielle sur le décodé ; un `x-uuencode` qui vaut
`NIL` et conclut par `NO [UNKNOWN-CTE]` ; et une section absente dont la taille
vaut zéro, faute de pouvoir valoir `NIL`.

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

### Ses deux appelants

Le client est écrit, couvert à 100 %, fuzzé et **éprouvé contre notre propre
serveur** — deux moitiés qui ne partagent aucun code, mises face à face. Son
premier appelant est arrivé le même jour : la remise des rapports DMARC.

**Le second est la file de réémission, le 2026-09-01** (voir C6). `send` lui-même
n'attend ni ne réessaie — il remet, ou il dit pourquoi il n'a pas pu —, et c'est
ce qui le garde éprouvable : la décision de recommencer vit ailleurs, dans
`ams-queue`, où elle est couverte à 100 %.

Les deux décisions qui manquaient — l'avis de non-remise et la politique de
reprise — ont été prises : un DSN de RFC 3464 remis LOCALEMENT, et une attente
qui double jusqu'à un plafond avec un abandon à cinq jours.

**Les deux portes de soumission y mènent** : SMTP authentifié et
`/v1/submissions`. La soumission par l'API remettait LOCALEMENT et refusait tout
destinataire d'ailleurs ; elle accepte désormais les mêmes que SMTP, et pas
d'autres. N'ouvrir qu'une des deux ferait deux règles pour un même geste, et
l'utilisateur découvrirait laquelle relaie en essayant.

### DANE (RFC 7672), depuis le 2026-09-01

Le chiffrement sortant n'authentifiait personne, et le registre disait pourquoi :
le `MX` vient d'un DNS non validé, et vérifier un certificat contre un nom qu'un
attaquant vient de choisir ne prouve rien. **DANE reprend la chaîne là où elle
s'arrêtait** : le domaine publie lui-même, dans son DNS signé, l'empreinte du
certificat qu'il présentera. Il n'y a plus de tiers à croire.

**LA CHAÎNE S'ARRÊTE AU RÉSOLVEUR, ET C'EST DIT.** Ce serveur ne valide aucune
signature DNSSEC : il pose le bit `AD` DANS LA QUESTION (§5.7 de RFC 6840) et
croit celui de la réponse. §2.1 de RFC 7672 l'autorise expressément pour un
résolveur valideur joint par un chemin sûr — et c'est **exactement l'hypothèse
que ce projet fait déjà pour SPF**, ni plus ni moins. Un résolveur qui ne valide
pas ne pose jamais ce bit, et DANE ne s'applique alors à personne ; le serveur
l'annonce au démarrage plutôt que de le laisser découvrir.

`DO` reste absent, et la distinction vaut d'être lue : `DO` demanderait les
SIGNATURES, qu'on ne saurait pas vérifier et qui grossissent chaque réponse ;
`AD` demande au résolveur de dire s'il a validé. On demande le verdict, pas de
quoi le refaire.

**DEUX USAGES SEULEMENT** (§3.1.3) : `DANE-TA(2)` et `DANE-EE(3)`. `PKIX-TA(0)`
et `PKIX-EE(1)` ne s'appliquent pas à SMTP — ils demanderaient une validation
WebPKI contre un nom qui vient du DNS, ce que DANE existe pour ne plus avoir à
faire. Ils sont traités comme INUTILISABLES, et non comme des refus.

Et les deux ne se vérifient pas pareil :

- **`DANE-EE(3)` : ni chaîne, ni nom, ni date** (§3.1.1, et §5.1 de RFC 7671). Le
  domaine a publié l'empreinte exacte de ce qu'il présente ; c'est plus fort que
  tout ce qu'une autorité pourrait attester. Un serveur qui sert dix domaines n'a
  pas à porter dix noms, et une horloge ne vaut pas mieux que le domaine.
- **`DANE-TA(2)` : la chaîne ET le nom.** L'autorité a pu signer pour d'autres.
  La chaîne se vérifie par `rustls`, avec l'autorité trouvée pour seule racine —
  **on n'écrit pas de validation X.509 ici**, un second vérificateur de chaîne
  dans ce dépôt finirait par diverger de celui qui sert partout ailleurs.

**UN JEU ENTIÈREMENT INUTILISABLE N'EST PAS UN ÉCHEC** (§2.2) : on fait comme
s'il n'y en avait aucun, et le courrier passe en opportuniste. C'est la bonne
façon d'échouer — un domaine qui publie un algorithme de demain ne doit pas voir
son courrier s'arrêter aujourd'hui. **Un jeu qui porte au moins un enregistrement
utilisable, lui, ENGAGE** : la remise est authentifiée, ou elle n'a pas lieu.

**L'ÉCHEC AJOURNE, ET RIEN NE L'AFFAIBLIT.** Pas de mode « observe », contrairement
à SPF et à DMARC. La différence n'est pas un oubli : ces deux-là décident du
courrier de QUELQU'UN D'AUTRE, et un faux positif y refuse un message légitime
qu'on ne reverra pas. DANE décide de NOTRE émission, le message reste dans notre
file, et il repartira quand le domaine aura réparé. Rien n'est perdu, donc rien
n'excuse d'affaiblir.

**LES DEUX RÉPONSES DOIVENT ÊTRE AUTHENTIQUES**, celle du `MX` comme celle du
`TLSA` (§2.2). Un `MX` qu'un tiers a pu réécrire désignerait un serveur qu'il a
choisi, dont le `TLSA` serait le sien. Et **l'absence de `MX` n'active pas DANE** :
§2.2 demande que cette absence soit elle-même prouvée, ce que ce résolveur ne rend
pas — le bit `AD` d'une réponse vide ne dit pas de quoi il parle. On retombe alors
sur l'opportuniste, plutôt que de prétendre ce qu'on n'a pas.

**LA PROTECTION SE COMPTE.** `RelayOutcome::Delivered` porte `authenticated`, et
l'arrêt du serveur dit combien de remises ont été authentifiées. Chiffré sans
authentifié écarte l'espion passif ; authentifié écarte l'attaquant actif. Une
protection qu'on ne voit pas est une protection qu'on croit avoir.

**MTA-STS (RFC 8461) reste à faire.** Il demande un client HTTPS sortant, un
magasin de racines WebPKI et un cache de politiques sur disque — trois surfaces
neuves —, et §2 de RFC 8461 dit que DANE l'emporte quand les deux existent. C'est
pourquoi DANE est venu d'abord.

### DNSSEC n'est pas validé, et c'est écrit partout

Le résolveur est cru sur parole. Un `pass` ne vaut donc que ce que vaut le chemin
jusqu'à lui, et c'est pourquoi le résolveur doit être **local, ou joint par un
lien de confiance**. Trois endroits le disent plutôt qu'un : le schéma de
configuration, l'aide d'`air-mail-admin`, et une ligne au démarrage du serveur.
Une lacune qu'on nomme est une lacune ; une lacune qu'on tait est un mensonge.

**DANE repose sur cette même hypothèse, et pas sur une plus forte** (voir
plus haut). Le bit `AD` dit ce que le résolveur A VALIDÉ ; le croire, c'est croire
le chemin jusqu'à lui, exactement comme pour SPF. La différence est que DANE
DÉCIDE — il refuse une remise —, et c'est pourquoi le serveur annonce la
condition au démarrage au lieu de la laisser dans un registre.

**Valider DNSSEC nous-mêmes reste à faire**, et ce serait la seule façon de ne
plus rien emprunter : RRSIG, DNSKEY, DS, une ancre de confiance, NSEC et NSEC3
pour la négation. C'est une crate entière soumise au 100 % de C2, et elle
remplacerait cette confiance sans rien changer d'autre — `Message::authentic_data`
est le seul point par lequel elle entre.

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
boîtes-là. Le doublon est moins grave que la perte.

**La file de réémission ne change rien à cela, et ce n'est pas un oubli** : elle
sert à ce qui SORT. Un `4yz` rendu au pair laisse la responsabilité du message
chez lui, où elle est bien — c'est LUI qui a l'expéditeur au bout du fil. Prendre
en charge un message pour ne le remettre qu'en partie ferait porter à ce serveur
un échec que le pair sait mieux traiter.

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

**HTTP est servi, en h2 et en h3** : `ams-proto-http` porte la sémantique de
RFC 9110, `ams-proto-h2` et `ams-proto-h3` le cadrage, et les deux ports
s'ouvrent — sur TLS, et seulement sur TLS. L'API REST y sert le courrier, les
jetons, la supervision, la soumission, et l'administration en lecture. HTTP/3
traverse une pile QUIC écrite ici, et l'extinction se dit en deux temps.

**Cette phrase disait « en cours, et aucun port HTTP n'est ouvert » longtemps
après que ce fut faux.** C'est le défaut que ce registre existe pour empêcher, et
il l'a commis sur lui-même : une section qui s'intitule « l'état réel » est celle
qu'on relit le moins, parce qu'on croit la connaître.

Sont outillées : C1 (les trois étages, et la couverture qui n'est exigible que
parce qu'ils sont séparés), C2 (le gate mesure 50 599 régions sur 28 crates,
toutes couvertes — et il compare des comptes, non un pourcentage arrondi), C3
(les lints, l'absence d'allocation dans les décodeurs, et 59 cibles de fuzz dont
la CI vérifie qu'elle les lance toutes), C4 (`ams-tls` n'offre que
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

Ce qui manque, et qu'aucune phrase ne doit laisser croire acquis : **la file de
réémission des messages sortants**. Un message qu'on ne peut pas remettre tout de
suite est perdu, et non retenu pour plus tard.

L'interface HTTP, elle, N'EST PLUS DE CETTE LISTE : l'API REST se sert en HTTP/2
et en HTTP/3, avec ses jetons, sa soumission et son administration en lecture.
Ces deux phrases-ci disaient le contraire longtemps après que ce fut faux — et
c'est exactement ce que ce registre existe pour empêcher.

**Toutes les commandes de RFC 9051 répondent** — plus aucune ne reçoit un
`NO [UNAVAILABLE]`, et la méthode qui l'écrivait a disparu du code —, et les
options que §E dit absorbées dans le protocole de base le sont aussi :
NAMESPACE, UNSELECT, UIDPLUS, ESEARCH, SEARCHRES, ENABLE, IDLE, SASL-IR,
LIST-EXTENDED, LIST-STATUS, MOVE, LITERAL-, le côté FETCH de BINARY.

**Les MOTS-CLEFS y sont aussi**, ceux de §E.15 : `$MDNSent`, `$Forwarded`,
`$Junk`, `$NonJunk` et `$Phishing`, avec les critères `KEYWORD` et `UNKEYWORD`.
L'ensemble est FERMÉ, et `PERMANENTFLAGS` n'annonce donc pas `\*` : ce serait
promettre qu'on accepte tout mot-clef nouveau.

**LA MANIÈRE DONT ON S'EN EST APERÇU MÉRITE D'ÊTRE NOTÉE.** Deux fois de suite,
une énumération complète d'une chose a servi à conclure la complétude d'une
autre : les COMMANDES étaient toutes servies, donc le protocole l'était ; puis
les OPTIONS de §E l'étaient aussi, donc le protocole l'était. Il ne l'était
toujours pas. **Une liste complète d'une chose ne prouve rien d'une autre**, et
la seule vérification qui vaille est la confrontation à l'ABNF de §9, mot par
mot — pas à sa propre liste.

Ce qui reste hors du serveur : la file de réémission des messages sortants.

## HTTP : h2 et h3, et pas HTTP/1.1

Décidé le 2026-08-30, et c'est une décision au sens de C6.

**LE CADRAGE D'HTTP/1.1 EST TEXTUEL, ET SA LONGUEUR SE DÉDUIT DE DEUX CHAMPS QUI
PEUVENT SE CONTREDIRE** — `Content-Length` et `Transfer-Encoding`. Toute la
famille des attaques par contrebande de requête vit dans cette contradiction, et
dans les désaccords d'analyse entre deux implémentations qui se relaient : l'une
lit une requête là où l'autre en lit deux, et la seconde n'a été envoyée par
personne.

HTTP/2 (RFC 9113) et HTTP/3 (RFC 9114) n'ont pas ce défaut. La longueur d'un
cadre est un nombre, écrit une fois ; `Transfer-Encoding` y est **interdit**
(§8.2.2) ; les noms de champs sont en minuscules, sans quoi la requête est mal
formée ; et un `CR` ou un `LF` dans une valeur la rend mal formée aussi. C'est le
même raisonnement, mot pour mot, que celui qui a fermé la contrebande SMTP dans
ce dépôt : **un octet de structure ne se transporte pas dans de la donnée**.

**LA CONSÉQUENCE EST RÉELLE ET SE DIT** : un client qui ne parle que HTTP/1.1 ne
pourra pas joindre ce serveur. La négociation passe par ALPN, donc explicitement,
et un client qui n'offre ni `h2` ni `h3` est refusé avant la première requête
plutôt qu'après. Certaines bibliothèques répandues — `requests` en Python, par
exemple — ne parlent aujourd'hui que HTTP/1.1 ; le choix des clients de l'API
REST devra en tenir compte, et c'est une question à trancher au moment de
définir cette API, pas avant.

### La sémantique ne s'écrit qu'une fois

`ams-proto-http` ne cadre RIEN, et c'est tout son objet. h2 et h3 ne partagent
aucun octet de cadrage, et leurs compressions d'en-têtes elles-mêmes diffèrent —
HPACK d'un côté, QPACK de l'autre. Ce qu'ils partagent, c'est le SENS : une
méthode, une cible, des champs, un code d'état, et les règles qui disent quelle
liste de champs est recevable. **Les écrire deux fois, c'est se donner deux
occasions de les écrire différemment** — et une différence entre les deux
versions du même serveur est exactement ce qu'un attaquant cherche.

### Ce que la grammaire refuse, et pourquoi chacun

- **`CONNECT`** demande un tunnel : c'est la méthode d'un mandataire, et ce
  serveur n'en est pas un. Sa forme est d'ailleurs à part — ni `:scheme` ni
  `:path` —, si bien que l'accepter ouvrirait un second jeu de règles pour une
  fonction qu'on ne rend pas. Le `CONNECT` étendu de RFC 8441, qui porte
  WebSocket, tombe par la même porte.
- **`TRACE`** renvoie la requête telle que reçue, en-têtes compris : c'est un
  miroir à jetons et à cookies.
- **Un nom de champ en majuscules** est mal formé, PAS corrigé. Le normaliser
  laisserait passer deux écritures du même nom là où un intermédiaire n'en
  accepte qu'une.
- **Une espace au bord d'une valeur** : c'est ainsi que s'écrivait le repliement
  d'en-tête d'HTTP/1.1, qu'un intermédiaire reconstituerait.
- **Un pseudo-en-tête après un champ ordinaire**, un pseudo-en-tête répété, un
  pseudo-en-tête inventé. Un intermédiaire qui ignorerait un nom inconnu et un
  serveur qui l'honorerait ne verraient pas la même requête.
- **`:authority` et `host` qui se contredisent** : deux autorités, c'est deux
  serveurs d'origine possibles — la contrebande, déplacée dans le nom d'hôte.
- **Deux `content-length` qui se contredisent** ; deux qui s'accordent sont
  licites, et le restent.

### Le cadrage : on ignore l'inconnu, on refuse le faux

`ams-proto-h2` porte les neuf octets de §4 et les réglages de §6.5.2. La règle
qui gouverne tout le module tient en une phrase, et elle se paie quand on
l'oublie dans un sens comme dans l'autre :

**Un cadre d'un type inconnu s'IGNORE** (§4.1), et un réglage d'un identifiant
inconnu aussi (§6.5.2). C'est ce qui permet aux extensions d'exister sans casser
les serveurs déployés — un serveur qui refuserait ce qu'il ne connaît pas serait
le maillon par lequel toute évolution devient impossible.

**Mais un `SETTINGS_MAX_FRAME_SIZE` à quarante-deux se REFUSE.** On sait ce qu'il
veut dire, et ce qu'il dit est hors de la plage que la RFC définit. Ignorer le
faux ferait tourner une connexion sur un réglage qu'on n'a pas retenu.

La borne de longueur, elle, s'applique à TOUS les types, inconnus compris : ce
qu'on ignore, il faut quand même le sauter, donc le retenir ou le lire. C'est la
seule borne qui protège la mémoire.

**LE BIT RÉSERVÉ EST IGNORÉ À LA LECTURE ET ÉCRIT À ZÉRO** (§4.1). Le refuser
casserait une extension future qui s'en servirait.

**LE REMPLISSAGE NON NUL EST REFUSÉ**, et c'est un choix : §6.1 dit qu'un
récepteur « MAY » le traiter comme une faute. Des octets qu'un pair choisit et
qu'on ne regarde pas sont un canal caché, et C7 tranche en faveur de la sécurité.

`PRIORITY` se lit et ne fait rien : §5.3.2 l'a déprécié. Le refuser casserait des
clients qui l'envoient toujours ; l'honorer demanderait de construire l'arbre de
priorités que la RFC a retiré, et dont la complexité a produit sa part de failles.
`PUSH_PROMISE` est refusé — §8.4 l'a déprécié, un client n'a jamais eu le droit
d'en envoyer, et ce serveur annonce `SETTINGS_ENABLE_PUSH` à zéro.

### HPACK : la table vient de la RFC, pas de la mémoire

Deux cent cinquante-sept codes de Huffman recopiés à la main, c'est deux cent
cinquante-sept occasions de se tromper d'un bit — et une erreur y est invisible :
elle décode un caractère pour un autre, sur une entrée précise, chez un client
précis. Les tables ont donc été **extraites du texte de la RFC**, et deux
propriétés vérifiées avant d'être écrites : le code est PRÉFIXE, et il est
CANONIQUE.

La seconde permet de décoder sans table de correspondance géante : par longueur
croissante, on compare le code accumulé au premier code de cette longueur. Une
table plate de 2^30 entrées serait plus rapide ; elle serait aussi impossible à
couvrir et à relire. C7 tranche.

**AUCUNE GARDE DE LONGUEUR DANS LE DÉCODEUR**, et c'est démontré plutôt que
supposé : la table est COMPLÈTE à trente bits — aucun nœud interne n'y subsiste —,
donc tout chemin de trente bits aboutit à un symbole. Un test le prouve. Écrire
un `if bits >= 30 { refuser }` aurait été une garde qu'aucune entrée ne peut
emprunter. Et si la table changeait, le contrôle de remplissage refuserait quand
même : le filet est là, il est simplement ailleurs.

**LE REMPLISSAGE EST FAIT DES BITS DE TÊTE DU CODE D'`EOS`**, et le code le dit
ainsi plutôt que « des uns ». Les deux formulations donnent le même octet ; seule
la seconde dit pourquoi.

### Un défaut écrit, puis trouvé par son propre test

Le décodeur d'entier HPACK accumulait les octets de continuation avec
`checked_shl`. **`checked_shl` ne rend `None` que si le DÉCALAGE dépasse la
largeur du type** : `127u32.checked_shl(28)` rend `Some`, et jette silencieusement
les bits qui débordent. La suite `ff ff ff ff ff 7f` se lisait donc comme la
valeur 255.

Un multiplicateur, lui, déborde AVANT — et c'est ce débordement-là qui refuse
l'entier. Il rend du même coup inutile la borne sur le NOMBRE d'octets de
continuation, qu'il atteint toujours le premier : une garde de moins, et c'est
la mesure de couverture qui l'a montrée inatteignable.

La leçon générale se range à côté de celle du `saturating_sub` de 2026-08-28 :
**les fonctions `checked_*` ne vérifient que ce que leur nom dit**, et `shl`
vérifie le décalage, pas la valeur.

### Les tables HPACK, et ce que le décompresseur ne fait PAS

La table statique est extraite de la RFC comme celle de Huffman : soixante et
une entrées dont l'index est un NOMBRE QUE LE PAIR ENVOIE. Se tromper d'une
ligne, c'est décoder `:method` là où le client a écrit `:path`, et router une
requête vers autre chose que ce qu'elle demandait.

**LA TABLE DYNAMIQUE EST L'ÉTAT PARTAGÉ D'UNE CONNEXION**, et trois conséquences
en découlent, chacune écrite dans le code :

1. **Une désynchronisation ne se rattrape pas.** Si l'encodeur et le décodeur
   cessent d'être d'accord sur le contenu de la table, tous les en-têtes suivants
   se lisent de travers, et rien ne le signale. C'est pourquoi une faute HPACK
   tue la connexion, jamais un seul flux.
2. **Insérer DÉCALE les index.** Un décodeur qui insère là où l'encodeur n'a pas
   inséré lira tout le reste avec un cran d'écart.
3. **La taille est bornée par CE QU'ON A ANNONCÉ**, pas par ce que le pair
   demande. `SETTINGS_HEADER_TABLE_SIZE` est notre chiffre ; une mise à jour qui
   le dépasse est une faute, et non une requête à honorer.

Une entrée plus grosse que la table la VIDE et n'entre pas (§4.4) : ce n'est pas
une faute, et un décodeur qui refuserait se désynchroniserait d'un encodeur qui,
lui, a vidé. Une mise à jour de taille doit venir AU DÉBUT d'un bloc (§4.2) ; la
tolérer ailleurs laisserait un encodeur changer la taille au milieu.

L'arène des octets est LINÉAIRE, et se recompacte quand la place manque en
queue : un anneau couperait un nom en deux au bord, et un nom coupé ne se compare
pas. La compaction est rare, et C7 préfère son coût à une lecture en deux
morceaux qu'il faudrait traiter partout.

**« JAMAIS INDEXÉ » N'EST PAS « SANS INDEXATION »** (§7.1.3). Le premier dit
qu'un intermédiaire ne doit JAMAIS mettre le champ dans sa table, même en
ré-encodant — c'est ce qu'un client pose sur un jeton d'autorisation, pour qu'il
ne finisse pas dans un état partagé où une attaque par compression pourrait le
deviner. Le second dit seulement « moi je ne l'indexe pas ». Les deux
représentations partagent leurs trois premiers bits, et **l'ordre de
reconnaissance est donc une règle** : tester le plus court motif d'abord
trahirait une promesse qu'on n'a pas faite mais qu'on relaie.

**LE DÉCOMPRESSEUR NE JUGE PAS LES CHAMPS.** Il rend des paires ; ce qui décide
qu'une LISTE est recevable vit dans `ams-proto-http`, et n'est écrit qu'une fois
pour h2 et h3. Cette frontière a été confirmée par le fuzz : une propriété
écrite à l'envers — « un nom décodé est un nom » — a été démentie en trois
secondes par un nom d'un seul octet nul. Le fuzz avait raison ; la propriété
éprouve maintenant la JOINTURE des deux étages, ce qui est la chose utile.

### Une fenêtre de contrôle de flux peut être NÉGATIVE

C'est le piège de ce module, et il n'est pas rare de le manquer. §6.9.2 : quand
`SETTINGS_INITIAL_WINDOW_SIZE` change, toutes les fenêtres de flux OUVERTS sont
ajustées de la différence. Si le pair réduit la fenêtre initiale alors qu'il a
déjà envoyé des données, l'ajustement rend la fenêtre négative — et la RFC le dit
en toutes lettres.

**Une fenêtre stockée dans un `u32` ne peut pas être négative.** Elle passerait
par zéro en soustrayant, ou déborderait par le haut ; dans les deux cas le pair
pourrait envoyer des données qu'on aurait dû refuser. La fenêtre est donc signée,
et sur soixante-quatre bits pour que l'arithmétique intermédiaire ne déborde
jamais.

Deux fenêtres, et il faut les deux : chaque `DATA` consomme celle de son FLUX
**et** celle de la CONNEXION (§5.2.1). N'en vérifier qu'une laisse un pair ouvrir
cent flux et envoyer cent fois la fenêtre — c'est la mémoire du serveur qu'il
choisit.

On refuse AVANT de consommer, jamais après : un récepteur qui soustrairait
d'abord aurait déjà accepté les octets, et sa fenêtre dirait le contraire de ce
qu'il a fait.

### Les flux : deux mots d'état pour deux milliards de numéros

§5.1.1 : un client ouvre des flux IMPAIRS, et chaque numéro doit être
STRICTEMENT supérieur à tous les précédents. Ce n'est pas de l'hygiène — un
numéro réemployé désignerait deux requêtes au même moment, et la réponse de l'une
pourrait partir vers l'autre.

La même section dit qu'ouvrir un flux **ferme implicitement** tous les flux
oisifs de numéro inférieur, et c'est ce qui permet de ne RIEN retenir des flux
fermés : au-delà du plus grand numéro reçu, un flux est oisif ; en deçà et hors
de la table, il est fermé. Deux mots d'état suffisent là où il faudrait sinon
retenir tout ce qu'un pair a ouvert — c'est-à-dire ce qu'il choisit.

**Les états « réservés » de §5.1 n'existent pas ici** : ils ne servent qu'à la
poussée serveur, que §8.4 a dépréciée et que ce serveur n'émet pas. Les porter
serait écrire deux états qu'aucune transition ne peut atteindre.

`REFUSED_STREAM` est une PROMESSE (§8.7) : un client peut réémettre sans risque
ce qui l'a reçu. Le rendre pour un flux qu'on a commencé à traiter ferait
exécuter deux fois ce qui ne devait l'être qu'une — c'est pourquoi il est rendu
au refus d'ouverture, et là seulement.

Un `RST_STREAM` sur un flux déjà fermé n'est PAS une faute : il a pu croiser
notre réponse sur le fil.

### Deux défauts trouvés par le fuzz, dans la même méthode

`Streams::set_initial_window` en portait deux, et le fuzz les a trouvés en
quelques secondes :

1. **Elle acceptait une taille au-delà de 2^31-1**, que §6.5.2 refuse. La lecture
   des `SETTINGS` l'appliquait déjà — mais cette méthode est PUBLIQUE, et un
   appelant qui l'oublierait fabriquait des fenêtres de quatre gibioctets. C'est
   le même raisonnement que « le magasin ne doit pas se fier à la session » :
   une vérification faite ailleurs est une vérification qu'on ne voit pas en
   lisant l'endroit qui en dépend.
2. **Elle appliquait à moitié.** Elle ajustait les fenêtres au fil d'une boucle
   et s'arrêtait à la première qui débordait, laissant la moitié déplacées et
   l'autre non — un état que ni nous ni le pair ne saurions décrire, et qui
   ferait diverger les deux comptes pour de bon. Elle vérifie maintenant TOUT
   avant d'appliquer QUOI QUE CE SOIT.

`Window::new` borne désormais elle aussi : **une structure qui garantit son
invariant vaut mieux qu'une qui le suppose**.

### Le flot de `CONTINUATION` : une borne que la RFC ne donne pas

Un bloc d'en-têtes peut s'étaler sur autant de cadres qu'on veut. Un `HEADERS`
sans `END_HEADERS`, puis des `CONTINUATION` — **et rien dans la RFC ne borne leur
nombre.** Un pair envoie donc un `HEADERS` puis des `CONTINUATION` sans fin,
chacun d'un octet, et un serveur qui accumule sans compter s'arrête quand sa
mémoire s'arrête.

C'est la faille dite « CONTINUATION flood », qui a touché la plupart des
implémentations en 2024. Ce n'est pas une erreur de code : c'est une borne que la
RFC ne donne pas et que chacun devait poser.

**ON EN POSE DEUX**, parce qu'aucune ne suffit seule : mille cadres d'un octet
passent sous une borne de taille, et un seul cadre de seize mébioctets passe sous
une borne de nombre.

§4.3 exige par ailleurs que les cadres d'un bloc se suivent **sans aucun autre
cadre entre eux, sur aucun flux**. Ce n'est pas une commodité : la table HPACK
est mise à jour dans l'ordre du bloc, et laisser un cadre s'intercaler rendrait
cet ordre dépendant de l'entrelacement — donc non reproductible.

### L'encodeur n'indexe JAMAIS, et c'est une décision

HPACK permet d'insérer dans une table dynamique pour que le champ suivant coûte
un octet. §7.1 de RFC 7541 décrit ce que cela ouvre : quand un attaquant peut
faire émettre par le serveur des en-têtes de son choix À CÔTÉ d'un secret, la
TAILLE du bloc comprimé lui dit si sa devinette coïncide. C'est CRIME et BREACH,
transposées à HPACK. La RFC recommande de ne pas indexer les champs sensibles —
ce qui suppose de savoir lesquels le sont.

**On renverse la question** : rien n'est indexé, donc rien ne fuit, et il n'y a
pas de liste de champs sensibles à tenir à jour. Le coût est quelques dizaines
d'octets par réponse ; C7 dit que la sécurité prime, et il n'y a même pas
d'arbitrage difficile ici. La table STATIQUE, elle, sert : elle est publique,
identique pour tous, et ne porte aucun secret — `:status 200` s'écrit en un
octet.

Corollaire : notre table dynamique d'émission reste vide, il n'y a rien à
évincer, et **un encodeur sans état ne peut pas se désynchroniser**.

### Un troisième défaut trouvé par le fuzz

Le décodeur HPACK coupait le tampon de l'appelant en DEUX PARTS ÉGALES, une pour
le nom et une pour la valeur. Un nom long avec une valeur vide échouait donc sur
un tampon pourtant suffisant, et l'appelant devait fournir deux fois le plus long
des deux au lieu de leur somme. Le nom et la valeur s'écrivent maintenant l'un
après l'autre dans le même tampon, et la coupure se fait à la longueur du nom.

Ce n'était pas une faille — c'était une interface qui mentait sur ce qu'elle
demandait, et le fuzz l'a trouvée en quelques secondes parce que la propriété
« ce qu'on écrit se relit » ne tenait pas.

### La bombe de décompression a sa propre borne

HPACK et QPACK compriment : mille champs identiques tiennent en quelques octets
sur le fil et en plusieurs mébioctets une fois décomprimés. **Aucune borne PAR
CHAMP ne l'arrête** — seule celle du TOTAL le fait. Elle se compte comme §6.5.2
de RFC 9113 : nom, valeur, plus trente-deux octets par champ. Ces trente-deux-là
ne sont pas sur le fil ; ils représentent ce qu'une entrée coûte à retenir, et
les omettre ferait passer pour gratuits dix mille champs vides.

Elle s'applique AVANT tout examen du champ : le coût d'un champ ne dépend pas de
sa validité, et une bombe faite de champs invalides passerait sinon entre les
gouttes.

`SETTINGS_MAX_HEADER_LIST_SIZE` d'HTTP/2 existe, et ne remplace pas cette
borne : c'est un RENSEIGNEMENT donné au pair, que rien n'oblige à respecter. Un
serveur qui n'aurait que ce réglage pour se protéger n'aurait rien du tout.

## La sonde qui fabriquait la panne qu'elle mesurait

`crates/ams-server/tests/chiffrement.rs` échouait environ une fois sur
vingt-cinq, toujours de la même façon : `Connection reset by peer`, **zéro octet
lu**, sur une connexion ouverte quelques microsecondes plus tôt. Le défaut a
tenu plusieurs semaines parce que le symptôme accusait le serveur, et qu'une
première tentative de correction — faire lire la bannière à la sonde — avait
remplacé un échec sur vingt-cinq par deux blocages sur vingt-cinq, et fut
annulée.

L'instrumentation a tranché. Au moment de l'échec, l'enfant était **vivant**, il
**écoutait** (`ss` le montrait en `LISTEN` sur son port), et il avait écrit ses
onze lignes de démarrage. Le serveur n'y était donc pour rien.

La panne venait de la fonction qui attendait le démarrage. Elle ouvrait une
connexion d'essai et la fermait aussitôt, sans rien lire :

1. le serveur accepte la sonde et lui écrit sa bannière ;
2. la sonde est déjà fermée : son noyau répond un `RST` ;
3. **un `RST` détruit la socket cliente sans passer par `TIME-WAIT`** — le port
   éphémère redevient libre sur-le-champ, au lieu des soixante secondes
   habituelles ;
4. le `connect` suivant peut reprendre ce port, donc le MÊME quadruplet, alors
   que le serveur n'a pas encore effacé l'ancienne connexion de sa table ;
5. le `SYN` tombe sur une connexion que le serveur croit établie, et la nouvelle
   connexion meurt sans qu'un octet ne l'ait traversée.

Sous charge — huit tests en parallèle sur quatre cœurs, plus `openssl` — la
fenêtre entre 4 et 5 s'élargit avec l'ordonnancement, et c'est là que le test
tombait. C'est aussi pourquoi il ne tombait JAMAIS lancé seul : quarante
exécutions isolées, aucune faute.

### Ce qu'on en retient

**Une sonde qui parle le protocole modifie ce qu'elle mesure.** Celle-ci
consommait une place de connexion, nourrissait le compteur du garde anti-flooding
(C8), et laissait derrière elle une connexion réinitialisée. Aucune de ces trois
choses n'était voulue, et la troisième cassait le test.

Le serveur ANNONCE son écoute sur son erreur standard, juste après le `bind` :
c'est cela qu'on attend maintenant, et l'attente ne touche plus au réseau. Rien
n'est perdu à ne plus sonder — entre le `bind` et le premier `accept`, le noyau
met les connexions en file, et un client n'y voit aucune différence.

### Et le journal se lit sans tuer

L'ancien code tuait le serveur pour lire son erreur standard, parce que
`read_to_string` sur le tuyau d'un enfant vivant n'atteint jamais la fin de
fichier. Rapporter l'état d'un serveur exigeait donc de le détruire d'abord —
et l'attente du démarrage, elle, ne pouvait rien lire du tout.

Un fil recopie maintenant ce tuyau dans un tampon partagé. Le journal est
lisible à tout instant sans jamais bloquer, le démarrage s'y adosse, l'échec
porte l'état RÉEL du serveur, et le tuyau ne se remplit plus au point d'arrêter
l'enfant qui écrit dedans.

## L'étage deux d'HTTP/2 : ce qu'une connexion ne peut pas devenir

Les cadres, les réglages, les flux et HPACK savaient chacun une chose. La
machine de connexion les noue : un cadre entre, l'état bouge, une réponse
s'écrit dans un tampon que l'appelant fournit, un événement remonte. Elle ne
lit ni n'écrit rien elle-même (C1).

### Le préambule est dans le type, pas dans une garde

Une connexion ne s'obtient qu'en lisant le préambule : `Handshake::open` rend
une `Connection`, ou rien. Il n'existe donc aucun état « connexion dont le
préambule n'est pas encore lu », et pas davantage la garde qui l'aurait vérifié
à chaque cadre.

C'est la même règle qu'ailleurs dans ce dépôt, et elle a encore servi ici :
**une garde inatteignable n'est pas une garde, c'est une affirmation non
vérifiée.** Le compte des régions couvertes la trouve à chaque fois, parce
qu'une branche qu'aucune entrée n'emprunte ne s'exécute jamais.

Quatre autres ont été retirées de la même façon en écrivant cet étage :

- `Settings::write` écrivait dans un tampon intermédiaire de la BONNE TAILLE,
  ce qui rendait son échec impossible — et il fallait quand même vérifier la
  place du tampon de sortie. Elle écrit maintenant directement dans celui-ci :
  une seule vérification, sur le seul tampon qui puisse manquer.
- `Streams::end_remote` rendait `STREAM_CLOSED` sur un flux qui avait déjà fini.
  Or tout `END_STREAM` est précédé de ce qui rend déjà cette faute — `consume`
  pour un `DATA`, `open` pour un `HEADERS`. Elle ne rend plus rien.
- La recharge de fenêtre AJOUTAIT un crédit qu'elle venait de calculer à partir
  de cette même fenêtre : le débordement était arithmétiquement impossible. Elle
  REMPLIT désormais, ce qui ne peut pas échouer. `Streams::credit` a disparu
  avec elle — personne ne crédite notre fenêtre de réception, c'est nous qui
  l'ouvrons.
- Les règles de taille et de flux de §4 étaient écrites deux fois : dans
  `FrameHeader::check`, et à nouveau dans chaque traitement de cadre. Deux
  vérités pour une règle. La machine appelle `check` en tête, et ne les redit
  plus.

### Deux inondations qu'aucune fenêtre n'arrête

Le contrôle de flux borne les DONNÉES. Il ne borne rien d'autre, et deux
familles de cadres passent donc à côté.

**Les cadres de service** — `PING`, `SETTINGS`, `PRIORITY`, `WINDOW_UPDATE`, les
types inconnus — coûtent un traitement, parfois une réponse, et ne font
progresser aucun flux. Un compteur les compte, et un `DATA` ou un bloc
d'en-têtes complet le remet à zéro : une connexion qui travaille ne l'approche
jamais.

**Les flux annulés** sont l'autre inondation, et **ce n'est pas la même borne**.
`HEADERS` puis `RST_STREAM`, aussitôt, sans relâche : le compteur de flux
simultanés ne les voit jamais, puisqu'ils sont fermés avant d'être comptés, et
le serveur travaille pour rien. C'est *Rapid Reset* (CVE-2023-44487), qui a mis
à genoux la moitié du web en octobre 2023.

Les compter avec les cadres de service ne servirait à RIEN : chaque `HEADERS`
est un progrès, et remettrait à zéro le compteur que le `RST_STREAM` suivant
vient d'incrémenter. Il faut donc un second compte, et **ce n'est pas un
compteur mais un budget** : chaque annulation en dépense un, chaque réponse
menée à son terme en rend un. Un client qui annule ce qu'il n'attend plus reste
sous la borne aussi longtemps qu'il consomme aussi ce qu'il demande ; un client
qui n'annule que pour faire travailler la remplit sans jamais la vider.

C'est aussi la couture avec l'étage qui émettra : `Connection::response_sent`
n'a pas d'autre raison d'exister.

### Un flux refusé se décode quand même

La table dynamique HPACK est **commune à toute la connexion**, et se met à jour
dans l'ordre des blocs. Sauter le décodage d'un bloc parce que son flux est
refusé décalerait la table pour tous les blocs suivants : le pair et nous ne
lirions plus les mêmes en-têtes, sans qu'un seul cadre soit fautif.

Un flux refusé — trop de flux de front, remorques, flux déjà fermé — remonte
donc son bloc à décoder, accompagné de la raison du refus, et son `RST_STREAM`
part avec. L'appelant décode, puis jette.

### Les remorques ne sont pas servies, et c'est une décision

§8.1 permet un second `HEADERS` en fin de message. Rien ne s'en sert pour une
REQUÊTE — gRPC les emploie dans l'autre sens — et les servir ferait passer un
second jeu d'en-têtes par toute la pile, après que la requête a été jugée sur
le premier. C7 tranche : ce qui n'apporte rien et ouvre un chemin de plus ne se
sert pas. Le flux est annulé, et lui seul.

### Deux fenêtres par flux, et elles ne se ressemblent pas

§5.2.1 en donne une par sens. Celle de réception dit ce que le pair peut encore
nous envoyer : c'est nous qui l'ouvrons, lui qui la consomme. Celle d'émission
dit ce que nous pouvons encore lui envoyer : c'est lui qui l'ouvre, nous qui la
consommons. N'en tenir qu'une reviendrait à croire son propre compte pour celui
du pair.

La conséquence la plus facile à manquer est dans §6.9.2 : quand le pair change
sa `SETTINGS_INITIAL_WINDOW_SIZE`, ce sont NOS fenêtres d'ÉMISSION qui bougent,
pas celles de réception. Les confondre ferait bouger les fenêtres du mauvais
côté, et les deux comptes divergeraient sans qu'un seul cadre soit fautif.

Et la fenêtre de la CONNEXION, elle, ne suit pas ce réglage du tout (§6.9.2) :
elle part de la valeur de §6.9.1, et seul un `WINDOW_UPDATE` la change. Lui
appliquer le réglage compterait deux crédits pour un.

### La recharge, et le crédit nul

Recharger à chaque cadre ferait un `WINDOW_UPDATE` par `DATA` — autant de cadres
que de données. Attendre l'épuisement complet arrêterait l'émission entre le
moment où la fenêtre se ferme et celui où notre crédit arrive. On recharge donc
à la moitié.

Une fenêtre annoncée à zéro est licite, et mènerait tout droit à fabriquer un
`WINDOW_UPDATE` de zéro — que §6.9 refuse. Le crédit se calcule donc avant de
décider d'écrire, et un crédit nul n'écrit rien.

## L'étage qui répond, et le quatrième état des flux

### Le demi-fermé qui manquait

Un serveur qui refuse une requête n'attend pas d'en avoir lu le corps : il
répond `413`, et le client peut encore être en train d'envoyer. Le flux n'est
pas fermé pour autant — ce qui arrive après compte toujours dans les fenêtres,
et l'oublier ferait diverger notre contrôle de flux de celui du pair.

`half-closed (local)` de §5.1 porte donc son poids : c'est le seul état où l'on
accepte encore des données sur un flux dont on n'écrira plus rien. Les deux
moitiés d'une fermeture sont symétriques, et **c'est la seconde qui rend la
place** — un flux dont les deux côtés ont dit leur dernier mot ne compte plus
dans les flux simultanés de §5.1.2.

Les deux états réservés de §5.1, en revanche, restent absents : ils ne servent
qu'à la poussée serveur, que §8.4 a dépréciée et que ce serveur n'émet pas. Les
porter serait écrire deux états qu'aucune transition ne peut atteindre.

### Une tête de réponse tient dans un cadre, ou elle ne part pas

§6.10 permettrait de l'étaler sur des `CONTINUATION`. On ne le fait pas. Le pair
annonce au moins seize kibioctets de charge (§6.5.2), une tête de réponse qui
n'y tient pas n'existe pas dans un service qui va bien, et **n'émettre jamais de
`CONTINUATION` nous retire de la liste de ceux qui peuvent en inonder un
autre** : on refuse cette inondation à la réception, il serait étrange de se
réserver le droit de la produire.

### Ce qu'on refuse de recevoir, on refuse de l'écrire

§8.2.2 interdit les champs propres à la connexion, et §8.3 réserve le `:` aux
pseudo-en-têtes. Un serveur qui vérifie ces règles à la RÉCEPTION mais pas à
l'ÉMISSION laisse l'intermédiaire suivant recevoir ce qu'il vient de refuser —
et `transfer-encoding` est justement la moitié de la contradiction dont vit la
contrebande de requête.

La faute est donc `INTERNAL_ERROR` : c'est notre code qui a proposé le champ,
pas le pair.

### Trois bornes pour un corps, et c'est la plus petite qui décide

La taille de cadre que le pair accepte, sa fenêtre de connexion, sa fenêtre de
flux — plus la place du tampon qu'on nous donne. En oublier une, c'est écrire un
cadre que le pair traitera comme une faute de contrôle de flux, et il aura
raison.

Écrire zéro octet n'est pas une faute : c'est une fenêtre fermée, et l'appelant
attend le `WINDOW_UPDATE`. Un cadre vide ne s'écrit que pour dire la fin.

### `take` plutôt que `consume`, et pourquoi ce n'est pas un relâchement

`Window::consume` sert à la RÉCEPTION : le pair a déjà envoyé, dépasser la
fenêtre est sa faute, et il faut le dire. À l'ÉMISSION il n'y a pas de faute
possible — on choisit combien envoyer, et jamais plus que ce qui est ouvert. Une
méthode qui rendrait une faute là la rendrait pour un appel que personne ne peut
écrire.

`Window::take` prend au plus ce qui est ouvert et rend ce qu'elle a pris. Elle
ne peut pas rendre une fenêtre négative, et elle ne fabrique pas de garde
inatteignable. `Streams::consume_send` a disparu au profit de `take_send` pour
la même raison.

C'est la sixième garde inatteignable retirée sur cet étage. Le compte des
régions couvertes les trouve toutes, et **c'est là son intérêt principal** :
bien plus que de prouver que les tests passent partout, il montre les endroits
où le code prétend se défendre contre ce qui ne peut pas arriver.

## La jointure : d'un bloc décodé à une requête

`Event::Head` désigne un bloc dans l'accumulateur ; `Connection::read_head` en
fait une `RequestHead`. C'est trois lignes de code et deux décisions.

### Une interface ne se juge pas sur ce qu'elle promet

Le décodeur HPACK rendait un champ qui EMPRUNTE le tampon fourni. L'appelant ne
pouvait donc décoder qu'UN champ par tampon : le second appel voulait le
réemprunter, et l'emprunt du premier n'était pas fini — il vivait dans le champ
qu'on venait de garder.

Le décodeur était ainsi inutilisable pour ce à quoi il sert, et **cela ne s'est
vu qu'en écrivant l'appelant**. Ni les tests ni le fuzz ne l'avaient montré : les
uns décodaient un champ à la fois avec un tampon neuf, l'autre recopiait chaque
paire avant de passer à la suivante. Tous deux contournaient le défaut sans le
nommer.

Il rend maintenant aussi CE QU'IL N'A PAS EMPLOYÉ, et tout un bloc se décode
dans un seul tampon.

### Deux familles de fautes, et elles ne se punissent pas pareil

Une faute de COMPRESSION condamne la connexion : la table est partagée, et un
décodeur qui s'est trompé une fois ne saura plus rien lire. Une liste bien
décomprimée mais qui ne fait pas une requête — un pseudo-en-tête manquant, deux
autorités qui se contredisent — ne condamne que son FLUX (§8.1.1).

Les confondre coûterait cher dans les deux sens. Fermer la connexion sur une
requête malformée, c'est offrir à un client maladroit d'emporter les requêtes
des autres. Ne fermer que le flux sur une faute HPACK, c'est continuer à lire
une table dont on ne sait plus rien.

## QUIC : ce qui change, et pourquoi cela nous regarde

QUIC n'est pas « TCP sur UDP ». Trois choses le distinguent, et toutes trois
déplacent du travail vers nos crates.

**Le cadrage n'a qu'une source.** Toute longueur est un entier de §16, écrit une
fois, borné à soixante-deux bits. Il n'y a pas de second champ qui pourrait dire
autre chose — donc pas de contrebande de requête, non parce que le protocole est
plus récent, mais parce qu'il n'y a plus deux façons de savoir où un message
s'arrête. C'est la même raison qu'en HTTP/2, et elle vaut d'être répétée.

**Tout est chiffré, en-tête compris.** Le numéro de paquet lui-même est masqué
(RFC 9001 §5.4) : un observateur ne relie pas deux paquets d'une même connexion
en les regardant passer. C'est ce qui distingue QUIC de TCP, dont le numéro de
séquence est en clair.

**La perte est notre affaire.** Le noyau ne retransmet rien : la détection de
perte, le contrôle de congestion et les temporisations (RFC 9002) sont du code,
ici, et non un réglage du système.

La protection des paquets, elle, ne vit PAS dans `ams-proto-quic` : elle demande
de l'AEAD, donc une bibliothèque de chiffrement, et un crate qui en dépendrait
ne serait plus `no_std`. Elle ira avec le reste du matériel TLS — les clés
viennent de la poignée de main, pas de la grammaire.

### L'écriture n'est pas canonique, et ce n'est pas un relâchement

§16 le dit en toutes lettres : la valeur 37 s'écrit sur un, deux, quatre ou huit
octets, et **les quatre écritures sont valides**. Un décodeur qui refuserait les
longues refuserait des paquets parfaitement conformes.

C'est l'exact contraire de HPACK, où une écriture non canonique est une attaque
— on y a d'ailleurs mis une borne pour cela. La différence tient en une ligne :
ici la longueur est ANNONCÉE et bornée à huit octets ; là-bas elle était
implicite et non bornée. **Ce n'est pas la canonicité qui protège, c'est la
borne.**

Notre écriture à nous, en revanche, est toujours la plus courte. Non par
conformité — rien ne l'exige — mais parce que c'est ce qui fait tenir un paquet
dans un datagramme, et un datagramme dans un chemin dont on ne connaît pas la
MTU.

### Le numéro de paquet, et la fenêtre qui glisse

Un numéro va jusqu'à 2^62 - 1, et l'écrire en entier coûterait huit octets sur
des paquets qui en font parfois quarante. On n'écrit donc que les bits de poids
faible, et le receveur reconstruit le reste.

Si l'écrivain tronque trop court, deux numéros se réduisent aux mêmes bits, le
receveur en choisit un — le mauvais —, le paquet est déchiffré avec le mauvais
nonce, l'authentification échoue, et le paquet est jeté. **Cela ne casse pas la
sécurité ; cela casse la connexion, en silence.** C'est pourquoi l'annexe A.2
demande d'écrire assez pour distinguer DEUX FOIS le nombre de paquets non
acquittés : la fenêtre de reconstruction est centrée sur le numéro attendu, une
moitié devant, une moitié derrière.

### Deux défauts trouvés par le fuzz, sur la même ligne

La reconstruction pouvait rendre un numéro **hors de l'espace de soixante-deux
bits** — trouvé en trois minutes.

Le premier cas était un `largest` hors borne : rien dans le calcul ne ramenait le
résultat dans ses bornes, parce que rien ne vérifiait l'entrée. **Une borne
qu'on ne vérifie qu'à la sortie n'est pas une borne : c'est une espérance.**

Le second est plus intéressant, et il est apparu APRÈS la première correction :
avec `largest` valant exactement 2^62 - 1, le numéro attendu vaut 2^62, hors de
l'espace, et le candidat qu'on en tire aussi. Le pseudo-code de l'annexe A.3 ne
s'en garde pas — parce que §12.3 exige d'avoir fermé la connexion avant d'en
arriver là. La garde est donc à nous, et son absence ne se serait vue qu'après
2^62 paquets, ou jamais.

Une différence d'une unité s'est glissée au passage : la RFC compare à `2^62`, et
la première écriture comparait à `2^62 - 1`. Un seul numéro s'en trouvait
reconstruit autrement — le tout dernier que la connexion puisse porter. C'est
assez pour justifier une constante nommée `ESPACE`, plutôt qu'un `MAX` qu'on
croit interchangeable.

## Les en-têtes de paquet : ce qu'on lit avant d'avoir la moindre clé

### On ne lit que la moitié, et c'est le protocole qui l'exige

La protection d'en-tête (RFC 9001 §5.4) masque **les bits réservés, la longueur
du numéro de paquet, et le numéro lui-même**. Le module d'en-têtes s'arrête donc
exactement là où le masque commence, et rend l'endroit où il commence.

Cette coupure n'est pas une commodité de mise en œuvre. C'est l'ordre imposé par
le protocole : pour ôter le masque il faut la clé, pour trouver la clé il faut
l'identifiant de destination, pour lire l'identifiant il faut avoir lu l'en-tête
jusque-là. **Un module qui prétendrait tout lire d'un coup mentirait sur ce
qu'il sait.**

C'est aussi la partie de QUIC qu'on traite sans savoir à qui l'on parle : le
port est ouvert au monde entier, et ces octets-là ont été choisis par un
inconnu.

### La longueur de l'identifiant court n'est pas sur le fil

Un en-tête long annonce la longueur de chaque identifiant. Un en-tête COURT
n'annonce rien : le receveur la connaît parce que c'est LUI qui a choisi cet
identifiant et l'a donné au pair.

La même suite d'octets, lue avec deux longueurs différentes, désigne donc deux
connexions différentes. **Un serveur qui ne se souviendrait pas des longueurs
qu'il émet ne saurait lire aucun paquet court** — ce n'est pas un détail de mise
en œuvre, c'est ce que le protocole demande de retenir.

### Zéro à vingt octets, et la borne n'est pas décorative

La longueur vient du fil, et un octet peut en annoncer deux cent cinquante-cinq.
Sans la borne de §17.2, un pair choisirait combien on retient de lui. Et un
identifiant VIDE est parfaitement légal : un pair qui n'a qu'une adresse n'a
rien à router, et vingt octets par paquet valent d'être économisés.

Un identifiant hors borne fait JETER le paquet, et ne ferme pas la connexion :
il peut venir de n'importe qui, et une connexion qu'on ferme sur un paquet
égaré est une connexion qu'un tiers peut fermer.

### Le bit fixe, et ce qu'il sert à distinguer

§17.2 : le bit 0x40 vaut un, et un paquet où il vaut zéro n'est pas un paquet de
cette version. C'est ce qui permet de distinguer QUIC d'autres protocoles sur le
même port UDP — et le vérifier tôt évite de déchiffrer ce qui n'est pas à nous.

### Trois formes qui ne se lisent pas de la même façon

- Un `Initial` porte un jeton, et lui seul (§17.2.2).
- Un `Retry` n'a **ni longueur ni numéro de paquet** (§17.2.5) : tout ce qui suit
  les identifiants est le jeton, sauf les seize derniers octets, qui
  l'authentifient. Il se lit donc à l'envers, par la queue.
- La version ZÉRO n'est pas une version (§17.2.1) : le reste du paquet est une
  liste de versions, et les bits de type du premier octet ne veulent alors plus
  rien dire. Un serveur n'en reçoit jamais — il est celui qui les émet — mais un
  paquet qu'on ne sait pas nommer se jette sans qu'on puisse dire pourquoi.

## Les trames de QUIC, et l'inverse d'HTTP/2

### Ce qu'on ne connaît pas est une FAUTE

§12.4 : « An endpoint MUST treat the receipt of a frame of unknown type as a
connection error of type FRAME_ENCODING_ERROR. » En HTTP/2, un cadre inconnu
s'IGNORE ; ici, il condamne la connexion.

Ce n'est pas une incohérence entre deux protocoles voisins : ce sont deux façons
différentes d'étendre. HTTP/2 laisse un émetteur essayer et voir. QUIC exige que
toute extension soit NÉGOCIÉE d'abord, par un paramètre de transport. Un type
inconnu veut donc dire qu'on n'a pas négocié ce qu'on croyait — et continuer à
lire un flux qu'on ne comprend plus serait deviner.

Les deux règles se ressemblent au point qu'on pourrait les confondre en écrivant
les deux crates l'un après l'autre. Elles sont écrites ici pour qu'on ne le
fasse pas.

### Une trame ne porte pas sa longueur

Son type dit sa forme, et sa forme dit sa fin. Rien n'annonce « la trame
suivante commence à tel octet ». Un décodeur qui se tromperait d'un octet lirait
donc le reste du paquet comme des trames imaginaires — et c'est exactement
pourquoi tout se refuse au premier doute plutôt que de tenter de se rattraper.

C'est aussi pourquoi la cible de fuzz vérifie qu'une trame lue consomme **au
moins un octet et jamais plus qu'on ne lui en a donné** : un décodeur qui
n'avance pas boucle sans fin, et un décodeur qui avance trop lit le paquet
suivant comme le sien.

### Les intervalles d'un `ACK` restent sur le fil

Leur nombre vient du pair, et rien ne le borne d'utile : les retenir tous
demanderait une table dont il choisirait la taille. On garde donc les octets, et
un parcours les lit à la demande — l'appelant décide combien il en veut.

Une faute arrête ce parcours définitivement. Continuer après un intervalle
illisible lirait les octets suivants comme des intervalles, et il n'y a plus
aucune raison de croire qu'ils en sont.

### Trois bornes que la RFC pose et qu'on aurait pu manquer

- **2^60 pour un compte de flux** (§19.11), et non 2^62 : un numéro de flux est
  fait d'un compte et de deux bits de type, et un compte plus grand ferait un
  numéro hors de l'espace des entiers.
- **La somme du décalage et de la longueur** d'un `STREAM` ou d'un `CRYPTO` ne
  peut pas dépasser 2^62 - 1 (§19.8), sans quoi le flux désignerait des octets
  qu'aucun décalage ne pourrait nommer.
- **Le rang de retrait d'un `NEW_CONNECTION_ID`** ne peut pas dépasser le rang
  annoncé (§19.15) : il retirerait l'identifiant qu'on vient de donner.

### Un identifiant vide est licite dans un en-tête, et pas dans une trame

§17.2 admet zéro octet : un pair qui n'a rien à router économise vingt octets par
paquet. §19.15, elle, exige de un à vingt — un identifiant qu'on DONNE au pair
pour qu'il s'en serve doit désigner quelque chose.

La borne haute, en revanche, n'est écrite qu'une fois : c'est le type
`ConnectionId` qui la porte, et la redire dans la trame ferait deux vérités pour
une règle.

### Sans `LEN`, une trame `STREAM` va jusqu'au bout du paquet

C'est ce qui permet de n'écrire aucune longueur pour la dernière trame d'un
paquet — quelques octets gagnés sur chaque paquet de données. La conséquence
pour l'appelant est stricte : **il ne doit présenter QUE le paquet**, et rien de
ce qui suit dans le datagramme. Un datagramme peut porter plusieurs paquets
coalescés (§12.2), et se tromper de frontière ferait lire les paquets suivants
comme la charge du premier.

## Les flux QUIC, et deux bits qui suppriment une négociation

Le bit de poids faible d'un numéro de flux dit QUI l'a ouvert ; le suivant dit
s'il est bidirectionnel. Le reste est un compteur.

Personne n'a donc à demander la permission d'ouvrir un flux, ni à s'accorder sur
qui prend les numéros pairs : le numéro lui-même le dit. En HTTP/2, la même
question se réglait par la convention « le client prend les impairs », et les
flux poussés par le serveur ont fini par être dépréciés parce que cette
convention ne suffisait pas.

Un flux unidirectionnel ne va que dans un sens, et c'est le sien : celui qui
l'ouvre est le seul à y écrire. Recevoir des données sur un flux unidirectionnel
qu'on a ouvert soi-même est une faute d'état — pas un cas qu'on tolérerait.

Et `MAX_STREAMS` borne le RANG, pas le numéro : §4.6 compte les flux d'un type,
et les quatre types ont leurs comptes séparés.

## La perte est notre affaire

Le noyau ne retransmet rien. C'est nous qui décidons qu'un paquet est perdu, et
quand réessayer. Une estimation trop courte fait retransmettre ce qui était en
route — et l'on inonde un réseau déjà chargé. Une estimation trop longue fait
attendre une seconde ce qui aurait pu partir en dix millisecondes.

### Le pair dit combien de temps il a attendu, et il peut mentir

Un `ACK` porte un délai d'acquittement, qu'on RETIRE de l'échantillon — sans
quoi on prendrait la politesse du pair pour de la latence. Mais ce délai vient
de lui. §5.3 pose donc deux gardes :

- le délai est borné par ce que le pair a **annoncé pouvoir attendre** ;
- il n'est retiré que si l'échantillon reste **au-dessus du minimum observé**.

Un pair qui annoncerait un délai énorme ferait sinon croire à un réseau
instantané, et l'on retransmettrait tout, tout le temps.

L'ordre des opérations compte aussi : le minimum se met à jour sur l'échantillon
BRUT, avant toute correction. L'inverse ferait juger une correction avec un
minimum qu'elle vient elle-même d'abaisser, et l'estimation s'effondrerait.

### Une borne qu'on PARCOURT n'est pas une borne

Le délai de retransmission double à chaque essai. La première écriture doublait
`essais` fois dans une boucle ; avec `u32::MAX`, elle tournait quatre milliards
de fois pour un résultat connu d'avance, et le test de saturation mettait
**soixante-treize secondes**. Au-delà de soixante-quatre doublements, toute base
a saturé.

Le défaut n'était pas dans le résultat — il était juste — mais dans le temps
qu'il mettait à l'être. C'est le genre de chose qu'un test qui mesure trouve, et
qu'un test qui vérifie ne voit pas.

### Deux façons de dire qu'un paquet est perdu, et il faut les deux

§6.1 : un paquet est perdu si un paquet suffisamment plus RÉCENT a été acquitté
— trois d'écart —, ou s'il a été envoyé assez LONGTEMPS avant le plus récent
acquitté — neuf huitièmes d'aller-retour.

Aucun ne suffit seul. Le seuil de paquets ne voit rien quand il n'y a plus rien
à envoyer : le dernier paquet d'un échange n'a aucun successeur pour le déclarer
perdu. Le seuil de temps, lui, attend une fraction d'aller-retour même quand la
preuve est déjà là.

Les deux chiffres — trois, et neuf huitièmes — ne sont pas des réglages de
confort. Ils disent ce qu'on accepte de voir arriver dans le désordre avant
d'appeler cela une perte, et **déclarer perdu ce qui n'était qu'en retard fait
ralentir un chemin qui va bien**.

### Une rafale perdue est UN événement de congestion, pas dix

§7.3.2. Diviser la fenêtre une fois par paquet perdu la ramènerait au minimum
sur la première rafale venue, et l'on ne s'en relèverait qu'après plusieurs
secondes. La période de récupération dure jusqu'à ce que tout ce qui était en vol
soit acquitté ou perdu ; pendant ce temps, les pertes suivantes ne divisent plus
rien, et les acquittements ne font plus croître — ces paquets-là étaient déjà en
vol quand la congestion s'est produite, et ne prouvent rien du nouveau régime.

Le contrôle de congestion n'est pas une optimisation : §7 en fait une
obligation. Un émetteur QUIC sans contrôle de congestion n'est pas un émetteur
rapide, c'est un émetteur qui écroule le chemin qu'il partage — et le noyau ne
l'en empêchera pas.

## Les paramètres de transport, et la règle qui explique l'autre

§18.1 : « An endpoint MUST ignore transport parameters that it does not
understand. » Les paramètres inconnus s'IGNORENT — c'est exactement l'inverse
des trames, où §12.4 fait d'un type inconnu une faute de connexion.

Les deux règles vont ensemble, et ne se comprennent qu'ensemble : **on ignore ce
qu'on ne connaît pas là où l'on NÉGOCIE, et on refuse ce qu'on ne connaît pas là
où l'on EXÉCUTE.** Un pair qui veut une extension l'annonce dans ses paramètres ;
s'il n'obtient pas de réponse, il sait qu'il ne doit pas s'en servir. Une trame
inconnue veut donc dire que cette négociation n'a pas eu lieu, ou qu'elle a été
mal comprise.

C'est la troisième fois dans ce dépôt que deux protocoles voisins traitent
l'inconnu de deux façons opposées, et la troisième fois que la raison en vaut la
peine. Il fallait l'écrire quelque part.

### Les défauts sont des valeurs, pas des absences

§18.2 donne à presque chaque paramètre une valeur par défaut, qui vaut dès le
premier paquet — avant même que les paramètres du pair n'arrivent. Traiter un
paramètre absent comme « pas de limite » plutôt que comme sa valeur par défaut
ouvrirait exactement les portes que ces défauts ferment.

### Un paramètre deux fois est une faute, et ce n'est pas de la pédanterie

§7.4. Sans cette règle, deux valeurs pour un même paramètre laisseraient chaque
mise en œuvre choisir la sienne — et deux pairs n'auraient plus les mêmes
limites, sans qu'aucun sache lequel a tort. Un bit par paramètre connu suffit à
le refuser : dix-sept paramètres tiennent dans un `u32`.

### Une valeur occupe tout ce qu'elle annonce, et rien de plus

Des octets en trop derrière un entier voudraient dire qu'on n'a pas lu ce que le
pair a écrit — et l'on prendrait sa limite pour une autre. La vérification tient
en une comparaison, et il faut la faire pour CHAQUE paramètre entier : un seul
oublié laisserait passer une limite lue de travers.

### Ce qu'un client ne peut pas annoncer

Quatre paramètres n'appartiennent qu'au serveur : l'identifiant de destination
d'origine, le jeton de réinitialisation, l'adresse préférée, et l'identifiant de
source d'un `Retry`. Un client qui les enverrait prétendrait avoir émis ce
`Retry` ou choisi cet identifiant d'origine — c'est-à-dire **réécrire ce qui
prouve que la poignée de main n'a pas été détournée**.

## HTTP/3 : ce qui disparaît, et pourquoi c'est l'essentiel

HTTP/2 devait construire des flux au-dessus d'une connexion TCP unique :
numéros de flux, machine d'états par flux, contrôle de flux par flux,
`WINDOW_UPDATE`, `RST_STREAM`, `PRIORITY`. Tout cela est descendu dans QUIC, et
n'a plus à être écrit.

**Ce qui disparaît avec, et qui compte davantage** : le blocage de tête de
ligne. En HTTP/2, un paquet perdu arrêtait TOUS les flux, parce que TCP livre
dans l'ordre ou ne livre pas. En HTTP/3, il n'arrête que le flux auquel il
appartenait.

Ce qui reste ici tient en peu de chose, et c'est voulu : le cadrage, les types
de flux unidirectionnels, trois réglages, et QPACK.

### Une trame porte sa longueur, et c'est l'inverse de QUIC

Une trame QUIC se lit jusqu'au bout ou pas du tout : son type dit sa forme, et
sa forme dit sa fin. Une trame HTTP/3 annonce un type PUIS une longueur.

La raison tient à ce qu'elles servent : QUIC cadre ce qu'il COMPREND, HTTP/3
cadre ce qu'il TRANSPORTE. Un type inconnu doit pouvoir être sauté, et l'on ne
saute que ce dont on connaît la taille.

### Troisième règle, troisième protocole

HTTP/2 ignore ce qu'il ne connaît pas. QUIC le refuse. HTTP/3 l'ignore à
nouveau. Ce n'est pas de l'inconstance :

- **QUIC refuse** parce que ses extensions se négocient dans les paramètres de
  transport, et qu'une trame inconnue y signale une négociation manquée ;
- **HTTP/3 ignore** parce que ses trames portent leur longueur, et qu'une
  extension peut donc traverser un pair qui ne la connaît pas.

Trois protocoles, trois traitements de l'inconnu, et chacun est juste dans son
cadre. C'est le genre de chose qu'on confond en écrivant les crates l'un après
l'autre — d'où ce paragraphe.

### Les types réservés sont un piège, et il est voulu

§11.2.1 réserve 0x02, 0x06, 0x08 et 0x09 — ceux que RFC 7540 donnait à
`PRIORITY`, `PING`, `WINDOW_UPDATE` et `CONTINUATION`. §11.2.2 fait de même pour
quatre identifiants de réglage.

Les recevoir n'est pas une trame inconnue qu'on ignore : c'est un pair qui parle
HTTP/2 sur une connexion HTTP/3, et **ce qui suit ne sera pas ce qu'on croit**.
La RFC en fait donc une faute, et non un silence. C'est une trappe posée exprès,
et la respecter est ce qui empêche une confusion de protocoles de passer pour
une extension.

### Un flux critique ne se ferme pas

Le flux de contrôle et les deux flux QPACK ne se ferment pas : §6.2.1 en fait
une faute `H3_CLOSED_CRITICAL_STREAM`. La connexion n'aurait plus par où
s'entendre.

Un flux de type INCONNU, en revanche, s'abandonne sans que la connexion en
souffre — c'est ce qui permet à une extension d'ouvrir ses propres flux sans
casser les pairs qui ne la connaissent pas.

### La poussée n'est pas servie, et c'est une décision

Un flux de poussée est ouvert par le SERVEUR (§4.6). Un client qui en ouvrirait
un prétendrait pousser vers nous — ce qui n'existe pas. Et ce serveur n'en émet
pas : la poussée serveur a été retirée d'HTTP/2 faute d'usage, et rien ne
justifie de la réintroduire.

### Zéro est la valeur par défaut de la table QPACK

Et ce n'est pas rien : sans annonce, aucune table dynamique n'existe, et
l'encodeur ne peut employer que la table statique. C'est le contraire d'HPACK,
dont la table faisait quatre kibioctets d'office.

De même, zéro flux bloqué par défaut — et c'est tout l'intérêt de QPACK. Un flux
bloqué attend une insertion qu'un autre flux n'a pas encore livrée ; zéro veut
dire « ne me fais jamais attendre », et c'est ce qui rend QPACK utilisable sur un
transport qui livre dans le désordre.

## Un socle pour HPACK et QPACK, et pourquoi il fallait l'extraire

QPACK réemploie **la table de Huffman de RFC 7541 Appendice B** et **les entiers
à préfixe de son §5.1**, à l'identique : RFC 9204 §4.1.1 renvoie à RFC 7541
plutôt que de les redéfinir.

Les recopier dans deux crates ferait deux vérités pour une table de deux cent
cinquante-sept entrées. Mais ce n'est pas le pire.

**Le pire serait deux occasions d'écrire le même défaut.** Le décodeur d'entiers
de ce dépôt en a déjà eu un : `checked_shl` ne dit rien du débordement de
VALEUR, et faisait lire `ff ff ff ff ff 7f` comme la valeur 255. Il a été trouvé
par son propre test, corrigé, et documenté. Le réimplémenter pour QPACK serait
offrir l'occasion de le réécrire — et cette fois, peut-être, sans le test qui
l'avait vu.

### Ce que le socle ne sait pas

Il ne connaît ni HTTP/2 ni HTTP/3, et ne nomme donc **aucun code de fil** :
HPACK ferme avec `COMPRESSION_ERROR`, QPACK avec
`QPACK_DECOMPRESSION_FAILED`. Un socle qui nommerait le premier obligerait le
second à le traduire — ou pire, à s'en accommoder. Il rend ce qui a mal tourné,
et la traduction est le travail de celui qui a une connexion à fermer.

Il ne connaît pas non plus les TABLES : la statique de HPACK a soixante et une
entrées, celle de QPACK quatre-vingt-dix-neuf, et leurs tables dynamiques n'ont
ni les mêmes règles ni le même ordre. **Seul ce qui est vraiment commun y vit** —
extraire ce qui se ressemble sans être identique aurait fait un socle plein de
conditions, et c'est exactement ce qu'on voulait éviter.

### Et ce que l'extraction a retiré au passage

HPACK réexportait Huffman, sans s'en servir autrement qu'à travers les chaînes.
Un enrobage que personne n'appelle est une interface qu'on entretient sans s'en
servir : il est parti avec le reste. Qui veut Huffman prend le socle.

## QPACK : le problème que HPACK n'avait pas

HPACK suppose que les blocs d'en-têtes arrivent DANS L'ORDRE : sa table
dynamique se met à jour au fil des blocs, et le décodeur doit avoir vu le bloc
`n` pour lire le bloc `n+1`. Sur TCP, c'est acquis.

**Sur QUIC, ce ne l'est plus** : deux flux avancent indépendamment, et le bloc du
flux 8 peut arriver avant celui du flux 4. Employer HPACK tel quel rendrait le
blocage de tête de ligne qu'HTTP/3 venait justement de retirer — non plus dans
le transport, mais dans la compression.

QPACK y répond en séparant les INSERTIONS des RÉFÉRENCES. Les insertions
voyagent sur un flux à part, ordonné ; chaque section dit de combien
d'insertions elle dépend, et le décodeur ne bloque que si elles ne sont pas
encore arrivées. **Un encodeur qui ne référence rien de dynamique ne bloque
jamais personne** — et c'est le mode que ce serveur emploie par défaut.

### Une table qui ressemble à celle de HPACK, et qui n'est pas la même

HPACK avait soixante et une entrées choisies en 2013 ; QPACK en a
quatre-vingt-dix-neuf, « generated by analyzing actual Internet traffic in
2018 ». **Elle commence à zéro**, là où celle de HPACK commençait à un.

Les deux se ressemblent assez pour qu'on les confonde, et diffèrent assez pour
que la confusion soit indétectable : l'index 2 désigne `:method GET` dans l'une
et `age 0` dans l'autre, et le message décodé serait faux sans qu'aucune faute ne
se voie. C'est pourquoi cette table est ENGENDRÉE depuis la RFC, et non recopiée
à la main — la mise en page de l'appendice coupe d'ailleurs dix valeurs en deux,
et c'est exactement là qu'une transcription se serait trompée.

L'appendice prévient aussi que les entrées se répètent : `content-type` y figure
dix-neuf fois, `:status` vingt-deux. Un décodeur qui s'attendrait à des noms
uniques se tromperait.

### Le compte d'insertions est écrit modulo, comme un numéro de paquet

§4.5.1.1 n'écrit pas le compte tel quel : il l'écrit modulo deux fois le nombre
d'entrées que la table peut porter. C'est la même idée que le numéro de paquet
tronqué de QUIC, avec la même conséquence : **une reconstruction fausse ne se
voit pas, elle décale simplement toute la table.**

Et les deux gardes de bord de l'algorithme ne sont pas décoratives : sans elles,
une section reconstruirait un compte que le pair n'a pas écrit. Un compte
reconstruit à zéro, en particulier, veut dire qu'on s'est trompé de tour — le
zéro écrit ayant son propre sens, « cette section ne dépend de rien ».

### Deux façons de désigner la table dynamique

HPACK n'en avait qu'une. QPACK en a deux : relative au rang de la section, et
APRÈS ce rang.

La raison est dans le désordre. Un encodeur qui insère une entrée pendant qu'il
écrit une section doit pouvoir la référencer ; mais l'index relatif se compte
depuis un rang fixé au DÉBUT de la section, et cette entrée n'existait pas
encore. Sans le second mode, l'encodeur devrait choisir entre ne pas insérer
pendant qu'il écrit, ou refaire son préfixe après coup — c'est-à-dire écrire la
section deux fois.

### Le fanion de Huffman d'un nom littéral n'est pas où on l'attend

§4.5.6 : le premier octet est `001NHxxx`. Les trois bits de bas sont le préfixe
de la LONGUEUR DU NOM, et `H` la précède — dans le même octet que les bits de
type. En HPACK, le nom était une chaîne ordinaire, avec son propre octet.

Lire cette longueur avec un préfixe de sept bits, comme le ferait une chaîne
ordinaire, la lirait de travers. C'est le genre de différence qu'on ne voit pas
en relisant, et qu'on voit en écrivant le test.

## Une table dynamique QPACK de zéro octet, et ce que cela ferme

§3.2.3 : « When the maximum table capacity is zero, the encoder MUST NOT insert
entries into the dynamic table and MUST NOT send any encoder instructions on the
encoder stream. » Annoncer zéro ferme **trois choses d'un coup** :

- **le blocage de compression.** Une section ne peut dépendre d'aucune
  insertion, donc ne peut jamais attendre. Le blocage de tête de ligne qu'on a
  retiré du transport ne revient pas par la compression.
- **CRIME et BREACH à la réception.** Une table dynamique partagée entre des
  champs d'origines différentes est ce qui rend l'attaque possible ; sans table,
  il n'y a rien à mesurer. C'est le pendant, côté décodage, de l'encodeur HPACK
  qui n'indexe jamais.
- **tout un étage de code.** Une table qu'on annonce inutilisable serait un
  chemin qu'aucune entrée ne peut emprunter — et la couverture le dirait.

Le coût est quelques dizaines d'octets par requête, que le client aurait
économisés en indexant. C7 tranche, et il n'y a pas d'arbitrage difficile : une
API REST n'envoie pas mille requêtes identiques par connexion.

**On lit quand même les instructions.** Un pair qui en envoie doit s'entendre
dire pourquoi on refuse — et non voir sa connexion se fermer sans un mot. C'est
aussi ce qui permettra d'annoncer une table plus tard sans réécrire la lecture.

### On refuse une insertion sur son TYPE, sans lire sa charge

§4.3.3 ne borne ni le nom ni la valeur d'une insertion. Attendre de les avoir
pour refuser une instruction qu'on refusera de toute façon donnerait au pair le
moyen de choisir combien nous retenons — c'est-à-dire précisément ce que C3
interdit.

§4.3 met le type dans les bits de tête du premier octet. Il suffit :
`encoder_instruction_kind` classe, `check_encoder_instruction_kind` juge, et
aucune charge n'entre dans un tampon. Le classement est total — les quatre motifs
couvrent les deux cent cinquante-six valeurs —, donc il n'y a pas de type inconnu
à prévoir.

**`Set Dynamic Table Capacity` à zéro fait exception, et c'est délibéré.** §3.2.3
demande à la lettre de n'envoyer AUCUNE instruction quand la table est nulle.
Celle-ci ne demande pourtant rien qu'on refuse, et fermer la connexion d'un pair
qui annonce renoncer à la table serait le punir de nous avoir obéi.

### Accuser ce qu'on n'a pas envoyé est une faute de compte

Notre encodeur n'insère rien : aucune section que nous émettons ne déclare un
compte d'insertions non nul. §4.4.1 fait alors de TOUT accusé de section une
faute — « every encoded field section with a non-zero Required Insert Count has
already been acknowledged » est vrai à vide —, et §4.4.3 de tout incrément, qu'il
soit nul ou qu'il dépasse ce qu'on a envoyé.

Ce n'est pas du formalisme : un pair qui accuse ce qui n'existe pas ne tient pas
la même table que nous, et plus rien ne se lira ensuite.

§4.4.2 en revanche **n'a aucune condition d'erreur**. Une annulation de flux dit
qu'on peut relâcher ce qu'une section référençait ; sans table il n'y a rien à
relâcher, et rien à refuser non plus. Elle passe donc — et se compte comme une
trame de service, parce qu'un flux critique n'est borné par rien d'autre et
qu'une annulation répétée sans fin est le travail gratuit de *Rapid Reset* par
une autre porte.

### Nos deux flux QPACK s'ouvrent, et ne portent que leur type

§4.2 dit « at most one », et non « exactly one » : les ouvrir n'est pas dû. On le
fait quand même, et l'on n'y écrira jamais rien — notre encodeur n'emploie que la
table statique, notre décodeur n'a aucun accusé à rendre.

**La raison est qu'un flux absent et un flux muet ne se distinguent pas d'un flux
qui tarde.** Un pair qui attend ceux de son vis-à-vis pour commencer attendrait
indéfiniment, et rien dans ce qu'il verrait ne le lui dirait. Deux octets à
l'ouverture d'une connexion suppriment la question.

Le prix est **trois flux unidirectionnels de crédit au lieu d'un**. §6.2 de
RFC 9114 demande justement au pair d'en donner assez pour ces trois-là ; un pair
plus avare ne verra pas la connexion s'ouvrir, et on le lui dit plutôt que de
servir à moitié.

### Une borne de représentation qui empêche un flux de se figer

Les instructions de §4.4 et le `Set Dynamic Table Capacity` de §4.3.1 sont un
motif de bits suivi d'un entier à préfixe, et rien d'autre. `decode_integer`
s'arrête à 2^32-1 : son multiplicateur déborde après cinq octets de continuation.
Six octets, donc, et jamais un de plus.

**Cette borne tranche entre deux choses que la lecture confond** : « il en
manque » et « cet entier ne se reconstruira jamais » rendent la même faute. Sans
elle, on attendrait pour toujours la suite d'une instruction que le pair
n'achèvera pas — un flux figé, sans erreur et sans trace. C'est exactement le
défaut qu'avait eu le tampon du flux de contrôle, et c'est pourquoi il est nommé
ici plutôt que découvert deux fois.

### Lire et juger sont deux choses

La lecture dit ce que le pair a écrit ; le jugement dit si nous l'acceptons, et
cela dépend de ce que NOUS avons annoncé. Les mêmes octets sont licites pour un
serveur qui tient une table et fautifs pour celui-ci.

Une lecture qui refuserait d'elle-même ne pourrait plus servir aux deux — et le
jour où l'on voudrait une table, il faudrait la réécrire. C'est pourquoi
`read_encoder_instruction` et `check_encoder_instruction` sont deux fonctions.

### Un code par flux, et non un code par faute

§6 de RFC 9204 nomme `QPACK_ENCODER_STREAM_ERROR` et
`QPACK_DECODER_STREAM_ERROR` séparément. Le pair doit savoir LEQUEL de ses deux
flux QPACK a fauté, et non seulement que l'un des deux l'a fait — il n'a pas les
mêmes choses à corriger.

### La borne d'une représentation n'est pas celle du protocole

Les entiers à préfixe de RFC 7541, que QPACK réemploie, s'arrêtent à 2^32-1. Un
numéro de flux QUIC va jusqu'à 2^62-1. Un accusé de réception pour un flux
au-delà de quatre milliards ne peut donc pas s'écrire.

On le dit plutôt que de tronquer : un accusé tronqué désignerait un AUTRE flux,
et l'encodeur du pair évincerait des entrées qu'une section en vol référence
encore.

## La jointure QPACK, et une règle qui a trouvé sa place

`read_section` fait d'une section de champs une `RequestHead` ; `write_section`
fait d'un statut et de champs une section. C'est le pendant exact de
`Connection::read_head` et `write_head` en HTTP/2 — et cela devait l'être :
les deux protocoles servent la même sémantique.

### Sans table dynamique, une section ne dépend de rien

Une section qui réclamerait des insertions n'attendrait pas : **elle attendrait
pour toujours**, puisque nous avons annoncé zéro et que §3.2.3 interdit au pair
d'en faire. On le dit plutôt que de le subir.

De même, un index qui désigne la table dynamique ne désigne rien — le pair
n'aurait pas pu l'y mettre. Les quatre représentations qui la référencent sont
donc refusées d'un bloc.

### Une règle qui vivait à deux endroits

« Ce qu'on refuse de recevoir, on refuse de l'écrire » était écrite dans HTTP/2.
RFC 9114 §4.2 la reprend mot pour mot pour HTTP/3. L'écrire une seconde fois
aurait fait deux vérités pour une règle — et le jour où l'une changerait, l'autre
laisserait passer ce que la première refuse.

Elle vit maintenant dans `ams-proto-http`, avec le reste de la sémantique
commune. C'est le troisième morceau qui remonte là : les champs propres à la
connexion, les pseudo-en-têtes, et maintenant ce que l'on s'autorise à écrire.

### Deux familles de fautes, pour la troisième fois

Une faute de DÉCOMPRESSION condamne la connexion ; une liste bien décomprimée
qui ne fait pas une requête ne condamne que son flux (§4.1.2 de RFC 9114). C'est
la même distinction qu'en HTTP/2 §8.1.1, avec des codes différents — et c'est
elle qui empêche un client maladroit d'emporter les requêtes des autres.

## La protection des paquets QUIC : le seul endroit où une erreur fuit

Partout ailleurs dans ce dépôt, une erreur se traduit par un refus. Ici, elle se
traduit par une FUITE :

- un nonce réemployé livre la clé d'authentification de GCM, et donc la capacité
  de forger n'importe quel message ;
- un masque d'en-tête mal calculé laisse le numéro de paquet en clair, et permet
  de suivre un utilisateur qui change de réseau ;
- un déchiffrement qui accepte ce qu'il ne devrait pas ouvre la connexion à qui
  sait envoyer un datagramme.

C'est pourquoi ce crate est le seul dont **chaque valeur est comparée aux
vecteurs de la RFC**, et non seulement à elle-même : l'annexe A de RFC 9001
donne les cinq secrets, les six clés, les trois masques, le chiffré d'un paquet
et le jeton d'un `Retry`. Tous se retrouvent, à l'octet près.

### Ce sont les STRUCTURES qu'on compare, pas seulement les résultats

L'annexe A.1 écrit `HkdfLabel` en toutes lettres :
`00200f746c73313320636c69656e7420696e00` pour « client in ». Ce sont ces
octets-là que les tests comparent d'abord.

La raison est méthodologique : une structure fausse avec un secret faux peut
donner un résultat juste par accident, et l'on ne saurait pas lequel des deux
est en cause. Comparer la structure sépare les deux questions.

### Le préfixe `tls13 ` sépare les univers

Sans lui, une clé dérivée pour QUIC et une clé dérivée pour autre chose à partir
du même secret et de la même étiquette seraient la même clé. Et le contexte vide
s'écrit quand même : l'omettre ferait une structure d'un octet plus courte, donc
une clé différente de celle que le pair a calculée.

### Les clés des paquets `Initial` sont publiques, et c'est assumé

Le sel est dans la RFC, l'identifiant de destination voyage en clair. N'importe
qui peut calculer ces clés ; elles ne cachent rien. **Elles empêchent un
intermédiaire de modifier un paquet sans que cela se voie** — ce que l'histoire
de TCP a montré être un problème réel, et non théorique.

Le jeton d'un `Retry` a la même nature : sa clé est publique, et ce qui rend la
forge impossible n'est pas le secret de la clé mais le fait que le calcul inclue
**l'identifiant de destination d'origine**, que seul un témoin du paquet
`Initial` connaît.

### L'échantillon se prend à quatre octets du numéro, toujours

§5.4.2. Quelle que soit la longueur RÉELLE du numéro de paquet, on échantillonne
comme s'il en faisait quatre — parce que le receveur ne connaît pas cette
longueur : elle est justement sous le masque qu'il cherche à ôter.

C'est un serpent qui se mord la queue, et la RFC le coupe en fixant le point
d'échantillonnage. Un décodeur qui échantillonnerait selon la longueur qu'il
croit lire obtiendrait un masque sans rapport.

Et quatre bits sont masqués sur un en-tête long, cinq sur un court. Se tromper
laisse le bit de phase de clé en clair, ce qui permet à un observateur de
compter les mises à jour.

### Une borne de paquet qui sert de garde de sûreté

Les trois AEAD ne refusent qu'au-delà de leur propre limite de longueur —
soixante-quatre gibioctets pour GCM. Ces refus-là sont inatteignables, et donc
invérifiables.

On borne donc le clair à 65 527 octets, la plus grande charge UDP que §18.2 de
RFC 9000 permet d'annoncer. Cette borne est réelle, elle se vérifie, et **elle
met les AEAD hors d'atteinte de leurs propres limites** — ce qui permet de
traiter leur refus comme l'impossibilité qu'il est.

### Une garde qu'on ne peut pas atteindre est une garde qu'on ne peut pas vérifier

Les bornes d'usage de §6.6 valent 2^23 paquets chiffrés et 2^36 à 2^52 paquets
refusés. Une première écriture les comparait directement : c'était juste, et
aucun test ne pouvait le montrer.

Elles vivent maintenant dans le compteur, et l'on peut en poser de plus basses.
§6.6 l'autorise explicitement, un opérateur prudent peut le vouloir, et les
tests s'en servent — **on peut descendre, jamais monter** : l'annexe B démontre
ces bornes, elles ne sont pas des préférences.

### La borne d'intégrité existe parce que QUIC jette au lieu de fermer

TLS ferme au premier enregistrement qui ne s'authentifie pas. QUIC JETTE le
paquet et continue — sans quoi n'importe qui fermerait une connexion en envoyant
un datagramme. Mais cela donne à un adversaire autant d'essais qu'il veut, et
c'est ce compte-là qui les borne.

Une mise à jour de clé remet à zéro le compte des paquets CHIFFRÉS, et jamais
celui des refusés : les essais d'un adversaire ne s'oublient pas parce qu'on a
changé de clé.

## L'écriture des trames, et l'aller-retour qui la vérifie

Un décodeur sans encodeur ne se vérifie que sur des exemples. Avec lui, il se
vérifie sur **tout ce qu'on peut fabriquer** — c'est la propriété d'aller-retour,
et c'est la seule qui couvre les combinaisons auxquelles personne n'a pensé.

Deux détails valent d'être écrits :

- **une trame `STREAM` lue sans champ de longueur se réécrit AVEC.** La forme
  sans longueur n'a de sens qu'en dernière position d'un paquet, et l'écrivain ne
  sait pas s'il y est. C'est à l'appelant de choisir cette économie, et
  `write_last` la lui donne.
- **un décalage nul ne s'écrit pas** : il se déduit, et l'écrire coûterait un
  octet sur la première trame de chaque flux.

Et ce qu'on refuse de lire, on refuse de l'écrire : un rang de retrait au-delà du
rang annoncé, un identifiant de connexion vide dans un `NEW_CONNECTION_ID`, un
compte de flux au-delà de 2^60. Les mêmes bornes, aux deux bouts.

## Les acquittements, et un défaut que seul le fuzz pouvait trouver

### Trois espaces de numéros, et ils ne se mélangent jamais

§12.3 : `Initial`, `Handshake` et les données applicatives ont chacun leur
numérotation. Ce n'est pas une commodité : les trois emploient des CLÉS
différentes, et le numéro de paquet entre dans le nonce. Partager la numérotation
ferait réemployer un nonce entre deux espaces — et un nonce réemployé livre la
clé d'authentification de GCM.

La seule exception est `0-RTT` et `1-RTT`, qui partagent un espace : un paquet
précoce peut être retransmis en `1-RTT`, et c'est la même donnée sous une autre
protection.

### On ne répond pas à un acquittement par un acquittement

§13.2.1 : un paquet qui ne sollicite rien ne fait rien envoyer, **même s'il laisse
un trou**. Sans cette règle, deux pairs qui n'ont plus rien à se dire
s'acquitteraient mutuellement sans fin, et la connexion ne deviendrait jamais
oisive.

En revanche, un paquet sollicitant qui arrive DANS LE DÉSORDRE s'acquitte sans
attendre : c'est ce qui évite au pair de croire à une perte et de retransmettre
ce qui était en route.

### On oublie les plus anciens, jamais les plus récents

§13.2.3 permet d'oublier des intervalles. Un pair qui enverrait des paquets aux
numéros très espacés obligerait sinon à en retenir autant qu'il en choisit. Ce
sont les récents qui empêchent une retransmission inutile — ce sont donc les
anciens qui tombent.

### L'ordre des deux côtés d'un `zip` décide lequel perd un élément

`Zip::next` interroge le PREMIER itérateur, puis le second ; si le second est
épuisé, **l'élément déjà tiré du premier est jeté**. Une première écriture de la
réunion des intervalles mettait la destination en premier : chaque écriture
consommait donc deux places de la table et n'en remplissait qu'une, laissant un
trou.

La table restait triée, les trous ne se voyaient pas, et l'on continuait d'y
ranger — jusqu'à ce qu'un intervalle se retrouve du mauvais côté d'un autre.
L'`ACK` acquittait alors **un paquet jamais reçu**, et l'émetteur, le croyant
arrivé, ne le retransmettait jamais.

C'est le pire défaut de cette famille : la connexion ne se ferme pas, rien ne se
plaint, et des données disparaissent. Il a fallu cinq numéros dans un ordre
précis pour qu'il se voie — **le fuzz l'a trouvé, et aucun test écrit à la main
ne serait tombé dessus**.

Deux leçons. La première : `zip` n'est pas symétrique, et l'employer pour éviter
une branche demande de savoir de quel côté mettre quoi. La seconde : l'invariant
qui a été violé — *la table ne prend jamais de trou* — se vérifie mieux
directement que par ses conséquences, et il a maintenant son test.

## L'ouverture d'un paquet : six étapes dont l'ordre n'est pas négociable

1. lire l'en-tête EN CLAIR, jusqu'à l'identifiant de destination ;
2. y trouver les clés ;
3. ôter la protection d'en-tête, ce qui découvre la longueur du numéro ;
4. reconstruire le numéro, qui entre dans le nonce ;
5. déchiffrer, l'en-tête servant de données associées ;
6. **alors seulement**, vérifier les bits réservés.

Chaque étape a besoin de la précédente. La sixième est celle qu'on met au mauvais
endroit : §17.2 dit « after removing both packet and header protection », et §9.5
de RFC 9001 explique pourquoi. **Refuser un paquet après n'avoir ôté que la
protection d'EN-TÊTE dit à un attaquant que son masque était bon**, et lui donne
un oracle pour le deviner.

C'est aussi pourquoi ce crate existe séparément : la grammaire ne connaît pas les
clés, le chiffrement ne connaît pas la grammaire, et ni l'un ni l'autre ne sait
ouvrir un paquet. La séparation suit l'ordre des opérations, elle n'est pas une
élégance.

### Deux façons de refuser, et elles ne se valent pas

Un paquet se JETTE, ou il condamne la connexion. La distinction n'est pas de
degré : le port est ouvert au monde entier, et **fermer une connexion sur un
paquet qu'on n'a pas pu authentifier l'offrirait à qui sait envoyer un
datagramme**.

On ne condamne donc que ce qu'on découvre APRÈS avoir déchiffré — c'est-à-dire ce
qui vient d'un pair authentifié. Les bits réservés, et l'espace de numéros
épuisé. Tout le reste se jette.

Et la question se pose une seule fois : `code()` rend `None` pour ce qui se
jette, et `se_jette()` est défini comme `code().is_none()`. Deux réponses
séparées auraient pu diverger, et c'est exactement le genre de divergence qui ne
se voit pas.

### Les charges se rendent par leurs rangs, et non par des tranches

Le déchiffrement se fait en place. Rendre une tranche du datagramme
l'emprunterait pour toute la durée du paquet, et l'appelant ne pourrait plus
ouvrir le suivant — or §12.2 en met plusieurs dans un datagramme.

Des rangs le laissent libre, et c'est lui qui découpe, puisque c'est lui qui
possède le tampon. La contrainte du protocole a donc dicté la forme de
l'interface, et non l'inverse.

### Un en-tête court ne peut être que le dernier

§12.2 : il ne porte pas de longueur. Les paquets à en-tête long, eux, disent où
ils s'arrêtent — c'est ce qui permet d'en coaliser plusieurs.

### Ce que les vecteurs de l'annexe A prouvent

Les deux `Initial` de RFC 9001 font mille deux cents et cent trente-cinq octets,
chiffrés et masqués. Les ouvrir met en jeu toute la chaîne, et **une seule des
six étapes fausse fait tout échouer**. C'est ce qu'aucun test écrit à la main ne
remplace : chaque morceau pris séparément peut être juste sans que le tout le
soit.

Le paquet du client rend sa trame `CRYPTO` de 245 octets suivie de 917 octets de
remplissage — soit exactement les 1162 que l'annexe annonce.

## Les flux QUIC (RFC 9000 §3, §4.1, §4.5, §4.6)

Un flux arrive dans le désordre et se lit dans l'ordre. Tout le reste de ce
module n'est que le moyen de tenir cette promesse-là.

### La fenêtre appartient à l'appelant, et sa taille EST la limite annoncée

`ams-quic` n'alloue pas. La fenêtre de réassemblage est donc fournie par
l'appelant, et les deux ne peuvent pas diverger : annoncer plus qu'on ne peut
retenir ferait perdre des octets qu'on a déjà acquittés, et annoncer moins ferait
attendre un pair qui a le droit d'envoyer.

### On ne peut pas retirer un acquittement

C'est la contrainte qui décide de tout dans le réassemblage. Une fois un paquet
acquitté, son contenu est à nous : le pair ne le renverra plus. Un réassembleur
qui jetterait ce qu'il ne peut pas ranger perdrait donc des octets **en
silence**, et le flux se figerait sans que rien ne l'explique.

D'où le refus explicite (`TooManyHoles`) plutôt que l'oubli, et une borne —
soixante-quatre intervalles — qu'un pair honnête ne peut pas atteindre : un
intervalle par paquet en vol au pire, et une fenêtre de trente-deux kibioctets
n'en laisse pas plus de vingt-huit sur un même flux.

### On réunit en insérant, et non après

Insérer d'abord puis réunir demande une place de plus le temps d'un appel — et
cette place-là manque exactement quand on comble le dernier trou, c'est-à-dire au
moment où le désordre DIMINUE. Un flux honnête se voyait fermer pour avoir rangé
ce qui manquait.

Défaut écrit, puis trouvé par le test qui comble les trous. Il n'aurait pas été
trouvé par le fuzz avant longtemps : il demande d'atteindre la borne, puis de
descendre.

### Une fenêtre trop courte se refuse

La règle — fenêtre aussi grande que la limite annoncée — est celle de
l'appelant. Une contrainte qu'on ne vérifie pas n'en est pas une : elle se
saurait en production, sous la forme d'un flux qui se fige. Et c'est le pire des
manquements possibles ici, puisqu'il fait exactement ce que ce module existe pour
empêcher.

### On range avant de compter

Si la place manque, rien ne doit avoir bougé. Un refus qui aurait déjà fait
monter le plus grand décalage laisserait le contrôle de connexion désaccordé de
ce que le flux dit — et l'écart ne se rattrape pas.

### C'est la somme des plus grands décalages, non le nombre d'octets

§4.1 : « the maximum of the sum of the absolute byte offsets of all streams ».
Compter les octets reçus ferait payer deux fois une retransmission, et un pair
honnête finirait par se voir fermer la connexion pour avoir renvoyé ce qu'on
n'avait pas reçu.

C'est pourquoi `Recv::on_stream` et `Recv::on_reset` rendent une PROGRESSION, et
non une longueur : le contrôle de connexion ne peut consommer que cela.

### La même arithmétique, deux fautes différentes

Dépasser la limite qu'on a annoncée est la faute du PAIR, et se dit par un
`FLOW_CONTROL_ERROR`. Dépasser celle qu'il nous a annoncée est la NÔTRE, et ne se
dit à personne : le pair fermerait la connexion sans explication. `Flow` porte
donc un côté, et la même opération rend deux fautes.

Rendre la nôtre plutôt que de la saturer en silence est ce qui la fait voir en
essai plutôt qu'en production.

### Une limite plus basse n'est pas une faute

§4.1 : « it is not an error to advertise a smaller limit, but the smaller limit
has no effect ». La refuser fermerait des connexions pour deux `MAX_DATA` arrivés
dans le désordre — ce qui arrive sans que personne n'ait tort. Il en va de même
pour `MAX_STREAMS` (§4.6), qui « MUST be ignored » s'il n'augmente pas.

### Une taille finale ne change pas

§4.5. C'est la même contradiction qu'une double longueur en HTTP/1.1 : deux
façons de savoir où un flux s'arrête, et rien pour les départager. QUIC la refuse
plutôt que de choisir, et ce module aussi — y compris APRÈS la fin du flux, car
§4.5 ne s'arrête pas à `Data Recvd`.

### Un flux annulé compte quand même sa taille finale

§4.5 : le receveur la compte dans son contrôle de connexion **même s'il n'a
jamais reçu ces octets**. C'est pourquoi `Send::reset` déclare exactement ce
qu'on a émis : moins se contredirait avec ce que le pair a déjà, plus lui ferait
réserver du crédit pour des octets qui ne viendront jamais.

### `Reset Read` est un état séparé

§3.2. Entre `Reset Recvd` et `Reset Read`, on sait que le flux est mort mais
l'application ne le sait pas encore, et c'est elle qui décide quand libérer ce
qui va avec. Lire ce qui était arrivé avant l'annulation ne ramène pas le flux
dans un état où il se terminerait normalement.

### Un `STOP_SENDING` n'est pas une fermeture, c'est une demande

§3.5 : on DEVRAIT répondre par un `RESET_STREAM`, mais rien n'oblige à le faire
dans l'instant — un `STOP_SENDING` peut croiser sur le fil le `FIN` qui rendait
la demande sans objet. C'est à l'appelant de décider, et `Send::stop_sending` lui
dit seulement qu'il y a une décision à prendre.

### On compte les flux par rang, et non par flux vivants

§4.6 : « Only streams with a stream ID less than (max_streams * 4 +
first_stream_id_of_type) can be opened ». Un flux fermé n'a pas rendu son rang ;
c'est un `MAX_STREAMS` qui rend du crédit, et lui seul.

Et ouvrir le rang N ouvre aussi tous ceux d'avant (§2.1) : les flux d'un type ne
s'ouvrent pas dans l'ordre, et un rang qui saute des numéros les crée
implicitement. Compter autrement laisserait des rangs jamais consommés, et le
plafond ne bornerait plus rien.

### Les quatre comptes sont indépendants

Deux types de flux, deux sens d'ouverture. Les confondre laisserait un pair
épuiser un crédit qu'on avait accordé pour autre chose.

### Les deux côtés d'un flux posent la même question

À la réception : « qu'est-ce qui est arrivé, et qu'est-ce qui manque ? » À
l'émission : « qu'est-ce qui est acquitté, et qu'est-ce qu'il faut renvoyer ? »
C'est le même calcul, sur les mêmes décalages, avec les mêmes façons de se
tromper. Il vit donc dans un seul ensemble d'intervalles, `Plages` : l'écrire
deux fois donnerait deux occasions de le rater.

## La machine d'état d'une connexion (RFC 9000 §8.1, §10 ; RFC 9001 §4.1, §4.9)

### Une connexion QUIC ne se ferme pas, elle s'éteint

Il n'y a pas de `FIN` à acquitter, pas de poignée de main de fermeture : un
`CONNECTION_CLOSE` part, et l'émetteur reste encore trois délais de
retransmission à répondre aux paquets en retard.

Disparaître tout de suite ferait répondre par un `Stateless Reset` au prochain
paquet retardé — c'est-à-dire dire à un pair qui n'a rien fait de mal que sa
connexion n'a jamais existé.

### La borne d'amplification est une propriété de sécurité, non de service

§8.1 : un serveur qui répond librement à une adresse qu'il n'a pas validée est
une machine à amplifier. L'attaquant écrit l'adresse de sa victime dans un
datagramme de mille deux cents octets, et le serveur envoie à cette victime ce
qu'il croit être une réponse.

D'où la borne de trois. Elle ne se règle pas : la monter donnerait un meilleur
levier à l'attaquant, la descendre empêcherait des poignées de main honnêtes
d'aboutir — un certificat ne tient pas dans 1200 octets.

Et le compte porte sur TOUS les octets reçus et attribués à la connexion, y
compris ceux des paquets qu'on a jetés. Ne compter que ce qu'on sait lire
donnerait moins de crédit à un pair honnête dont un paquet s'est perdu qu'à
celui qui n'envoie que du bruit.

### Un `Handshake` valide l'adresse, et c'est gratuit

§8.1 : ses clés ne se dérivent qu'après avoir lu les trames `CRYPTO` de
l'`Initial`, ce qu'un attaquant qui usurpe une adresse ne peut pas faire — il ne
voit pas la réponse. La preuve est donc dans le fait même d'avoir su déchiffrer,
et ne coûte aucun aller-retour supplémentaire.

### Les clés se jettent, et pas au même moment des deux côtés

§4.9.1 de RFC 9001 : le client jette ses clés `Initial` quand il ÉMET son premier
`Handshake`, le serveur quand il en TRAITE un. La différence n'est pas
cosmétique : elle vient de ce que chacun sait avec certitude de l'autre.

Les clés de l'espace applicatif, elles, n'ont pas de champ dans cette machine —
§4.9.3 ne parle que des clés `0-RTT`, qu'on n'offre pas (C6), et celles de
`1-RTT` vivent aussi longtemps que la connexion. Un booléen de plus serait un
état qu'aucun événement ne peut changer.

### Le délai effectif est le plus petit des deux NON NULS

§10.1. Prendre le minimum tout court ferait qu'un pair qui n'annonce rien —
c'est-à-dire qui accepte de rester indéfiniment — annulerait le délai de celui
qui en voulait un.

Et le plancher de trois délais de retransmission existe pour qu'un pair ne puisse
pas annoncer une milliseconde et faire expirer toute connexion avant la première
retransmission.

### Le délai ne repart à l'émission que pour le premier paquet

§10.1 : « if no other ack-eliciting packets have been sent since last receiving
and processing a packet ». Le remettre à chaque envoi laisserait un pair muet
nous retenir indéfiniment, à la seule condition qu'on parle.

### L'inactivité ferme en silence

§10.1 : pas de `CONNECTION_CLOSE`. Si le pair est parti, personne ne le lira ;
s'il est encore là, son propre délai vient d'expirer aussi.

### En fermeture, on répond de moins en moins souvent

§10.2.1 : « an endpoint could wait for a progressively increasing number of
received packets ». Sans cela, un pair qui continue d'émettre — parce qu'il n'a
pas reçu notre fermeture, ou parce qu'il le fait exprès — obtiendrait une réponse
par paquet, et l'on amplifierait au moment précis où l'on n'a plus rien à dire.

On répond au premier, au deuxième, au quatrième, au huitième : l'écart double, et
le coût total reste logarithmique.

### En drainage, on ne répond jamais

§10.2.2 : sans cette règle, deux pairs qui se répondent échangeraient des
`CONNECTION_CLOSE` jusqu'à ce que l'un des deux abandonne.

Et venant de `Closing`, l'échéance ne bouge pas : « the draining state ends when
the closing state would have ended ». La repousser laisserait un pair prolonger
notre état en fermant après nous.

### Le temps vient de l'appelant

Ce crate ne lit pas d'horloge (C1). Tous les instants et toutes les durées sont
en microsecondes, et c'est l'appelant qui les fournit. La machine dit quand il
faudra la rappeler ; elle ne se réveille pas toute seule.

### Ce que le fuzz vérifie ici, et qu'un test ne peut pas

Deux des invariants sont des propriétés d'ORDRE : elles ne tiennent pas dans un
appel, mais dans une suite d'appels quelconque. Un crédit qui dépasserait la
borne après une séquence particulière d'événements, une clé qui reviendrait, un
état qui remonterait la pente — un test les vérifie sur les séquences qu'on a
imaginées, le fuzz sur celles qu'on n'a pas imaginées.

## La machine de connexion HTTP/3 (§4.1, §5.2, §6.2, §7.2.4 de RFC 9114)

### Nous sommes le serveur, et cela simplifie beaucoup

Ce serveur ne pousse pas, ne promet pas, et n'ouvre aucun flux bidirectionnel.
Les états qu'un client aurait — attendre une promesse, tenir un compte de
poussées à soi — n'existent donc pas, et pas davantage les gardes qui les
auraient protégés.

### Une connexion HTTP/3 tient à trois flux, et ils ne se ferment pas

Le flux de contrôle et les deux flux QPACK sont critiques : §6.2.1 et §4.2 de
RFC 9204 disent que les fermer est une faute, et non un adieu. Il n'y en a qu'un
de chaque par sens, et un second est une faute aussi.

La raison est la même dans les deux cas : ces flux portent l'état que les autres
présupposent. Un flux de contrôle qui se ferme emporte le seul canal par où la
connexion s'entend ; un second prétendrait décrire le même état deux fois, et
rien ne dirait lequel croire.

`on_critical_stream_closed` ne rend jamais `Ok`, et c'est voulu : son type dit ce
que la RFC dit, plutôt que de laisser l'appelant croire qu'il existe une
fermeture bénigne.

### Un type de flux inconnu n'est pas une faute de connexion

§6.2 : « The recipient MUST NOT consider unknown stream types to be a connection
error of any kind. » On abandonne le flux, et rien de plus — c'est ce qui permet
à une extension d'ouvrir les siens sans casser les pairs qui ne la connaissent
pas.

### La règle de §6.2.1 passe avant celle de §7.2

« If the first frame of the control stream is any other frame type, this MUST be
treated as a connection error of type H3_MISSING_SETTINGS. » *Any other* ne fait
pas d'exception pour les trames qui n'avaient de toute façon pas leur place là.

Les deux règles ferment la connexion, mais pas avec le même code — et c'est le
code que le pair lira dans son journal pour comprendre ce qu'il a fait de
travers. Lui dire « trame inattendue » quand il a simplement oublié ses réglages
l'enverrait chercher au mauvais endroit.

Le premier jet vérifiait la place d'abord ; la divergence a été trouvée par le
fuzz, sur un `DATA` en première trame.

### Aucune fenêtre ne borne le flux de contrôle

§6.2.1 nous demande même de lui donner assez de crédit pour qu'il ne bloque
jamais. Un pair peut donc y écrire des `MAX_PUSH_ID`, des trames inconnues et des
`CANCEL_PUSH` sans fin : chacune coûte un traitement, et aucune ne fait
progresser quoi que ce soit.

C'est la même famille de défaut que *Rapid Reset* en HTTP/2 — un travail gratuit
qu'aucun compteur existant ne voit. Seul un progrès remet le compteur à zéro.

### Un `GOAWAY` ne remonte jamais, dans les deux sens

§5.2 en fait une faute `H3_ID_ERROR` à la réception, parce qu'un client a pu
réémettre ailleurs les requêtes qu'un `GOAWAY` précédent avait déclarées perdues.
Les réaccepter les ferait exécuter deux fois — pour un serveur de courrier, un
message livré deux fois.

Et la même règle vaut pour le nôtre, où c'est nous qu'elle protège de nous-mêmes.
§5.2 décrit l'extinction en deux temps qu'elle rend possible : d'abord le maximum,
pour que le client cesse d'ouvrir ; puis, une fois les requêtes en vol arrivées,
le rang réel de ce qu'on servira.

### Un `MAX_PUSH_ID` qui recule contredit ce qu'il a déjà autorisé

§7.2.7 ne parle que de l'augmenter. On ne pousse pas, et ce plafond ne sert donc
qu'à une chose : vérifier que le client ne se contredit pas. Le garder sans
l'employer serait inutile ; l'ignorer laisserait passer une contradiction qu'on a
le devoir de voir.

### La séquence d'un message est courte, et c'est tout l'intérêt

§4.1 : une section d'en-têtes, puis des `DATA`, puis au plus une section
terminale. Un `DATA` avant les en-têtes ou quoi que ce soit après la section
terminale est une faute de CONNEXION, et non de flux — parce qu'une telle suite
ne vient pas d'un pair qui s'est trompé sur une requête, mais d'un pair qui ne
sait pas ce qu'il fait.

Les trames inconnues, elles, ne font pas avancer la séquence et ne la rompent pas
(« before, after, or interleaved with other frames »).

Un flux qui se termine sans en-têtes, en revanche, ne condamne que lui-même : un
client qui abandonne sa requête en route n'a pas cassé la connexion.

## L'administration par l'API, et le jeton qui l'ouvre

Un mot de passe ouvre le courrier, la soumission et la supervision de SON compte.
Il n'ouvre pas l'administration, et cette limite est dans le code, non dans une
configuration : un réglage finirait par être basculé, et un compte compromis
deviendrait alors le serveur entier.

Restait une contradiction : les ressources d'administration existaient dans le
routage, exigeaient une portée `Admin`, et **aucun jeton que ce serveur sait
émettre ne la portait**. Elles étaient donc du code qu'aucune requête ne pouvait
atteindre.

### Le jeton se frappe là où vit déjà le secret

`air-mail-admin token <config> --login <nom>` scelle un jeton `Admin` avec le
secret que la configuration porte. C'est donc depuis la machine du serveur, par
qui peut lire ce fichier — **la même autorité que celle qui peut arrêter le
service ou lire les boîtes**. On n'en ajoute aucune, et l'affirmation de
l'en-tête d'`api.rs` reste vraie mot pour mot.

Un quart d'heure par défaut, douze heures au plus. C'est court, et c'est le
point : ce jeton ouvre le serveur entier, et un jeton qui traîne dans un
historique de terminal est un jeton volé. Le refrapper coûte une commande.

Le nom de compte n'a pas besoin d'exister : il ne désigne pas une boîte, il dit
QUI AGIT. Exiger un compte existant ferait croire que le jeton en ouvre la boîte.

### Le secret hexadécimal se lit à un seul endroit

Le serveur le lit pour vérifier les jetons, l'outil pour en frapper. Deux lectures
de la même chaîne auraient fini par différer — l'une acceptant une longueur
impaire, l'autre non — et un secret réputé bon d'un côté n'aurait plus été la même
clé de l'autre. `ams_api::key_from_hex` est donc unique, et rend **trois cas
distincts** : longueur impaire, caractère non hexadécimal, clé trop courte.

Trois cas, et non une faute unique, parce que celui qui lit ce refus a écrit la
configuration : il a le droit de savoir ce qu'il doit corriger. C'est l'exact
contraire de ce qu'on dit à un client de l'API, et pour la même raison — ce qui
apprend à qui sonde ne doit pas se dire, ce qui aide qui répare doit se dire.

### Une représentation de compte ne porte aucun secret

§3.2 de RFC 9110 : elle dit l'état d'une ressource. Le mot de passe est une
ressource à part, qui ne se lit pas — et la séparation n'est pas une question de
présentation : c'est ce qui rend **impossible** de fuir une empreinte en lisant un
compte.

### Voir et lever un bannissement

C8 punit sans que personne ne décide, et c'est tout l'intérêt. Mais un garde qui
punit sans qu'on puisse voir qui il punit est un garde qu'on ne peut pas corriger :
un exploitant dont le propre réseau se fait bannir n'aurait que le redémarrage pour
s'en sortir, et redémarrer effacerait aussi les peines méritées.

**Lever, c'est oublier — et non raccourcir la peine.** Effacer la seule date de fin
laisserait les compteurs qui l'ont déclenchée : le premier événement suivant
rebannirait la source, et l'exploitant croirait sa levée sans effet. C'est aussi ce
qui rend la place : une table pleine de peines cesse d'apprendre, et lever en
libère une.

La levée répond `204` qu'il y ait eu quelque chose à lever ou non. Une source non
bannie EST dans l'état demandé, et répondre `404` ferait de cette ressource un
moyen de SONDER qui est banni sans avoir à lister.

Le bannissement se dit en **temps restant**, et non en date : l'horloge du garde
compte depuis l'ouverture du serveur et n'a de sens que pour lui. Il dit aussi la
longueur du préfixe — sans elle, « 2001:db8:: » ne dirait pas qu'un `/64` entier
est puni, et un exploitant croirait n'avoir banni qu'une machine. Cette longueur
voyage dans un champ à part : une barre oblique dans un chemin ferait deux segments
d'un seul (§3.3 de RFC 3986), et le routage y verrait une autre ressource.

### Le magasin de comptes est modifiable pendant qu'on sert

Les comptes étaient un `Arc<Vec<Account>>` lu une fois au démarrage. C'était juste
tant que rien ne les changeait ; ouvrir l'administration en écriture le rend faux.

**UN INSTANTANÉ PAR OPÉRATION, ET NON UN VERROU TENU.** La vue rend un `Arc` et
relâche le verrou aussitôt. Une remise en cours garde donc la vue qu'elle avait au
début — un `RCPT` accepté ne doit pas devenir un `RCPT` refusé au milieu du `DATA`
parce qu'un administrateur passait par là. Tenir le verrou pendant une transaction
ferait l'inverse : une écriture d'administration attendrait qu'un pair lent finisse
de parler.

**ON ÉCRIT D'ABORD, ON PUBLIE ENSUITE.** Si l'écriture échoue, la vue en mémoire
n'a pas bougé et le serveur continue de servir la vérité qui est sur le disque.
L'ordre inverse ferait servir un compte qui disparaîtrait au prochain démarrage,
sans que rien ne l'ait dit.

**ET CE QU'ON PUBLIE EST CE QU'ON A RELU.** Toute modification est réencodée puis
relue par le décodeur du démarrage. S'il la refuse, la modification est refusée :
il devient **impossible** d'écrire un magasin sur lequel le serveur refuserait de
redémarrer. C'est aussi ce qui donne gratuitement toutes les invariantes — nom
licite, pas de nom en double, empreinte au-dessus du plancher, pas d'adresse
partagée entre deux comptes. Les redire ici en aurait fait une seconde liste, qui
divergerait le jour où l'une changerait.

Le remplacement du fichier passe par `rename`, avec deux `fsync` : le premier met
les octets sur le disque avant que le nom ne les désigne, le second met le `rename`
lui-même sur le disque. C'est la discipline du Maildir, pour la même raison.

### La carte des boîtes a dû devenir modifiable aussi

Conséquence qu'on ne voit qu'en écrivant : un compte créé n'a pas de boîte. La
carte était lue une fois au démarrage, et un compte neuf aurait pu s'authentifier
sans jamais rien recevoir. **Un demi-compte est pire qu'un refus, parce que rien ne
le dit.**

La boîte s'ouvre donc AVANT que le compte ne soit écrit : si elle ne peut pas
s'ouvrir, le compte n'est pas écrit et rien n'a changé. L'ordre inverse laisserait
un compte inscrit sans boîte, à réparer à la main. Un répertoire qui survit à un
échec n'est pas un problème : une boîte vide ne se distingue pas d'une boîte neuve.

**RETIRER UN COMPTE NE SUPPRIME PAS SA BOÎTE.** Effacer des messages est
irréversible, et rien dans « retirer un compte » ne demande cela — un administrateur
qui se trompe doit pouvoir revenir. C'est aussi ce que fait déjà
`air-mail-admin account remove`, et deux outils qui feraient deux choses du même mot
seraient un piège.

### Ce qu'on refuse se dit ICI, contrairement à une soumission

Un dépôt refusé rend toujours la même réponse, pour que la soumission ne serve pas à
énumérer les comptes. Un compte refusé, lui, DIT pourquoi : qui le lit tient un jeton
d'administration, donc l'autorité qui peut déjà lire la liste des comptes. Lui cacher
la cause ne protégerait rien et l'enverrait chercher au hasard.

C'est la même règle que pour le secret de scellement mal écrit, et le même critère :
ce qui apprend à qui sonde ne se dit pas, ce qui aide qui répare se dit.

### `POST` crée, `PUT` pose un état

`POST /v1/accounts` refuse un compte qui existe déjà — `409`, parce que la demande
est bien formée et que c'est l'ÉTAT qui l'empêche (§15.5.10 de RFC 9110) ; un `400`
enverrait le client relire un corps qui n'a rien à corriger.

`PUT /v1/accounts/{compte}` crée ou remplace, et redemander le même état deux fois
donne le même résultat (§9.3.4). Un `login` dans le corps qui contredirait le chemin
est refusé : §3.4 fait de l'URI l'identité de la ressource, et deux noms poseraient
la question de savoir lequel nomme le compte.

**CE QU'UNE RESSOURCE N'EMPLOIE PAS, ELLE LE REFUSE.** Un `PUT` sur le secret qui
accepterait un champ `addresses` en silence ferait croire au client qu'on a changé
ses adresses. Et l'absence d'un champ n'est pas une liste vide : l'un ne touche pas
aux adresses, l'autre les efface toutes.

## La soumission par l'API (`POST /v1/submissions`)

La ressource répondait `501`. Elle remet désormais **localement**, par le même
chemin que SMTP : `MaildirDelivery`, les mêmes écritures, le même magasin. Une
seconde façon de remettre aurait fini par diverger, et deux messages identiques
n'auraient pas eu le même sort selon la porte d'entrée.

### Un compte n'écrit qu'en son nom

Le `From:` doit être une adresse que le compte authentifié déclare. Sans ce
contrôle, un compte ouvert suffirait à écrire au nom de n'importe qui d'autre sur
ce serveur — et le destinataire n'aurait aucun moyen de le voir, puisque le
message serait par ailleurs parfaitement authentique.

**Les adresses de RÉCEPTION servent d'identités d'émission**, et c'est une
équivalence qu'on pose : un compte peut écrire depuis ce qu'il peut recevoir. Elle
est conventionnelle, et elle évite un second champ dans le magasin de comptes qui
pourrait diverger du premier.

### Ce serveur ne relaie pas, et le dit en refusant tout

Un destinataire qui ne mène à aucun compte d'ici fait refuser le dépôt ENTIER.
L'accepter à moitié laisserait l'expéditeur croire que son message est parti là où
il ne partira jamais. Même chose pour un destinataire qu'on ne sait pas lire :
l'écarter en silence remettrait le message à moins de monde que l'expéditeur ne
l'a demandé, et rien dans la réponse ne le lui dirait.

### Une seule réponse pour toutes les raisons de refus

En-tête illisible, `From:` qui n'est pas à soi, destinataire illisible,
destinataire d'ailleurs : la même. Les distinguer ferait de la soumission un moyen
d'**énumérer les comptes locaux** — « celui-ci passe, celui-là non » —, et un seul
compte ouvert suffirait alors à dresser la liste de tous les autres. C'est la même
règle que pour un refus d'identifiants, et elle vaut pour la même raison.

### Le `Bcc` ne part pas

§3.6.3 de RFC 5322 : une copie cachée est cachée. Le message remis est écrit sans
ce champ — **à tous**, y compris à celui qui y figure : il sait déjà qu'il l'a
reçu, et lui montrer la liste révélerait les autres. Rien d'autre ne change :
l'en-tête se réécrit champ par champ dans l'ordre où il est venu, et le corps se
recopie tel quel. Un message qu'on remanierait davantage ne serait plus celui que
l'expéditeur a signé.

`Bcc` reste en revanche un champ de DESTINATAIRES : ce qui le distingue est qu'il
ne figure pas dans le message remis, et non qu'il ne serait pas remis.

### Le type du corps se vérifie APRÈS le routage, et l'autre contrôle avant

Ce qu'un corps a le droit d'être dépend de la ressource, et la ressource n'est
connue qu'une fois le chemin résolu. Une soumission porte un message (§5.2.1 de
RFC 2046) ; tout le reste porte du JSON — et **pas l'inverse** : accepter un
message là où l'on attend du JSON ferait lire un message comme une représentation.

Ce qui ne dépend pas de la ressource — un corps sur un `GET`, un corps trop long —
se refuse toujours **avant** le routage : c'est de là que vient toute la famille de
la contrebande de requête, et on ne la laisse pas entrer le temps de savoir où elle
allait.

### Le découpage d'une liste d'adresses vit à un seul endroit

Une liste se coupe sur les virgules — mais une virgule entre guillemets, dans un
commentaire ou entre chevrons n'en est pas une. C'est la seule règle difficile, et
elle tient dans trois lecteurs qui disent où s'arrête ce qui n'est pas une adresse.

L'`ENVELOPE` d'IMAP et les destinataires d'une soumission coupent la même chose.
**Deux copies de cette règle auraient fini par différer**, et deux vues d'un même
message auraient alors désigné des destinataires différents. Les trois lecteurs ont
donc déménagé dans `ams-mime::address` ; le squelette de boucle, lui, se réécrit
sans danger — c'est ce qu'il parcourt qui est délicat, pas la façon de le
parcourir.

### Ce que l'essai de bout en bout a montré

Un essai lance le binaire, échange un jeton en HTTP/3, dépose un message en
`message/rfc822`, puis relit la boîte : le message est là, son sujet revient
décodé, et le fichier écrit sur le disque n'a plus son `Bcc`. C'est le maillon que
rien ne traversait.

Il a aussi rappelé deux choses au passage. Le serveur refuse de démarrer sur un
magasin de comptes lisible par tout le monde — un essai qui écrirait en `0644`
n'éprouverait donc pas le serveur qu'on livre. Et `cargo fmt` recolle les lignes
d'un littéral coupé par `\` : les espaces d'indentation deviennent alors un
repliement, l'en-tête ne se termine plus, et l'essai n'éprouve plus ce qu'il croit.
`concat!` ne se laisse pas faire.

## Le résumé d'un message, et pourquoi ce n'est pas une enveloppe

La liste de messages de l'API rendait `null` pour le sujet et l'expéditeur, et un
commentaire disait pourquoi : `Mailbox::info` doit rester **bon marché**, car la
session IMAP l'appelle pour chaque message qu'un ensemble pourrait désigner, y
compris ceux qu'il ne désigne pas. Y mettre la lecture d'un en-tête aurait défait
cette promesse pour les deux protocoles à la fois.

### Deux besoins contraires sur les trois points qui comptent

L'`ENVELOPE` de §7.5.2 de RFC 9051 et le résumé d'une liste REST ne demandent pas
la même chose :

- **le décodage.** L'une rend les octets tels quels — un client IMAP doit
  recevoir ce que le message porte, et pouvoir le vérifier. L'autre rend le sens,
  parce qu'un client REST affiche sans rien savoir de MIME.
- **la longueur.** Une enveloppe porte tous les destinataires, donc elle est aussi
  longue que son auteur l'a voulu — d'où l'écoulement par morceaux. Un résumé
  tient dans deux tampons dont on connaît la taille avant de lire.
- **le coût.** Une enveloppe se compose une fois par message affiché ; un résumé,
  pour toute une page.

Vouloir une seule fonction pour les deux donnerait à chacun les contraintes de
l'autre. D'où deux chemins, et `ams_mime::write_digest` à côté de
`write_envelope`.

### Ce qui borne cette voie n'est pas ce qu'on croit

La borne d'en-tête est **la même que celle de l'enveloppe**, et c'est délibéré :
une borne plus courte ferait diverger deux vues d'un même message — un sujet
visible en IMAP, absent de l'API, sans que rien ne dise pourquoi.

Ce qui borne, c'est le NOMBRE d'appels — une page de cinquante, jamais une boîte
entière — et la taille des tampons de sortie, qui viennent des RFC : §2.1.1 de
RFC 5322 pour une ligne, §4.5.3.1.3 de RFC 5321 pour un chemin.

### Le nom d'affichage n'est pas rendu, et c'est une décision

`"Votre banque" <pirate@example.test>` est un message dont le nom ment, et rien
dans la RFC 5322 ne l'interdit — c'est la forme ordinaire de l'hameçonnage.
L'adresse est la seule partie qu'un lecteur peut recouper avec ce qu'il connaît.
Un client qui veut le nom a l'`ENVELOPE` d'IMAP, ou le message lui-même.

De même, `sole_address` sert d'abord à trouver un DOMAINE : sans chevrons, elle
rend la valeur entière — blanc, plis et commentaires compris —, et le découpage du
domaine écarte ensuite ce qui traîne. C'est juste pour ce qu'elle sert, et
insuffisant pour ce qu'on affiche : ce qu'on rend doit porter une arobase et aucun
des octets qui ne font que l'entourer.

### Ce qui n'est pas rendu entier n'est pas rendu

Un sujet trop long pour son tampon rend `null`, et non sa moitié : le tronquer
ferait afficher un texte qui n'est pas celui du message — et, pire, un texte qu'on
aurait choisi de couper là. Même chose pour ce qui n'est pas de l'UTF-8 : §6.2 de
RFC 2047 laisse un mot encodé nommer un jeu qu'on ne sait pas convertir, et l'on
recopie alors tel quel plutôt que d'inventer une conversion. Ces octets-là ne sont
pas du texte JSON.

**Mais l'absence et le vide restent distincts** : un message sans `Subject:` rend
`null`, un `Subject:` vide rend `""`. Les confondre ferait mentir la liste dans
les deux sens.

### Un pli s'efface, il ne devient pas un blanc

Le blanc qui suit un `CRLF` appartient déjà à la valeur (§2.2.3 de RFC 5322) :
`Jean<CRLF> Dupont` vaut `Jean Dupont`, et remplacer le pli par une espace en
mettrait deux. C'est la règle que suit déjà l'`ENVELOPE`, et deux règles pour un
même pli donneraient deux textes pour un même message.

L'espace qui suit le deux-points, lui, appartient à la syntaxe et non au sujet :
`Subject: facture` a pour sujet « facture ». Le garder ferait trier et afficher de
travers chez tous les clients à la fois.

**Outillé par** : `fuzz_ams_mime_digest`, cinquante-quatrième cible. Elle éprouve
qu'on n'écrit jamais au-delà des tampons, qu'un texte rendu ne porte pas de fin de
ligne, qu'une adresse rendue en est une, et que le résultat ne dépend pas de la
place qu'on laisse.

## L'extinction en deux temps (§5.2 de RFC 9114)

Le signal d'arrêt lâchait chaque connexion sans un mot : le client attendait son
délai d'inactivité pour découvrir qu'il n'y avait plus personne, et n'apprenait
jamais lesquelles de ses requêtes n'avaient pas été traitées. §5.2 décrit
exactement la manœuvre qui manquait.

### D'abord l'identifiant maximal, puis le rang réel

« An endpoint MAY send multiple GOAWAY frames indicating different identifiers,
but the identifier in each frame MUST NOT be greater than the identifier in any
previous frame. » Le premier `GOAWAY` porte donc le maximum : il dit « n'ouvre
plus rien » **sans condamner une seule requête en vol**. Le second, après le délai
de grâce, porte le rang qui suit la dernière requête servie.

L'ordre inverse serait faux, et c'est la raison de la règle : un client a pu
rejouer ailleurs ce qu'un premier `GOAWAY` avait déclaré perdu, et réaccepter ces
requêtes les ferait exécuter deux fois.

Le délai de grâce vaut cinq secondes — un plafond, pas une attente : dès que
toutes les connexions se sont tues, on n'attend plus. Pendant ce temps on ne
répond plus aux clients neufs : monter une poignée de main complète pour envoyer
un `GOAWAY` dans la seconde ferait perdre du temps aux deux.

### Le refus d'une requête est une PROMESSE

§8.1 : `H3_REQUEST_REJECTED` dit que la requête n'a pas été traitée. C'est ce qui
permet au client de la rejouer ailleurs sans risquer de la faire exécuter deux
fois — un `H3_REQUEST_CANCELLED` ne dirait pas cela, et un flux qu'on laisserait
pendre ne dirait rien du tout.

Le refus arrive **avant la lecture** : retenir les octets d'une requête qu'on ne
servira pas, au moment même où l'on s'éteint, serait absurde. Mais on continue de
CONSOMMER ce que le pair écrit — un `RESET_STREAM` n'arrête que notre sens (§3.3
de RFC 9000), et ne pas lire figerait sa fenêtre.

### Ce qui a dû être construit dans le transport

`ams-quic` savait annuler un flux — `Send::reset` existait, et sa taille finale
comptait déjà pour le contrôle de flux —, mais **`ams-quic-tls` n'émettait jamais
la trame**. Il a fallu la poser dans le paquet, la retenir dans l'enveloppe qui
sert à la retransmission, et la terminer à l'acquittement.

Trois choses s'y sont apprises :

- **Une annulation ne se refait pas, elle se redit.** Les octets d'un flux se
  retransmettent en reculant un curseur ; celle-ci porte une taille finale qui ne
  changera plus, donc perdue elle repart identique (§13.3 de RFC 9000).
- **Elle ne s'efface qu'à l'acquittement**, et non à l'émission. S'effacer plus
  tôt laisserait un paquet perdu emporter l'annulation en silence, et le pair
  tiendrait pour ouvert un flux que nous croirions clos.
- **Un flux annulé n'émet plus un octet** (§3.3). Sans cette garde, l'assemblage
  du paquet aurait paniqué : il tient pour impossible le refus que `on_sent`
  oppose à un flux annulé.

### Un défaut que seul l'essai sur socket pouvait montrer

Le second `GOAWAY` était écrit, puis **jeté**. Une connexion en fermeture n'émet
plus que son `CONNECTION_CLOSE` : fermer dans le même geste que l'écriture
supprimait ce qu'on venait d'écrire. Les essais du conducteur ne pouvaient pas le
voir — leur transport de fer-blanc retient tout ce qu'on lui donne.

C'est l'essai qui lit les deux `GOAWAY` sur une vraie socket qui l'a montré, et
c'est la même leçon que la configuration TLS d'HTTP/3 : ce qui n'est éprouvé
qu'en pièces détachées laisse passer ce qui ne rate qu'à l'assemblage.

L'écoute émet donc entre les deux : elle écrit les `GOAWAY`, les fait partir,
ferme, puis fait partir les fermetures. Et le code de fermeture vient de
l'application — §20.2 de RFC 9000 garde l'espace applicatif au protocole qui
roule dessus, et le transport n'a pas à connaître `H3_NO_ERROR`.

## L'API REST : le routage (`ams-api`)

### C'est la première surface de ce serveur qu'aucune RFC ne décrit

SMTP, POP3, IMAP, HTTP, QUIC : jusqu'ici, chaque octet accepté ou refusé l'était
parce qu'un document le disait. Ici, c'est nous qui décidons — et c'est
précisément pour cela que les règles doivent être écrites d'un seul endroit, sous
une forme qui se vérifie.

### On ne normalise pas : on refuse

Presque toute faute d'autorisation d'une API vit dans l'écart entre deux
écritures d'un même chemin. `/v1/accounts/marc`, `/v1/accounts/./marc`,
`/v1//accounts/marc` : trois chaînes, une ressource. Si le contrôle d'accès
regarde la chaîne et le service regarde la ressource, il existe une écriture qui
passe l'un et atteint l'autre.

Normaliser ne résout pas cela, **cela le déplace** : il faut alors que tout le
monde normalise pareil, y compris les intermédiaires, y compris demain. Refuser
n'exige d'accord avec personne : une seule écriture est acceptée, et c'est la
plus simple.

### On découpe avant de décoder, et l'on juge après

Les deux moitiés se contredisent en apparence, et ne se contredisent pas : le
découpage regarde une SYNTAXE — où sont les séparateurs — et le jugement regarde
un SENS — que dit ce segment.

Découper après décoder ferait d'un `%2F` un séparateur, et `a%2F..%2Fb`
deviendrait trois segments dont un `..`. Juger avant décoder laisserait passer
`%2e%2e`, qui s'écrit avec six octets dont aucun n'est un point et se décode en
`..`.

**Le premier jet faisait la seconde faute**, et un test l'a trouvée.

### La longueur se mesure après décodage, pour la même raison

Un nom de 255 octets s'écrit sur 255 octets, ou sur 765 s'il est entièrement
encodé. Mesurer la forme reçue ferait accepter ce nom dans une écriture et le
refuser dans l'autre — deux réponses pour une ressource.

**Défaut écrit puis trouvé par le fuzz**, sur un aller-retour qui réencodait ce
qu'on venait de décoder.

### « Une seule écriture » aurait été une propriété fausse

§6.2.2.2 de RFC 3986 déclare équivalentes les écritures qui ne diffèrent que par
le percent-encodage des caractères non réservés. La propriété juste est
l'aller-retour : réencoder ce qu'on a décodé doit redonner la même ressource.
Sans elle, il existerait un nom que le serveur accepte mais ne sait pas
désigner — et les deux moitiés du serveur ne parleraient plus du même objet.

### La chaîne vide ne peut désigner qu'une absence

Un segment vide est refusé au décodage. Il n'existe donc AUCUN segment valide
égal à `""`, et un accesseur qui rend `""` hors des bornes ne peut pas se
confondre avec un segment réel.

C'est ce qui permet à la table de routage de n'avoir aucune garde sur l'absence.
Le premier jet en avait une par accès — une douzaine de branches qu'aucun chemin
ne pouvait emprunter, et que la couverture a signalées une à une.

### Une ressource, puis une méthode — et non l'inverse

Le chemin dit CE QU'ON DÉSIGNE ; la méthode dit CE QU'ON EN FAIT. Les confondre
en une seule table rendrait impossible la distinction que §15.5.6 de RFC 9110
exige : 404 quand la ressource n'existe pas, 405 avec un `Allow` quand elle
existe mais pas avec ce verbe.

Ce n'est pas de la politesse. Un client qui reçoit 404 sur un `PATCH` ne sait pas
s'il s'est trompé de chemin ou de verbe, et réessaiera les deux.

### Chaque ressource porte sa portée, dans le même `match`

Ajouter une ressource sans lui donner de portée **ne compile pas**. C'est
l'inverse d'une liste de contrôle tenue à part, qui se désynchronise au premier
ajout — et dont le premier symptôme est une ressource servie sans droit.

Le domaine ne dépend que du chemin, le droit ne dépend que du verbe. Une
ressource qui aurait besoin d'échapper à cette règle serait le signe qu'elle en
mélange deux.

### `HEAD` demande le même droit que `GET`

§9.3.2 : il rend les mêmes en-têtes. Le laisser passer plus facilement rendrait
lisible par sa longueur ce qu'on refusait de rendre.

### L'empreinte d'un compte n'a aucune méthode de lecture

`/v1/accounts/{compte}/password` ne sert que `PUT`. C'est ce qui permet à
`GET /v1/accounts/{compte}` d'exister sans jamais rendre une empreinte : il n'y a
pas de représentation du compte qui la contienne.

### 404 pour ce qui n'existe pas ET pour ce qu'on n'a pas le droit de voir

La différence entre les deux réponses **est** l'information « cette ressource
existe », et un client sans aucun droit pourrait la collecter en balayant. 403
reste pour ce qui est visible mais interdit.

Et le message ne nomme jamais la règle touchée : « le chemin est refusé », et non
« le segment 3 contient un `..` ». La seconde formulation apprend à qui sonde
laquelle contourner. Le journal du serveur, lui, a le droit d'être précis — il ne
va pas au client.

### Quatre domaines qui n'ont rien à voir entre eux

Lire son courrier, administrer les comptes, déposer un message, regarder les
compteurs. Le premier ne doit jamais donner le deuxième : un jeton de client de
messagerie qui pourrait créer un compte serait un jeton d'administration déguisé.

Et la lecture n'est pas l'écriture — la distinction coûte un bit et évite la
faute la plus commune : un jeton donné pour consulter et qui pouvait effacer.

La portée vide est le défaut, de sorte qu'un jeton mal construit n'ouvre rien
plutôt que tout.

### Un identifiant n'a qu'une écriture

« 12 », et ni « +12 », ni « 012 », ni « 0x0c ». Chacune désigne le même message,
et chacune est une seconde clé pour un cache ou pour un journal.

Et la vérification est sur CHAQUE route qui en porte un, pas seulement la plus
courte : chacune est une porte, et une porte oubliée suffit.

## L'API REST : les jetons porteurs

### Ce n'est pas un JWT, et c'est la décision principale

Un JWT porte son algorithme DANS le jeton, dans un champ `alg` que le
vérificateur est censé lire pour savoir comment vérifier. C'est demander à un
message non authentifié comment l'authentifier, et deux familles d'attaques
entières vivent dans cette question : `alg: none`, qui supprime la vérification,
et la confusion `RS256` → `HS256`, qui fait vérifier une signature avec la clé
publique prise pour un secret partagé.

Ce jeton n'a pas de champ d'algorithme. Sa version en fixe un seul, et il n'y a
qu'une version. Il n'existe donc rien à négocier, et par conséquent rien à
confondre.

### L'ordre de vérification est tout

1. on décode l'écriture — et l'on refuse ce qui a plusieurs formes ;
2. on découpe la structure, **sans rien en croire** ;
3. on vérifie le sceau, sans jamais s'arrêter plus tôt ;
4. **et alors seulement** on interprète les champs.

Intervertir 3 et 4 ferait agir sur une expiration, une portée ou un nom de compte
que personne n'a authentifiés — c'est-à-dire sur ce que l'attaquant a écrit.

### HMAC est écrit ici, et vérifié contre RFC 4231

HMAC n'est pas une primitive : c'est une construction de quinze lignes au-dessus
d'un hachage, et RFC 4231 en donne sept vecteurs d'essai. Ces vecteurs prouvent
le résultat, là où appeler une bibliothèque ne prouve que la provenance.

Et l'écrire ici rend infaillible ce qui ne l'était pas : le constructeur des
bibliothèques HMAC rend un `Result` qu'aucune clé ne peut faire échouer, donc une
branche qu'aucun essai ne peut atteindre.

**Les motifs des vecteurs se construisent, ils ne se transcrivent pas.** Le
premier jet les recopiait à la main ; deux des sept étaient faux — un compte
d'octets répétés, chaque fois. Un vecteur mal transcrit ne prouve plus rien : il
fait échouer un code juste, ou passer un code faux.

### La comparaison est la moitié qui compte

Un sceau juste vérifié avec un `==` ne protège rien. `==` s'arrête au premier
octet qui diffère, et le temps qu'il met dit combien d'octets étaient bons : on
devine alors le sceau octet par octet, en trente-deux fois deux cent cinquante-six
essais au lieu de deux à la puissance deux cent cinquante-six.

### Une seule écriture par jeton

§3.5 de RFC 4648 : « the pad bits MUST be set to zero by conforming encoders », et
un décodeur qui les ignore accepte plusieurs écritures d'une même valeur.

Pour un jeton porteur, ce n'est pas une subtilité d'encodage : c'est une liste de
révocation qui ne reconnaît plus le jeton qu'elle a révoqué, ou un compteur
d'usage qu'on remet à zéro en changeant un caractère.

**Le calcul de ces bits est plus subtil qu'il n'y paraît.** Un groupe de `n`
caractères porte `6n` bits, dont `8(n-1)` font des octets ; le reste est du
remplissage. Le premier jet comptait les bits des caractères ABSENTS — douze au
lieu de quatre — et le masque couvrait alors les données elles-mêmes : « Zg », le
vecteur de §10 de RFC 4648 pour « f », se refusait. Trouvé par les vecteurs.

### Un jeton ne se révoque pas tout seul

Il se vérifie sans consulter quoi que ce soit — c'est ce qui le rend utilisable
sans état. Sa seule fin garantie est donc son expiration, et plus il vit, plus
longtemps un vol reste utile. D'où la borne de douze heures, vérifiée **à
l'émission** : la vérifier seulement à la lecture laisserait circuler des jetons
qu'on refuserait ensuite sans que personne ne comprenne pourquoi.

Et l'identifiant qu'il porte est ce qui rend une révocation possible : sans lui,
deux jetons du même compte avec la même expiration seraient identiques, et
révoquer l'un révoquerait le compte.

### Un jeton expiré se distingue d'un jeton faux, et cela ne coûte rien

On ne l'atteint qu'après un sceau valide : le dire n'apprend donc rien à qui
forge. Et cela apprend au client honnête qu'il doit se réauthentifier plutôt que
de croire son jeton refusé.

### Une clé ne s'affiche pas

Pas de `PartialEq`, et un `Debug` qui écrit `Key(<secret>)`. Une clé qui apparaît
dans un journal n'est plus une clé.

### Un seul espace après `Bearer`

§11.1 de RFC 9110 rend le nom du schéma insensible à la casse — le refuser
écarterait des clients conformes. Mais §11.4 tolère des espaces supplémentaires,
et les accepter donnerait deux écritures d'un même en-tête : c'est la valeur
entière qu'un journal ou un cache retient. Un jeton ne porte de toute façon
aucune espace.

## L'API REST : les représentations JSON

### Échapper n'est pas une formalité, c'est la sécurité entière

Presque tout ce que cette API rend vient d'ailleurs : un nom de boîte qu'un
client a choisi, un sujet qu'un inconnu a écrit, une adresse qu'un serveur
distant a envoyée. Un seul guillemet non échappé dans l'un d'eux ferme la chaîne,
et ce qui suit devient de la STRUCTURE — des champs que personne n'a voulus, dans
un document que le client croira de nous.

C'est la même faute que l'injection SQL, avec le même remède : ne jamais
concaténer, toujours passer par un écrivain qui sait ce qu'il écrit.

On échappe au-delà de ce que §7 de RFC 8259 exige. `<`, `>` et `&`, parce qu'un
document JSON finit parfois dans une page HTML et qu'un `<` non échappé y ouvre
une balise. `U+2028` et `U+2029`, licites en JSON, parce qu'ils **terminent une
ligne en JavaScript** : ce n'est pas notre faute, mais c'est notre client qui
plante.

### La structure est tenue par le type, et `finish` refuse l'inachevé

Un écrivain qui laisserait poser `{` puis `]` produirait un document illisible qui
partirait tout de même avec un 200. Et un JSON tronqué servi avec un 200 est pire
qu'une erreur : le client le lit à moitié, et croit avoir tout.

### Pas de nombres à virgule, dans un sens comme dans l'autre

§6 laisse la précision à l'implémentation et prévient que seuls les entiers de
-(2^53)+1 à (2^53)-1 sont sûrs d'être interopérables. Un flottant écrit ici serait
relu ailleurs avec une autre précision. Cette API n'a de toute façon que des
entiers à rendre : ce qui n'existe pas ne peut pas diverger.

### Le type de problème vient du code d'état, et non de la raison

C'est la décision qui compte dans les documents d'erreur. `NoSuchResource` et
`Forbidden` répondent toutes deux 404, précisément pour que « cette ressource
existe » ne se lise pas dans la réponse. Si le `type` venait de la raison, il
rendrait immédiatement la distinction qu'on venait d'effacer.

En le dérivant du code, l'indiscernabilité devient **structurelle** : deux raisons
qui partagent un code partagent nécessairement un type. Il n'y a plus de règle à
maintenir, seulement une fonction — et un essai vérifie que les deux documents
sont identiques octet pour octet.

Par la même logique, toutes nos fautes internes disent la même phrase : les
distinguer apprendrait au client ce que notre code a fait de travers, ce à quoi
il ne peut rien. Le journal du serveur, lui, garde la raison exacte.

### On n'est jamais seul à lire un corps JSON

Un corps traverse souvent plus d'un logiciel : un mandataire qui journalise, une
passerelle qui filtre, et nous. Si deux d'entre eux ne lisent pas la même chose
dans les mêmes octets, le filtre protège un document que le serveur ne verra
jamais.

Le lecteur refuse donc tout ce sur quoi les analyseurs divergent, même quand la
RFC le tolère :

- **les clés répétées** — §4 dit seulement « SHOULD be unique », et chaque
  analyseur en fait ce qu'il veut. `{"admin":false,"admin":true}` est le cas
  d'école ;
- **ce qui suit la valeur racine** — `{"a":1}{"b":2}` fait un document pour nous
  et deux pour un lecteur en flux ;
- **les échappements dans les clés** — savoir lequel de deux noms équivalents
  gagne est une question qu'on préfère ne pas poser, et les refuser rend la
  détection des doublons exacte ;
- **les virgules finales, les zéros de tête, les moitiés de paire
  d'indirection** — chacune a au moins deux interprétations répandues, dont
  certaines silencieuses.

Aucun client honnête n'écrit rien de tout cela.

### Le lecteur ne récurse pas

La pile d'imbrication est un tableau de taille fixe. Un corps qui n'est que cent
mille crochets ouvrants ne fait donc pas grandir la pile d'appels : il se heurte à
une borne, et se refuse.

### On ne décode que ce que l'appelant demande

La plupart des chaînes d'un corps n'ont aucun échappement : les rendre telles
quelles évite de copier, et évite surtout d'exiger un tampon pour chacune. Ce qui
en a se décode à la demande.

Et le signe d'un nombre est séparé de sa grandeur : aucun type entier de Rust ne
porte à la fois `u64::MAX` et les négatifs, et en choisir un obligerait à refuser
à la LECTURE ce que l'appelant aurait peut-être accepté.

### Ce que le fuzz vérifie ici, et qu'aucune moitié ne pourrait prouver seule

C'est la seule cible où l'écriture et la lecture d'un même format se font face.
Cela permet l'aller-retour : **ce que l'écrivain produit, le lecteur le relit à
l'identique.** Si l'un échappe mal ou si l'autre décode mal, la propriété s'en
aperçoit — sur des chaînes qu'on n'a pas choisies.

S'y ajoutent quatre invariants qui ne tiennent pas dans un appel : un document
accepté est équilibré et fini, aucune de ses clés n'est répétée ni échappée,
chacune de ses troncatures se refuse, et le lecteur avance toujours — un corps de
`n` octets rend au plus `n` événements, donc la boucle de l'appelant se termine.

## Le raccordement HTTP : la session (`ams-session::http`)

### Écrite une fois, servie par deux protocoles

HTTP/2 et HTTP/3 ne partagent aucun octet de cadrage, mais ils produisent tous
deux un `RequestHead` : une méthode, une cible, des champs. Tout ce qui suit —
router, authentifier, autoriser, refuser — ne dépend que de cela.

L'écrire deux fois, ce serait se donner deux occasions de l'écrire différemment,
et une différence entre les deux moitiés d'un même serveur est exactement ce
qu'un attaquant cherche : il lui suffirait de choisir le protocole où la règle
manque.

### Elle ne touche à rien, et c'est tout son objet

Cette session ne lit aucune boîte, ne vérifie aucun mot de passe, n'écrit aucun
message. Elle décide, et rend à l'appelant ce qu'il reste à faire — la même forme
que les sessions SMTP, POP3 et IMAP, et pour la même raison : une machine qui
n'attend jamais n'a besoin ni d'horloge, ni de disque, ni de réseau (C1).

### Trois refus précèdent le routage

Ce qui vaut pour toute ressource se vérifie avant de savoir laquelle est visée :
sinon, il existerait une ressource dont le chemin, à lui seul, ferait sauter une
règle générale.

1. **Le schéma doit être `https`.** La grammaire d'`ams-proto-http` accepte les
   deux et dit elle-même que « que `http` soit recevable est une question de
   POLITIQUE ». C'est ici qu'on la tranche (C4).
2. **Un corps n'est permis que là où il a un sens.** §9.3.1 de RFC 9110 : « content
   received in a GET request has no generally defined semantics ». Ce qui n'a pas
   de sens défini se lit différemment d'un logiciel à l'autre, et c'est de là que
   vient toute la famille de la contrebande de requête.
3. **Le type d'un corps doit être celui qu'on lit.** Les paramètres sont admis
   (§8.3), la casse ne compte pas (§8.3.1), mais le type lui-même doit être
   exactement le nôtre.

### Le tampon se partage en trois, et c'est ce qui rend le compte utilisable

Le chemin décodé, le jeton déchiffré, la réponse. Le premier jet déchiffrait le
jeton dans un tampon local, et cherchait ensuite le nom de compte dans l'écriture
du jeton — qui est encodée, donc ne le contient pas. Trois parts disjointes du
tampon de l'appelant font vivre le nom aussi longtemps que la réponse, sans
qu'aucune n'écrase l'autre.

### Une durée de vie impossible se refuse au montage

Au-delà de ce qu'un jeton peut vivre, chaque échange d'identifiants répondrait
500 — une faute de configuration qui ne se verrait qu'en production, requête après
requête. `Http::new` la refuse une fois pour toutes.

### Ce qu'on n'écrit pas compte autant

Pas de `server` : nommer le logiciel et sa version à qui demande, c'est répondre à
la première question de tout balayage.

Et deux champs sur **toute** réponse :

- `cache-control: no-store`, parce que ce qu'on rend dépend du jeton présenté, et
  qu'un intermédiaire qui garderait une réponse la servirait au compte suivant ;
- `x-content-type-options: nosniff`, parce qu'un JSON servi à un navigateur qui
  devine le type peut se faire lire comme du HTML — et ce qu'il porte vient
  d'ailleurs.

Un 401 porte en plus un `WWW-Authenticate` (§3 de RFC 6750), sans quoi un client
honnête ne peut que deviner comment s'authentifier.

### Un refus d'identifiants ne dit pas ce qui cloche

Ni « ce compte n'existe pas », ni « ce mot de passe est faux », ni « ce corps est
mal formé » : les trois se répondent à l'identique, sans quoi la forme de la
réponse dirait laquelle des trois choses on a réussie. C'est la même règle que
pour `AUTH` en SMTP.

### La bonne formulation de « aucune réponse ne redit ce que le client a écrit »

Le premier jet de la cible de fuzz cherchait les octets du client dans la
réponse. C'était plus faible ET faux : un client peut copier notre propre document
d'erreur et l'envoyer comme corps, ce que le fuzz a trouvé en quelques secondes.

Ce qui compte n'est pas que la réponse DIFFÈRE de l'entrée, c'est qu'elle n'en
DÉPENDE pas. La propriété juste est donc : **un refus est tiré d'un vocabulaire
fini**, écrit d'avance — l'un des dix documents que les dix raisons produisent, et
rien d'autre. Ajouter une raison sans l'ajouter à ce vocabulaire fait échouer la
cible, ce qui est exactement ce qu'on veut : une réponse qu'on n'a pas prévue est
une réponse qu'on n'a pas relue.

## Les représentations des ressources (`ams-session::http::render`)

### Le magasin lit, ce module écrit

Rien ici n'ouvre un fichier. L'appelant a lu la boîte — c'est son travail, et il
a le droit d'attendre — puis il passe ce qu'il a lu sous une forme que cette
crate sait rendre. La séparation n'est pas une élégance : c'est ce qui permet à
ces représentations d'être éprouvées exhaustivement, sans disque et sans horloge
(C1).

### Un UID n'est pas un rang, et c'est la décision principale

IMAP a deux façons de désigner un message : son numéro de séquence — sa place
dans la boîte — et son UID. Le premier CHANGE quand un message est effacé : le
message numéro 4 d'hier est le numéro 3 d'aujourd'hui.

Une API où l'on agit par requêtes séparées ne peut pas s'en servir. Un client qui
lirait la liste puis effacerait « le troisième » effacerait un autre message si
une livraison s'est glissée entre les deux appels. **Cette API ne connaît donc que
des UID**, et le mot « rang » n'y apparaît nulle part.

### Et un UID ne vaut que sous son `uidvalidity`

§2.3.1.1 de RFC 9051 : quand une boîte ne peut plus garantir la stabilité de ses
UID, elle change d'`UIDVALIDITY`, et tous les UID connus deviennent caducs. Il
accompagne donc **toute** représentation qui porte un UID.

### La pagination est par UID, et non par décalage

Une page repérée par « les vingt suivants à partir du rang 40 » se déplace dès
qu'un message arrive ou disparaît : le client voit deux fois le même message, ou
en saute un, sans jamais s'en apercevoir. Un curseur sur l'UID ne bouge pas.

Et la fin d'une pagination s'écrit `null`, non par l'absence du champ : un client
qui cherche `next` doit trouver une réponse, et non avoir à distinguer « il n'y a
plus rien » de « ce serveur ne pagine pas ».

### Les dates sont des nombres

Des secondes depuis l'époque, et non une chaîne. Un nombre n'a qu'une écriture ;
une date en a autant que de fuseaux, de décalages et de conventions de secondes
intercalaires — et deux logiciels qui l'écrivent différemment ne trient plus
pareil. Le client la met en forme, puisque c'est lui qui sait pour qui.

### Les drapeaux portent leurs noms d'IMAP

Deux vocabulaires pour la même chose finiraient par diverger, et un client qui
parle les deux ne saurait plus lequel croire — alors que c'est le même serveur, et
souvent la même boîte, qu'il regarde par deux fenêtres.

**Conséquence qu'il a fallu apprendre :** cinq des dix noms commencent par une
barre oblique inverse, qu'aucun JSON ne peut écrire nue. Ils sont donc TOUJOURS
échappés, et un lecteur qui se contenterait des chaînes non échappées refuserait
`\Seen` — le drapeau le plus employé de tous. Défaut écrit, puis trouvé par le
premier essai qui a nommé un drapeau système.

### On pose et l'on ôte, on ne remplace pas

Un remplacement complet des drapeaux écrase ce qu'un autre client vient de
poser : deux fenêtres ouvertes sur la même boîte se défont mutuellement, et
personne ne voit passer le conflit. Poser et ôter ne touchent que ce qu'on nomme.

Et poser puis ôter le même drapeau se refuse : choisir lequel l'emporte serait
inventer une règle que le client ne connaît pas.

### Un champ inconnu se refuse, sur une modification

Ailleurs, ignorer ce qu'on ne comprend pas est la bonne façon de rester
compatible. Sur une MODIFICATION, non : l'ignorer ferait croire au client qu'on a
fait ce qu'il demandait.

### La santé ne dit que « oui »

Pas de version, pas de date de construction, pas de nom de machine. Ce serait un
champ `server` sous un autre nom — et cette ressource-ci est justement celle qu'un
balayage interroge en premier.

### On n'écrit pas ce qu'on ne sait pas lire

C'est le défaut que le fuzz a trouvé, et il valait le détour. L'écrivain JSON
pouvait produire deux clés identiques dans un objet, ou une clé échappée — deux
choses que notre propre lecteur refuse, à juste titre.

Un écrivain qui peut produire un document que notre lecteur rejette est une
asymétrie, et les asymétries de ce genre finissent chez le client : il reçoit un
document que son analyseur lit autrement que le nôtre, ou pas du tout.

L'écrivain refuse donc désormais, comme le lecteur : les clés répétées, plus de
champs qu'on n'en retient, et les noms de champ qui ne sont pas des identifiants
ASCII. **La borne des deux côtés est la même, et ce n'est pas une coïncidence.**

## L'ALPN : ce qu'on annonce, et où l'on l'assemble

### `h2`, et rien d'autre

HTTP/1.1 n'est pas servi (C6) : son cadrage est textuel et sa longueur se déduit
de deux champs qui peuvent se contredire, d'où toute la famille des attaques par
contrebande de requête. Il n'a donc rien à faire dans une liste ALPN.

§3.4 de RFC 9113 : un client qui veut parler HTTP/2 sur TLS l'annonce par ALPN,
et le serveur le confirme. Comme on n'annonce que `h2`, un client qui n'offre que
`http/1.1` voit sa poignée de main échouer — **c'est le bon endroit pour dire
non**, puisque refuser après coup obligerait à répondre dans un cadrage qu'on ne
sait pas écrire.

### Une fonction, et non un paramètre

Une liste passée par l'appelant se remplirait un jour de `http/1.1` — « juste pour
un client ancien ». Or annoncer un protocole qu'on refuse de servir est pire que
de ne pas l'annoncer : le client le négocie, croit avoir accordé, et se voit
refuser après la poignée de main. `ams_tls::alpn()` rend toujours la même liste,
et c'est la seule qui soit sanctionnée.

L'essai vérifie l'absence autant que la présence : ni `http/1.1`, ni `http/1.0`,
ni `h2c`, ni `http/0.9`. C'est cette absence-là qui porte la garantie.

### Et pourquoi l'assemblage ne vit pas dans `ams-tls`

Poser cette liste sur une configuration demande une configuration, donc un
certificat — que cette crate ne peut pas fabriquer sans matériel, et qu'on ne
versionne pas.

**Le seuil de couverture ne mesure que les crates du périmètre sans
entrée-sortie**, et il ne lance que leurs essais. Une ligne d'assemblage posée
dans `ams-tls` ne serait donc couverte que par un essai d'intégration qui n'y
compte pas — ou bien il faudrait fabriquer un certificat dans les essais
unitaires, et faire dépendre le seuil de la présence d'`openssl` sur la machine.
Une fragilité qu'on ne veut pas dans un gate.

La découpe suit donc ce que chaque morceau peut prouver seul : **ce qu'on annonce
se vérifie sans rien, l'assemblage demande de quoi assembler.** Le second vit dans
l'écoute qui s'en sert, avec un essai d'intégration qui fabrique un certificat à
la volée.

## L'écoute HTTP/2 (`ams-loop-tokio::http`)

### Il n'y a pas de HTTP en clair, et ce n'est pas un réglage

SMTP, POP3 et IMAP montent en TLS par `STARTTLS`, et servent en clair quand aucun
certificat n'est nommé. Cette écoute-ci ne le peut pas : elle porte des jetons
porteurs, et un jeton qui traverse un réseau en clair est un jeton volé. La
configuration TLS n'est donc **pas** un `Option` — sans certificat, il n'y a pas
d'écoute HTTP du tout (C4).

### L'ALPN se vérifie, même en n'annonçant que `h2`

Un client qui n'envoie aucune extension ALPN négocie « rien » **sans que la
poignée de main échoue**, et §3.4 de RFC 9113 en fait une faute. Le refus après
coup ne coûte rien de plus, mais il faut le poser explicitement : la seule
présence d'une liste d'un élément ne suffit pas.

Un client qui n'offre que `http/1.1`, lui, voit sa poignée de main échouer. C'est
le bon endroit pour dire non : refuser après obligerait à répondre dans un cadrage
qu'on ne sait pas écrire.

### Une requête à la fois, et c'est annoncé

`SETTINGS_MAX_CONCURRENT_STREAMS = 1`. Entrelacer sert plus vite, mais demande de
retenir autant de requêtes à demi lues que de flux ouverts — donc de laisser le
pair décider combien de mémoire on garde. C7 tranche, et le pair reçoit le réglage
avant sa première requête.

### La boucle conduit, une interface répond

Tout ce qui touche au magasin vit derrière le trait `Api` : la boucle n'ouvre
aucune boîte et ne connaît aucun compte. C'est la même séparation qu'entre une
session et sa politique, et pour la même raison — ce qui décide et ce qui exécute
ne se vérifient pas de la même façon.

L'autorisation est faite **avant** l'appel : recevoir `Api::serve` veut dire qu'un
jeton scellé par notre clé, non expiré, ouvrait la portée que la route exige.
Cette interface n'a donc rien à revérifier, et rien à décider sur l'identité de
qui appelle.

Et l'identifiant qui distingue un jeton des autres du même compte vient de
l'appelant, lui aussi : une source d'aléa est une dépendance, et les dépendances
entrent par l'appelant.

### Deux règles que la relecture a imposées

**Le bloc d'en-têtes se décode même quand le flux est refusé.** La table HPACK est
commune à toute la connexion : sauter un bloc décalerait tous les suivants, et le
pair et nous ne lirions plus les mêmes en-têtes sans qu'un seul cadre soit fautif.

**Un corps qui déborde ne se tronque pas.** On cesse d'écrire, et la session voit
un corps plus court que ce qui était annoncé — ce qu'elle refuse. Tronquer en
silence ferait agir sur ce que le client n'a pas demandé.

### Ce que l'essai de bout en bout prouve, et ce qu'il ne peut pas

Le client est écrit à la main et **n'emploie pas notre encodeur HPACK** : les
en-têtes partent en représentations littérales sans indexation, que §6.2.2 de
RFC 7541 impose à tout décodeur d'accepter. C'est donc bien notre décodeur qui est
mis à l'épreuve, par des octets qu'il n'a pas produits.

**L'autoréférence qui demeure est du côté des réponses** : pour lire un code
d'état il faudrait décoder du HPACK, et le seul décodeur à portée est le nôtre.
L'essai contourne le problème plutôt que de le masquer — il vérifie les CORPS, qui
ne sont pas comprimés, et nos documents d'erreur portent leur code d'état à
l'intérieur.

Ce qui reste hors de portée : qu'un vrai client tiers nous lise. Cela demande un
vrai client tiers, comme `starttls.rs` emploie un vrai OpenSSL.

## L'API adossée au magasin (`ams-server::api`)

### Une seule vue du magasin pour les deux protocoles

Ce module ne lit pas les Maildir : il interroge le MÊME `Mailboxes` qu'IMAP. Ce
n'est pas une économie de lignes.

Une seconde voie de lecture aurait sa propre idée de ce qu'est un message
lisible, de ce que vaut un `UIDVALIDITY`, de quels dossiers existent. Deux
fenêtres ouvertes sur la même boîte finiraient par ne plus montrer la même chose,
et personne ne saurait laquelle croire.

### Un compte ordinaire n'obtient jamais la portée d'administration

Un mot de passe ouvre le courrier, la soumission et la supervision de SON compte.
Il n'ouvre pas l'administration — créer un compte, en effacer un, lever un
bannissement.

**Cette limite est dans le code, et non dans une configuration** : un réglage
finirait par être basculé, et un compte compromis deviendrait alors le serveur
entier. Le serveur l'annonce au démarrage, plutôt que de le laisser découvrir.

### Le sujet et l'expéditeur ne sont pas dans une liste

`Mailbox::info` est décrite comme devant être **bon marché** : la session IMAP
l'appelle pour chaque message qu'un ensemble pourrait désigner, y compris ceux
qu'il ne désigne pas. Y ajouter la lecture d'une enveloppe ferait ouvrir un
fichier par message listé, et défairait cette promesse pour les deux protocoles à
la fois.

Les rendre demande donc une voie séparée, avec sa propre borne. **Elle existe
désormais** : voir « Le résumé d'un message, et pourquoi ce n'est pas une
enveloppe ».

### La recherche réemploie l'évaluateur d'IMAP

`ams-proto-imap` sait déjà décider si un message correspond à une expression de
§6.4.4, et `BoiteImap` sait déjà lui lire ce qu'il demande — c'est ce qui sert
`SEARCH`. Un second évaluateur aurait fini par répondre différemment de celui
d'IMAP sur le même message, et personne ne saurait lequel croire.

Les critères JSON se traduisent donc vers la syntaxe d'IMAP. **Cela demandait un
écrivain de chaîne citée**, que la crate n'exposait pas : un sujet portant un
guillemet aurait coupé l'expression en deux, et la recherche aurait porté sur la
moitié — sans faute de syntaxe, avec des résultats plausibles. `write_quoted` vit
donc là où l'expression se lit, et non chez celui qui la construit.

**LES CRITÈRES SE COMBINENT PAR « ET », ET IL N'Y A PAS D'AUTRE FAÇON.** §6.4.4
admet `OR` et `NOT` ; cette ressource ne les sert pas. Un arbre en JSON serait un
second langage de recherche à côté de celui d'IMAP, qui le sert déjà.

**DES UID, ET NON DES RANGS** (§2.3.1.1) : un rang change dès qu'un message
disparaît, et rendre des rangs ferait désigner au client, une seconde plus tard,
d'autres messages que ceux qu'il a trouvés. La réponse dit aussi si la liste est
complète — un client qui croirait avoir tous les résultats agirait sur une moitié.

### Le message brut et une partie MIME se lisent par PORTÉES

Un message fait la taille que son expéditeur a voulue ; une réponse de cette API
rend une tranche d'un tampon que la boucle a alloué. Sans les portées de §14 de
RFC 9110, un message entier ne se lirait pas du tout par HTTP — ce n'est pas un
confort qui manquerait, c'est la ressource.

**LE CONTRAT GAGNE UN CONCEPT, ET NON DES EN-TÊTES.** Ouvrir `Served` à des champs
de réponse quelconques laisserait une API poser ce qui contredit ce que la boucle
garantit — `cache-control: no-store`, `nosniff`. Elle porte donc deux choses
typées : la ressource se lit-elle par morceaux, et ce que ce corps couvre. Chaque
boucle écrit `Accept-Ranges` et `Content-Range` à sa façon ; aucune n'apprend un
en-tête nouveau.

**UNE SEULE PORTÉE, ET C'EST LA PREMIÈRE** (§14.2). Les servir toutes demanderait
une réponse `multipart/byteranges`, c'est-à-dire un cadrage MIME que cette API ne
produit nulle part ailleurs. Rendre la première est sans ambiguïté : `Content-Range`
dit exactement quels octets partent.

**CE QUI EST MAL FORMÉ S'IGNORE, CE QUI EST HORS BORNES SE REFUSE.** §14.2 :
« An origin server MUST ignore a Range header field that contains a range unit it
does not understand. » Un champ illisible n'est pas une faute du client — c'est un
champ qu'on n'a pas compris, et la réponse est celle qu'on aurait donnée sans lui.
Une portée qui commence au-delà, elle, a son propre code (§15.5.17), et la réponse
porte la taille par un `Content-Range` en forme `*` : c'est ce qui permet de
recommencer sans deviner.

### Un écart assumé : `413` quand on ne peut pas envoyer d'un coup

Sans `Range`, si la représentation ne tient pas dans une réponse, **il n'y a pas de
réponse conforme**. Envoyer l'entier est impossible ; un `206` qu'on n'a pas demandé
n'est pas conforme (§15.3.7) ; tronquer en silence serait mentir.

On répond `413` avec `Accept-Ranges: bytes`, ce qui veut dire : « je ne peux pas te
l'envoyer d'un coup, voici la porte ». C'est un écart, il est écrit ici, et sa cause
est que ce serveur ne sait pas ÉCOULER une réponse — le jour où il le saura, cet
écart disparaîtra.

### Un début et une fin ne sont pas un début et une longueur

`part_span` rend un intervalle. Les confondre faisait lire au-delà du fichier, la
lecture échouait, et une partie parfaitement présente rendait `404`. Le défaut a été
écrit, puis trouvé par l'essai qui demande la seconde partie d'un message à deux
parties — pas par la compilation, qui voyait deux `u64`.

### Trois conditions pour ouvrir le port, et aucune n'est facultative

Une adresse d'écoute, un certificat, et un secret de scellement.

**Le certificat n'est pas négociable, et c'est la différence avec les trois autres
écoutes.** SMTP, POP3 et IMAP servent en clair et refusent l'authentification ;
l'API porte des jetons porteurs, et un jeton qui traverse un réseau en clair est
un jeton volé. Ce port ne s'ouvre donc pas sans chiffrement (C4).

Chaque refus se dit **au démarrage**, avec sa raison. Un port qu'on ouvrirait pour
répondre 500 à chaque requête serait pire qu'un port fermé. Et un secret illisible
**arrête** le démarrage : une configuration qui dit vouloir l'API avec un secret
qu'on ne peut pas lire s'est trompée, et démarrer sans elle ferait croire que tout
va bien.

Les essais du binaire vérifient les trois refus **et le port fermé** : vérifier
l'annonce sans vérifier le port laisserait passer un serveur qui dit non et écoute
quand même.

### Le secret est de l'hexadécimal, et il vit dans la configuration du serveur

Pas de base64, pas de texte brut : l'hexadécimal a une seule écriture par octet,
se relit à l'œil, et ne se confond pas avec une phrase de passe — ce qui évite
qu'un secret de trente-deux octets soit renseigné avec huit caractères tapés au
clavier.

Il vit dans la configuration du serveur et non dans le fichier de comptes : ce
n'est pas un secret de compte, c'est un secret de serveur. Le changer révoque tous
les jetons en cours d'un seul coup — ce qui est parfois exactement ce qu'on veut.

### La configuration TLS de l'API n'est pas celle des autres écoutes

Elle porte l'ALPN `h2`, et rien d'autre. La partager telle quelle ferait annoncer
`h2` sur le port SMTP, où il ne veut rien dire.
