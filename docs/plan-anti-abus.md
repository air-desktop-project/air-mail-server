# Le plan anti-abus : contrôles d'enveloppe et listes noires DNS

Ce document dit ce qui remplace `rspamd` quand `air-mail-server` prend la place
de Postfix, dans quel ordre, et **ce qu'on ne fera pas**.

## Le point de départ, mesuré et non supposé

L'inventaire du 7 septembre 2026 sur `mail.narro.ch` a montré ceci : `rspamd`
étiquetait **0,15 %** des messages, ne rejetait **rien**, et les dossiers
`Junk` étaient **vides**. Cinq boîtes, 20 Mo. Le filtre bayésien n'avait donc
rien appris, faute de matière à apprendre.

**ET POSTFIX N'ATTENDAIT PAS `rspamd` POUR REFUSER.** Le même inventaire porte
ses restrictions, et elles nomment SIX contrôles d'enveloppe déjà actifs :

```
smtpd_helo_required      = yes
smtpd_helo_restrictions  = permit_mynetworks, reject_invalid_helo_hostname,
                           reject_non_fqdn_helo_hostname
smtpd_sender_restrictions = permit_mynetworks, reject_non_fqdn_sender,
                            reject_unknown_sender_domain
smtpd_recipient_restrictions = reject_non_fqdn_recipient,
                               reject_unknown_recipient_domain, ...
```

Six, et voici ce que chacun devient :

| Le refus de Postfix | Chez air-mail-server |
|---|---|
| `reject_invalid_helo_hostname` | **déjà là** — `check_domain` tient §4.1.2 |
| `reject_non_fqdn_helo_hostname` | **fait** — `--require-fqdn-helo` |
| `reject_non_fqdn_sender` | **fait** — `--require-fqdn-sender` |
| `reject_non_fqdn_recipient` | **fait** — `--require-fqdn-recipient` |
| `reject_unknown_sender_domain` | à écrire, demande le DNS (§3) |
| `reject_unknown_recipient_domain` | **sans objet** — le serveur connaît ses domaines hébergés, et refuse déjà ce qui n'en est pas |

Les deux autres lignes des mêmes restrictions ne sont pas des contrôles
d'enveloppe, et toutes deux sont déjà tenues :

- `reject_unauth_destination` est la politique de relais — `accepts_recipient`
  la porte, et son paramètre `submitter` est très exactement ce qui sépare un
  relais d'un relais ouvert ;
- `reject_sender_login_mismatch` lie le compte authentifié à l'adresse annoncée.
  Le produit le fait sur **les deux** identités du message, là où l'option de
  Postfix n'en couvre qu'une : le `From:` de l'en-tête doit router vers le
  compte, **et** le chemin de retour de l'enveloppe aussi. Ce second point avait
  manqué — un compte pouvait déposer `MAIL FROM:<victime@ailleurs.test>` sous un
  `From:` légitime, ce qui perdait le rebond et la conformité SPF chez tous les
  destinataires — et c'est réparé.

**Cela change la nature du travail, et il faut le dire net.** Les contrôles
d'enveloppe ne sont pas des durcissements qu'on ajouterait : ce sont des refus
que narro.ch applique DÉJÀ, et que le remplaçant doit RESTAURER sous peine
d'être plus permissif que ce qu'il remplace le jour de la bascule.

**Et il n'y a AUCUNE liste noire.** Nulle part un `reject_rbl_client` ni un
`reject_rhsbl_*`. Les listes noires sont donc la seule pièce de ce document qui
change vraiment le comportement du site — et la seule qu'on posera après la
bascule, jamais pendant.

**Conséquence : on ne réécrit pas `rspamd`.** Un moteur de score entraînable
pour un site qui n'a jamais eu de quoi l'entraîner serait du travail offert au
vide. On prend l'autre moitié — celle qui coûte peu et qui, chez Postfix,
travaillait déjà avant `rspamd` : les contrôles d'enveloppe.

## L'ordre, et pourquoi

**Ce qui RESTAURE ce que Postfix faisait passe avant ce qui AJOUTE.** Le jour de
la bascule, le remplaçant ne doit pas être plus permissif que le remplacé ; ce
qu'il ferait de mieux peut attendre le lendemain.

1. Le `HELO`/`EHLO` qualifié — **fait**. Pur, aucune entrée-sortie.
2. L'expéditeur et le destinataire qualifiés — **faits**, même prédicat.
3. L'existence du domaine de l'expéditeur — un aller-retour DNS, sur une action
   qui existe déjà.
4. Les listes noires DNS — la seule pièce qui n'est pas une restauration, et la
   seule qui introduise un point de panne extérieur. **Après la bascule.**

Les trois premiers doivent être en place AVANT le jour J : ce sont des refus que
narro.ch applique déjà, et les perdre serait une régression silencieuse — un
serveur plus permissif n'alerte personne, il encaisse.

## 1. Le `HELO`/`EHLO` pleinement qualifié — `--require-fqdn-helo` — FAIT

Un nom sans point (`localhost`, `mail`, `pc-de-jean`) n'est pas le nom primaire
que §4.1.4 de RFC 5321 demande. Le refuser est **permis** par cette même
section : « If the EHLO command is not acceptable to the SMTP server, 501, 500,
502, or 550 failure replies MUST be returned as appropriate. »

Trois règles que le code tient, et que les essais gardent :

- **Un littéral d'adresse passe toujours.** §4.1.4 le RECOMMANDE à qui n'a pas
  de nom. Refuser ce que la RFC conseille reviendrait à refuser les émetteurs
  les mieux intentionnés.
- **Le nom n'est JAMAIS comparé à l'adresse du pair.** La même section
  l'interdit : « if the verification fails, the server MUST NOT refuse to accept
  a message on that basis. » Le contrôle est de forme, pas de véracité.
- **Le refus ne change rien.** §4.1.4 : « The SMTP server MUST stay in the same
  state after transmitting these replies that it was in before the EHLO was
  received. » La garde précède donc `quitter_la_transaction()`, et un essai
  vérifie qu'une transaction en cours survit intacte à un `EHLO` refusé.

La grammaire de §4.1.2 était déjà tenue par `check_domain` : l'équivalent de
`reject_invalid_helo_hostname` de Postfix ne demandait aucun code neuf.

**Le défaut est faux.** Un serveur ne se met à refuser du courrier que parce que
quelqu'un l'a écrit — et un fichier de configuration écrit avant ce champ le
relit faux, puisque Cap'n Proto rend zéro pour un champ absent.

## 2. L'expéditeur et le destinataire pleinement qualifiés — FAIT

`reject_non_fqdn_sender` et `reject_non_fqdn_recipient`, tous deux actifs sur
narro.ch. Un `MAIL FROM:<jean@localhost>` ou un `RCPT TO:<paul@srv>` n'est pas
adressable depuis l'extérieur.

Ces deux-là sont **purs** : aucune entrée-sortie, la même forme que le contrôle
du `HELO`. Ce sont donc les moins chers de tous, et ils ferment à eux seuls la
moitié de l'écart de permissivité.

Le prédicat est **littéralement le même** que celui du `HELO` : `Mailbox` porte
son domaine dans un `ClientId`, le type qu'annonce déjà `EHLO`. Une seule
fonction sert les trois contrôles.

C'est ce qu'est devenu `nom_qualifie` : une fonction, trois appelants. Trois
copies de ces quatre lignes auraient fini par diverger, et la divergence aurait
été invisible — deux contrôles qui ne refusent pas tout à fait la même chose.

**Les deux exigences sont indépendantes**, comme chez Postfix où elles vivent
dans deux listes distinctes. Un exploitant qui n'en pose qu'une obtient
exactement celle-là, et un essai le garde.

**Les codes étendus diffèrent** : `5.1.8` pour l'expéditeur, `5.1.3` pour le
destinataire. Les deux manquaient à `ams-proto-smtp`, qui n'avait que `5.1.1`
— juste pour le destinataire, mensonger pour l'expéditeur. L'écart compte pour
l'émetteur : `1.8` dit « votre domaine ne peut rien recevoir », `1.3` dit
« l'adresse que vous visez ne désigne aucune boîte, où que ce soit ».

### Quatre exemptions, et aucune n'est facultative

Elles se lisent dans la configuration de narro.ch, et trois sont des pièges.

1. **Le chemin nul, `MAIL FROM:<>`.** Il n'a pas de domaine du tout. C'est celui
   des avis de non-remise, qui doivent passer sous peine d'en provoquer
   d'autres. `Path::Null` est une variante distincte : l'exemption est
   structurelle, et non une condition qu'on pourrait oublier d'écrire.
2. **`RCPT TO:<Postmaster>` sans domaine.** RFC 5321 §4.1.1.3 l'autorise, et
   §4.5.1 exige que tout serveur accepte le courrier pour `postmaster`. Le
   refuser comme « non qualifié » violerait un MUST. `Path::Postmaster` est là
   aussi une variante distincte.
3. **Les clients authentifiés.** Postfix n'applique PAS ces contrôles sur
   `submission` ni sur `smtps` : les deux services y écrasent
   `smtpd_sender_restrictions` par `reject_sender_login_mismatch,
   permit_sasl_authenticated, reject`. Le contrôle ne vaut donc que pour
   l'entrant non authentifié — le `submitter` que la politique connaît déjà, et
   que `SmtpSession::submitter()` rend. L'appliquer partout refuserait du
   courrier que narro.ch accepte aujourd'hui : la même régression que celle
   qu'on cherche à éviter, dans l'autre sens.
4. **`permit_mynetworks`** précède `reject_non_fqdn_sender` dans
   `smtpd_sender_restrictions`, mais PAS `reject_non_fqdn_recipient` dans
   `smtpd_recipient_restrictions` — celui-là s'applique même en local. Les deux
   contrôles ne sont donc pas symétriques chez Postfix, et il vaut mieux le
   savoir avant de les écrire comme s'ils l'étaient.

### Le code de refus

Postfix dit `504 5.5.2` par défaut, réglable par `non_fqdn_reject_code`. On dira
`550`, avec le code étendu de RFC 3463 qui convient — `5.1.8` pour l'expéditeur
(« Bad sender's system address »), `5.1.3` pour le destinataire (« Bad
destination mailbox address syntax »). Les deux sont des refus permanents et
l'effet sur l'émetteur est le même ; le second dit simplement POURQUOI.

## Le mécanisme des deux contrôles DNS

Les deux qui suivent ont **le même besoin** : un aller-retour DNS au milieu de
l'enveloppe. C'est la raison de les concevoir d'un bloc plutôt qu'un par un.

`air-mail-server` a déjà exactement ce motif, pour SPF. La session rend
`Action::CheckSender` **avec une réponse vide** : elle n'a rien à dire tant
qu'elle ne sait pas. La boucle résout — le DNS est une entrée-sortie, elle n'a
rien à faire dans une couche sans allocation — puis rend le verdict, et c'est la
**session** qui compose le `250`, le `550` ou le `451`. Le vocabulaire de sortie
reste clos (C1), et le noyau reste portable vers Air (C7).

Les deux contrôles n'inventent donc rien : ils ajoutent un champ de verdict ou
une action de la même famille, résolue au même endroit,
`crates/ams-loop-tokio/src/connection.rs`.

## 3. L'existence du domaine de l'expéditeur

L'équivalent de `reject_unknown_sender_domain`. Le domaine de la partie droite
du `MAIL FROM:` doit avoir un `MX` ou, à défaut, un `A`/`AAAA` — RFC 5321 §5.1
autorise ce repli. Sans quoi aucune réponse n'est possible, et un expéditeur à
qui l'on ne peut pas répondre est presque toujours un expéditeur inventé.

Ce contrôle se greffe sur `Action::CheckSender`, **qui existe déjà et se
déclenche déjà au bon moment**, celui du `MAIL FROM:`. C'est un champ de plus
dans le verdict que la boucle rend, pas une action de plus.

Trois règles :

- **`NXDOMAIN` refuse en `550 5.1.8`** — permanent : le domaine n'existe pas.
- **`SERVFAIL` ou le silence ajournent en `451 4.4.3`** — temporaire : on ne
  sait pas. Refuser définitivement sur une panne de résolution ferait perdre du
  courrier légitime pour de bon.
- **Le chemin nul est exempté**, comme au contrôle précédent et pour la même
  raison.

## 4. Les listes noires DNS sur l'adresse du pair

**Le principe.** On renverse les quatre octets de l'adresse, on y colle la zone,
on demande un `A`. `192.0.2.1` chez `zen.spamhaus.org` devient
`1.2.0.192.zen.spamhaus.org`. `NXDOMAIN` veut dire « inconnu ». Une réponse
**dans `127.0.0.0/24`** veut dire « listé », et la valeur du dernier octet dit
pourquoi — les zones ne s'accordent pas dessus : chez Spamhaus, `127.0.0.2` est
le SBL, `127.0.0.4` à `127.0.0.7` le XBL, `127.0.0.10` et `127.0.0.11` le PBL,
les adresses résidentielles qui ne devraient jamais parler en SMTP direct.

### Le moment, et qui compose la réponse

À l'ouverture de connexion, avant la bannière. C'est là que le refus coûte le
moins cher aux deux bouts, et c'est là que Postfix le fait.

**Mais la boucle ne compose pas la réponse.** La première écriture de ce plan
disait « la boucle interroge, et n'ouvre pas de session du tout si l'adresse est
listée ». C'était plus simple, et c'était faux : le `554` serait alors composé
par la boucle, et C1 veut que le vocabulaire de sortie reste clos dans la
session — sans quoi le portage vers Air le réécrirait une seconde fois.

La forme juste reprend celle de `CheckSender`, à un tour plus tôt : la boucle
résout AVANT d'appeler `greeting()`, puis appelle `client_checked(verdict)`, qui
rend **soit** la bannière habituelle, **soit** le `554` suivi d'un
`Action::Close`. La session compose, la boucle résout ; l'adresse du pair
n'entre dans la session que par ce verdict, et non par un champ de plus.

Le garde, lui, garde son cas à part : un banni ne reçoit **rien**, pas même une
bannière, parce que répondre confirmerait qu'il y a un serveur ici. Le refus
d'une liste noire, lui, PARLE — pour la raison dite plus bas.

### La panne ne doit jamais refuser

Une zone qui ne répond pas ne doit **pas** faire refuser. Un `SERVFAIL`, un
dépassement de délai, une zone révoquée : le verdict est « inconnu », et le
courrier passe. L'inverse — refuser sur une panne de résolution — transformerait
un incident DNS en panne de courrier, et c'est précisément l'accident qu'on a
passé toute la migration à rendre impossible.

### La révocation silencieuse, et la sonde qui l'attrape

Une zone publique abandonnée peut se mettre à répondre `127.0.0.1` **à tout**,
et refuser alors le courrier du monde entier. RFC 5782 §5 donne de quoi s'en
apercevoir, et en fait une obligation de la zone : « IPv4-based DNSxLs MUST
contain an entry for 127.0.0.2 for testing purposes. IPv4-based DNSxLs MUST NOT
contain an entry for 127.0.0.1. »

La sonde est donc double, au démarrage puis périodiquement :
`2.0.0.127.<zone>` **doit** répondre, `1.0.0.127.<zone>` **ne doit pas**. Une
zone qui échoue à l'une des deux est **désarmée**, avec un message
d'exploitation — une zone muette et une zone devenue folle sont l'une et l'autre
inutilisables, et la seconde est de loin la plus dangereuse. L'équivalent IPv6
est `::FFFF:7F00:2` et `::FFFF:7F00:1`, même section.

### La réponse qui n'est pas un verdict

Les grandes zones gratuites répondent dans `127.255.255.0/24` quand elles
refusent la question elle-même — question venue d'un résolveur public, ou volume
dépassé. **Ces réponses ne veulent pas dire « listé »**, et les prendre pour un
verdict ferait refuser tout le courrier. C'est pourquoi l'intervalle de verdict
est `127.0.0.0/24` et non `127.0.0.0/8` : tout le reste est « inconnu », et
journalisé.

**C'est un piège de déploiement pour narro.ch en particulier.** La machine
résout par `127.0.0.53` — `systemd-resolved`, qui suit vers l'amont configuré
par l'hébergeur. Si cet amont est un résolveur public, Spamhaus refusera
chaque question, et le serveur croira n'avoir rien à refuser. La sonde de
démarrage l'attrape : `2.0.0.127.<zone>` ne répondra pas `127.0.0.2`, et la
zone sera désarmée avec un message plutôt que d'être silencieusement inutile.
**À vérifier sur la machine avant d'armer la zone.**

### Le reste

- **Les IPv6.** Le nibble inversé, 32 étiquettes. Peu de zones les servent
  utilement ; on interroge, et « inconnu » est une réponse normale.
- **Le code de refus** est `554 5.7.1`, avec le nom de la zone et l'adresse dans
  le texte : l'émetteur légitime pris à tort doit pouvoir savoir **où** se
  délister. Un refus qui ne dit pas où aller est un refus qu'on ne peut pas
  corriger.
- **Pas de score, pas de pondération.** Une zone listée refuse, point. Le score
  est ce qui rend `rspamd` impossible à déboguer et impossible à couvrir à
  100 %. Un exploitant qui veut plusieurs zones en pose plusieurs, et chacune
  est un refus franc.
- **L'option** est `--dnsbl <zone>`, répétable. Aucune zone par défaut : le
  produit n'envoie pas de requêtes chez un tiers que l'exploitant n'a pas nommé.
  Pour narro.ch ce sera `zen.spamhaus.org`, la zone qui attrape le plus pour ce
  qu'elle coûte.

## Ce que cela vaut, honnêtement

Ces contrôles attrapent les robots : ceux qui annoncent `localhost`, ceux qui
parlent depuis une adresse résidentielle listée, ceux qui inventent un domaine
d'expéditeur. C'est **le gros du volume**, et c'est ce que Postfix attrapait
avant même d'appeler `rspamd`. La mesure des étiquettes le dit dans l'autre
sens : si `rspamd` n'en étiquetait que 0,15 %, c'est aussi parce que l'enveloppe
avait déjà écarté le reste.

Ils n'attrapent **pas** le courrier indésirable qui vient d'un vrai serveur,
avec un vrai domaine, un SPF valide et une signature DKIM valide — celui des
plateformes d'envoi détournées. Pour celui-là, il faudrait le score que l'on
refuse d'écrire. Vu la mesure — 0,15 % d'étiquetés, 0 rejet, 0 message dans
`Junk` — c'est un manque théorique sur ce site. S'il devenait réel, la réponse
serait DMARC en refus et une liste de domaines, pas un moteur bayésien.
