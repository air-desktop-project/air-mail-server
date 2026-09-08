# Remplacer Postfix + Dovecot par air-mail-server sur `mail.narro.ch`

**État : ÉTUDE CLOSE, DÉCISIONS PRISES. Rien n'a été MODIFIÉ sur la machine de
production.** Établi le 2026-09-07.

Les §1 à §5 ont été écrits par observation EXTERNE, avant tout accès. Le §6 les
corrige et les complète : `inventaire.sh` a tourné SUR la machine le même jour —
en lecture seule, sans rien modifier, sans lire une seule empreinte de mot de
passe ni une clé privée. **Quand les deux divergent, c'est le §6 qui dit vrai.**

Les trois décisions qu'il posait sont tranchées : les mots de passe (§5), le
chemin de sortie (§6), et l'ouverture de l'API. La fenêtre est fixée au **samedi
12 septembre 2026, 09:00** — avancée d'une semaine le 2026-09-08, la phase 0
ayant été menée sur la vraie machine. Voir `bascule.md`, qui fait foi.

---

## 1. Ce qui tourne aujourd'hui, et comment on le sait

Tout ce qui suit a été **mesuré depuis l'extérieur**, sans accès à la machine.
Ce qui n'a pas pu l'être est nommé en §6 : c'est ce que `inventaire.sh` ira
chercher.

### Le DNS

| Enregistrement | Valeur |
|---|---|
| `MX narro.ch` | `10 mail.narro.ch` |
| `A mail.narro.ch` | `37.59.106.115` |
| `AAAA mail.narro.ch` | `2001:41d0:305:2100::b711` |
| `PTR` des deux | `mail.narro.ch` — **cohérent dans les deux familles** |
| `SPF narro.ch` | `v=spf1 mx include:_spf.resend.com -all` |
| `DMARC` | `p=none; rua=…; ruf=…; fo=1` |
| `DKIM` | sélecteur `mail`, clé RSA publiée |
| `MTA-STS`, `TLSRPT`, `TLSA` | **aucun** |

Le `PTR` cohérent en IPv4 ET en IPv6 est le point le plus important de ce
tableau : c'est ce que les grands hébergeurs regardent en premier, et il est
déjà bon. Le remplacement ne doit pas le casser — il ne le touche pas.

`include:_spf.resend.com` dit qu'une partie du courrier de `narro.ch` part par
Resend, et non par ce serveur. **Cela ne change pas** : le SPF reste tel quel.

### Les services

| Port | Ce qui répond |
|---|---|
| 25 | `220 mail.narro.ch ESMTP Postfix` |
| 587 | `220 mail.narro.ch ESMTP Postfix` |
| 465 | `220 mail.narro.ch ESMTP Postfix` (TLS implicite) |
| 993 | `* OK [CAPABILITY IMAP4rev1 …] Dovecot (Ubuntu) ready` |
| 143, 110, 995 | **fermés** — ni IMAP en clair, ni POP3 |

Postfix annonce, en clair sur le 25 :

    PIPELINING SIZE 52428800 VRFY ETRN STARTTLS
    ENHANCEDSTATUSCODES 8BITMIME DSN SMTPUTF8 CHUNKING

Dovecot annonce : `IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+
AUTH=PLAIN AUTH=LOGIN`.

**POP3 est fermé** : c'est une bonne nouvelle, il n'y a rien à reprendre de ce
côté. **Le 143 est fermé aussi** : tous les clients passent déjà par 993, donc
par du TLS implicite.

---

## 2. Trois défauts trouvés en éprouvant, dont un qui rendait la migration
   IMPOSSIBLE

Je n'ai pas raisonné sur la faisabilité : j'ai monté un Maildir aux noms que
Dovecot écrit réellement, et je l'ai servi.

### 2.1 — Le serveur REFUSAIT DE DÉMARRER sur une boîte Dovecot — **corrigé**

Dovecot écrit `,S=<taille>` dans le nom de CHAQUE message, et souvent
`,W=<vtaille>`. air-mail-server se réserve `U=` et `S=`, et refusait — à juste
titre — de recomposer un nom qui en portait déjà un. Résultat :

    air-mail-server : boîte de `alice` : nom de fichier :
                      la partie unique porte déjà un champ `U=` ou `S=`

Le processus s'arrêtait. **Aucune migration n'était possible**, et le blocage
B3 était donc bien plus profond que « il faut une machine ».

Corrigé : l'adoption dépouille `U=` et `S=` avant de recomposer, et PRÉSERVE le
reste — le `W=` de Dovecot survit. La taille écrite est la VRAIE, relue sur le
disque, et non celle que l'ancien serveur annonçait.

### 2.2 — Un message au nom illisible disparaissait EN SILENCE — **corrigé**

Les drapeaux Maildir se lisent dans l'ordre ASCII. Un fichier `:2,RSF` (au lieu
de `:2,FRS`) n'est ni servi, ni adopté, ni effacé : il reste sur le disque,
invisible. `IMAP` répondait `EXISTS 2` là où le disque portait trois messages,
et **le journal ne disait rien**.

Le compte existait pourtant déjà (`MailboxSummary.unreadable`) ; personne ne
l'imprimait. Le serveur l'annonce désormais au démarrage, en nommant le remède.

Ce compte ne couvre que l'INBOX — les sous-dossiers sont ouverts à la demande.
C'est `verifier.sh` qui fait l'audit complet, dossier par dossier, et c'est lui
qui décide si l'on bascule.

### 2.3 — Les mots de passe NE SE MIGRENT PAS — **TRANCHÉ le 2026-09-07**

`air-mail-admin account add` lit un mot de passe **en clair** sur l'entrée
standard et le hache lui-même en argon2id. Il n'existe aucun moyen d'importer
une empreinte existante.

Or Dovecot stocke des empreintes dans un schéma à lui (`{SHA512-CRYPT}`,
`{BLF-CRYPT}`, `{ARGON2ID}`…), et une empreinte ne se convertit pas : c'est
tout l'objet d'une fonction de hachage.

**Trois issues étaient possibles ; la première est retenue** — voir §5. Cinq
secrets initiaux distincts, tirés au hasard et distribués hors bande le vendredi
18, puis chacun pose le sien.

Cela a demandé deux ajouts au produit, tous deux faits le même jour :
`account passwd`, parce que `account add` effaçait les adresses du compte, et
`PUT /v1/me/password`, parce qu'un mot de passe n'ouvre jamais la portée
`Admin`.

---

## 3. La parité, fonction par fonction

### Ce qui passe sans rien perdre

| Fonction | Aujourd'hui | air-mail-server |
|---|---|---|
| SMTP 25 avec `STARTTLS` | oui | oui |
| Soumission 587 `STARTTLS` | oui | oui |
| Soumission 465 TLS implicite | oui | `--listen-smtps` |
| IMAP 993 TLS implicite | Dovecot | `--listen-imaps` |
| `IMAP4rev1` annoncé | oui | oui, **et** `IMAP4rev2` |
| `IDLE` (RFC 2177) | oui | oui |
| Taille max 50 Mio | `SIZE 52428800` | `--max-message 52428800` |
| `CHUNKING`/`BDAT` | oui | oui |
| `DSN` (RFC 3461) | oui | oui, dès que la file est configurée |
| `PIPELINING` | oui | oui |
| Plusieurs adresses par boîte | tables Postfix | `--address`, répétable |
| Plusieurs domaines | tables Postfix | `--hosted`, répétable |
| Signature DKIM sortante | opendkim (à confirmer) | `--dkim-selector` + `--dkim-key` |
| Vérification SPF/DKIM/DMARC | milters (à confirmer) | intégrée |

### Ce qui CHANGE, et que les utilisateurs verront

| | Aujourd'hui | Après | Conséquence |
|---|---|---|---|
| `AUTH LOGIN` | offert | **non offert** | un client réglé sur « LOGIN » explicitement échouera ; `PLAIN` reste |
| `SMTPUTF8` | offert | **non offert** | une adresse d'enveloppe non-ASCII serait refusée |
| Ligne de texte | Postfix wrappe jusqu'à `line_length_limit` (2048 par défaut) | **refusée dès 999 octets**, par `500 5.5.2 Line too long` | un émetteur qui produit des lignes longues passe aujourd'hui et ne passera plus |
| `VRFY` | offert | **décliné** | c'est un gain : `VRFY` sert à moissonner des adresses |
| `ETRN` | offert | absent | obsolète, aucun usage moderne |
| `UIDVALIDITY` | celle de Dovecot | **nouvelle** | chaque client RETÉLÉCHARGE toute la boîte une fois |

La dernière ligne est celle qui se voit le plus : après la bascule, chaque
client IMAP considère que les boîtes sont neuves et rapatrie tout. Sur une boîte
de plusieurs gibioctets, c'est long, et cela se dit AVANT.

### Ce qu'air-mail-server ne sait PAS faire

| Fonction | Conséquence si elle est utilisée aujourd'hui |
|---|---|
| **Sieve** (filtres serveur) | les règles de tri sont perdues ; les clients doivent filtrer eux-mêmes |
| **Quotas** | plus de limite par boîte ; le disque devient la seule borne |
| **Antispam** (rspamd, SpamAssassin) | plus de filtrage de contenu ; SPF/DKIM/DMARC restent |
| **Attrape-tout** | une adresse non attribuée est refusée, et non remise |
| **LMTP** | sans objet ici : le serveur remet lui-même |
| **Une clé DKIM par domaine** | un seul couple sélecteur/clé pour tous les domaines servis |

**`inventaire.sh` dira lesquelles sont réellement en service.** Si Sieve ou les
quotas le sont, ce sont des blocages à part entière, et il faut en décider avant
d'aller plus loin.

---

### Sur la longueur des lignes, et sur la taille des messages

**La taille tient, et elle a été vérifiée.** `--max-message 52428800` s'annonce
en `SIZE 52428800` et se respecte : une pièce jointe de 30 Mio passe, un message
de 55 Mio est refusé par `552 5.3.4 Message exceeds maximum size` — le code
juste. Sans cette option, le défaut est de 10 Mio, soit un cinquième de ce que
`mail.narro.ch` accepte aujourd'hui : **l'oublier refuserait des pièces jointes
qui passent depuis des années.**

**La longueur des LIGNES, en revanche, est plus stricte qu'aujourd'hui.** Mesuré :
998 octets passent, 999 sont refusés par `500 5.5.2 Line too long`. C'est
exactement la borne de §4.5.3.1.6 de RFC 5321, et le refus est propre et
diagnostiqué — la connexion ne tombe pas.

Mais la même RFC dit que les receveurs DEVRAIENT savoir traiter plus long, et
Postfix le fait : son `line_length_limit` vaut 2048 par défaut, et il REPLIE au
lieu de refuser. Un émetteur qui produit des lignes de 1 500 octets — cela existe,
chez de vieux logiciels et dans du courrier non-MIME — est accepté aujourd'hui et
ne le sera plus.

Rien ne permet de savoir, sans lire les journaux de Postfix, si cela vous arrive.
C'est le genre de chose qui se voit après la bascule, sur un correspondant
précis, et il vaut mieux l'avoir lu ici avant.

---

## 3bis. Le courrier sortant sera-t-il accepté ? — MESURÉ, ET OUI

C'est la question qui décide de tout le reste : un serveur de courrier qui émet
sans être authentifié voit ses messages classés en indésirable, ou refusés.

Éprouvé le 2026-09-07 de bout en bout, sur un montage complet :

1. un compte authentifié dépose un message par `587` sous `STARTTLS` ;
2. le message part en file, et **il est signé** — `d=narro.ch; s=mail`,
   `rsa-sha256`, canonicalisation `relaxed/relaxed`, avec **sur-signature** des
   en-têtes (`from:from:to:to:…`), qui interdit à un intermédiaire d'en ajouter
   un second exemplaire ;
3. réinjecté tel quel dans un serveur qui vérifie, contre un DNS qui publie la
   clé sous `mail._domainkey.narro.ch` :

       Authentication-Results: mx.ailleurs.test;
           spf=pass smtp.mailfrom=narro.ch;
           dkim=pass header.d=narro.ch header.s=mail;
           dmarc=pass header.from=narro.ch

**Les trois passent.** C'est exactement ce que Gmail, Microsoft 365 ou Proton
regardent — et c'est ce qui lève le blocage B4 le jour où cette machine émet.

Deux détails utiles au jour J :

- **Le serveur imprime au démarrage l'enregistrement TXT à publier**, en entier.
  Comparez-le à ce que `mail._domainkey.narro.ch` publie déjà : s'ils diffèrent,
  c'est que la clé privée reprise n'est pas celle de la clé publiée, et rien ne
  se vérifiera.
- **`--relay` sans `--resolver` fait REFUSER le démarrage**, et c'est heureux :
  sans résolveur, aucun `MX` ne serait trouvé et tout message accepté reviendrait
  à son expéditeur après péremption.

---

## 4. Ce que la bascule ne touche pas

- **Les certificats TLS.** air-mail-server lit une chaîne et une clé en PEM :
  les fichiers Let's Encrypt existants conviennent tels quels. Il les RELIT tout
  seul, mais **par interrogation toutes les 300 secondes** — un renouvellement
  n'est donc pris en compte qu'au bout de cinq minutes au plus. C'est sans
  conséquence pour `certbot`, qui renouvelle un mois à l'avance.
  Un seul point d'attention : le compte sous lequel tourne le serveur doit
  pouvoir LIRE `privkey.pem`.
- **Le DNS.** Ni le `MX`, ni le `SPF`, ni le `DMARC`, ni le `PTR` ne changent.
  C'est ce qui rend le retour en arrière possible sans attendre une propagation.
- **La clé DKIM — PLUS DEPUIS LE 2026-09-07.** Un sélecteur `ams202609` en 2048
  bits est publié le mardi 8, et rspamd signe avec dès ce jour-là : la clé
  s'éprouve UNE SEMAINE sous Postfix, si bien que le jour J ne change plus que le
  serveur. L'ancien sélecteur `mail` reste publié tant que le nouveau n'a pas
  fait ses preuves — deux sélecteurs qui cohabitent ne gênent personne, un seul
  qui ne vérifie pas fait tomber tout le sortant dans les indésirables.
- **L'adresse IP.** Le remplacement se fait sur la même machine.

---

## 5. Les mots de passe — TRANCHÉ le 2026-09-07 : l'issue A

| | Ce que ça coûte | Ce que ça risque |
|---|---|---|
| **A. Réinitialiser tous les mots de passe** | un mot de passe neuf à distribuer à chaque utilisateur, hors bande | tout le monde doit reconfigurer ses clients le même jour |
| **B. Demander à chaque utilisateur de choisir son mot de passe avant la bascule** | un formulaire ou un échange par utilisateur | ceux qui ne répondent pas restent bloqués le jour J |
| **C. Faire accepter à air-mail-server les empreintes Dovecot** | du développement : lire `{SHA512-CRYPT}` et `{BLF-CRYPT}` | affaiblit une propriété affichée du produit — « argon2id, et rien d'autre » |

**L'ISSUE A EST RETENUE**, avec une précision qui compte : **cinq secrets
DISTINCTS**, et non une valeur commune. Un secret partagé laisserait, entre la
bascule et le moment où chacun l'aura changé, n'importe lequel des cinq ouvrir la
boîte des quatre autres — et cette fenêtre dure aussi longtemps que la personne
la plus lente à lire son courrier.

C'est le seul des trois qui ne demande ni coopération préalable ni développement
du produit, et il fait tourner tous les mots de passe d'un coup, ce qu'aucun de
vous n'a probablement fait depuis l'installation.

**Ce que la décision a tout de même coûté au produit**, et qui n'était pas prévu :

- `account passwd`, parce que le seul chemin qui existait — `account add` —
  EFFAÇAIT les adresses du compte sans le dire ;
- `PUT /v1/me/password`, parce qu'un mot de passe n'ouvre jamais la portée
  `Admin` : sans elle, chaque secret choisi aurait transité par l'administrateur.

L'issue B aurait été plus raisonnable si les boîtes avaient été nombreuses.
L'inventaire en a compté cinq.

**C reste la porte de secours**, si quelqu'un ne peut pas supporter d'être
déconnecté : ce serait un ajout au produit, pas un réglage, et il faudrait
décider s'il est temporaire — le temps que chacun se reconnecte, puis re-haché en
argon2id — ou définitif. Le temporaire est défendable ; le définitif ne l'est
pas. Personne ne l'a demandé.

---

## 6. L'INVENTAIRE, LANCÉ LE 2026-09-07 — ce que la machine porte

`inventaire.sh` a tourné sur `box2` (`2001:41d0:305:2100::b711`, le `Hostname`
qui correspond à l'`AAAA` de `mail.narro.ch`). Sa sortie entière est versée à côté
de ce document. Voici ce qu'elle change.

### Ce qui rend la migration FACILE

| | |
|---|---|
| Format des boîtes | **Maildir** — `maildir:/var/vmail/%d/%n/Maildir`. Rien à convertir. |
| Volumétrie | **20 Mo, 713 fichiers, 5 boîtes.** La copie prendra une seconde. |
| Sieve | **`mail_plugins` est VIDE** — aucun filtre serveur à reprendre. |
| Quotas | aucun. |
| Comptes | `contact`, `thierry.delhaise`, `vincent.delhaise`, `support`, `kelly.garro` |
| Alias | `postmaster@`, `abuse@`, `root@` → `contact@`. Trois `--address` de plus sur un compte. |
| Domaines | `narro.ch`, un seul. Une seule clé DKIM suffit donc. |
| Certificats | `/etc/letsencrypt/live/mail.narro.ch/{fullchain,privkey}.pem`, valides au 11 novembre, `certbot.timer` actif. |
| Clé DKIM | `/var/lib/rspamd/dkim/narro.ch.mail.key`, PKCS#1 — un format que ce serveur lit. **Sa clé publique dérivée est IDENTIQUE à celle que le DNS publie** : vérifié. |
| Port 25 sortant | **il passe** — `220 mx.google.com` depuis la machine. OVH ne le bloque pas. |

**Cinq boîtes change la décision de §5** : réinitialiser cinq mots de passe est
l'affaire d'un après-midi. Les empreintes sont en `{SHA512-CRYPT}`, donc
non importables — mais avec cinq personnes, l'option A est sans discussion.

### LE COURRIER NE PART PAS D'ICI — TRANCHÉ : on garde le relais

    relayhost = [smtp.resend.com]:465
    smtp_sasl_auth_enable = yes
    smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
    smtp_tls_wrappermode = yes

**Tout le courrier sortant transite aujourd'hui par Resend**, avec
authentification. C'est pourquoi le SPF porte `include:_spf.resend.com`.

**air-mail-server n'avait PAS de relais de sortie** au moment de l'étude : il
résolvait le `MX` et remettait en direct, sans option pour passer par un tiers.
`--relayhost` a été ajouté depuis — voir plus bas.

**L'option 2 EXISTE DÉSORMAIS** : `--relayhost` a été ajouté au produit le
2026-09-07, et éprouvé de bout en bout — un compte authentifié dépose, le message
part chez le relais après `AUTH PLAIN` sous TLS, et le relais le reçoit.

    printf %s $SECRET | air-mail-admin config write serveur.conf \
        --relay --queue-spool /var/spool/ams/file \
        --relayhost smtp.resend.com:465 --relayhost-implicit-tls \
        --relayhost-user «votre compte Resend» \
        --mta-sts-anchors /etc/ssl/certs/ca-certificates.crt \
        --mta-sts-cache /var/cache/ams/mtasts

Le mot de passe se lit sur l'entrée standard, jamais sur la ligne de commande. Le
certificat du relais est VÉRIFIÉ — Postfix, lui, expédie aujourd'hui sous
`smtp_tls_security_level = encrypt`, qui chiffre sans vérifier ; on présente un
mot de passe, et cela ne suffit pas.

**L'ISSUE 2 EST RETENUE** (2026-09-07) : on garde le relais Resend pour la
bascule. Les trois qui étaient possibles, et pourquoi celle-là :

1. **Remettre en direct depuis l'IP OVH.** C'est techniquement prêt — le 25
   sortant passe, le `PTR` est cohérent en IPv4 ET IPv6, le SPF autorise déjà
   `mx`, et DKIM signera. Le risque est la RÉPUTATION : cette adresse n'a
   probablement jamais émis, et les grands hébergeurs s'en méfient au début.
   C'est aussi la seule façon de lever B4.
2. **Ajouter un relais de sortie au produit.** Un `--relayhost` avec SASL et TLS
   implicite. Ce n'est pas un réglage, c'est une fonction — mais elle est
   modeste, et elle préserve exactement le comportement actuel.
3. **Garder Postfix en sortie seulement**, devant air-mail-server. Cela ferait
   cohabiter deux MTA sur une machine, ce qui complique tout.

**Ne pas mélanger les deux décisions** : basculer de serveur ET de chemin de
sortie le même jour rendrait tout diagnostic impossible. C'est la raison du
choix — le jour J ne change QUE le serveur.

**Ce que ce choix implique, et qu'il faut savoir** : au jour 1, narro.ch hérite
de la réputation que Resend porte pour lui. C'est un avantage immédiat, et cela
veut dire que la « vraie » réputation de narro.ch n'existe pas encore. Passer en
direct plus tard reste possible, et c'est ce qui lèvera B4 — mais après la
bascule, jamais pendant.

### Ce qu'air-mail-server ne reprendra pas, et qui est EN SERVICE

| | |
|---|---|
| **rspamd** | `smtpd_milters = inet:localhost:11332`. Filtrage de contenu à l'entrée. Aucun équivalent : SPF, DKIM et DMARC resteront, le reste disparaît. |
| **`recipient_delimiter = +`** | `contact+facture@narro.ch` arrive aujourd'hui dans `contact`. Mesuré : ce serveur répond `550 5.1.1 Mailbox unavailable`. |
| **TLS 1.2 en réception** | Postfix accepte `>=TLSv1.2` ; ce serveur ne fait QUE du TLS 1.3. Un pair qui n'a pas 1.3 ne pourra plus chiffrer avec nous. |
| **Péremption de la file** | `maximal_queue_lifetime = 1d` ici, cinq jours par défaut là-bas. Pour la parité : `--queue-expire-seconds 86400`. |

### Deux détails d'exploitation

- **`privkey.pem` est `root:root` en 0600.** Un serveur qui tourne sous un compte
  dédié ne pourra pas la lire. Il faut un groupe, un `deploy-hook` de `certbot`
  qui recopie, ou accepter que le serveur démarre en root et abandonne ses
  privilèges — ce que celui-ci ne sait pas encore faire.
- **Aucune sauvegarde du courrier n'est programmée.** Les seuls minuteurs sont
  ceux d'Ubuntu. La phase 0.2 de `bascule.md` n'est donc pas une formalité :
  c'est la PREMIÈRE sauvegarde de ces boîtes.
- **nginx sert le 80 et le 443** sur la même machine. Rien à faire pour la
  bascule, mais à savoir si l'on publie un jour MTA-STS, qui a besoin du 443
  sous `mta-sts.narro.ch`.

### Ce que la clé DKIM a de particulier

Elle fait **1024 bits**. Ce n'est pas une régression — on la reprend telle
quelle — mais c'est court pour 2026, et les grands hébergeurs le remarquent. À
faire tourner un jour, APRÈS la bascule et pas pendant : changer de clé et de
serveur le même jour rendrait tout diagnostic impossible.

## 7. Suite

- `bascule.md` — la marche à suivre, et le retour en arrière.
- `pour-les-utilisateurs.md` — ce qui change pour eux, à leur transmettre.
- `repetition-generale.sh` — **la séquence ENTIÈRE, jouée d'un bout à l'autre**
  sur un magasin de forme Dovecot : copie, traduction des noms, audit, service
  IMAP réel, fenêtre, retour en arrière. Chaque pièce avait son banc ; leur
  enchaînement, non — et c'est là que les défauts se logeaient.
- `verifier.sh --essais` — **le banc de l'audit lui-même**. Cinq écarts montés de
  toutes pièces doivent tous le faire ÉCHOUER : un dossier vide perdu, un
  dossier non vide perdu, un message manquant, un nom illisible, et le magasin
  sain qui doit passer.
- `verifier.sh` — l'audit qui décide si l'on bascule ou non.
- `repeter-la-configuration.sh` — **la commande du manuel est-elle encore
  valable ?** Il l'EXTRAIT de `bascule.md` plutôt que de la recopier — une copie
  dériverait sans que rien ne le dise — la joue sur un arbre jetable, et relit ce
  qu'elle a écrit. À lancer avant chaque relecture du manuel.
- `renommer-dossiers.py --essais` — **le décodeur d'UTF-7 modifié s'éprouve
  avant de renommer quoi que ce soit** : aller-retour sur vingt-quatre noms
  contre un encodeur écrit séparément, plus les deux exemples qu'on n'a pas
  inventés — celui de la RFC et celui de Dovecot sur cette machine.
- `renommer-dossiers.py` — **les noms de dossiers ne se copient pas tels
  quels**. Dovecot les écrit en UTF-7 modifié sur le disque (`.&AMk-t&AOk--2025`),
  air-mail-server en UTF-8 (`.Été-2025`). Sans traduction, « Éléments envoyés »
  devient « &AMk-l&AOk-ments envoy&AOk-s » chez le client — pour un domaine
  francophone, ce n'est pas un cas limite. Il traduit aussi `subscriptions` en
  `ams-abonnements`, sans quoi `LSUB` ne rend rien et les clients réglés pour
  n'afficher que les dossiers abonnés les montrent tous disparus.
- `rapatrier.sh --essais` — **le banc du retour en arrière**, rejouable : une
  fenêtre de bascule montée de toutes pièces, et le compte vérifié. Le défaut
  d'origine — les messages LUS pendant la fenêtre, recopiés — le fait tomber.
- `rapatrier.sh` — le retour en arrière du courrier, **sans doublon**. La
  commande `rsync --ignore-existing` que `bascule.md` prescrivait d'abord
  dupliquait tout message dont un drapeau avait bougé pendant la fenêtre : lire
  un message change son nom ET son dossier, et `rsync` compare des chemins.
  Trouvé en RÉPÉTANT la manœuvre sur un banc, pas en la relisant.
