# Remplacer Postfix + Dovecot par air-mail-server sur `mail.narro.ch`

**État : ÉTUDE. Rien n'a été touché sur la machine de production.**
Établi le 2026-09-07, par observation EXTERNE uniquement — aucune connexion
n'a été ouverte sur le serveur.

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

### 2.3 — Les mots de passe NE SE MIGRENT PAS — **décision à prendre**

`air-mail-admin account add` lit un mot de passe **en clair** sur l'entrée
standard et le hache lui-même en argon2id. Il n'existe aucun moyen d'importer
une empreinte existante.

Or Dovecot stocke des empreintes dans un schéma à lui (`{SHA512-CRYPT}`,
`{BLF-CRYPT}`, `{ARGON2ID}`…), et une empreinte ne se convertit pas : c'est
tout l'objet d'une fonction de hachage.

**Il n'y a donc que trois issues, et c'est à vous de choisir.** Elles sont
présentées en §5.

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
- **La clé DKIM.** Le sélecteur `mail` reste publié, et la même clé privée sert.
- **L'adresse IP.** Le remplacement se fait sur la même machine.

---

## 5. La seule décision qui vous revient : les mots de passe

| | Ce que ça coûte | Ce que ça risque |
|---|---|---|
| **A. Réinitialiser tous les mots de passe** | un mot de passe neuf à distribuer à chaque utilisateur, hors bande | tout le monde doit reconfigurer ses clients le même jour |
| **B. Demander à chaque utilisateur de choisir son mot de passe avant la bascule** | un formulaire ou un échange par utilisateur | ceux qui ne répondent pas restent bloqués le jour J |
| **C. Faire accepter à air-mail-server les empreintes Dovecot** | du développement : lire `{SHA512-CRYPT}` et `{BLF-CRYPT}` | affaiblit une propriété affichée du produit — « argon2id, et rien d'autre » |

**Ce que je recommande : A, avec la fenêtre de bascule pour l'appliquer.** C'est
le seul des trois qui ne demande ni développement ni coopération préalable, et
il a un mérite qu'on oublie : il fait tourner tous les mots de passe d'un coup,
ce qu'aucun de vous n'a probablement fait depuis l'installation.

Si le nombre de boîtes est élevé (l'inventaire le dira), B devient plus
raisonnable.

**C mérite d'être posé si et seulement si la coupure est inacceptable.** Ce
serait un ajout au produit, pas un réglage, et il faudrait décider s'il est
temporaire (le temps que chacun se reconnecte, puis re-haché en argon2id) ou
définitif. Le temporaire est défendable ; le définitif ne l'est pas.

---

## 6. Ce que je ne sais pas encore, et comment le savoir

`docs/migration/inventaire.sh` répond à tout ce qui suit. Il est **strictement
en lecture**, ne divulgue **aucune empreinte** ni **aucune clé privée**, et
s'exécute en une commande :

    sudo bash inventaire.sh > inventaire-$(hostname)-$(date +%F).txt

Ce qu'il faut en tirer :

1. **Le format des boîtes.** Maildir, ou `mdbox`/`sdbox` ? S'il ne s'agit pas de
   Maildir, il faut d'abord CONVERTIR avec `doveadm sync`, et cela change tout
   le calendrier.
2. **La liste des comptes**, de leurs alias et des domaines servis.
3. **Le schéma des empreintes** — pour trancher §5.
4. **Sieve, quotas, antispam, attrape-tout** : en service, ou non ?
5. **Les chemins des certificats** et le compte qui les lit.
6. **La clé DKIM** : son chemin, et sous quel compte elle est lisible.
7. **La volumétrie** : combien de messages, combien d'octets, par compte.
   C'est ce qui dimensionne la fenêtre de bascule.
8. **L'espace disque libre** : il en faut le double du courrier, puisqu'on
   travaille sur une COPIE.

---

## 7. Suite

- `bascule.md` — la marche à suivre, et le retour en arrière.
- `pour-les-utilisateurs.md` — ce qui change pour eux, à leur transmettre.
- `verifier.sh` — l'audit qui décide si l'on bascule ou non.
- `renommer-dossiers.py` — **les noms de dossiers ne se copient pas tels
  quels**. Dovecot les écrit en UTF-7 modifié sur le disque (`.&AMk-t&AOk--2025`),
  air-mail-server en UTF-8 (`.Été-2025`). Sans traduction, « Éléments envoyés »
  devient « &AMk-l&AOk-ments envoy&AOk-s » chez le client — pour un domaine
  francophone, ce n'est pas un cas limite. Il traduit aussi `subscriptions` en
  `ams-abonnements`, sans quoi `LSUB` ne rend rien et les clients réglés pour
  n'afficher que les dossiers abonnés les montrent tous disparus.
- `rapatrier.sh` — le retour en arrière du courrier, **sans doublon**. La
  commande `rsync --ignore-existing` que `bascule.md` prescrivait d'abord
  dupliquait tout message dont un drapeau avait bougé pendant la fenêtre : lire
  un message change son nom ET son dossier, et `rsync` compare des chemins.
  Trouvé en RÉPÉTANT la manœuvre sur un banc, pas en la relisant.
