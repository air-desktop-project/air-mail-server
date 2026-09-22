# La bascule, et le retour en arrière

Ce document se lit AVANT le jour J, en entier, et se suit ligne à ligne le jour
même. Il suppose que `etude-narro.md` a été lu.

**Les décisions qu'il posait sont prises**, et datées du 2026-09-07 : cinq
secrets initiaux distincts (§5 de l'étude) — **six depuis le 2026-09-15**, voir
ci-dessous —, le relais Resend gardé pour la bascule, le sélecteur DKIM
`ams202609` en 2048 bits publié une semaine avant, et l'API REST ouverte pour
que chacun pose son propre mot de passe.

**Le principe qui gouverne tout : on ne remplace rien tant que la copie n'a pas
été éprouvée, et on garde l'ancien intact jusqu'à ce qu'on décide de ne plus en
avoir besoin.**

## IL Y A SIX BOÎTES, ET NON CINQ

`ofrou-sierre@narro.ch` a été créée le **2026-09-15**, c'est-à-dire APRÈS la
phase 0. Elle ne figure donc dans aucun relevé du 7, ni dans l'inventaire, ni
dans les décomptes de ce document — et **toutes ses boucles l'ont ignorée
jusqu'au 2026-09-21**. Elles la nomment désormais. Une boucle qui nomme les
comptes un par un est juste le jour où on l'écrit, et fausse le jour où une
boîte naît : c'est ce qui est arrivé ici.

**Ce n'est pas une personne, c'est une machine** : la passerelle Milesight du
chantier OFROU Sierre, qui envoie ses alertes en `submission` authentifié et ne
lit jamais sa boîte. Personne ne se plaindra donc si elle est oubliée — les
alertes cesseront, et c'est tout ce qui se verra. Trois conséquences, et chacune
a sa place plus bas :

- **son secret ne se distribue pas par courrier** : il se TAPE dans l'interface
  de la passerelle, joignable par son seul lien 4G. Prévoyez-y un accès AVANT la
  fenêtre — c'est la seule pièce de cette bascule qui dépend d'un appareil
  distant que vous ne contrôlez pas depuis la machine ;
- **son secret n'a pas de tiret** : l'interface Milesight n'accepte que des
  caractères alphanumériques (§0.4) ;
- **sa boîte n'a AUCUN sous-dossier** — ni `Sent`, ni `Trash` : rien à traduire,
  aucun rôle à poser, et lui en poser un serait NUISIBLE (§0.4bis-2).

**Son mot de passe actuel n'est conservé nulle part.** Celui qui est dans la
passerelle aujourd'hui a été tiré le 2026-09-15 et n'a pas été gardé : la
bascule n'a donc pas le choix de le reconduire, elle en pose un neuf. C'est de
toute façon ce que l'option A de §5 de l'étude fait des cinq autres.

---

## RETOUR EN ARRIÈRE — mardi 22 septembre 2026, 09:48 UTC, après quatre heures

> **`mail.narro.ch` est de nouveau servi par Postfix et Dovecot.** Décision
> prise à 09:47, exécutée en **36 secondes** (air-mail-server arrêté 09:48:46,
> redirections retirées 09:49:22), deux messages rapatriés, la plate-forme
> remise sur ses anciens identifiants. Rien n'est perdu.
>
> **LA CAUSE : LE SERVEUR NE PARLE QUE TLS 1.3, ET APPLE MAIL NE PARLE QUE
> TLS 1.2.** Capturé sur la machine, `ClientHello` d'Apple Mail vers le 993 :
> pas d'extension `supported_versions`, `legacy_version 0x0303`, groupes
> `secp256r1/384/521`, vingt-deux suites 1.2. Le serveur répond « alert
> protocol version » — c'est C4, écrit noir sur blanc dans `ams-tls/provider.rs`.
> La pile IMAP/SMTP de Mail (`CFStream`, celle que son journal nomme) ne monte
> pas en 1.3 : **aucun réglage côté client ne contourne cela**, et c'est le
> client de tous les comptes, sur Mac comme sur iPhone.
>
> **POURQUOI AUCUN CONTRÔLE NE L'A VU** : chaque essai du §0.6, de la veille et
> du jour J venait d'OpenSSL ou de Python — des piles qui font du 1.3. Le
> manuel demandait « §0.6 avec un vrai client » ; il ne disait pas LEQUEL, et
> il ne l'a pas exigé. Il l'exige désormais : **Apple Mail, avant toute
> nouvelle fenêtre**, et la capture du `ClientHello` pour le prouver.
>
> **DEUX AUTRES DÉFAUTS TROUVÉS DANS LES QUATRE HEURES**, qui auraient suffi
> chacun à remonter : (1) le garde comptait les pairs IPv4 d'une écoute `[::]`
> sous `::/64` — un client qui se trompe vingt fois bannissait l'IPv4 entière
> pour une heure, mesuré `{"source":"::","prefixBits":64}` ; **corrigé dans
> `source_de`**, avec son essai. (2) L'identifiant est le nom nu et non
> l'adresse — voir plus bas, à corriger dans le produit.
>
> **ET LE RETOUR EN ARRIÈRE AVAIT LUI-MÊME UN TROU** : `ufw reload` ne retire
> PAS les règles `*nat` déjà chargées. Après restauration des fichiers et
> rechargement, `nft list ruleset | grep -c redirect` disait encore **4** —
> Postfix écoutait, le 25 partait toujours vers un port vide. Dix-neuf
> secondes d'aveuglement, et la ligne manquante est à l'étape 2bis.

## ~~LA BASCULE EST FAITE~~ — mardi 22 septembre 2026, 05:49 UTC (07:49 CEST)

> **AVANCÉE AU MATIN, LE JOUR MÊME.** La fenêtre était annoncée à 22:00 ; elle
> s'est ouverte à 07:49, sur décision prise à 07:10. **Coupure réelle : 41
> secondes** — Postfix arrêté à 05:49:31 UTC, air-mail-server à l'écoute sur
> les quatre ports à 05:50:12. Les cinq n'ont pas été prévenus du changement
> d'heure : c'est un choix, et il est écrit ici pour ne pas être oublié.
>
> **UN SEUL ACCROC, ET IL A COÛTÉ LES 41 SECONDES.** Le serveur a refusé de
> démarrer : « boîte de `thierry.delhaise` : Read-only file system ». L'unité
> du paquet porte `ProtectSystem=strict` avec `ReadWritePaths=/var/lib/air-mail`
> seulement — et `/var/vmail-ams` n'y est pas. En phase 0, la veille, et à
> chaque répétition, le serveur avait été lancé **à la main** ; jamais PAR
> L'UNITÉ sur ce chemin. Un drop-in `ReadWritePaths=/var/vmail-ams` l'a réglé
> (étape 6quater, ajoutée). Le banc qui manquait : démarrer par `systemctl`,
> et non par `sudo -u air-mail air-mail-server`.
>
> **CE QUE LA BASCULE A CASSÉ, ET QU'AUCUN RELEVÉ NE NOMMAIT** : la plate-forme
> narro (quartz) émet ses alertes clients par `mail.narro.ch:587`, authentifiée
> `support@narro.ch` avec le mot de passe de Dovecot. Coupée de 05:50 à 05:58 —
> identifiant ET secret faux —, réparée dans `app.env` de l'instance preprod.
> Voir « L'IDENTIFIANT N'EST PLUS L'ADRESSE », plus bas.

## LA FENÊTRE ÉTAIT FIXÉE : mardi 22 septembre 2026, 22:00 CEST

**CELLE DU SAMEDI 12 NE S'EST PAS OUVERTE**, et rien n'y a échoué : elle n'a pas
été tenue. Le manuel a servi entre-temps à trouver ce que personne n'avait vu —
la sixième boîte absente de toutes les boucles, les rôles de dossiers que le
delta emporte, le certificat que le compte de service ne peut pas lire. C'est
cette version-là qui se joue, et non celle du 12.

**CE QUE LA NOUVELLE DATE CHANGE, ET QUI EST ASSUMÉ.** Deux hypothèses du 12
tombent, et il vaut mieux les nommer que les découvrir :

- **le soir d'un jour ouvré, et non le samedi matin.** Le samedi matin, c'était
  le volume entrant au plus bas. 22:00 un mardi n'en est pas loin — le courrier
  d'affaires s'est tu — et de toute façon une coupure de vingt minutes RETARDE
  le courrier, elle n'en perd pas : c'est tout l'objet de la coupure franche ;
- **un jour de préavis, et non quatre.** §0.7 en demandait quatre. La lettre
  part donc le soir du 21, en même temps que les secrets, et non quatre jours
  avant. Cinq personnes auront une soirée pour la lire.

## L'IDENTIFIANT N'EST PLUS L'ADRESSE, ET PERSONNE NE L'AVAIT ÉCRIT

Dovecot authentifiait sur l'adresse complète — `/etc/dovecot/users` est écrit
ainsi, et chaque client, la passerelle Milesight et la plate-forme narro
portent donc `prenom.nom@narro.ch` comme identifiant. **air-mail-server veut le
NOM DU COMPTE, `prenom.nom`, et REFUSE l'adresse** (mesuré le 2026-09-22 : `support`
ouvre, `support@narro.ch` non — `ams_auth::authenticate` compare à `login`, et
rien d'autre).

Ce manuel disait pourtant « identifiant = l'adresse complète » pour la
passerelle, et la lettre « nom d'utilisateur : le même qu'avant ». Les deux
étaient faux, et **rien de la phase 0 ne pouvait le voir** : tous les essais
s'authentifiaient avec le nom nu, parce que c'est ainsi qu'on crée un compte.
Un inventaire qui relève `mail_location` et pas la FORME de l'identifiant est
un inventaire qui manque la moitié de la migration.

Ce que cela touche, et ce qui en a été fait :

| Qui | Identifiant à poser | Fait ? |
|---|---|---|
| la plate-forme narro, `quartz:/opt/vsl-iot-platform-preprod/env/app.env` | `EMAIL_HOST_USER=support` + le secret neuf | **fait 05:58 UTC**, sauvegarde `app.env.avant-ams-*`, workers redémarrés, essai Django arrivé. ⚠️ **Le déploiement RÉGÉNÈRE `app.env`** : reporter la valeur là où le déploiement la lit |
| la passerelle Milesight | `ofrou-sierre` — SANS `@narro.ch` | à saisir dans son interface |
| les cinq clients de courrier | `prenom.nom` — SANS `@narro.ch` | une ligne à envoyer aux cinq |

**Et le produit devrait accepter les deux formes.** « Le remplaçant accepte ce
que le remplacé acceptait » vaut ici plus qu'ailleurs : sept configurations
tenues par cinq personnes et deux machines. Mais l'identité authentifiée devient
ensuite le nom de la boîte — `authenticate` doit rendre le login canonique, et
SMTP, IMAP, l'API et leurs bancs doivent le reprendre. C'est le premier chantier
d'après-bascule, pas un correctif de fenêtre.

**ET UNE MARGE QUI DISPARAÎT.** Le samedi laissait deux jours devant soi pour
reprendre ; mardi soir, le lendemain est un jour ouvré. Le retour en arrière ne
dépend d'aucun DNS et tient en quelques minutes — c'est écrit plus bas —, mais
cela se pèse AVANT d'ouvrir la fenêtre, pas pendant.

**~~AVANCÉE D'UNE SEMAINE le 2026-09-08~~**, après une phase 0 menée sur la vraie
machine dans la nuit. Ce qui fixait le 19 était la semaine d'épreuve de la clé
DKIM ; elle ne peut pas avoir lieu — Resend efface notre signature — et ce
qu'elle devait prouver l'a été autrement, plus solidement.

Le chemin qui y mène, et pourquoi chaque étape est là :

| Quand | Quoi | Pourquoi cette date |
|---|---|---|
| ~~**mardi 8 septembre**~~ **FAIT** | sélecteur **`ams202609`**, clé **2048 bits**, publié — et **rspamd signe avec** | la clé s'éprouve sous Postfix, en production. Le jour J ne changera plus que le serveur |
| ~~la semaine d'épreuve DKIM~~ **SANS OBJET** | ~~on vérifie que les signatures se valident chez Gmail et Outlook~~ | **IMPOSSIBLE PAR RESEND** : il reconstruit le message, réécrit le `Message-ID` et signe avec SON sélecteur. Notre signature n'arrive jamais. Vérifié autrement le 2026-09-08 — `R_DKIM_ALLOW` en local, et `dkim=pass header.s=ams202609` chez Google en envoi direct |
| **mardi 8** | le 8443 vu de l'EXTÉRIEUR · §0.6 avec un vrai client · `pour-les-utilisateurs.md` envoyé aux cinq | ce document PORTE la date, la durée de coupure et le moment des secrets : le relire si l'un des trois change |
| **mercredi 9** | **LA PORTE** : le §0.6 doit être passé le soir | un défaut de la classe de ceux du 8 septembre, et l'on reprend le 19 — la courbe de découverte ne se serait pas aplatie |
| ~~**vendredi 11**~~ **REFAIT LE 21** | ~~distribution des cinq secrets initiaux~~ | posés le 11, jamais servis, restés dix jours dans cinq boîtes : **retirés**, et six neufs posés le 21 |
| ~~**samedi 12, 09:00**~~ **NON TENUE** | ~~la fenêtre~~ | elle n'a pas été ouverte. Les trois défauts trouvés depuis sont corrigés dans ce document |
| **lundi 21** | le sixième compte dans `comptes.bin` · **six secrets posés et ÉPROUVÉS** · `pour-les-utilisateurs.md` redaté et envoyé | un secret posé qu'on n'a pas vu ouvrir la porte n'est pas un secret posé : `AUTH PLAIN` sur les six, et un témoin au mauvais secret qui doit être REFUSÉ |
| **mardi 22, 22:00** | la fenêtre | le courrier d'affaires s'est tu, les cinq sont joignables dans la soirée |

**Le détail du mardi soir.** 22:00 sauvegarde et copie finale ; 22:30 arrêt de
Postfix, delta, démarrage d'`air-mail-server` ; 22:50 `verifier.sh` décide ;
23:00 essais clients, **dont la saisie du secret dans la passerelle Milesight** ;
00:00 fin. **Coupure réelle : environ vingt minutes.**

**LA PASSERELLE EST LA SEULE CASE QUI SE COCHE AILLEURS.** Tout le reste se fait
sur la machine ; celle-là se fait dans une interface web jointe en 4G, et à
23:00 un mardi. L'accès s'ouvre AVANT la fenêtre, pas pendant.

**AVANT D'OUVRIR LA FENÊTRE, ON MUSELLE LES MISES À JOUR AUTOMATIQUES.**
`unattended-upgrades` est ACTIF sur cette machine — relevé le 2026-09-08. Un
redémarrage de Postfix, de Dovecot ou de rspamd décidé par `apt` au milieu de la
coupure ajouterait une cause qu'on ne soupçonnerait pas, pendant les vingt
minutes où l'on a le moins de temps pour chercher.

    sudo systemctl mask unattended-upgrades     # avant d'ouvrir la fenêtre
    sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer
    # …et une fois la bascule tenue :
    sudo systemctl unmask unattended-upgrades
    sudo systemctl start apt-daily.timer apt-daily-upgrade.timer

**LE `mask` SEUL NE MUSELAIT RIEN**, et cette page l'a prescrit seul pendant
deux semaines. `unattended-upgrades.service` est l'unité de FIN D'ARRÊT
(`unattended-upgrade-shutdown --wait-for-signal`, qui n'agit qu'en éteignant la
machine). Le passage quotidien, lui, vient d'`apt-daily-upgrade.timer` →
`apt.systemd.daily install`, que le `mask` ne touche pas. Trouvé le 2026-09-22
en le jouant : les deux timers s'arrêtent (`stop`, pas `disable` — un `start`
les rend, et le redémarrage aussi). Sur cette machine, `Automatic-Reboot` n'est
pas défini : il ne redémarre jamais la machine de lui-même.

**Et on le remet.** Une machine de courrier qui ne se met plus à jour est un
problème plus lent, mais plus grave, que celui qu'on vient d'éviter.

**LE RETOUR EN ARRIÈRE NE DÉPEND D'AUCUN DNS.** La bascule ne touche ni le `MX`
ni le `A` : même machine, même enregistrement. Revenir, c'est redémarrer Postfix
et rapatrier le courrier de la fenêtre par `rapatrier.sh` — quelques minutes,
sans propagation à attendre.

**LA PHASE 0 EST FAITE**, dans la nuit du 7 au 8 septembre, sur la vraie machine :
sauvegarde vérifiée, paquet posé sans rien remplacer, 573 messages copiés et
servis sur les ports hauts, audit du §0.5 sans aucun écart ni nom illisible.
Postfix et Dovecot n'en ont rien su. **Neuf défauts y ont été trouvés, dont trois
auraient tué la bascule** — ils sont corrigés dans ce document et dans le produit.

**~~Pourquoi le 19 et pas le 12~~ — CETTE RAISON EST TOMBÉE.** Elle disait que la
clé DKIM avait besoin de sa semaine sous Postfix. Cette semaine ne peut pas avoir
lieu : le relais Resend efface notre signature, il n'y a rien à observer. Et ce
qu'elle devait prouver l'a été autrement, en une nuit et plus solidement — la
clé privée du serveur signe ce que le DNS publie, et Google le valide.

**La date n'est donc plus contrainte par DKIM.** Ce qui la contraint encore : le
préavis dû aux cinq utilisateurs, et l'audit du §0.5 sur les vraies boîtes. Le
second est passé le 2026-09-08 ; le premier est ramené à une soirée, et c'est
une décision prise en connaissance de cause (voir en tête de section).

---


## Pourquoi une coupure franche vaut mieux qu'une bascule douce

On pourrait vouloir n'interrompre personne. C'est un piège : pendant qu'on
« bascule doucement », du courrier arrive dans DEUX magasins, et un retour en
arrière devient une fusion manuelle.

SMTP est fait pour l'inverse. **Quand rien n'écoute sur le 25, l'émetteur
réessaie** — pendant des jours, chez tous les MTA sérieux. Une coupure de vingt
minutes ne perd donc AUCUN courrier : elle le retarde. Une bascule douce ratée,
elle, en perd.

On coupe donc franchement, et on fait en sorte que la coupure soit courte.

---

## Phase 0 — avant le jour J (à froid, sans risque)

### 0.1 Inventaire

    sudo bash inventaire.sh > inventaire-mail.narro.ch-$(date +%F).txt

Relisez-le : il nomme vos comptes. Les points d'arrêt :

- **Le format n'est pas Maildir** → arrêtez-vous. Convertissez d'abord
  (`doveadm sync -u <compte> maildir:/chemin/neuf`), et reprenez cette phase.
- **Sieve est en service et des scripts existent** → décidez de leur sort avant
  de continuer. air-mail-server ne les exécutera pas.
- **Des quotas sont en service** → il n'y en aura plus. Vérifiez que le disque
  suffit sans eux.
- **L'espace libre est inférieur au double du courrier** → il faut de la place
  pour la copie.

### 0.1bis La clé DKIM 2048, UNE SEMAINE AVANT — mardi 8

> **FAIT LE 2026-09-08.** Ce qui suit décrit une procédure qui a été exécutée,
> et non un projet. Ce qui a été posé, sur `box2` / `vps-9d275e3a.vps.ovh.net` :
>
> | | |
> |---|---|
> | Clé | 2048 bits, `/var/lib/rspamd/dkim/narro.ch.ams202609.key`, `_rspamd:_rspamd` 0600 |
> | Empreinte SHA-256 du DER public | `505f5e3014988b97be544c9588f5f8bde8d94e040727d4e0a6cabbe81099fc10` |
> | DNS | **une** ressource TXT chez Gandi, TTL 3600, vérifiée sur les trois serveurs faisant autorité |
> | rspamd | `selector = "ams202609"` ; `configtest` OK ; rechargé sans erreur |
> | Sélecteur `mail` | **toujours publié**, intact — c'est le filet de la semaine |
>
> **La clé a été engendrée SUR LA MACHINE**, et sa partie publique est allée
> jusqu'à l'API de Gandi sans qu'aucun octet passe par un presse-papier. Une
> première clé, engendrée sur le poste faute d'accès, a été détruite avec son
> enregistrement avant d'avoir signé quoi que ce soit — remplacer coûtait alors
> zéro, ce qui n'aurait plus été vrai une heure plus tard.
>
> **La boucle a été fermée** : `rspamc` signe (`DKIM_SIGNED [narro.ch:s=ams202609]`),
> et le message signé, relu comme un courrier entrant, donne **`R_DKIM_ALLOW`**.
> La clé privée du serveur signe ce que la clé publique du DNS vérifie.
>
> **Le retour en arrière tient en deux lignes**, la sauvegarde étant déjà posée :
>
>     sudo cp /etc/rspamd/local.d/dkim_signing.conf.avant-ams202609 \
>             /etc/rspamd/local.d/dkim_signing.conf
>     sudo systemctl reload rspamd
>
> **`sign_local = false` n'a pas été touché** : le courrier émis depuis la
> machine elle-même n'est pas signé, seules les soumissions authentifiées sur le
> 587 le sont. Un essai lancé en `ssh` avec `sendmail` ne prouverait donc rien.
>
> Reste le seul contrôle qui ne se fait pas d'ici : lire
> `Authentication-Results` chez Gmail et chez Outlook.

**Sélecteur `ams202609`, décidé le 2026-09-07.** Une date dans le nom rend la
rotation suivante lisible dans le DNS ; réutiliser `mail` empêcherait l'ancienne
et la nouvelle clé de cohabiter pendant la semaine d'épreuve.

**CE QUI EST PUBLIÉ AUJOURD'HUI TIENT SUR 1024 BITS.** Relevé le 2026-09-08 :
`mail._domainkey.narro.ch` rend une clé dont le DER commence par `MIGf`, la
signature d'un module de 1024 bits. C'est la raison de fond de la rotation, et
non le seul changement de serveur.

**LA ZONE EST CHEZ GANDI** — `ns-{34-b,65-a,133-c}.gandi.net`. Le panneau et
l'API acceptent une LISTE de valeurs, et cette liste veut dire « plusieurs
ressources », jamais « plusieurs morceaux d'une seule ». C'est exactement le
piège décrit plus bas.

    # 1. La clé, chez rspamd, à côté de l'ancienne — et TOUT ce qu'il faut
    #    publier, imprimé aux trois formes qu'un panneau peut demander.
    sudo bash docs/migration/publier-dkim.sh --engendrer

    # 2. On publie chez Gandi ce que l'étape 1 a imprimé.

    # 3. ON VÉRIFIE CE QUE LE DNS SERT VRAIMENT.
    sudo bash docs/migration/publier-dkim.sh --verifier

    # ... ou, depuis n'importe quelle machine, avec la seule empreinte que
    #     l'étape 1 a imprimée — elle ne porte aucun secret :
    bash docs/migration/publier-dkim.sh --verifier --empreinte <sha256>

    # Si vous venez de publier, interrogez la source plutôt qu'un cache :
    bash docs/migration/publier-dkim.sh --verifier --serveur ns-133-c.gandi.net

**LA PARTIE PUBLIQUE NE TIENT PAS DANS UNE CHAÎNE DNS.** Une clé 2048 fait
environ 392 caractères en base64, au-delà des 255 octets d'une chaîne de
caractères DNS. L'enregistrement TXT doit donc être **découpé en plusieurs
chaînes qui se concatènent, À L'INTÉRIEUR D'UNE SEULE RESSOURCE** :

    ams202609._domainkey.narro.ch. IN TXT (
        "v=DKIM1; k=rsa; p=MIIBIjANBgkq…"   ← premier morceau, ≤ 255 caractères
        "…le reste de la clé" )

**DEUX RESSOURCES AU LIEU D'UNE EST LA FAUTE LA PLUS COÛTEUSE DE LA BASCULE**,
et c'est celle que la liste de valeurs de l'hébergeur invite à commettre. La
zone se charge, le panneau affiche deux lignes vertes, `dig` répond — et tout
vérificateur abandonne : la RFC 6376 §3.6.2 lui interdit de choisir entre deux
clés. Le courrier part, il est accepté, il tombe dans les indésirables. Chez les
autres. Une semaine plus tard. **Aucun journal local ne s'en émeut.**

C'est pourquoi l'étape 3 n'est pas un conseil. `publier-dkim.sh --verifier`
compte les ressources, recompose les chaînes, décode la clé, mesure sa taille,
et **compare son empreinte à celle de la clé privée qui signera** — parce qu'un
enregistrement irréprochable portant la clé d'un autre sélecteur passerait tous
les autres contrôles.

> **`dig +short TXT … | tr -d '" '` EST FAUX, ET CETTE PAGE L'A CONSEILLÉ.**
> Ce raccourci retire aussi les espaces INTÉRIEURS aux chaînes. Il donne la
> bonne réponse sur `p=`, dont le base64 n'en contient jamais, et la mauvaise
> sur tout le reste — et surtout, `+short` imprimant une ligne par ressource, il
> écrase les deux en une et **cache précisément la faute qu'on cherche**. Le
> banc du script tient ce cas (essai K).

    # 4. rspamd signe avec, EN GARDANT L'ANCIENNE en place.
    #    `selector = "ams202609";` dans /etc/rspamd/local.d/dkim_signing.conf
    #    `path = "/var/lib/rspamd/dkim/$domain.$selector.key";`
    sudo systemctl reload rspamd

**PUIS ON REGARDE PENDANT UNE SEMAINE.** Envoyez-vous un message vers Gmail et
vers Outlook, et lisez l'en-tête `Authentication-Results` du destinataire : il
doit dire `dkim=pass header.d=narro.ch`. C'est le seul contrôle qui compte —
tout le reste se vérifie chez soi, celui-là se vérifie chez les autres.

**L'ANCIENNE CLÉ RESTE PUBLIÉE** tant que la nouvelle n'a pas fait ses preuves.
Deux sélecteurs qui cohabitent ne gênent personne — ce sont deux NOMS
différents, et non deux ressources au même nom ; un seul qui ne vérifie pas fait
tomber tout le courrier sortant dans les indésirables.

### 0.2 Sauvegarde, et vérification de la sauvegarde

**Un instantané OVH du VPS**, pris depuis le manager. C'est le filet de dernier
recours ; il ne remplace pas ce qui suit.

**Et une copie du courrier ET de la configuration**, hors de la machine :

    sudo tar -C / -czf /tmp/avant-ams-$(date +%F).tar.gz \
        var/vmail etc/postfix etc/dovecot etc/rspamd var/lib/rspamd/dkim

**`etc/opendkim` N'EXISTE PAS SUR CETTE MACHINE**, et `tar` s'arrête sur un
chemin absent : la commande d'origine le nommait, et la sauvegarde aurait paru
échouer. C'est **rspamd** qui signe ici — d'où `etc/rspamd` et le répertoire des
clés, qui porte celle du sélecteur `ams202609`.

**RELUE LE 2026-09-10**, sur les deux exemplaires, et le décompte est celui-ci :

| | |
|---|---|
| entrées | 1 008 |
| dont répertoires | 140 |
| dont fichiers | 868 |
| **dont MESSAGES** (`cur/` et `new/`) | **573** |

Ce document annonçait « 842 fichiers de courrier ». Le nombre était faux et
l'étiquette aussi : 842 ne comptait ni les fichiers ni les messages, et **qui
vérifierait une restauration en cherchant 842 messages conclurait qu'il en manque
269**. Les 573 sont le même compte que celui de `verifier.sh` sur
`/var/vmail-ams` — c'est celui-là qui se contrôle.

La clé privée `var/lib/rspamd/dkim/narro.ch.ams202609.key` est bien dedans.

**ET ELLE EST À DEUX ENDROITS**, ce qui est le minimum pour appeler cela une
sauvegarde : `/root/avant-ams-2026-09-08.tar.gz` sur la machine — elle a été
déplacée de `/tmp`, où la commande ci-dessus l'écrit —, et
`~/sauvegardes-narro/` sur le poste. Même empreinte SHA-256 des deux côtés. Celle
qui vit sur la machine qu'elle protège ne protège de rien : c'est la seconde qui
compte.
    # …puis rapatriez-la, et VÉRIFIEZ qu'elle se relit :
    tar -tzf avant-ams-*.tar.gz | wc -l

Une sauvegarde qu'on n'a pas ouverte n'est pas une sauvegarde. Le chemin
`var/vmail` est à remplacer par celui que l'inventaire a montré.

### 0.3 Poser air-mail-server SANS rien remplacer

    sudo dpkg -i air-mail-server_*.deb

Le paquet **n'active ni ne démarre le service** — c'est délibéré, et
`check-paquet.sh` l'éprouve. Postfix et Dovecot continuent de tourner, intacts.

### 0.3bis Le pare-feu du jour J, ÉCRIT à froid et PAS appliqué

Le serveur ne liera jamais un port sous 1024 (C10, unité sans capacité,
`ip_unprivileged_port_start = 1024`) : le jour J, ce sont les ports hauts qui
écoutent, et le pare-feu qui y ramène le 25, le 587, le 465 et le 993 — RIEN
D'AUTRE : le 143, le 110 et le 995 n'étaient pas servis par Dovecot, et un
remplaçant n'ouvre pas ce que le remplacé fermait.

Sur cette machine, `ufw` est actif et `nftables.service` désactivé. La table
`inet mail` de `installation.md` §6 y serait perdue au premier redémarrage, et
activer `nftables.service` pour la garder effacerait ufw et fail2ban (son
`flush ruleset`). La redirection s'écrit donc dans les fichiers d'ufw, qui les
rejoue à chaque démarrage et à chaque `ufw reload`.

**ON L'ÉCRIT MAINTENANT ET ON NE L'APPLIQUE PAS** : dès que ces blocs sont
chargés, le 25 est ramené sur le 2525 — et en phase 0 c'est Postfix qui sert le
25. Un `ufw reload` à ce stade coupe le courrier. Les blocs sont appliqués à
l'étape 6ter de la phase 1, et retirés à l'étape 2bis de la phase 2.

Dans `/etc/ufw/before.rules`, AVANT la ligne `*filter` :

    # air-mail-server — ramène les ports d'usage sur les ports hauts (bascule)
    *nat
    :PREROUTING ACCEPT [0:0]
    -A PREROUTING -p tcp --dport 25  -j REDIRECT --to-ports 2525
    -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 2525
    -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-ports 4465
    -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 9993
    COMMIT

Et LE MÊME BLOC dans `/etc/ufw/before6.rules`, avant SON `*filter` : les deux
fichiers sont chargés par deux commandes distinctes (`iptables-restore` et
`ip6tables-restore`), et n'en poser qu'un rendrait la bascule IPv4 seule — le
défaut exact que ce document interdit à chaque page.

Les deux blocs se relisent sans les charger — **et la redirection va DANS le
shell privilégié**, ce qui n'est pas un détail : écrite `sudo iptables-restore
--test < /etc/ufw/before.rules`, elle est faite par le shell qui LANCE `sudo`,
donc sans privilèges, sur un fichier en `0640 root:root`. On obtient
« Permission denied » et l'on croit son bloc fautif. Cette page l'a écrit ainsi
jusqu'au 2026-09-21, où la commande a été jouée pour de vrai.

    sudo sh -c 'iptables-restore  --test < /etc/ufw/before.rules'
    sudo sh -c 'ip6tables-restore --test < /etc/ufw/before6.rules'

> **FAIT LE 2026-09-21, à 20:52.** Les deux blocs sont posés — sauvegardes
> `/etc/ufw/before{,6}.rules.avant-ams-20260921-205253` —, les deux se relisent,
> et `nft list ruleset | grep -c redirect` rend **0** : rien n'est appliqué. Le
> 25 répond toujours depuis l'extérieur, Postfix écoute sur les quatre ports.
>
> **LES TROIS `ufw allow` DE L'ÉTAPE 6ter ONT ÉTÉ POSÉS EN MÊME TEMPS, ET
> AVANT** — parce que `ufw allow` RECHARGE le pare-feu. Posés après les blocs
> `*nat`, ils les auraient appliqués sur-le-champ, Postfix servant encore : le
> 25 renvoyé sur un port que rien n'écoute, et le courrier entrant qui tombe
> sans un mot dans les journaux. L'ordre est donc : les ouvertures d'abord, les
> blocs ensuite. Il ne reste à l'étape 6ter qu'un `ufw reload`.
>
> ⚠️ **JUSQU'À LA FENÊTRE, ON NE TOUCHE PLUS À ufw**, et un REDÉMARRAGE aurait
> le même effet qu'un `ufw reload` : il chargerait `before.rules`. Pour revenir
> en arrière avant la bascule, ôter les deux blocs `*nat` (ou restaurer les deux
> sauvegardes), et seulement ensuite recharger.

### 0.4 Une configuration en PORTS HAUTS, sur une COPIE du courrier

**AVANT DE TAPER QUOI QUE CE SOIT, REJOUEZ LA COMMANDE.** Depuis un dépôt de
développement, et non depuis la machine :

    cargo build --release
    bash docs/migration/repeter-la-configuration.sh

Il EXTRAIT de ce document la commande ci-dessous, remplace les chemins de
production par un arbre jetable, la joue, puis relit la configuration écrite pour
vérifier qu'elle porte bien ce que ce document promet. Il ne touche à rien.

Ce n'est pas une précaution de style. Ce manuel a été faux **quatre fois**, et
chaque fois d'une façon qui ne se serait vue que le jour J, Postfix déjà arrêté.
La quatrième — `--resolver 127.0.0.53` sans port — aurait fait REFUSER la
commande, et elle a été trouvée en la jouant, pas en la relisant.


    # **LES DEUX SERVEURS NE RANGENT PAS AU MÊME ENDROIT.** Dovecot pose
    #     /var/vmail/narro.ch/<compte>/Maildir
    # là où air-mail-server attend
    #     /var/vmail-ams/<compte>
    # Un `rsync` de racine à racine donnerait une arborescence où le serveur ne
    # trouverait AUCUNE boîte — et il démarrerait sans rien dire, un compte sans
    # boîte étant un compte dont la boîte se créera à la première remise. On
    # copie donc COMPTE PAR COMPTE.
    sudo mkdir -p /var/vmail-ams
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro \
                  ofrou-sierre; do
        sudo rsync -aH --delete \
            "/var/vmail/narro.ch/$compte/Maildir/" "/var/vmail-ams/$compte/"
    done
    sudo chown -R air-mail:air-mail /var/vmail-ams

    printf %s "$SECRET_RESEND" | sudo -u air-mail air-mail-admin config write \
        /var/lib/air-mail/essai.conf \
        --domain mail.narro.ch --hosted narro.ch --hosted mail.narro.ch \
        --maildir /var/vmail-ams --accounts /var/lib/air-mail/comptes.bin \
        --listen 127.0.0.1:2525 --listen-imaps 127.0.0.1:9993 \
        --max-message 52428800 \
        --tls-cert /var/lib/air-mail/tls/fullchain.pem \
        --tls-key  /var/lib/air-mail/tls/privkey.pem \
        --relay --queue-spool /var/lib/air-mail/file \
        --queue-expire-seconds 86400 \
        --require-fqdn-helo \
        --require-fqdn-sender --require-fqdn-recipient \
        --require-sender-domain \
        --listen-http [::]:8443 \
        --dkim-selector ams202609 \
        --dkim-key /var/lib/rspamd/dkim/narro.ch.ams202609.key \
        --resolver 127.0.0.53:53 \
        --public-suffix-list /usr/share/publicsuffix/public_suffix_list.dat \
        --relayhost smtp.resend.com:465 --relayhost-implicit-tls \
        --relayhost-user «le compte Resend, dans /etc/postfix/sasl_passwd» \
        --mta-sts-anchors /etc/ssl/certs/ca-certificates.crt \
        --mta-sts-cache /var/lib/air-mail/mtasts

**LA LIGNE DE DÉMARRAGE COMPTE MOINS DE MESSAGES QUE L'AUDIT, ET C'EST NORMAL.**
Relevé le 2026-09-08 : le serveur annonce « 5 boîte(s) sous `/var/vmail-ams`
(549 message(s)) » quand `verifier.sh` en compte 573. Les 549 sont la somme des
`INBOX` ; les 24 manquants sont les `Sent`. Rien n'est perdu — une session IMAP
rend bien 33 messages dans `INBOX` et 14 dans `Sent` pour le même compte. Ne
tirez pas de cet écart la conclusion qu'une copie a raté.

**CETTE COMMANDE VIENT DE L'INVENTAIRE**, valeur par valeur, et chacune a une
raison :

**TOUTES LES ADRESSES D'ÉCOUTE SONT EN `[::]`, ET NON EN `0.0.0.0`.**
`0.0.0.0` est de l'IPv4 SEULEMENT. Or `mail.narro.ch` a une AAAA
(`2001:41d0:305:2100::b711`), et **Dovecot écoute aujourd'hui sur les deux
familles** : s'en tenir à `0.0.0.0` ferait de la bascule une régression, pas un
remplacement.

Mesuré le 2026-09-08, en phase 0, sur l'API : `401` en IPv4 — donc le port
passe — et **rien du tout en IPv6**. Le serveur écoutait pourtant, sur
`0.0.0.0:8443`. Avec `[::]:8443`, `ss` montre `*:8443` et les deux familles
répondent `401`.

Ce que cela aurait donné le jour J : les serveurs qui résolvent le `MX` en AAAA
et préfèrent l'IPv6 — Google, la plupart des MTA modernes — trouvent le port 25
injoignable et se rabattent après délai, quand ils se rabattent ; les clients des
utilisateurs tentent l'IPv6 d'abord et échouent. **Un défaut intermittent,
dépendant du réseau de chacun**, le pire à diagnostiquer un soir de bascule.

`[::]` suffit à couvrir les deux parce que `net.ipv6.bindv6only = 0` sur cette
machine — à vérifier, c'est le défaut de Linux mais il se change :

    sysctl net.ipv6.bindv6only    # doit valoir 0
    sudo ss -ltn | grep 8443      # doit montrer `*:8443`, et non `0.0.0.0:8443`

**`--listen-http [::]:8443` OUVRE L'API REST**, et il faut savoir pourquoi
c'est là : sans elle, `/v1/me/password` n'est joignable de nulle part, et les
utilisateurs ne peuvent pas poser leur propre mot de passe.

- **Pourquoi 8443 et pas 443** : nginx tient déjà le 443 sur cette machine
  (l'inventaire le montre), et il ne peut pas relayer vers l'API — celle-ci ne
  parle QUE `h2`, délibérément (C6), quand `proxy_pass` de nginx sort en
  HTTP/1.1. Un port à elle est plus simple qu'un montage `stream` avec
  `ssl_preread`, pour cinq utilisateurs.
- **Le certificat est le même**, celui de Let's Encrypt : rien de plus à
  renouveler.
- **Ce que cela expose** : le point d'échange de jetons, et rien d'autre sans
  jeton. Un mot de passe n'ouvre JAMAIS la portée `Admin` — c'est écrit dans le
  code, pas dans une configuration —, si bien que `/v1/accounts` reste fermé à
  qui n'a pas frappé un jeton avec `air-mail-admin token`. Les essais par
  martèlement sont comptés par le videur, qui ferme la porte au bout de vingt
  par minute, **y compris sur un mot de passe actuel faux**.
**LA DÉCISION EST PRISE : ON L'OUVRE** (2026-09-07). Sans elle, la moitié de ce
qui a été écrit pour les mots de passe ne sert à rien : chaque secret choisi
devrait transiter par l'administrateur, ce qu'un changement de mot de passe
existe précisément pour éviter.

La fermer resterait tenable — ôter la ligne, et poser les six secrets par
`account passwd` en §0.4ter — mais c'est un repli, pas le plan. Celui de la
passerelle se pose de toute façon ainsi : elle n'appellera jamais cette API.

**LE PARE-FEU N'A PAS ÉTÉ MESURÉ.** `inventaire.sh` ne le regarde pas, et le 8443
n'est aujourd'hui ouvert par rien. À vérifier DEPUIS L'EXTÉRIEUR pendant la
phase 0, où l'API tourne déjà sur le port d'essai — pas le jour J, où le
découvrir fermé ferait croire à une panne du serveur :

    # Depuis une autre machine :
    curl -sS --max-time 10 -o /dev/null -w '%{http_code}\n' \
        https://mail.narro.ch:8443/v1/health

    # ON N'ATTEND PAS `200`, ET C'EST LE PIÈGE : `/v1/health` exige la portée
    # `Observe`, donc sans jeton il répond `401`. Un `401` PROUVE que le port
    # est ouvert et que le serveur répond — c'est ce qu'on cherche à savoir.
    #
    #   401  → ouvert, le serveur parle. C'est le résultat attendu.
    #   000  → rien n'a répondu : port filtré, ou serveur arrêté.
    #
    # Si c'est `000`, il faut ouvrir le port aux DEUX endroits :
    #   sudo ufw allow 8443/tcp        # si ufw est en service sur la machine
    # et le groupe de sécurité OVH, qui se règle depuis leur console.

**LES TROIS `--require-fqdn-*` NE SONT PAS DES DURCISSEMENTS**, ce sont des
restaurations :
l'inventaire montre `reject_non_fqdn_helo_hostname`,
`reject_non_fqdn_sender` et `reject_non_fqdn_recipient` dans les restrictions de
Postfix. Les omettre rendrait le remplaçant PLUS PERMISSIF que le remplacé le
jour de la bascule, et un serveur plus permissif n'alerte personne — il encaisse.

Les trois exemptions valent ici aussi, et deux d'entre elles comptent pour
narro.ch : `<>` laisse passer les avis de non-remise, et `<Postmaster>` sans
domaine reste joignable — c'est le compte `contact`, qui porte `postmaster@`.
Les six comptes, eux, sont AUTHENTIFIÉS quand ils émettent, donc exemptés :
rien de ce qu'ils envoient aujourd'hui ne se met à être refusé.

**LE `HELO` N'A PAS D'EXEMPTION, ET LA PASSERELLE MILESIGHT PASSE QUAND MÊME.**
`--require-fqdn-helo` s'applique à tout le monde — il ne peut pas en être
autrement, l'`EHLO` précède l'`AUTH`. Or cette passerelle se présente `EHLO
127.0.0.1`, et Postfix le REFUSE : il a fallu lui écrire une dérogation dans
`master.cf` le 2026-09-15, sur `submission` et `smtps` seulement. Ici, rien à
faire : `nom_qualifie` ne demande qu'un point dans le nom, et `127.0.0.1` en a
trois. Le remplaçant est donc plus permissif que le remplacé sur ce point — et
il l'est PARTOUT, port 25 compris, là où la dérogation de `master.cf` ne touche
que `submission` et `smtps`. C'est un écart assumé et non un oubli : un point
dans un `EHLO` n'a jamais arrêté personne, et les six contrôles d'enveloppe,
eux, sont tenus.

**À voir de ses yeux en §0.6, sur le 2525**, et non à déduire d'ici : c'est la
seule des six boîtes dont l'émetteur ne se reconfigure pas en deux clics.

`--require-sender-domain` est le quatrième, et c'est
`reject_unknown_sender_domain`. Il exige un résolveur — `--resolver 127.0.0.53:53`
est déjà là, l'inventaire l'ayant relevé — et `config write` REFUSE la
configuration s'il manque, plutôt que d'ajourner tout le courrier en silence.

Les six contrôles d'enveloppe de Postfix sont donc tenus. Ce qui reste au plan —
les listes noires DNS — ne restaure rien : c'est la seule pièce qui change
vraiment le comportement du site, et elle attendra APRÈS la bascule.

| | |
|---|---|
| `--max-message 52428800` | `message_size_limit` de Postfix. **Sans elle, le défaut est 10 Mio** — un cinquième — et des pièces jointes qui passent depuis des années seraient refusées. |
| `--queue-expire-seconds 86400` | `maximal_queue_lifetime = 1d`. Le défaut du produit est de CINQ jours. |
| `--dkim-selector ams202609` | **le nouveau sélecteur**, décidé le 2026-09-07. Une date dans le nom rend la rotation suivante lisible dans le DNS. Réutiliser `mail` aurait empêché l'ancienne et la nouvelle clé de cohabiter pendant la semaine d'épreuve. |
| `--dkim-key /var/lib/rspamd/...` | c'est **rspamd** qui signe, pas opendkim. Le fichier est celui de la clé 2048 posée le mardi 8, et non l'ancienne clé 1024 du sélecteur `mail`. |
| `--relayhost smtp.resend.com:465` | `relayhost = [smtp.resend.com]:465` avec `smtp_tls_wrappermode = yes`. Le compte et le secret sont dans `/etc/postfix/sasl_passwd`. |
| `--mta-sts-anchors` | **exigé par `--relayhost`** : on présente un mot de passe, et sans autorités on ne saurait pas à qui. |
| `--resolver 127.0.0.53:53` | `systemd-resolved` écoute là. **`--relay` sans résolveur fait REFUSER le démarrage**, et c'est heureux. |

**Le compte `air-mail` doit lire trois fichiers qui ne lui appartiennent pas** —
et la version d'origine de ce paragraphe n'en comptait que deux. Fait et vérifié
le 2026-09-08 :

**LE CERTIFICAT EST ILLISIBLE EN ENTIER, PAS SEULEMENT LA CLÉ.**
`/etc/letsencrypt/live` et `/etc/letsencrypt/archive` sont en `0700 root`.
`fullchain.pem` a beau être en 0644, un fichier lisible dans un répertoire qui ne
se traverse pas est un fichier illisible. Un `deploy-hook` recopie les deux —
**et il faut un crochet, pas un `chmod`** : certbot réécrit ces fichiers à chaque
renouvellement, et sans lui le serveur servirait un certificat périmé soixante
jours après la bascule, sans que rien ne le dise avant que les clients ne
refusent la connexion.

    sudo tee /etc/letsencrypt/renewal-hooks/deploy/air-mail-server > /dev/null <<'FIN'
    #!/bin/sh
    set -eu
    CIBLE=/var/lib/air-mail/tls
    LIGNEE="${RENEWED_LINEAGE:-/etc/letsencrypt/live/mail.narro.ch}"
    case "$LIGNEE" in *mail.narro.ch) ;; *) exit 0 ;; esac
    install -d -o air-mail -g air-mail -m 0700 "$CIBLE"
    install -o air-mail -g air-mail -m 0600 "$LIGNEE/fullchain.pem" "$CIBLE/fullchain.pem"
    install -o air-mail -g air-mail -m 0600 "$LIGNEE/privkey.pem"   "$CIBLE/privkey.pem"
    systemctl is-active --quiet air-mail-server && systemctl reload-or-restart air-mail-server || true
    FIN
    sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/air-mail-server
    # On le joue UNE FOIS pour peupler, sans attendre un renouvellement :
    sudo RENEWED_LINEAGE=/etc/letsencrypt/live/mail.narro.ch \
        /etc/letsencrypt/renewal-hooks/deploy/air-mail-server

La configuration pointe alors sur `/var/lib/air-mail/tls/`, et non sur
`/etc/letsencrypt/live/`.

**ET LES DEUX COMMANDES DE CE MANUEL DISAIENT LE CONTRAIRE** — corrigé le
2026-09-21. Ce paragraphe a expliqué pendant deux semaines pourquoi
`/etc/letsencrypt/live` est illisible par `air-mail`, et les commandes de la
§0.4 comme de l'étape 6 nommaient ce chemin-là. La configuration d'essai posée
sur la machine le 2026-09-08, elle, porte bien `/var/lib/air-mail/tls` : la
faute ne vivait que dans le manuel, et elle attendait le jour J, à l'étape 8,
Postfix déjà arrêté. `repeter-la-configuration.sh` REFUSE désormais une commande
qui nomme `/etc/letsencrypt/live` — la prose ne surveille rien, un banc si.

**LA CLÉ DKIM PASSE PAR LE GROUPE, POUR N'EN GARDER QU'UNE COPIE.** Elle est en
`0600 _rspamd:_rspamd`, et rspamd doit continuer de la lire tant qu'il signe.
Recopier une clé privée, c'est deux endroits à protéger et à faire tourner :

    sudo chmod 640 /var/lib/rspamd/dkim/narro.ch.ams202609.key
    sudo usermod -aG _rspamd air-mail
    # à vérifier des DEUX côtés, la régression est silencieuse :
    sudo -u air-mail -g _rspamd test -r /var/lib/rspamd/dkim/narro.ch.ams202609.key
    sudo -u _rspamd test -r /var/lib/rspamd/dkim/narro.ch.ams202609.key

Les six comptes, avec les alias que `valiases` porte. Le mot de passe se lit sur
l'entrée standard, **jamais sur la ligne de commande** : ce que `ps` affiche,
tout le monde le lit.

Avec six boîtes, l'option A de §5 de l'étude — tout réinitialiser — est la plus
simple. **Gardez chaque mot de passe au moment où vous le tirez** : il ne se relit
pas, et il n'y a pas de « mot de passe oublié » ici.

    # Un secret de vingt-quatre octets, sans dépendre d'un outil qui pourrait
    # ne pas être là.
    secret() { head -c 18 /dev/urandom | base64; }

    for compte in thierry.delhaise vincent.delhaise support kelly.garro; do
        mot=$(secret)
        printf '%s : %s\n' "$compte" "$mot"          # À NOTER MAINTENANT.
        printf %s "$mot" | sudo -u air-mail air-mail-admin account add \
            /var/lib/air-mail/comptes.bin --login "$compte" --address "$compte@narro.ch"
    done

    # `contact` porte en plus les alias de `/etc/postfix/valiases` — ils sont
    # QUATRE depuis le 2026-09-08 : `apple-review@` s'est ajouté aux trois.
    mot=$(secret); printf 'contact : %s\n' "$mot"
    printf %s "$mot" | sudo -u air-mail air-mail-admin account add \
        /var/lib/air-mail/comptes.bin --login contact \
        --address contact@narro.ch --address postmaster@narro.ch \
        --address abuse@narro.ch --address root@narro.ch \
        --address apple-review@narro.ch \
        --address postmaster@mail.narro.ch

    # **`ofrou-sierre` N'EST PAS TIRÉE PAR LA BOUCLE**, et ce n'est pas un
    # oubli : son secret part dans une INTERFACE WEB, pas dans un courrier.
    # `base64` y produit `+`, `/` et `=`, que l'interface Milesight refuse —
    # elle n'accepte que des caractères alphanumériques. Un secret refusé au
    # moment de la saisie, sur un appareil joint en 4G, se découvre mal.
    #
    # L'alphabet est celui de `poser-les-secrets.sh` : ni `0`/`O`, ni `1`/`l`/`I`.
    # Celui-là se recopie d'un écran à l'autre, à la main, une seule fois — et
    # il ne se change jamais ensuite.
    mot=$(LC_ALL=C tr -dc 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789' \
        < /dev/urandom | head -c 24)
    printf 'ofrou-sierre : %s\n' "$mot"          # À NOTER, ET À TAPER DANS LA
                                                 # PASSERELLE PENDANT LA FENÊTRE.
    printf %s "$mot" | sudo -u air-mail air-mail-admin account add \
        /var/lib/air-mail/comptes.bin --login ofrou-sierre \
        --address ofrou-sierre@narro.ch

`postmaster@` est ici une exigence, pas une commodité : §4.5.1 de RFC 5321 la
pose, et le serveur AVERTIT au démarrage si personne ne la reçoit.

**IL EN FAUT DEUX, ET LA SECONDE SEULE EMPÊCHE LE SERVEUR DE DÉMARRER.**
`postmaster@narro.ch` couvre le DOMAINE servi ; `postmaster@mail.narro.ch`
couvre le NOM DE LA MACHINE, que la RFC exige aussi. Or une adresse dans un
domaine que `--hosted` n'annonce pas fait REFUSER le démarrage — c'est pourquoi
la commande de configuration porte `--hosted mail.narro.ch` en plus de
`--hosted narro.ch`.

Le 2026-09-08, en phase 0, le serveur conseillait d'ajouter cette adresse sans
dire qu'il fallait aussi annoncer le domaine. En suivant son conseil à la lettre,
il refusait de repartir — code de sortie 1. Le conseil a été corrigé dans le
produit, et un essai tient désormais l'enchaînement : suivre le conseil doit
donner un serveur qui démarre. **On a néanmoins écrit les deux ici**, parce qu'un
manuel qui dépend d'un message d'aide pour être complet n'est pas complet.

> **FAIT LE 2026-09-21, à 22:12.** Les six comptes sont dans `comptes.bin`
> — `ofrou-sierre` par `account add`, les cinq autres par `account passwd`, qui
> ne touche pas aux adresses : celles de `contact` ont été relues après coup, et
> les six y sont. Les secrets du 11 septembre, distribués et jamais servis, sont
> caducs.
>
> **ILS ONT ÉTÉ ÉPROUVÉS, ET PAS SEULEMENT POSÉS.** `air-mail-server` a été
> démarré sur `essai.conf` — en `127.0.0.1`, sans déranger Postfix —, et les six
> se sont authentifiés en `AUTH PLAIN` à travers un tunnel, depuis le poste où
> vivent les secrets. **Avec un témoin** : `contact` avec un mauvais secret doit
> être REFUSÉ, sans quoi un « OK » ne prouverait pas que c'est CE secret-là qui
> ouvre. Serveur arrêté, tunnel fermé, service toujours `disabled`.
>
> Les secrets ne sont ni sur onyx, ni dans un journal, ni dans aucun tampon de
> terminal : ils ont traversé `ssh` sur l'entrée standard d'`air-mail-admin`, et
> ils vivent dans un seul fichier en 0600, sur le poste.

**SIX SECRETS DISTINCTS, ET NON UN SEUL PARTAGÉ.** Les commandes ci-dessus en
tirent un par compte, et c'est délibéré : un secret commun laisserait, entre la
bascule et le moment où chacun l'aura changé, n'importe lequel des cinq ouvrir
la boîte des quatre autres. Ce n'est pas une fenêtre théorique — elle dure aussi
longtemps que la personne la plus lente à lire son courrier. **Le sixième ne se
change jamais** : la passerelle ne sait pas le faire, il reste donc celui que
vous posez, et c'est une raison de plus pour qu'il n'ouvre que sa propre boîte.

### 0.4ter Chacun pose ensuite le sien, sans passer par vous

Ces secrets sont des secrets de PASSAGE — les cinq humains, s'entend : celui de
`ofrou-sierre` est définitif, §0.4ter ne la concerne pas. Une fois connecté,
chacun pose le sien lui-même :

    curl -X PUT https://mail.narro.ch:8443/v1/me/password \
         -H "Authorization: Bearer $JETON" \
         -H 'Content-Type: application/json' \
         -d '{"current_password":"celui-qu-on-vous-a-donné","password":"le-vôtre"}'

Le jeton s'obtient contre ses propres identifiants :

    curl -X POST https://mail.narro.ch:8443/v1/tokens \
         -H 'Content-Type: application/json' \
         -d '{"login":"votre-compte","password":"celui-qu-on-vous-a-donné"}'

**Aucun mot de passe choisi ne transite par l'administrateur**, et c'est le
point. La route n'exige aucune portée — elle agit sur soi —, mais elle **exige le
mot de passe actuel** : sans lui, un jeton ramassé au passage suffirait à
verrouiller le propriétaire hors de sa boîte.

Si quelqu'un préfère ne pas toucher à `curl`, la voie d'administration reste
ouverte, et c'est `account passwd` — **jamais `account add`**, qui effacerait les
adresses du compte :

    printf %s "$NOUVEAU" | sudo -u air-mail air-mail-admin account passwd \
        /var/lib/air-mail/comptes.bin --login contact

Le serveur relit son magasin dès que le fichier bouge : aucun redémarrage, et
aucune session en cours n'est interrompue.

### 0.4bis Traduire les noms de dossiers, et les abonnements

**Les deux serveurs ne nomment pas leurs dossiers de la même façon sur le
disque.** Dovecot écrit `.&AMk-t&AOk--2025` (UTF-7 modifié, RFC 3501 §5.1.3) ;
air-mail-server écrit `.Été-2025` (UTF-8). Copié tel quel, un dossier accentué
ressort chez le client sous son nom ENCODÉ : le courrier est là, le dossier est
là, et l'utilisateur ne retrouve plus ses affaires.

Pour un domaine francophone — « Éléments envoyés », « Reçus », « Archivé » — ce
n'est pas un cas limite, c'est le cas courant.

Les abonnements se perdent de la même manière : Dovecot les écrit dans
`subscriptions` avec `.` comme séparateur, air-mail-server dans
`ams-abonnements` avec `/`. Sans conversion, `LSUB` ne rend rien, et les clients
réglés pour n'afficher que les dossiers abonnés — c'est le défaut de plusieurs —
les montrent tous disparus.

    python3 renommer-dossiers.py --essais                    # le décodeur d'abord
    python3 renommer-dossiers.py /var/vmail-ams              # à blanc
    python3 renommer-dossiers.py /var/vmail-ams --pour-de-vrai

Il ne touche pas aux noms purement ASCII, et refuse de renommer si la cible
existe déjà.

**DEUX DÉFAUTS DE CE SCRIPT ONT ÉTÉ TROUVÉS SUR LA MACHINE LE 2026-09-08**, et
tous deux se voyaient seulement en écrivant vraiment — un banc qui n'éprouve que
le décodeur les laissait passer. Ils sont corrigés, et tenus par un essai de bout
en bout :

- Dovecot écrit `V<TAB>2` en tête de `subscriptions` : le script prenait cet
  en-tête pour un dossier et posait un abonnement fantôme ;
- il écrivait `ams-abonnements` sous l'identité qui lance, c'est-à-dire **`root`
  en 0600** — donc ILLISIBLE par `air-mail`. Les abonnements seraient restés
  invisibles, ce qui est exactement le défaut que ce paragraphe répare : le
  client n'aurait affiché **aucun dossier**. Le fichier prend désormais
  l'appartenance de la boîte.

### 0.4bis-3 CONVERTIR LES FINS DE LIGNE, AVANT TOUTE ADOPTION

**C'est le défaut le plus grave que la phase 0 ait trouvé, et il ne se voyait
d'aucune façon dans l'audit.**

Dovecot stocke les messages avec des fins de ligne `LF` nues — c'est son défaut,
`mail_save_crlf = no`. air-mail-server stocke du `CRLF`, comme la RFC 5322 le
veut sur le fil, et son décodeur refuse un `LF` isolé. Il ne trouve alors pas la
ligne vide qui sépare les en-têtes du corps.

Mesuré le 2026-09-08 sur les 573 messages réels de `narro.ch` :

    FETCH 1 (ENVELOPE)     → ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)
    FETCH 1 (BODY[TEXT])   → {0}
    FETCH 1 (BODY[HEADER]) → 101864 octets, soit le message ENTIER

**Ni expéditeur, ni sujet, ni date, ni corps.** Les cinq boîtes se seraient
ouvertes sur des lignes blanches — et `verifier.sh` aurait dit « OK, aucun
écart », parce qu'il compte des fichiers et ne les lit pas.

    python3 convertir-fins-de-ligne.py --essais                   # le banc d'abord
    python3 convertir-fins-de-ligne.py /var/vmail-ams             # à blanc
    python3 convertir-fins-de-ligne.py /var/vmail-ams --pour-de-vrai

**L'ORACLE EST DANS LE NOM, ET IL VIENT DE DOVECOT.** Chaque message porte
`,S=<taille du fichier>` et `,W=<taille RFC822>` — et `W=` est exactement la
taille qu'aura le fichier une fois converti. Le script ne convertit donc pas en
aveugle : il vérifie message par message contre un nombre calculé par l'autre
serveur, et **un seul octet d'écart arrête tout sans rien écrire**. Sur les 573
messages de narro.ch : 573 oracles, aucun écart.

**L'ORDRE N'EST PAS NÉGOCIABLE : `rsync`, PUIS ce script, PUIS le premier
démarrage.** air-mail-server réécrit les noms quand il adopte une boîte venue
d'ailleurs — il lit la taille par `stat` et l'inscrit dans son propre `,S=` —, et
c'est ce nom qui fait foi ensuite : la taille servie ne vient pas d'un `stat` par
message. Convertir APRÈS l'adoption laisserait un `S=` qui ment de la longueur
d'un message entier.

Le script est idempotent, conserve la date de modification — c'est elle qui fait
l'`INTERNALDATE` d'IMAP — et l'appartenance des fichiers, et n'entre jamais dans
`tmp/`, où Maildir dépose ce qui n'est pas encore livré.

### 0.4bis-2 Les rôles de dossiers, que personne ne pose

**AIR-MAIL-SERVER N'ATTRIBUE AUCUN RÔLE DE SON CRU**, et c'est écrit dans son
code : « ce serveur ne désigne aucune boîte de son cru, c'est le client qui dit à
quoi la sienne servira ». Défendable pour une installation neuve. **Pour une
migration, c'est un trou** : Dovecot, lui, désignait `\Sent`, `\Drafts`,
`\Junk`, `\Trash` et `\Archive`.

Sans eux, `LIST … RETURN (SPECIAL-USE)` rend des dossiers sans rôle, et le client
**crée les siens** : l'utilisateur se retrouve avec « Sent » et « Éléments
envoyés », son courrier envoyé réparti entre les deux.

Le magasin les retient dans `ams-usages` à la racine du compte — une ligne par
rôle, `\Usage`, une TABULATION, le nom de la boîte. Les cinq rôles servis sont
exactement les cinq dossiers de Dovecot :

    for compte in contact support thierry.delhaise vincent.delhaise kelly.garro; do
        boite="/var/vmail-ams/$compte"
        printf '\\Archive\tArchive\n\\Drafts\tDrafts\n\\Junk\tJunk\n\\Sent\tSent\n\\Trash\tTrash\n' \
            | sudo tee "$boite/ams-usages" > /dev/null
        sudo chown air-mail:air-mail "$boite/ams-usages"
        sudo chmod 600 "$boite/ams-usages"
    done

**`ofrou-sierre` N'EST PAS DANS CETTE BOUCLE, ET NE DOIT PAS Y ÊTRE.** Sa boîte
n'a qu'une `INBOX` — aucun `Sent`, aucun `Trash`. Un `ams-usages` qui donnerait
`\Sent` à un dossier ABSENT ne serait pas seulement inutile : le jour où un
client voudrait créer son `Sent`, le serveur le lui REFUSERAIT par
`UsageDejaPris` (RFC 6154 §3 — un usage déjà pris se refuse avant de créer quoi
que ce soit), et le refus serait incompréhensible pour qui n'a jamais vu ce
fichier. **Un rôle ne se pose que sur un dossier qui existe.**

**ON VÉRIFIE AVEC LA COMMANDE QUE THUNDERBIRD ENVOIE**, et non avec un `LIST` nu :

    LIST (SUBSCRIBED) "" "*" RETURN (SPECIAL-USE)

Elle doit rendre, pour chaque dossier, `\Subscribed` ET son rôle :

    * LIST (\Subscribed \Sent \HasNoChildren) "/" "Sent"

Si elle ne rend RIEN, les abonnements ne sont pas posés — c'est §0.4bis. Si elle
rend les dossiers sans rôle, ce sont les `ams-usages` qui manquent.

**`--essais` D'ABORD, ET CE N'EST PAS DU ZÈLE.** Le décodeur d'UTF-7 modifié est
écrit à la main, sur un encodage tordu, et il décide du NOM QUE L'UTILISATEUR
VERRA. Une faute n'y produit aucune erreur : elle produit un dossier qui
s'appelle « &AMk-l&AOk-ments envoy&AOk-s » chez le client, et personne ne saura
d'où ça vient.

Les essais font l'aller-retour sur vingt-quatre noms — dont ceux qu'un domaine
francophone porte réellement — contre un encodeur écrit séparément, vérifient
l'exemple littéral de RFC 3501 §5.1.3 et celui que Dovecot écrit sur cette
machine, et s'assurent qu'une séquence illisible est rendue TELLE QUELLE plutôt
que devinée : renommer sur une supposition ferait perdre le dossier.

### 0.4quater La répétition générale, sur un banc

**AVANT DE TOUCHER À LA MACHINE**, depuis un dépôt de développement :

    cargo build --release
    bash docs/migration/repetition-generale.sh

Elle monte un magasin de forme DOVECOT — celle que l'inventaire a relevée —,
déroule les phases 0.4 à 1 de ce document, vérifie que le serveur SERT ce que
Dovecot rangeait, puis joue le retour en arrière. Elle ne touche à rien d'autre
qu'un répertoire jetable.

**Chaque pièce avait déjà son banc ; leur ENCHAÎNEMENT, non.** Or c'est là que
les défauts se logeaient — aucun ne vivait DANS une pièce, tous vivaient entre
deux. La première exécution en a trouvé deux de plus, tous deux dans cette
étape-ci et la suivante.

### 0.5 L'audit qui décide

    # `verifier.sh` compare compte par compte : on lui donne de l'ancien magasin
    # une vue qui a la MÊME forme que le neuf.
    sudo mkdir -p /var/vmail-vue
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro \
                  ofrou-sierre; do
        sudo ln -sfn "/var/vmail/narro.ch/$compte/Maildir" "/var/vmail-vue/$compte"
    done
    bash verifier.sh --essais                     # le banc d'abord
    #    **AVEC `sudo`, ET CE N'EST PAS UNE PRÉCAUTION DE STYLE.** Le magasin
    #    appartient à `air-mail` : sans privilèges, `find` ne lit rien et se
    #    tait. Les deux totaux valent alors zéro, aucun écart n'est possible, et
    #    cet audit annonçait « OK : aucun écart » APRÈS N'AVOIR OUVERT AUCUN
    #    FICHIER — le feu vert de la bascule, rendu sans rien examiner.
    #
    #    Mesuré le 2026-09-10 sur la machine : sans `sudo`, « 0 / 0 — OK » ;
    #    avec, « 573 / 613 — NE BASCULEZ PAS ». Le script refuse désormais de
    #    conclure quand il n'a rien lu, mais la commande juste est ici.
    sudo bash verifier.sh /var/vmail-ams /var/vmail-vue

**S'il refuse, on ne bascule pas.** Il refuse pour deux raisons, et les deux
comptent :

- un **écart de décompte** entre l'ancien magasin et la copie ;
- un **nom illisible**, c'est-à-dire un message qui ne sera pas servi.

Un nom illisible se corrige à la main : les drapeaux Maildir se rangent dans
l'ordre ASCII (`:2,FRS`, jamais `:2,RSF`).

### 0.6 Éprouver la copie, pour de bon

Sur les ports hauts, sans déranger personne :

    # IMAP : les boîtes, les messages, les drapeaux
    openssl s_client -connect 127.0.0.1:9993 -quiet
    # puis : a LOGIN jean «mot de passe» / b LIST "" "*" / c SELECT INBOX
    #        d FETCH 1:* (FLAGS)          ← BODY.PEEK[] pour lire sans marquer

    # SMTP : un message entrant, un message sortant
    swaks --to jean@narro.ch --server 127.0.0.1:2525
    swaks --to «votre adresse ailleurs» --from jean@narro.ch \
          --server 127.0.0.1:2525 --auth PLAIN --auth-user jean

Ce qu'il faut avoir vu de ses yeux avant de continuer :

- [ ] chaque compte se connecte en IMAP ;
- [ ] `EXISTS` correspond, boîte par boîte, à ce que Dovecot annonçait ;
- [ ] les drapeaux `\Seen` / `\Answered` / `\Flagged` ont survécu ;
- [ ] les sous-dossiers (`Sent`, `Drafts`, `Junk`, `Trash`) sont là ;
- [ ] **`FETCH 1 (ENVELOPE)` NE REND PAS `NIL`** — sur plusieurs messages, pas
      un seul. C'est LE contrôle qui manquait : une enveloppe nulle veut dire que
      le serveur n'a pas su séparer les en-têtes du corps, et le client
      n'affichera ni sujet, ni expéditeur, ni date. L'audit ne le voit pas ;
- [ ] **`FETCH 1 (BODY.PEEK[TEXT])` ne rend pas `{0}`** — un corps vide sur un
      message qui n'est pas vide est le même défaut, vu de l'autre côté ;
- [ ] **`LIST (SUBSCRIBED) "" "*" RETURN (SPECIAL-USE)` rend les dossiers AVEC
      leurs rôles** — c'est la commande que Thunderbird envoie vraiment. Vide, ce
      sont les abonnements qui manquent (§0.4bis) ; sans rôles, les `ams-usages`
      (§0.4bis-2) ;
- [ ] **le serveur écoute sur les DEUX familles** : `ss -ltn` doit montrer
      `*:8443` et non `0.0.0.0:8443`, et le `curl` de §0.4 doit rendre `401`
      en IPv4 (`-4`) COMME en IPv6 (`-6`). C'est le seul écouteur public de la
      phase 0 — SMTP et IMAP sont en `127.0.0.1` ici, à dessein — et donc le
      seul qui prouve ici que `[::]` fait ce qu'on en attend. Le même contrôle
      sur le 2525, le 4465 et le 9993 se fait le jour J, à « La coupure
      s'arrête ici » ;
- [ ] un message entrant arrive ;
- [ ] un message sortant part, et **porte une signature DKIM valide** ;
- [ ] le certificat servi est bien celui de `mail.narro.ch` ;
- [ ] **APPLE MAIL SE CONNECTE, EN IMAP ET EN SMTP** — sur le port d'essai, via
      un tunnel s'il le faut. Pas `openssl`, pas Python, pas `swaks` : ces
      piles font du TLS 1.3 et le serveur aussi, donc elles ne prouvent rien
      sur le client que les cinq emploient. Le 2026-09-22, la bascule a tenu
      quatre heures avant qu'on découvre qu'Apple Mail ne parle que TLS 1.2
      (C4). La preuve se lit dans son journal
      (`~/Library/Containers/com.apple.mail/Data/Library/Logs/Mail/`) — une
      ligne `CONNECTED` après `INITIATING CONNECTION` — et, en cas de doute,
      dans une capture du `ClientHello` sur la machine :
      `tcpdump -i any -s0 -w hello.pcap 'src host <le Mac> and tcp dst port 993'`,
      puis lire l'extension `supported_versions` (0x002b) — absente, c'est
      TLS 1.2 au plus.

**Attention en lisant les boîtes** : un `FETCH BODY[…]` sans `.PEEK` POSE le
drapeau `\Seen`. Employez `BODY.PEEK[…]`, sans quoi vous marquerez comme lu ce
que vous étiez venu vérifier.

#### SCRAM : à poser AVANT la fenêtre, ou pas du tout

Depuis le 2026-09-22, ce serveur sait `SCRAM-SHA-256` — le mot de passe ne
traverse plus le fil, même chiffré. **Ce n'est pas obligatoire pour basculer**, et
la prudence dit de ne pas le poser le soir même : une pièce de plus dans une
fenêtre de coupure est une pièce de plus qui peut manquer.

S'il est posé, **il l'est pour les six comptes ou pour aucun** : un compte sans
vérificateur reste joignable en `PLAIN`, mais SCRAM lui répondra comme à un
compte inconnu — et un client qui choisit SCRAM parce qu'il le voit annoncé
échouera, alors que le mot de passe est juste. C'est exactement la forme du
défaut du 22 septembre : un client qui ne peut pas se connecter, et un serveur
qui ne dit pas pourquoi.

    # La clé, une fois, AILLEURS que le magasin.
    sudo -u air-mail air-mail-admin scram init /etc/air-mail/scram.key

    # Un vérificateur par compte — il se dérive du mot de passe EN CLAIR,
    # donc au moment où on le pose, et jamais après.
    for compte in thierry.delhaise vincent contact support facture ofrou-sierre; do
        printf %s "«le secret de ce compte»" | sudo -u air-mail air-mail-admin \
            account passwd /var/lib/air-mail/comptes.bin --login "$compte" \
            --scram-key /etc/air-mail/scram.key --scram /var/lib/air-mail/scram.bin
    done

Puis les deux chemins dans la configuration (`--scram-key` et `--scram`), et le
service relancé. **Ce qu'il faut avoir vu avant de continuer :**

- [ ] `AUTH SCRAM-SHA-256 PLAIN` dans la réponse à `EHLO` sous TLS, et
      `AUTH=SCRAM-SHA-256` dans les capacités IMAP ;
- [ ] **un vrai client ouvre sa session en SCRAM** — Thunderbird le choisit tout
      seul dès qu'il le voit. Apple Mail, lui, ne le fait pas : il reste en
      `PLAIN`, et c'est bien ainsi ;
- [ ] `SCRAM-SHA-256-PLUS` **n'apparaît qu'en TLS 1.3**, et son absence en
      TLS 1.2 n'est pas un défaut — voir `crates/ams-loop-tokio/src/liaison.rs`.

**ET SI L'ON HÉSITE, ON NE POSE RIEN** : sans les deux options, SCRAM n'existe
pas — ni annoncé, ni stocké —, et la bascule est exactement celle qui était
prévue. Il se posera à froid, un autre jour, sans coupure.

### 0.7 Prévenir

`pour-les-utilisateurs.md` est fait pour être envoyé tel quel. **Il porte la
date**, la durée de coupure et le moment où les secrets arrivent — il faut donc
le relire si l'un des trois change, sans quoi cinq personnes liront une date
fausse.

La fenêtre étant fixée au **mardi 22 à 22:00**, il part **le soir du 21**, en
même temps que les secrets initiaux de §0.4 — et non quatre jours avant, comme
cette page le demandait pour le 12. C'est une soirée de préavis pour cinq
personnes : le dire est plus honnête que de laisser le manuel promettre un délai
qu'on ne tient pas.

> **FAIT LE 2026-09-21.** La lettre redatée est partie aux cinq, et les six
> secrets avec, par un canal privé distinct du courriel.

**IL N'Y A DONC PAS DE RAPPEL SÉPARÉ.** L'envoi et les secrets sont le même
geste, ce qui retire au passage le risque que §0.4 signalait — un secret qui
traîne pendant que la bascule attend. Les cinq du 11 septembre ont vécu dix
jours ainsi ; ils ont été retirés pour cette raison.

**LA PASSERELLE NE LIT PAS CETTE LETTRE**, et c'est le piège de la veille : la
liste des destinataires a CINQ noms quand le magasin en a six. Ce qui la
concerne, elle, n'est pas un envoi mais un accès — celui de son interface, à
ouvrir avant la fenêtre.

---

## Ce que chaque étape coûte — mesuré sur 50 000 messages

Chiffres relevés le 2026-09-07, sur une boîte de 50 000 messages / 200 Mo,
disque SSD. **Le vôtre différera** ; ce qui ne différera pas, ce sont les ORDRES
DE GRANDEUR et lequel domine.

| Étape | Durée |
|---|---|
| Copie initiale (`rsync`, 200 Mo, 50 000 fichiers) | **3,0 s** |
| Le delta de la fenêtre, quand rien n'a changé | **0,5 s** |
| Traduction des noms de dossiers | instantanée (elle porte sur les dossiers, pas les messages) |
| `verifier.sh` | **9,8 s** |
| Premier démarrage : **adoption des 50 000 messages** | **1,26 s** (1,07 s de CPU) |
| Démarrages suivants, boîte déjà adoptée | **0,22 s** |
| `SELECT INBOX` sur 50 000 messages | 0,27 s |
| `SEARCH ALL` | 0,01 s |

**L'adoption ne coûte rien**, et c'est la bonne surprise : renommer cinquante
mille fichiers pour leur donner un UID prend une seconde. Ce qui domine est la
COPIE, donc votre disque.

**Extrapolez linéairement, et prévoyez large.** Un demi-million de messages
donnerait une trentaine de secondes de copie, une centaine de secondes d'audit et
douze secondes d'adoption : la fenêtre reste sous les cinq minutes. La demi-heure
annoncée aux utilisateurs est donc confortable, et c'est délibéré — mieux vaut
rouvrir en avance qu'expliquer un retard.

### Ce qui est préservé, et qui a été vérifié

- **Les drapeaux** : `\Seen`, `\Answered`, `\Flagged`, `\Draft`, `\Deleted`.
- **La date d'arrivée** : l'`INTERNALDATE` que le client affiche vient de la date
  du fichier, que le renommage conserve. Un message de février 2023 reste daté de
  février 2023 — sans quoi toutes les boîtes paraîtraient reçues le jour de la
  bascule.
- **Le `W=` de Dovecot**, et tout champ qu'un autre outil aurait posé.

---

## Phase 1 — la bascule (la coupure commence)

Chronométrez chaque étape la première fois : la fenêtre réelle est ce qui
décidera si l'on recommence un autre jour.

    # 1. On arrête d'accepter du courrier. Les émetteurs réessaieront.
    sudo systemctl stop postfix dovecot

    # 2. On vide ce que Postfix tient encore en file.
    #    **`postqueue -p` SE LIT AVANT L'ARRÊT**, il a besoin du démon. Après,
    #    c'est le spool qu'on compte :
    sudo find /var/spool/postfix/{incoming,active,deferred,maildrop} -type f | wc -l
    #    S'il reste des messages, laissez-les : ils sont dans /var/spool/postfix
    #    et le retour en arrière les retrouvera. (Le 2026-09-22 : 0.)

    # 3. Le delta : ce qui est arrivé depuis la copie de 0.4.
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro \
                  ofrou-sierre; do
        sudo rsync -aH --delete \
            "/var/vmail/narro.ch/$compte/Maildir/" "/var/vmail-ams/$compte/"
    done
    sudo chown -R air-mail:air-mail /var/vmail-ams

    # 3bis. **LE `--delete` VIENT DE DÉFAIRE LES RENOMMAGES DE 0.4bis.**
    #       Il a effacé les répertoires en UTF-8 et remis ceux de Dovecot. On
    #       retraduit donc, et le script est fait pour être relancé : il ne
    #       touche que ce qui reste à traduire.
    #       OUBLIER CETTE LIGNE rend tous les dossiers accentués illisibles,
    #       et cela ne se verra qu'une fois les clients reconnectés.
    python3 renommer-dossiers.py /var/vmail-ams --pour-de-vrai
    sudo chown -R air-mail:air-mail /var/vmail-ams

    # 3ter. **IL A AUSSI EFFACÉ LES RÔLES DE DOSSIERS**, et cette ligne-là
    #       manquait — trouvée le 2026-09-21, en relisant ce que `--delete`
    #       emporte vraiment. Le `rsync` synchronise `Maildir/` SUR LA RACINE DU
    #       COMPTE, où vivent `ams-usages`, `ams-abonnements` et `ams-index.bin`
    #       : aucun des trois n'existe du côté Dovecot, donc les trois sont
    #       « surnuméraires », donc les trois sautent.
    #
    #       Le 3bis ci-dessus recrée `ams-abonnements` — c'est ce que
    #       `renommer-dossiers.py` fait —, et `ams-index.bin` se refait tout
    #       seul à l'adoption. `ams-usages`, PERSONNE ne le recrée : les rôles
    #       posés en §0.4bis-2 seraient perdus, et chaque client se remettrait à
    #       créer son propre « Sent » à côté de celui qu'il vient de recevoir.
    #       C'est le défaut exact que §0.4bis-2 existe pour éviter, réintroduit
    #       par l'étape 3 vingt minutes avant la réouverture.
    for compte in contact support thierry.delhaise vincent.delhaise kelly.garro; do
        boite="/var/vmail-ams/$compte"
        printf '\\Archive\tArchive\n\\Drafts\tDrafts\n\\Junk\tJunk\n\\Sent\tSent\n\\Trash\tTrash\n' \
            | sudo tee "$boite/ams-usages" > /dev/null
        sudo chown air-mail:air-mail "$boite/ams-usages"
        sudo chmod 600 "$boite/ams-usages"
    done
    #       `ofrou-sierre` n'y est pas, pour la raison de §0.4bis-2 : sa boîte
    #       n'a pas les dossiers que ces rôles nomment.

    # 3quater. **LES FINS DE LIGNE, QUE LA PHASE 1 NE REJOUAIT PAS.** Le delta
    #       vient de Dovecot en `LF` nu — et `rsync` a remplacé TOUS les fichiers,
    #       pas seulement les nouveaux, puisque la conversion avait changé leur
    #       taille. §0.4bis-3 dit « rsync, PUIS ce script, PUIS le premier
    #       démarrage » et la phase 1 l'oubliait : le serveur aurait servi des
    #       enveloppes NIL sur les 705 messages. Le script est idempotent et
    #       vérifie chaque message contre le `W=` de Dovecot.
    #       (Le 2026-09-22 : 705 convertis, 0 déjà en CRLF, aucun écart.)
    sudo python3 convertir-fins-de-ligne.py /var/vmail-ams --pour-de-vrai
    sudo chown -R air-mail:air-mail /var/vmail-ams

    # 4. L'audit, une dernière fois. S'il refuse : ON REMONTE (voir plus bas).
    # `verifier.sh` compare compte par compte : on lui donne de l'ancien magasin
    # une vue qui a la MÊME forme que le neuf.
    sudo mkdir -p /var/vmail-vue
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro \
                  ofrou-sierre; do
        sudo ln -sfn "/var/vmail/narro.ch/$compte/Maildir" "/var/vmail-vue/$compte"
    done
    #    **AVEC `sudo`, ET CE N'EST PAS UNE PRÉCAUTION DE STYLE.** Le magasin
    #    appartient à `air-mail` : sans privilèges, `find` ne lit rien et se
    #    tait. Les deux totaux valent alors zéro, aucun écart n'est possible, et
    #    cet audit annonçait « OK : aucun écart » APRÈS N'AVOIR OUVERT AUCUN
    #    FICHIER — le feu vert de la bascule, rendu sans rien examiner.
    #
    #    Mesuré le 2026-09-10 sur la machine : sans `sudo`, « 0 / 0 — OK » ;
    #    avec, « 573 / 613 — NE BASCULEZ PAS ». Le script refuse désormais de
    #    conclure quand il n'a rien lu, mais la commande juste est ici.
    sudo bash verifier.sh /var/vmail-ams /var/vmail-vue

    # 5. L'instantané OVH. C'est ici qu'il vaut le plus cher.
    #    **CE VPS N'A PAS L'OPTION `snapshot`** (`GET /vps/…/option` ne rend
    #    que `automatedBackup`, relevé le 2026-09-22). Ce qui en tient lieu :
    #    la sauvegarde automatique quotidienne, à 23:19 UTC, rotation 1 —
    #    `GET /vps/…/automatedBackup/restorePoints?state=available`. Celle de
    #    la veille (2026-09-21T23:19:26Z) contenait déjà la préparation. Et la
    #    sauvegarde `tar` de §0.2 a été REFAITE à 05:47, à deux endroits :
    #    1 183 entrées, 705 messages, même empreinte des deux côtés.

    # 6. La configuration DÉFINITIVE : les vrais ports, la vraie racine.
    #
    #    **LE NOM DU FICHIER N'EST PAS LIBRE.** L'unité systemd que le paquet
    #    installe lance `--config /var/lib/air-mail/air-mail.conf`, et rien
    #    d'autre. Ce document disait `serveur.conf` : on aurait écrit une
    #    configuration parfaite que le service n'aurait jamais lue, et
    #    l'étape 8 aurait échoué à 09:40, au milieu des vingt minutes de
    #    coupure — avec, pour tout indice, un service qui refuse de démarrer.
    #
    #    La répétition du §0.4 écrit `essai.conf`, et c'est voulu : elle ne doit
    #    surtout pas écraser celle-ci.
    #
    #    **PAS DE PORT SOUS 1024 DANS CETTE COMMANDE, ET CE N'EST PAS UN CHOIX.**
    #    Ce document a dit `--listen [::]:25 … --listen-smtps [::]:465
    #    --listen-imaps [::]:993` pendant des jours. Le serveur refuse de
    #    s'exécuter en superutilisateur (C10), l'unité du paquet le lance en
    #    `air-mail` avec `CapabilityBoundingSet=` et `AmbientCapabilities=`
    #    VIDES, et `net.ipv4.ip_unprivileged_port_start` vaut 1024 sur la
    #    machine (mesuré le 2026-09-16). L'étape 8 aurait dit « écoute sur
    #    [::]:25 : Permission denied (os error 13) » et refusé de démarrer —
    #    Postfix déjà arrêté, dans les vingt minutes de coupure. La voie est
    #    celle de `installation.md` §6 : des PORTS HAUTS, et le pare-feu qui y
    #    ramène les ports d'usage (étape 6ter).
    #
    #    **TOUT EN `[::]`, ET NON EN `127.0.0.1` NI EN `0.0.0.0`.** La
    #    répétition de 0.4 écoutait en `127.0.0.1` POUR NE PAS ÊTRE JOINTE ; le
    #    jour J on veut l'être, et par les deux familles — `mail.narro.ch` a une
    #    AAAA, Dovecot servait les deux. Sur `mail.air-desktop.org`, une
    #    configuration en `0.0.0.0` a servi l'IPv4 seule quatre jours sans que
    #    rien ne le dise (« Connection refused » en IPv6, mesuré le 2026-09-16).
    #
    #    Le 587 n'a pas de ligne à lui : le pare-feu le ramène sur le 2525, le
    #    même écouteur `STARTTLS` que le 25 — c'est ainsi que Postfix servait
    #    `submission`, par le même démon.
    printf %s "$SECRET_RESEND" | sudo -u air-mail air-mail-admin config write \
        /var/lib/air-mail/air-mail.conf \
        --domain mail.narro.ch --hosted narro.ch --hosted mail.narro.ch \
        --maildir /var/vmail-ams --accounts /var/lib/air-mail/comptes.bin \
        --listen [::]:2525 --listen-smtps [::]:4465 --listen-imaps [::]:9993 \
        --max-message 52428800 \
        --tls-cert /var/lib/air-mail/tls/fullchain.pem \
        --tls-key  /var/lib/air-mail/tls/privkey.pem \
        --relay --queue-spool /var/lib/air-mail/file \
        --queue-expire-seconds 86400 \
        --require-fqdn-helo \
        --require-fqdn-sender --require-fqdn-recipient \
        --require-sender-domain \
        --listen-http [::]:8443 \
        --dkim-selector ams202609 \
        --dkim-key /var/lib/rspamd/dkim/narro.ch.ams202609.key \
        --resolver 127.0.0.53:53 \
        --public-suffix-list /usr/share/publicsuffix/public_suffix_list.dat \
        --relayhost smtp.resend.com:465 --relayhost-implicit-tls \
        --relayhost-user «le compte Resend, dans /etc/postfix/sasl_passwd» \
        --mta-sts-anchors /etc/ssl/certs/ca-certificates.crt \
        --mta-sts-cache /var/lib/air-mail/mtasts

    # 6bis. On la RELIT avant de démarrer. `config show` dit aussi ce qui manque.
    #       Les trois lignes d'écoute doivent dire `[::]:2525`, `[::]:4465`,
    #       `[::]:9993` — et `repeter-la-configuration.sh` l'a déjà vérifié à
    #       froid, en jouant CETTE commande et pas seulement celle de 0.4.
    sudo -u air-mail air-mail-admin config show /var/lib/air-mail/air-mail.conf

    # 6ter. LE PARE-FEU RAMÈNE LES PORTS D'USAGE SUR LES PORTS HAUTS.
    #
    #    Sur cette machine c'est `ufw` qui tient le pare-feu (actif, avec
    #    fail2ban derrière), et `nftables.service` est DÉSACTIVÉ. **NE L'ACTIVEZ
    #    PAS** pour charger la table de `installation.md` §6 : `/etc/nftables.conf`
    #    commence par `flush ruleset`, et au prochain redémarrage il effacerait
    #    ufw ET fail2ban. La redirection s'écrit donc DANS ufw, qui la recharge
    #    lui-même à chaque démarrage — les deux blocs ont été préparés en §0.3bis,
    #    il ne reste qu'à les appliquer.
    #
    #    **ET LES PORTS HAUTS DOIVENT ÊTRE OUVERTS DANS ufw**, ce qui n'a rien
    #    d'évident : la redirection se fait en `PREROUTING`, AVANT le filtrage,
    #    si bien que la chaîne `INPUT` voit arriver du 2525 — pas du 25. Un
    #    `ufw allow 25/tcp` seul laisse tout passer… jusqu'à la redirection, où
    #    tout est jeté, sans un mot dans le journal du serveur.
    # **LES TROIS OUVERTURES SONT DÉJÀ POSÉES** (2026-09-21, §0.3bis) : elles
    # rechargent le pare-feu, et devaient donc précéder les blocs `*nat`, pas
    # les suivre. Elles sont laissées ici parce qu'elles sont idempotentes — et
    # parce qu'un manuel qui suppose un état qu'il n'a pas vérifié est un manuel
    # qui ment un jour sur deux.
    sudo ufw status | grep -E '2525|4465|9993'   # les trois doivent être là
    sudo ufw allow 2525/tcp comment 'air-mail-server SMTP+submission (25/587 redirigés)'
    sudo ufw allow 4465/tcp comment 'air-mail-server SMTPS (465 redirigé)'
    sudo ufw allow 9993/tcp comment 'air-mail-server IMAPS (993 redirigé)'
    sudo ufw reload            # applique AUSSI les blocs *nat de §0.3bis
    sudo nft list ruleset | grep -c redirect     # doit dire 4, et non 0

    #    Un port redirigé n'est joignable QUE DU DEHORS : depuis la machine,
    #    `127.0.0.1:25` est refusé, et un contrôle local doit viser le 2525.

    # 7. On empêche l'ancien de revenir tout seul au prochain redémarrage.
    sudo systemctl disable postfix dovecot

    # 6quater. **L'UNITÉ DOIT POUVOIR ÉCRIRE LE MAGASIN**, et elle ne le peut
    #    pas telle que le paquet la livre : `ProtectSystem=strict` ne laisse
    #    écrire que `ReadWritePaths=/var/lib/air-mail`. Le 2026-09-22, l'étape 8
    #    a rendu « boîte de `thierry.delhaise` : Read-only file system » et le
    #    serveur a refusé de démarrer — Postfix arrêté, le 25 déjà redirigé.
    #    Quarante et une secondes de coupure, toutes dues à cette ligne absente.
    #    Rien ne pouvait le voir avant : à la main, `sudo -u air-mail
    #    air-mail-server` n'a pas de cloisonnement.
    sudo mkdir -p /etc/systemd/system/air-mail-server.service.d
    printf '[Service]\nReadWritePaths=/var/vmail-ams\n' \
        | sudo tee /etc/systemd/system/air-mail-server.service.d/maildir.conf > /dev/null
    sudo systemctl daemon-reload

    # 8. On démarre.
    sudo systemctl enable --now air-mail-server
    sudo journalctl -u air-mail-server -n 60 --no-pager

**Lisez les soixante lignes.** Le serveur dit au démarrage tout ce qu'il ne fera
pas : pas de résolveur, pas de liste de suffixes, pas de clé DKIM, pas de
quarantaine. Une ligne « ATTENTION » sur un nom de fichier illisible s'y trouve
aussi, s'il en reste.

### La coupure s'arrête ici

    # Sur la machine : les trois écouteurs, sur les DEUX familles.
    sudo ss -ltn | grep -E ':(2525|4465|9993) '
    #    doit montrer `*:2525`, `*:4465`, `*:9993` — et non `0.0.0.0:…`, qui
    #    serait l'IPv4 seule, ni `127.0.0.1:…`, qui serait la configuration
    #    d'essai de 0.4 restée en place.

    # Depuis l'extérieur, pas depuis la machine — ET DANS LES DEUX FAMILLES.
    # Un MTA moderne résout la AAAA d'abord ; s'il n'y trouve rien, il se
    # rabat après délai, quand il se rabat. Un `-6` qui échoue est une panne
    # que seuls certains émetteurs verront, et c'est la pire à diagnostiquer.
    swaks -4 --to jean@narro.ch --server mail.narro.ch
    swaks -6 --to jean@narro.ch --server mail.narro.ch
    openssl s_client -4 -connect mail.narro.ch:993 -quiet
    openssl s_client -6 -connect mail.narro.ch:993 -quiet

> **VU LE 2026-09-22, de 05:50 à 06:00 UTC.** Les quatre écouteurs sur `*:` ;
> 25, 465, 587 et 993 joints en IPv4 ET en IPv6 depuis l'extérieur, certificat
> `mail.narro.ch` vérifié par le système — le 25 en IPv4 depuis `quartz`, parce
> qu'un accès résidentiel filtre le 25 sortant et rend un délai d'attente qu'on
> prendrait pour une panne. Les six comptes en `AUTH PLAIN` sur le vrai 993 :
> `EXISTS` juste, `ENVELOPE` non nulle, corps non vide, rôles 5/5 (0 pour la
> passerelle, voulu). Un message Gmail → `thierry.delhaise@narro.ch` arrivé en
> quelques secondes, `Received-SPF: pass`. Un message Django → boîte locale
> arrivé. **Le sortant vers Gmail, lui, n'est pas arrivé** — voir plus bas.
>
> **LE SERVEUR EST STRICT SUR LES FINS DE LIGNE DE CE QU'IL REÇOIT** : un
> `DATA` en `LF` nu est refusé « 554 5.6.0 Bare CR or LF in message data », là
> où Postfix tolérait. Les clients de courrier envoient du `CRLF` ; un script
> maison qui pousse `message.as_bytes()` sans la politique `SMTP` de Python ne
> passe plus. À savoir avant de croire à une panne.

**ET LA PASSERELLE, QUI NE SE PLAINDRA PAS.** Le secret de `ofrou-sierre` tiré
en §0.4 doit être saisi dans l'interface Milesight — `mail.narro.ch`, port 587
`STARTTLS`, **identifiant `ofrou-sierre`, SANS `@narro.ch`** (cette page disait
l'inverse jusqu'au 2026-09-22 : c'était la forme de Dovecot, et air-mail-server
la refuse), `From:` obligatoirement `ofrou-sierre@narro.ch`. Tant qu'il ne l'est pas, la passerelle échoue en
silence : son interface n'affiche qu'un « Server error » muet, et le diagnostic
n'est plus dans `/var/log/mail.log` mais dans le journal d'`air-mail-server`.
**C'est la dernière case de la fenêtre, et la seule qui se coche ailleurs que
sur cette machine.**

---

## Phase 2 — le retour en arrière

**Il se décide vite ou pas du tout.** Plus il attend, plus il y a de courrier
neuf à rapatrier.

### Les critères, fixés d'avance

On remonte si, dans les deux heures :

- un compte ne peut pas se connecter et la cause n'est pas comprise en 15 min ;
- du courrier entrant est REFUSÉ (et non simplement retardé) ;
- un message sortant est refusé par un destinataire pour cause de DKIM ou de SPF ;
- `verifier.sh` trouve un écart qu'il n'avait pas trouvé en phase 1 ;
- le serveur redémarre tout seul plus d'une fois.

On NE remonte PAS pour : des clients qui retéléchargent (c'est attendu), un
mot de passe oublié, un client réglé sur `AUTH LOGIN` (il se reconfigure).

### La marche à suivre

    # 1. Arrêter le neuf. La coupure recommence, et c'est voulu.
    sudo systemctl disable --now air-mail-server

    # 2. RAPATRIER LE COURRIER ARRIVÉ DEPUIS LA BASCULE.
    #    C'est l'étape qu'on oublie, et la seule qui perde quelque chose.
    #
    #    **PAS AVEC `rsync --ignore-existing`.** Cette page l'a prescrit, et la
    #    répétition sur banc a montré que c'était faux : `--ignore-existing`
    #    compare des CHEMINS, or lire un message change son nom ET son dossier
    #    (`new/1725…` devient `cur/1725…:2,S`). Chaque message dont un drapeau a
    #    bougé pendant la fenêtre se retrouvait DEUX FOIS dans l'ancien magasin,
    #    une fois lu et une fois non lu. Un doublon visible par l'utilisateur,
    #    pendant un retour en arrière.
    #
    #    `rapatrier.sh` compare la PARTIE UNIQUE du nom Maildir, qui ne change
    #    ni quand on lit, ni quand on étiquette, ni quand un serveur donne un
    #    UID. Sans `--pour-de-vrai`, il n'écrit rien et dit ce qu'il ferait.
    bash rapatrier.sh --essais                                 # le banc d'abord
    bash rapatrier.sh /var/vmail-ams /var/vmail-vue            # à blanc
    bash rapatrier.sh /var/vmail-ams /var/vmail-vue --pour-de-vrai

**`--essais` D'ABORD, MÊME ICI — SURTOUT ICI.** On lance ce script quand tout le
reste a déjà échoué, sous pression, Postfix arrêté et les utilisateurs qui
attendent. C'est le pire moment pour découvrir qu'il se trompe, et le banc coûte
une seconde.

Il monte deux magasins, y joue une fenêtre de bascule — dix-huit messages
communs dont six lus pendant la fenêtre, donc RENOMMÉS par Maildir, deux
arrivées, un effacement, et un message qui vit légitimement dans `INBOX` ET dans
`Sent` — puis vérifie que deux messages exactement sont rapatriés, qu'aucun
doublon n'apparaît, que l'effacé n'a pas disparu de l'ancien, et qu'un SECOND
passage n'ajoute rien.

Ce dernier point compte le jour J : on relance ce qui a l'air d'avoir échoué.
    sudo chown -R vmail:vmail /var/vmail

    # 2bis. RETIRER LA REDIRECTION AVANT DE RELANCER POSTFIX.
    #    Sans cela, le 25, le 587, le 465 et le 993 continuent d'être ramenés
    #    sur des ports hauts que plus rien n'écoute : Postfix et Dovecot
    #    démarrent, `systemctl` les dit actifs, et personne ne les joint. Un
    #    retour en arrière qui a l'air d'avoir réussi, et qui n'a rien rendu.
    #    Ôter les deux blocs `*nat` posés en §0.3bis (jusqu'à leur `COMMIT`
    #    inclus), puis :
    sudo ufw reload
    sudo nft list ruleset | grep -c redirect     # doit dire 0
    #    **ET IL DIT 4.** Mesuré le 2026-09-22 à 09:49 : `ufw reload` recharge
    #    ses fichiers, mais un `*nat` qui n'y figure PLUS n'est pas vidé pour
    #    autant — `iptables-restore` ne touche qu'aux tables qu'on lui donne.
    #    Postfix écoutait, le 25 était encore renvoyé sur le 2525 vide :
    #    dix-neuf secondes avant que la ligne ci-dessous ne soit trouvée.
    #    On retire donc les huit règles UNE À UNE, dans les deux familles :
    for ipt in iptables ip6tables; do
        for r in "25 2525" "587 2525" "465 4465" "993 9993"; do set -- $r
            sudo $ipt -t nat -D PREROUTING -p tcp --dport $1 -j REDIRECT --to-ports $2
        done
    done
    sudo nft list ruleset | grep -c redirect     # 0, cette fois pour de vrai

    # 3. Remettre l'ancien en marche.
    sudo systemctl enable --now postfix dovecot

    # 3bis. ET LA PLATE-FORME, qui s'authentifie désormais en `support` avec le
    #    secret neuf : restaurer sur quartz
    #    /opt/vsl-iot-platform-preprod/env/app.env.avant-ams-<horodatage>
    #    puis redémarrer vsl-preprod-notification-worker, -gunicorn, -export-worker.
    #    Sans quoi les alertes clients restent coupées APRÈS le retour en arrière.
    #    **LE GLOB SE DÉVELOPPE DANS LE SHELL PRIVILÉGIÉ** — `env/` est en 0750 :
    sudo sh -c 'f=/opt/vsl-iot-platform-preprod/env/app.env; cp -p "$(ls -t $f.avant-ams-* | head -1)" "$f"'
    sudo systemctl restart vsl-preprod-notification-worker vsl-preprod-gunicorn vsl-preprod-export-worker
    #    (Fait le 2026-09-22 à 09:49 ; Django s'authentifie de nouveau en
    #    `support@narro.ch` sur Postfix — vérifié dans mail.log.)

    # 4. Vérifier depuis l'extérieur.
    swaks --to jean@narro.ch --server mail.narro.ch

### Ce que le retour en arrière ne rend pas

Il faut le savoir avant, pas après :

- **Les UID IMAP changent une seconde fois.** Les clients retéléchargent encore.
- **Un message effacé pendant la fenêtre reste effacé** : `--ignore-existing`
  ne ressuscite pas ce que l'utilisateur a supprimé.
- **Un drapeau posé pendant la fenêtre est perdu** pour les messages qui
  existaient déjà des deux côtés : on garde ceux de l'ancien magasin. C'est
  délibéré — l'inverse écraserait des drapeaux justes par des drapeaux d'une
  fenêtre de deux heures. **Ce n'est PAS un doublon** : c'est précisément ce que
  `rapatrier.sh` existe pour éviter, et ce que la commande `rsync` prescrite
  auparavant provoquait.
- **Les mots de passe redeviennent les anciens.** Si vous les aviez tous
  réinitialisés (option A), il faut le dire aux utilisateurs, et vite.

### Le filet de dernier recours

L'instantané OVH de l'étape 5. Il remet la machine dans l'état exact d'avant la
bascule — **et perd tout le courrier arrivé depuis**. On ne s'en sert que si le
système de fichiers lui-même est en cause.

---

## Phase 3 — après, et pas tout de suite

Ne faites rien de cette liste le jour même.

- **J+7** : `/var/vmail` (l'ancien magasin) reste en place. Ne l'effacez pas.
- **J+7** : `postfix` et `dovecot` restent installés, désactivés. Ne les
  désinstallez pas : le retour en arrière en dépend.
- **AVANT TOUTE NOUVELLE FENÊTRE — dans le produit** : (1) **TLS 1.2 sur les
  écouteurs** (`rustls-rustcrypto` avec `tls12`, `TLS12` dans les versions),
  ou l'aveu que ce serveur ne sert pas Apple Mail — C4 est une contrainte,
  pas une loi de la nature, et elle a été posée avant de savoir ce que les
  clients parlent ; (2) `compte@domaine-hébergé` accepté à l'AUTH ;
  (3) le garde qui démappe les pairs IPv4 — fait. Puis le §0.6 avec Apple
  Mail, pour de vrai.
- **J+0, mais pas dans la fenêtre** : rendre les mises à jour (`unmask` et
  `start` des deux timers, en tête de ce document), et **faire accepter
  `compte@domaine-hébergé` à l'authentification** — le chantier nommé sous
  « L'IDENTIFIANT N'EST PLUS L'ADRESSE ». Tant qu'il n'est pas fait, chaque
  nouveau client se configure avec le nom nu.
- **J+0** : **Resend n'a remis aucun des quatre essais sortants vers Gmail**
  (deux par air-mail-server, deux envoyés d'onyx DIRECTEMENT à Resend, le chemin
  exact de Postfix), tous acceptés `250` avec un identifiant — le dernier :
  `01a0c7b1-bc9f-77df-8663-e7e0d393557a`. Les notifications de la plate-forme
  arrivent en une seconde par le même relais. Ce n'est donc pas la bascule ;
  c'est à lire dans le tableau de bord Resend, la clé étant en envoi seul.
- **J+0** : la plate-forme narro envoie ~25 messages par jour à des adresses
  saisies dans un formulaire public (`liouwong@gmail.com`,
  `taylorvulk@yahoo.com`…) — des inscriptions de robots, relayées par Resend
  sous `support@narro.ch`. Un sujet pour le portail, et pour la réputation du
  relais.
- **J+7** : livrer dans le PAQUET ce que la bascule a appris : l'unité doit
  documenter `ReadWritePaths` pour un magasin hors de `/var/lib/air-mail`
  (`installation.md` le dit désormais), et `check-installation.sh` devrait
  démarrer PAR L'UNITÉ sur un magasin ailleurs.
- **J+30** : `MTA-STS` (mode `testing` depuis le 2026-09-09, servi par le vhost
  nginx `mta-sts.narro.ch` de cette machine) et `TLSRPT` sont DÉJÀ publiés ;
  ce qui reste est le passage de `testing` à `enforce`, et `DMARC` de `p=none`
  à `p=quarantine`. Un changement à la fois, une semaine d'écart.
- **J+30** : alors seulement, désinstaller l'ancien et libérer `/var/vmail`.
