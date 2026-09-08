# La bascule, et le retour en arrière

Ce document se lit AVANT le jour J, en entier, et se suit ligne à ligne le jour
même. Il suppose que `etude-narro.md` a été lu.

**Les décisions qu'il posait sont prises**, et datées du 2026-09-07 : cinq
secrets initiaux distincts (§5 de l'étude), le relais Resend gardé pour la
bascule, le sélecteur DKIM `ams202609` en 2048 bits publié une semaine avant, et
l'API REST ouverte pour que chacun pose son propre mot de passe.

**Le principe qui gouverne tout : on ne remplace rien tant que la copie n'a pas
été éprouvée, et on garde l'ancien intact jusqu'à ce qu'on décide de ne plus en
avoir besoin.**

---

## LA FENÊTRE EST FIXÉE : samedi 12 septembre 2026, 09:00 CEST

**AVANCÉE D'UNE SEMAINE le 2026-09-08**, après une phase 0 menée sur la vraie
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
| **vendredi 11** | distribution des **cinq secrets initiaux, tous distincts** | un secret commun laisserait chacun ouvrir la boîte des autres |
| **samedi 12, 09:00** | la fenêtre | volume entrant au plus bas, utilisateurs joignables, deux jours de marge |

**Le détail du samedi.** 09:00 sauvegarde et copie finale ; 09:30 arrêt de
Postfix, delta, démarrage d'`air-mail-server` ; 09:50 `verifier.sh` décide ;
10:00 essais clients ; 11:00 fin. **Coupure réelle : environ vingt minutes.**

**AVANT D'OUVRIR LA FENÊTRE, ON MUSELLE LES MISES À JOUR AUTOMATIQUES.**
`unattended-upgrades` est ACTIF sur cette machine — relevé le 2026-09-08. Un
redémarrage de Postfix, de Dovecot ou de rspamd décidé par `apt` au milieu de la
coupure ajouterait une cause qu'on ne soupçonnerait pas, pendant les vingt
minutes où l'on a le moins de temps pour chercher.

    sudo systemctl mask unattended-upgrades     # avant d'ouvrir la fenêtre
    sudo systemctl unmask unattended-upgrades   # une fois la bascule tenue

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
second est passé le 2026-09-08.

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
clés, qui porte celle du sélecteur `ams202609`. Vérifié le 2026-09-08 : l'archive
tient 1 008 entrées, dont 842 fichiers de courrier et la clé DKIM.
    # …puis rapatriez-la, et VÉRIFIEZ qu'elle se relit :
    tar -tzf avant-ams-*.tar.gz | wc -l

Une sauvegarde qu'on n'a pas ouverte n'est pas une sauvegarde. Le chemin
`var/vmail` est à remplacer par celui que l'inventaire a montré.

### 0.3 Poser air-mail-server SANS rien remplacer

    sudo dpkg -i air-mail-server_*.deb

Le paquet **n'active ni ne démarre le service** — c'est délibéré, et
`check-paquet.sh` l'éprouve. Postfix et Dovecot continuent de tourner, intacts.

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
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro; do
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
        --tls-cert /etc/letsencrypt/live/mail.narro.ch/fullchain.pem \
        --tls-key  /etc/letsencrypt/live/mail.narro.ch/privkey.pem \
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
dépendant du réseau de chacun**, le pire à diagnostiquer un samedi matin.

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

La fermer resterait tenable — ôter la ligne, et poser les cinq secrets par
`account passwd` en §0.4ter — mais c'est un repli, pas le plan.

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
Les cinq comptes, eux, sont AUTHENTIFIÉS quand ils émettent, donc exemptés :
rien de ce qu'ils envoient aujourd'hui ne se met à être refusé.

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

**LA CLÉ DKIM PASSE PAR LE GROUPE, POUR N'EN GARDER QU'UNE COPIE.** Elle est en
`0600 _rspamd:_rspamd`, et rspamd doit continuer de la lire tant qu'il signe.
Recopier une clé privée, c'est deux endroits à protéger et à faire tourner :

    sudo chmod 640 /var/lib/rspamd/dkim/narro.ch.ams202609.key
    sudo usermod -aG _rspamd air-mail
    # à vérifier des DEUX côtés, la régression est silencieuse :
    sudo -u air-mail -g _rspamd test -r /var/lib/rspamd/dkim/narro.ch.ams202609.key
    sudo -u _rspamd test -r /var/lib/rspamd/dkim/narro.ch.ams202609.key

Les cinq comptes, avec les alias que `valiases` porte. Le mot de passe se lit sur
l'entrée standard, **jamais sur la ligne de commande** : ce que `ps` affiche,
tout le monde le lit.

Avec cinq boîtes, l'option A de §5 de l'étude — tout réinitialiser — est la plus
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

    # `contact` porte en plus les trois alias de `/etc/postfix/valiases`.
    mot=$(secret); printf 'contact : %s\n' "$mot"
    printf %s "$mot" | sudo -u air-mail air-mail-admin account add \
        /var/lib/air-mail/comptes.bin --login contact \
        --address contact@narro.ch --address postmaster@narro.ch \
        --address abuse@narro.ch --address root@narro.ch \
        --address postmaster@mail.narro.ch

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

**CINQ SECRETS DISTINCTS, ET NON UN SEUL PARTAGÉ.** La boucle ci-dessus en tire
un par compte, et c'est délibéré : un secret commun laisserait, entre la bascule
et le moment où chacun l'aura changé, n'importe lequel des cinq ouvrir la boîte
des quatre autres. Ce n'est pas une fenêtre théorique — elle dure aussi longtemps
que la personne la plus lente à lire son courrier.

### 0.4ter Chacun pose ensuite le sien, sans passer par vous

Ces cinq secrets sont des secrets de PASSAGE. Une fois connecté, chacun pose le
sien lui-même :

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
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro; do
        sudo ln -sfn "/var/vmail/narro.ch/$compte/Maildir" "/var/vmail-vue/$compte"
    done
    bash verifier.sh --essais                     # le banc d'abord
    bash verifier.sh /var/vmail-ams /var/vmail-vue

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
      `*:993` et non `0.0.0.0:993`, et un client IPv6 doit se connecter ;
- [ ] un message entrant arrive ;
- [ ] un message sortant part, et **porte une signature DKIM valide** ;
- [ ] le certificat servi est bien celui de `mail.narro.ch`.

**Attention en lisant les boîtes** : un `FETCH BODY[…]` sans `.PEEK` POSE le
drapeau `\Seen`. Employez `BODY.PEEK[…]`, sans quoi vous marquerez comme lu ce
que vous étiez venu vérifier.

### 0.7 Prévenir

`pour-les-utilisateurs.md` est fait pour être envoyé tel quel. **Il porte la
date**, la durée de coupure et le moment où les secrets arrivent — il faut donc
le relire si l'un des trois change, sans quoi cinq personnes liront une date
fausse.

La fenêtre étant fixée au samedi 12, envoyez-le **au plus tard le mardi 8**
— quatre jours — et rappelez le vendredi 11, en même temps que les secrets
initiaux de §0.4.

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
    sudo postqueue -p        # doit être vide, ou presque
    #    S'il reste des messages, laissez-les : ils sont dans /var/spool/postfix
    #    et le retour en arrière les retrouvera.

    # 3. Le delta : ce qui est arrivé depuis la copie de 0.4.
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro; do
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

    # 4. L'audit, une dernière fois. S'il refuse : ON REMONTE (voir plus bas).
    # `verifier.sh` compare compte par compte : on lui donne de l'ancien magasin
    # une vue qui a la MÊME forme que le neuf.
    sudo mkdir -p /var/vmail-vue
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro; do
        sudo ln -sfn "/var/vmail/narro.ch/$compte/Maildir" "/var/vmail-vue/$compte"
    done
    bash verifier.sh /var/vmail-ams /var/vmail-vue

    # 5. L'instantané OVH. C'est ici qu'il vaut le plus cher.

    # 6. La configuration DÉFINITIVE : les vrais ports, la vraie racine.
    sudo -u air-mail air-mail-admin config write /var/lib/air-mail/serveur.conf \
        «les mêmes options qu'en 0.4, mais» \
        --listen [::]:25 --listen [::]:587 \
        --listen-smtps [::]:465 --listen-imaps [::]:993 \
        --maildir /var/vmail-ams

    # 7. On empêche l'ancien de revenir tout seul au prochain redémarrage.
    sudo systemctl disable postfix dovecot

    # 8. On démarre.
    sudo systemctl enable --now air-mail-server
    sudo journalctl -u air-mail-server -n 60 --no-pager

**Lisez les soixante lignes.** Le serveur dit au démarrage tout ce qu'il ne fera
pas : pas de résolveur, pas de liste de suffixes, pas de clé DKIM, pas de
quarantaine. Une ligne « ATTENTION » sur un nom de fichier illisible s'y trouve
aussi, s'il en reste.

### La coupure s'arrête ici

    # Depuis l'extérieur, pas depuis la machine :
    swaks --to jean@narro.ch --server mail.narro.ch
    openssl s_client -connect mail.narro.ch:993 -quiet

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

    # 3. Remettre l'ancien en marche.
    sudo systemctl enable --now postfix dovecot

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
- **J+30** : si tout va bien, on peut publier `MTA-STS` et `TLSRPT`, qui
  n'existent pas aujourd'hui, et faire passer `DMARC` de `p=none` à
  `p=quarantine`. Un changement à la fois, une semaine d'écart.
- **J+30** : alors seulement, désinstaller l'ancien et libérer `/var/vmail`.
