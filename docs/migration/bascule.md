# La bascule, et le retour en arrière

Ce document se lit AVANT le jour J, en entier, et se suit ligne à ligne le jour
même. Il suppose que `etude-narro.md` a été lu et que la décision de §5 (les
mots de passe) est prise.

**Le principe qui gouverne tout : on ne remplace rien tant que la copie n'a pas
été éprouvée, et on garde l'ancien intact jusqu'à ce qu'on décide de ne plus en
avoir besoin.**

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

### 0.2 Sauvegarde, et vérification de la sauvegarde

**Un instantané OVH du VPS**, pris depuis le manager. C'est le filet de dernier
recours ; il ne remplace pas ce qui suit.

**Et une copie du courrier ET de la configuration**, hors de la machine :

    sudo tar -C / -czf /tmp/avant-ams-$(date +%F).tar.gz \
        var/vmail etc/postfix etc/dovecot etc/opendkim etc/opendkim.conf
    # …puis rapatriez-la, et VÉRIFIEZ qu'elle se relit :
    tar -tzf avant-ams-*.tar.gz | wc -l

Une sauvegarde qu'on n'a pas ouverte n'est pas une sauvegarde. Le chemin
`var/vmail` est à remplacer par celui que l'inventaire a montré.

### 0.3 Poser air-mail-server SANS rien remplacer

    sudo dpkg -i air-mail-server_*.deb

Le paquet **n'active ni ne démarre le service** — c'est délibéré, et
`check-paquet.sh` l'éprouve. Postfix et Dovecot continuent de tourner, intacts.

### 0.4 Une configuration en PORTS HAUTS, sur une COPIE du courrier

    sudo rsync -aH --delete /var/vmail/ /var/vmail-ams/
    sudo chown -R ams:ams /var/vmail-ams

    sudo -u ams air-mail-admin config write /etc/ams/essai.conf \
        --domain mail.narro.ch --hosted narro.ch \
        --maildir /var/vmail-ams --accounts /etc/ams/comptes.bin \
        --listen 127.0.0.1:2525 --listen-imaps 127.0.0.1:9993 \
        --max-message 52428800 \
        --tls-cert /etc/letsencrypt/live/mail.narro.ch/fullchain.pem \
        --tls-key  /etc/letsencrypt/live/mail.narro.ch/privkey.pem \
        --relay --queue-spool /var/spool/ams/file \
        --dkim-selector mail --dkim-key /etc/opendkim/keys/narro.ch/mail.private \
        --resolver 127.0.0.53 \
        --public-suffix-list /usr/share/publicsuffix/public_suffix_list.dat

Les chemins viennent de l'inventaire ; ceux-ci sont des exemples. Les comptes se
créent selon la décision de §5 :

    printf %s "$MOT_DE_PASSE" | sudo -u ams air-mail-admin account add \
        /etc/ams/comptes.bin --login jean --address jean@narro.ch \
        --address j.dupont@narro.ch

Le mot de passe se lit sur l'entrée standard, **jamais sur la ligne de
commande** : ce que `ps` affiche, tout le monde le lit.

### 0.5 L'audit qui décide

    bash verifier.sh /var/vmail-ams /var/vmail

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
- [ ] un message entrant arrive ;
- [ ] un message sortant part, et **porte une signature DKIM valide** ;
- [ ] le certificat servi est bien celui de `mail.narro.ch`.

**Attention en lisant les boîtes** : un `FETCH BODY[…]` sans `.PEEK` POSE le
drapeau `\Seen`. Employez `BODY.PEEK[…]`, sans quoi vous marquerez comme lu ce
que vous étiez venu vérifier.

### 0.7 Prévenir

`pour-les-utilisateurs.md` est fait pour être envoyé tel quel. Comptez au moins
une semaine, et rappelez la veille.

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
    sudo rsync -aH --delete /var/vmail/ /var/vmail-ams/
    sudo chown -R ams:ams /var/vmail-ams

    # 4. L'audit, une dernière fois. S'il refuse : ON REMONTE (voir plus bas).
    bash verifier.sh /var/vmail-ams /var/vmail

    # 5. L'instantané OVH. C'est ici qu'il vaut le plus cher.

    # 6. La configuration DÉFINITIVE : les vrais ports, la vraie racine.
    sudo -u ams air-mail-admin config write /etc/ams/serveur.conf \
        «les mêmes options qu'en 0.4, mais» \
        --listen 0.0.0.0:25 --listen 0.0.0.0:587 \
        --listen-smtps 0.0.0.0:465 --listen-imaps 0.0.0.0:993 \
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
    #    `--ignore-existing` ne recopie QUE ce qui est neuf : les messages que
    #    l'ancien magasin porte déjà gardent leurs drapeaux d'origine.
    sudo rsync -aH --ignore-existing /var/vmail-ams/ /var/vmail/
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
  fenêtre de deux heures.
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
