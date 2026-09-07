# La bascule, et le retour en arrière

Ce document se lit AVANT le jour J, en entier, et se suit ligne à ligne le jour
même. Il suppose que `etude-narro.md` a été lu et que la décision de §5 (les
mots de passe) est prise.

**Le principe qui gouverne tout : on ne remplace rien tant que la copie n'a pas
été éprouvée, et on garde l'ancien intact jusqu'à ce qu'on décide de ne plus en
avoir besoin.**

---

## LA FENÊTRE EST FIXÉE : samedi 19 septembre 2026, 09:00 CEST

Décidée le 2026-09-07. Le chemin qui y mène, et pourquoi chaque étape est là :

| Quand | Quoi | Pourquoi cette date |
|---|---|---|
| **mardi 8 septembre** | nouveau sélecteur DKIM **2048 bits** publié, et **rspamd signe avec** | la clé s'éprouve sous Postfix, en production. Le jour J ne changera plus que le serveur |
| 9 → 17 septembre | on vérifie que les signatures se valident chez Gmail et Outlook | une semaine de vrai courrier vaut mieux qu'un essai |
| **jeudi 17** | `deploy-hook` certbot pour `privkey.pem` ; première sauvegarde complète ; copie et `verifier.sh` à blanc | le blanc trouve les surprises pendant qu'on a le temps |
| **vendredi 18** | distribution des **cinq secrets initiaux, tous distincts** | un secret commun laisserait chacun ouvrir la boîte des autres |
| **samedi 19, 09:00** | la fenêtre | volume entrant au plus bas, utilisateurs joignables, deux jours de marge |

**Le détail du samedi.** 09:00 sauvegarde et copie finale ; 09:30 arrêt de
Postfix, delta, démarrage d'`air-mail-server` ; 09:50 `verifier.sh` décide ;
10:00 essais clients ; 11:00 fin. **Coupure réelle : environ vingt minutes.**

**LE RETOUR EN ARRIÈRE NE DÉPEND D'AUCUN DNS.** La bascule ne touche ni le `MX`
ni le `A` : même machine, même enregistrement. Revenir, c'est redémarrer Postfix
et rapatrier le courrier de la fenêtre par `rapatrier.sh` — quelques minutes,
sans propagation à attendre.

**Pourquoi le 19 et pas le 12 :** la clé DKIM a besoin de sa semaine sous
Postfix. Le 12 ne serait tenable qu'en publiant le sélecteur le jour même de
cette décision, et sans marge.

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
    sudo chown -R ams:ams /var/vmail-ams

    printf %s "$SECRET_RESEND" | sudo -u ams air-mail-admin config write \
        /etc/ams/essai.conf \
        --domain mail.narro.ch --hosted narro.ch \
        --maildir /var/vmail-ams --accounts /etc/ams/comptes.bin \
        --listen 127.0.0.1:2525 --listen-imaps 127.0.0.1:9993 \
        --max-message 52428800 \
        --tls-cert /etc/letsencrypt/live/mail.narro.ch/fullchain.pem \
        --tls-key  /etc/letsencrypt/live/mail.narro.ch/privkey.pem \
        --relay --queue-spool /var/spool/ams/file \
        --queue-expire-seconds 86400 \
        --require-fqdn-helo \
        --require-fqdn-sender --require-fqdn-recipient \
        --require-sender-domain \
        --listen-http 0.0.0.0:8443 \
        --dkim-selector mail --dkim-key /var/lib/rspamd/dkim/narro.ch.mail.key \
        --resolver 127.0.0.53:53 \
        --public-suffix-list /usr/share/publicsuffix/public_suffix_list.dat \
        --relayhost smtp.resend.com:465 --relayhost-implicit-tls \
        --relayhost-user «le compte Resend, dans /etc/postfix/sasl_passwd» \
        --mta-sts-anchors /etc/ssl/certs/ca-certificates.crt \
        --mta-sts-cache /var/cache/ams/mtasts

**CETTE COMMANDE VIENT DE L'INVENTAIRE**, valeur par valeur, et chacune a une
raison :

**`--listen-http 0.0.0.0:8443` OUVRE L'API REST**, et il faut savoir pourquoi
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
- **Si vous préférez fermer** : ôtez la ligne, et les mots de passe se posent
  alors par `account passwd` en §0.4ter. Les utilisateurs perdent le
  libre-service, vous gardez la main.

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
| `--dkim-key /var/lib/rspamd/...` | c'est **rspamd** qui signe aujourd'hui, pas opendkim. La clé publique dérivée de ce fichier est identique à celle que le DNS publie — vérifié. |
| `--relayhost smtp.resend.com:465` | `relayhost = [smtp.resend.com]:465` avec `smtp_tls_wrappermode = yes`. Le compte et le secret sont dans `/etc/postfix/sasl_passwd`. |
| `--mta-sts-anchors` | **exigé par `--relayhost`** : on présente un mot de passe, et sans autorités on ne saurait pas à qui. |
| `--resolver 127.0.0.53:53` | `systemd-resolved` écoute là. **`--relay` sans résolveur fait REFUSER le démarrage**, et c'est heureux. |

**Le compte sous lequel tourne le serveur doit lire deux fichiers que root seul
possède** : `privkey.pem` et la clé DKIM de rspamd. Un groupe, ou un
`deploy-hook` de `certbot` qui recopie, ou les deux.

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
        printf %s "$mot" | sudo -u ams air-mail-admin account add \
            /etc/ams/comptes.bin --login "$compte" --address "$compte@narro.ch"
    done

    # `contact` porte en plus les trois alias de `/etc/postfix/valiases`.
    mot=$(secret); printf 'contact : %s\n' "$mot"
    printf %s "$mot" | sudo -u ams air-mail-admin account add \
        /etc/ams/comptes.bin --login contact \
        --address contact@narro.ch --address postmaster@narro.ch \
        --address abuse@narro.ch --address root@narro.ch

`postmaster@` est ici une exigence, pas une commodité : §4.5.1 de RFC 5321 la
pose, et le serveur AVERTIT au démarrage si personne ne la reçoit.

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

    printf %s "$NOUVEAU" | sudo -u ams air-mail-admin account passwd \
        /etc/ams/comptes.bin --login contact

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

    python3 renommer-dossiers.py /var/vmail-ams              # à blanc
    python3 renommer-dossiers.py /var/vmail-ams --pour-de-vrai

Il ne touche pas aux noms purement ASCII, et refuse de renommer si la cible
existe déjà.

### 0.5 L'audit qui décide

    # `verifier.sh` compare compte par compte : on lui donne de l'ancien magasin
    # une vue qui a la MÊME forme que le neuf.
    sudo mkdir -p /var/vmail-vue
    for compte in contact thierry.delhaise vincent.delhaise support kelly.garro; do
        sudo ln -sfn "/var/vmail/narro.ch/$compte/Maildir" "/var/vmail-vue/$compte"
    done
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
    sudo chown -R ams:ams /var/vmail-ams

    # 3bis. **LE `--delete` VIENT DE DÉFAIRE LES RENOMMAGES DE 0.4bis.**
    #       Il a effacé les répertoires en UTF-8 et remis ceux de Dovecot. On
    #       retraduit donc, et le script est fait pour être relancé : il ne
    #       touche que ce qui reste à traduire.
    #       OUBLIER CETTE LIGNE rend tous les dossiers accentués illisibles,
    #       et cela ne se verra qu'une fois les clients reconnectés.
    python3 renommer-dossiers.py /var/vmail-ams --pour-de-vrai
    sudo chown -R ams:ams /var/vmail-ams

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
    bash rapatrier.sh /var/vmail-ams /var/vmail-vue            # à blanc
    bash rapatrier.sh /var/vmail-ams /var/vmail-vue --pour-de-vrai
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
