# Installer air-mail-server

Ce document dit comment mettre ce serveur en service, dans l'ordre où les
décisions se prennent. Il ne répète pas le pourquoi : celui-ci vit dans
[`contraintes.md`](contraintes.md) et dans le code, qui porte ses raisons.

**Tout ce qui est écrit ici a été vérifié contre le binaire**, pas contre le
souvenir qu'on en a. Là où quelque chose n'est pas fait, c'est dit.

---

## Ce qu'il faut savoir avant de commencer

Trois décisions de ce serveur changent la façon de l'installer, et il vaut mieux
les connaître avant de taper la première commande.

**Il refuse de s'exécuter en superutilisateur** (C10), et il n'y a pas d'option
pour le forcer. Les ports 25, 465, 587, 110, 995, 143 et 993 sont donc
inaccessibles directement : ils s'atteignent par une redirection de pare-feu,
posée hors du serveur. C'est du travail en plus, et c'est le prix de ne jamais
avoir de code de privilèges à se tromper.

**Il ne se règle que par un fichier binaire**, produit par `air-mail-admin`
(C11). Il n'a aucune option de réglage en ligne de commande — deux sources de
configuration seraient une de trop.

**L'absence de valeur EST l'absence de service.** Il n'y a presque aucun drapeau
d'activation : pas de certificat, pas de `STARTTLS` ; pas de résolveur, pas de
SPF ; pas de dossier de file, pas d'émission. Le serveur annonce à chaque
démarrage ce qu'il sert et ce qu'il ne sert pas — **ces lignes sont la première
chose à lire**, et elles disent ce qui manque plutôt que de le taire.

---

## En un geste, si vous préférez

```sh
git clone https://github.com/air-desktop-project/air-mail-server
cd air-mail-server
sudo ./scripts/installer.sh
```

Il fait les gestes MÉCANIQUES des sections 1, 2, 6 et 7 : construire, le compte
Unix, l'arborescence et ses permissions, les binaires, l'unité systemd, et la
table du pare-feu ÉCRITE dans un fichier.

**Il n'écrit pas la configuration et n'ajoute aucun compte** — ces deux-là
demandent un domaine et des mots de passe, c'est-à-dire des décisions. Il
imprime les commandes exactes en terminant.

### Ou par un paquet Debian, sur Ubuntu

**LA CIBLE DE DÉPLOIEMENT EST UBUNTU**, et c'est ce qui décide du format : un
`.deb`, et rien d'autre. Debian et Ubuntu partagent `dpkg`, la charte, et
l'emplacement des unités systemd ; le paquet vaut donc pour les deux, mais c'est
la seconde qu'il vise.

```sh
./scripts/paquet.sh                       # produit air-mail-server_<version>_<arch>.deb
sudo dpkg -i air-mail-server_*.deb
```

**IL EST ÉPROUVÉ SUR LA DISTRIBUTION QU'IL VISE**, et pas seulement sur la
machine de développement : l'intégration continue tourne sur `ubuntu-latest`, où
`scripts/check-paquet.sh` construit le paquet, le déballe, et **exécute son
`postinst`** sous des doublures — onze contrôles, à chaque poussée.

Le paquet fait poser son arborescence **par `installer.sh` lui-même** : il n'y a
pas deux textes qui décrivent la même unité systemd, et donc pas deux textes qui
peuvent diverger.

Ce qu'il ajoute au script, et qui manquait :

| | `installer.sh` | le paquet |
|---|---|---|
| dépendances | supposées | calculées par `dpkg-shlibdeps` |
| mise à jour | à refaire à la main | `dpkg -i` de la version suivante |
| **désinstallation** | **impossible** | `dpkg -r`, et le service s'arrête d'abord |

**`dpkg --purge` N'EFFACE PAS VOTRE COURRIER.** `/var/lib/air-mail` porte les
boîtes en plus de la configuration, et un purge n'est pas une raison de perdre
du courrier. Le paquet le laisse en place et vous dit comment l'effacer
vous-même, si c'est ce que vous voulez.

Il n'active ni ne démarre le service : le serveur refuse de démarrer sans
configuration, et l'allumer ferait échouer le service à chaque démarrage de la
machine — ce qui apprendrait à le voir échouer sans s'en inquiéter.

**Il n'y a pas de `.rpm`**, et c'est une décision plutôt qu'un retard : voir
`docs/v1.md`, B6.

**Il n'applique aucune règle de pare-feu.** Poser des règles sur une machine
distante est précisément ce qui peut vous couper de la session par laquelle vous
lui parlez. Il écrit la table, vous la relisez, vous la chargez.

Pour voir ce qu'il ferait sans qu'il touche à rien :

```sh
./scripts/installer.sh --racine /tmp/essai
```

`--racine` préfixe TOUT chemin écrit, à la façon d'un `DESTDIR`. C'est ainsi que
`scripts/check-installation.sh` le fait tourner à chaque poussée — arborescence,
permissions, validité de l'unité, idempotence — plutôt que de le relire.

Les sections qui suivent décrivent les mêmes gestes à la main, et disent
pourquoi chacun.

---

## 1. Construire

La chaîne d'outils est épinglée à une version exacte (`rust-toolchain.toml`), et
`rustup` la prend seul :

```sh
git clone https://github.com/air-desktop-project/air-mail-server
cd air-mail-server
cargo build --release
```

Deux binaires en sortent, dans `target/release/` :

| binaire | rôle |
|---|---|
| `air-mail-server` | le serveur ; ne lit qu'un fichier de configuration |
| `air-mail-admin` | tout le reste : configuration, comptes, jetons |

Aucun outil C++ n'est nécessaire : le code dérivé des schémas Cap'n Proto est
committé.

---

## 2. Le compte Unix, et où vivent les fichiers

Un compte dédié, sans interpréteur de commandes ni mot de passe :

```sh
sudo useradd --system --home-dir /var/lib/air-mail --create-home \
             --shell /usr/sbin/nologin air-mail
```

Une disposition qui marche, et qu'on peut changer :

```
/var/lib/air-mail/
├── air-mail.conf      la configuration binaire
├── comptes.bin        les comptes et leurs empreintes
├── maildir/           le courrier
├── file/              la file de réémission (si l'on émet)
└── dkim.pem           la clé privée DKIM (si l'on signe)
```

**Les deux programmes resserrent leur masque de création** : ce qu'ils créent
naît en `0600`, leurs répertoires en `0700`. Il n'y a rien à faire pour cela — et
rien pour le desserrer, ce qui est voulu : tout ce que ce serveur pose sur le
disque est soit un secret, soit le courrier de quelqu'un.

> **Une installation antérieure au 2026-09-03 doit être resserrée à la main.**
> Un masque ne vaut que pour ce qui NAÎT après lui. Le serveur examine au
> démarrage le Maildir, la configuration et le magasin des comptes, et dit
> lesquels restent ouverts avec la commande qui les referme :
>
> ```sh
> chmod -R go= /var/lib/air-mail
> ```

---

## 3. La première configuration

Le minimum qui serve à quelque chose :

```sh
air-mail-admin config write /var/lib/air-mail/air-mail.conf \
    --domain mail.example.com \
    --hosted example.com \
    --maildir /var/lib/air-mail/maildir \
    --accounts /var/lib/air-mail/comptes.bin \
    --listen 127.0.0.1:2525
```

`--hosted` est **répétable**, et sans lui le serveur n'accepte de courrier pour
personne : un serveur qui accepterait tout serait un relais ouvert.

`config write` **refuse d'écraser un fichier qu'il ne reconnaît pas**. Un chemin
tapé de travers ne détruit donc pas le fichier de quelqu'un d'autre ; si vous
vouliez bien remplacer celui-là, effacez-le d'abord.

Pour relire ce qu'on vient d'écrire :

```sh
air-mail-admin config show /var/lib/air-mail/air-mail.conf
```

Cette sortie **dit aussi ce qui est absent** — « TLS AUCUN — le serveur sert EN
CLAIR », « SPF AUCUN RÉSOLVEUR », « API REST AUCUNE ». Une ligne manquante se
lirait « rien à signaler », or c'est l'inverse.

---

## 4. Les comptes

```sh
printf %s "$MOT_DE_PASSE" | air-mail-admin account add \
    /var/lib/air-mail/comptes.bin --login jean \
    --address jean@example.com --address contact@example.com
```

**Le mot de passe se lit sur l'entrée standard**, jamais en argument : ce que
`ps` affiche, tout le monde le lit.

`--address` est répétable et donne les adresses qui arrivent dans cette boîte.
Sans aucune, le compte se connecte mais ne reçoit rien.

Le nom du compte est aussi le nom de sa boîte : ni vide, ni `.`, ni `..`, sans
`/`, sans point en tête.

**Un compte ajouté pendant que le serveur tourne est vu sans redémarrage** — il
relit le magasin quand le fichier change, au plus une fois par seconde. Les deux
programmes se partagent ce fichier par un verrou, si bien que des ajouts
simultanés ne se perdent pas.

### SCRAM, si vous voulez que le mot de passe ne traverse jamais le fil

`PLAIN` sous TLS ne montre le mot de passe à personne sur le chemin — mais il le
montre au SERVEUR, qui doit le comparer. `SCRAM-SHA-256` (RFC 7677) ne le fait
pas traverser du tout : le client prouve qu'il le connaît sans l'envoyer.

Il demande **deux fichiers, et ils ne doivent pas vivre au même endroit** :

```sh
# 1. La clé de scellement, une fois pour toutes. `0600`, et AILLEURS que le magasin.
air-mail-admin scram init /etc/air-mail/scram.key

# 2. Un vérificateur par compte, dérivé du mot de passe.
printf %s "$MOT_DE_PASSE" | air-mail-admin account passwd \
    /var/lib/air-mail/comptes.bin --login jean \
    --scram-key /etc/air-mail/scram.key --scram /var/lib/air-mail/scram.bin
```

> **`scram init` N'ÉCRASE JAMAIS UNE CLÉ EXISTANTE.** Une clé perdue rend TOUS
> les vérificateurs illisibles d'un coup, et rien ne les reconstitue : il
> faudrait reposer chaque mot de passe. Un `init` lancé deux fois par distraction
> coûterait donc autant qu'une suppression du magasin.

**POURQUOI DEUX FICHIERS, ET DEUX ENDROITS.** Le vérificateur SCRAM n'est pas une
empreinte : §9 de RFC 5802 dit qu'il permet d'usurper le serveur auprès des
clients. Il est donc scellé, et la clé qui l'ouvre ne vit pas avec lui — les
mettre côte à côte ne vaudrait pas mieux qu'un seul fichier en clair. C'est à
cette condition, et à elle seule, que ce serveur sert SCRAM (`docs/v1.md`, B7).

Puis on nomme les deux chemins dans la configuration :

```sh
air-mail-admin config write /etc/air-mail/ams.conf \
    … \
    --scram-key /etc/air-mail/scram.key --scram /var/lib/air-mail/scram.bin
```

`config write` **refuse l'une sans l'autre** : une clé sans magasin n'a rien à
ouvrir, un magasin sans clé ne s'ouvre pas, et dans les deux cas le serveur
démarrerait sans que le défaut se voie avant le premier client qui essaie.

Ce qu'il faut savoir ensuite :

- **les comptes sans vérificateur restent joignables en `PLAIN`.** SCRAM leur
  répond comme à un compte inconnu — §7 de RFC 5802 l'exige, sans quoi le magasin
  s'énumérerait — et refuse à la preuve ;
- **`SCRAM-SHA-256-PLUS` s'ajoute tout seul aux connexions TLS 1.3**, et à elles
  seules. Il lie la preuve à la session TLS elle-même (RFC 9266), ce qui ferme le
  relais par un intermédiaire muni d'un certificat valide. En TLS 1.2, la liaison
  ne peut pas être prouvée unique, et n'est donc pas annoncée ;
- **le magasin se relit à chaud**, comme celui des comptes : un vérificateur
  ajouté pendant que le serveur tourne est vu au plus une seconde après.
- **un vérificateur est LIÉ au mot de passe dont il est dérivé** (depuis la
  0.2.16) : l'empreinte du compte entre dans son scellement. Changer le mot de
  passe — par l'API, par `account passwd`, par quoi que ce soit — éteint l'ancien
  vérificateur, et l'ancien mot de passe ne passe plus par SCRAM. L'API redérive
  elle-même le vérificateur du mot de passe qu'elle pose.

### Mettre à jour depuis une version antérieure à 0.2.16

Les vérificateurs écrits avant la 0.2.16 ne sont pas liés, et **ne s'ouvrent
plus** : leurs comptes ne passent qu'en `PLAIN` tant qu'on ne les a pas liés. Le
démarrage le signale. Une commande les lie, une fois pour toutes :

```sh
sudo -u air-mail air-mail-admin scram bind /var/lib/air-mail/comptes.bin \
    --scram-key /etc/air-mail/scram.key --scram /var/lib/air-mail/scram.bin
```

> **NE LA LANCEZ QUE SI AUCUN MOT DE PASSE N'A ÉTÉ CHANGÉ PAR L'API** depuis la
> dernière dérivation. Jusqu'en 0.2.15, l'API ne touchait pas le magasin SCRAM :
> un compte dont le mot de passe a été changé par elle porte encore le
> vérificateur de l'ANCIEN. Le lier à l'empreinte du nouveau rouvrirait
> exactement la porte qu'on ferme. En cas de doute sur un compte,
> `account passwd --scram …` le redérive depuis le mot de passe en clair.
>
> Le signe qui rassure : `comptes.bin` n'a pas été modifié depuis `scram.bin`.

### Les mots de passe applicatifs : un secret par client de messagerie

Thunderbird et Apple Mail ne connaissent que l'identifiant et le mot de passe.
Avec un seul secret par compte, révoquer le client d'un poste perdu oblige à
changer le mot de passe, donc à reconfigurer tous les autres. Un **mot de passe
applicatif** se révoque seul.

```sh
# Le magasin, nommé dans la configuration. Il porte des CONDENSATS DE SECRETS :
# `0600`, comme celui des comptes — lisible par tous, il empêche de démarrer.
air-mail-admin config write /etc/air-mail/ams.conf … \
    --app-passwords /var/lib/air-mail/applicatifs.bin

# En créer un. Le secret est écrit UNE FOIS sur la sortie standard : copiez-le.
sudo -u air-mail air-mail-admin app-password add /var/lib/air-mail/applicatifs.bin \
    --accounts /var/lib/air-mail/comptes.bin --login jean --name "Thunderbird — bureau"

# Les voir (jamais un secret), en révoquer un.
sudo -u air-mail air-mail-admin app-password list /var/lib/air-mail/applicatifs.bin
sudo -u air-mail air-mail-admin app-password remove /var/lib/air-mail/applicatifs.bin \
    --login jean --id 0123456789abcdef
```

L'utilisateur peut aussi les gérer lui-même par l'API (`/v1/me/app-passwords`).
Ce qu'il faut savoir :

- **ils ouvrent IMAP, SMTP et POP3, en `PLAIN`** — toujours sous TLS —, avec le
  nom de compte ou une de ses adresses. **Ni SCRAM, ni l'API REST** ;
- **le mot de passe principal reste valable** à côté d'eux ;
- la date de dernière utilisation est tenue **à l'heure près** ;
- `account remove … --app-passwords <magasin>` retire aussi ceux du compte :
  sans cela, un compte recréé sous le même nom en hériterait.

### La délégation : ouvrir une boîte à un autre compte

Une boîte partagée — `support`, `compta` — est un compte comme un autre, dont
d'autres comptes atteignent la boîte **par l'API**, sous
`/v1/accounts/support/mailboxes/…`. Qui y accède, et pour quoi faire, se décide
**par l'administration seule** : ni le titulaire ni le délégué ne peuvent
s'ouvrir un accès.

```sh
# Le magasin, nommé dans la configuration. `0600`, comme les autres.
air-mail-admin config write /etc/air-mail/ams.conf … \
    --delegations /var/lib/air-mail/delegations.bin

# Poser une délégation, avec un jeton d'administration (`admin:write`).
# Droits : read, write, send — écrire et envoyer impliquent lire.
curl --http2 -X PUT -H "Authorization: Bearer $JETON" \
    -d '{"rights":["write","send"]}' \
    https://mail.example.org:8443/v1/accounts/support/delegates/jean
```

- **la table se relit à chaque requête** : une délégation retirée
  (`DELETE …/delegates/jean`) cesse de valoir tout de suite, sans révoquer de
  jeton ;
- sans le droit, la réponse est `404`, comme pour un compte qui n'existe pas ;
- `send` permet d'envoyer avec pour `From:` une adresse du titulaire ;
- chaque écriture sur la boîte d'autrui est **journalisée avec son acteur** ;
- `account remove … --delegations <magasin>` retire celles du compte, dans les
  deux sens (l'API le fait d'elle-même en supprimant un compte) ;
- **IMAP ne les voit pas encore** : un client de messagerie n'atteint que sa
  propre boîte.

---

## 5. Le chiffrement

Sans certificat, le serveur sert en clair et ne l'annonce pas. C'est utilisable
pour une remise entrante ; ce ne l'est pas pour relever son courrier :

> **POP3 et IMAP exigent un certificat pour servir à quelque chose.** Leurs
> sessions refusent l'authentification hors chiffrement, sans réglage possible.
> Un `--listen-pop3` sans `--tls-cert` ouvre un port où personne ne pourra
> relever son courrier — le serveur le dit au démarrage.

```sh
air-mail-admin config write /var/lib/air-mail/air-mail.conf \
    --domain mail.example.com --hosted example.com \
    --maildir /var/lib/air-mail/maildir \
    --accounts /var/lib/air-mail/comptes.bin \
    --tls-cert /etc/letsencrypt/live/mail.example.com/fullchain.pem \
    --tls-key  /etc/letsencrypt/live/mail.example.com/privkey.pem \
    --listen 127.0.0.1:2525 \
    --listen-imap 127.0.0.1:1143 \
    --listen-pop3 127.0.0.1:1110
```

**Le serveur refuse de démarrer si la clé privée est lisible par tout le monde.**
Le partage par groupe reste permis — c'est ce dont Let's Encrypt a besoin :

```sh
sudo chgrp air-mail /etc/letsencrypt/live/mail.example.com/privkey.pem
sudo chmod 640      /etc/letsencrypt/live/mail.example.com/privkey.pem
```

Les deux options TLS vont **ensemble, ou aucune**. Il n'y a pas de troisième
réglage : « annoncer sans pouvoir » ferait mentir la bannière.

---

## 6. Les ports privilégiés

Le serveur **refuse de s'exécuter en superutilisateur** (C10), et ne peut donc
pas lier un port sous 1024. Les deux moitiés se mesurent :

```
# ip netns exec ams-srv air-mail-server --config … 
air-mail-server : le serveur refuse de s'exécuter en tant que superutilisateur
(C10) ; les ports privilégiés s'atteignent par une redirection de pare-feu

$ air-mail-server --config …   # avec `--listen 0.0.0.0:25`
air-mail-server : écoute sur 0.0.0.0:25 : Permission denied (os error 13)
```

La redirection n'est donc pas un confort : c'est le seul chemin.

```
table inet mail {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        tcp dport 25  redirect to :2525
        tcp dport 587 redirect to :2525
        tcp dport 465 redirect to :4465
        tcp dport 143 redirect to :1143
        tcp dport 993 redirect to :9993
        tcp dport 110 redirect to :1110
        tcp dport 995 redirect to :9995
    }
}
```

avec la configuration qui lui répond :

```
air-mail-admin config write /var/lib/air-mail/air-mail.conf \
    --listen [::]:2525 --listen-smtps [::]:4465 \
    --listen-imap [::]:1143 --listen-imaps [::]:9993 \
    --listen-pop3 [::]:1110 --listen-pop3s [::]:9995 \
    --tls-cert … --tls-key … …
```

**`[::]`, ET NON `0.0.0.0`.** Le second est de l'IPv4 seule ; le premier couvre
les deux familles dès que `net.ipv6.bindv6only` vaut 0, ce qui est le défaut de
Linux. La table `inet mail` ci-dessus redirige déjà dans les deux familles — une
écoute en `0.0.0.0` derrière elle sert donc l'IPv4 et REFUSE l'IPv6, et rien ne
le dit : un émetteur qui résout la AAAA d'abord se rabat après délai, quand il
se rabat. Cette page a donné `0.0.0.0` en exemple, l'exemple a été suivi sur
`mail.air-desktop.org`, et le port 25 y a refusé l'IPv6 pendant quatre jours
(mesuré et corrigé le 2026-09-16). `ss -ltn` doit montrer `*:2525`, pas
`0.0.0.0:2525`.

**Cette table a été éprouvée**, dans deux espaces de noms réseau reliés par un
`veth` — l'un portant le serveur et la table, l'autre jouant le client. Ce qui
suit est ce qui en est sorti, et non ce qu'on en attendait.

| port | redirigé vers | mesuré |
|---|---|---|
| 25 | 2525 | `220 mail.essai.test ESMTP`, `STARTTLS` accepté |
| 587 | 2525 | `220 mail.essai.test ESMTP` |
| 465 | 4465 | poignée de main **TLS 1.3**, puis la bannière |
| 993 | 9993 | poignée de main **TLS 1.3**, puis `* OK [CAPABILITY IMAP4rev2 …]` |
| 110 | 1110 | `+OK POP3 server ready` |
| 143 | 1143 | **redirection NON éprouvée** — le port 1143 l'a été, directement |
| 995 | 9995 | **redirection NON éprouvée** — le port 9995 l'a été, directement |

Un message remis par le **465** a été relu par le **993**, sujet et corps
intacts, à travers la redirection.

**LES DEUX DERNIÈRES LIGNES DISENT MOINS QUE LES CINQ AUTRES**, et c'est
délibéré. Les ports 1143 et 9995 ont été éprouvés le 2026-09-06 — le premier
répond `* OK [CAPABILITY …]` en `STARTTLS`, le second une poignée de main
TLS 1.3 puis `+OK POP3 server ready` —, mais **pas à travers la table** : la
mesure `veth` demande des privilèges que la séance qui les a ajoutés n'avait
pas. Leur règle a la forme exacte des cinq autres, et rien ne distingue une
redirection de port d'une autre ; ce n'est pas une raison pour écrire qu'on l'a
vue marcher.

### L'adresse du client survit à la redirection

C'est ce qui compte pour le garde et pour la trace, et cela se vérifie dans
l'en-tête déposé :

```
Received: from client.essai.test ([10.99.0.2])
	by mail.essai.test with ESMTPS;
```

`redirect` change la DESTINATION, jamais la source.

### Les sept redirections, et deux qui sont récentes

Le 143 et le 995 ont été ajoutés le 2026-09-06 : avant cette date, le 995
n'était pas servable du tout, et le 143 ne pouvait pas l'être en même temps que
le 993. Chaque protocole porte désormais une LISTE d'écoutes, et chacune garde
son mode — d'où `--listen-imap` ET `--listen-imaps`, `--listen-pop3` ET
`--listen-pop3s` dans la commande ci-dessus.

### N'ajoutez PAS de chaîne `output`

Un port redirigé n'est joignable que **depuis l'extérieur**. Depuis la machine
elle-même, `127.0.0.1:25` ET son adresse publique sur le 25 sont refusés : le
trafic local ne passe pas par `prerouting`. Un contrôle local doit donc viser
le port haut — `127.0.0.1:2525`.

La correction qui vient à l'esprit est une chaîne `output`. **Elle est un
piège**, et voici la mesure. Avant :

```
srv → 10.99.0.2:25   '220 MTA-EXTERIEUR'
```

après avoir ajouté `chain output { type nat hook output priority dstnat; }`
avec `tcp dport 25 redirect to :2525` :

```
srv → 127.0.0.1:25   '220 mail.essai.test ESMTP'    ← ce qu'on voulait
srv → 10.99.0.2:25   '220 mail.essai.test ESMTP'    ← le MTA extérieur a disparu
```

La règle ne distingue pas « le 25 de cette machine » du « 25 de n'importe qui » :
**toute** connexion locale vers un port 25, où qu'il soit, revient au serveur
lui-même. Une sonde qui croit interroger un MTA distant s'interroge elle-même,
et n'a aucun moyen de s'en apercevoir.

---

## 7. L'unité systemd

**Elle est écrite par `scripts/installer.sh`**, et la voici telle qu'il la pose.
Les deux textes sont identiques, et c'est le script qui fait foi : deux copies
d'un même fichier finissent par diverger, et celle qui TOURNE doit gagner.

```ini
[Unit]
Description=air-mail-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=air-mail
Group=air-mail
ExecStart=/usr/local/bin/air-mail-server --config /var/lib/air-mail/air-mail.conf
Restart=on-failure
RestartSec=5s

# Le serveur pose déjà 0077 lui-même ; le redire ici couvre ce qui serait
# créé avant qu'il n'ait la main.
UMask=0077

# Ce serveur n'a besoin d'aucun privilège : il refuse même de démarrer en root.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

ReadWritePaths=/var/lib/air-mail
# SI LE MAGASIN DE COURRIER EST AILLEURS, IL FAUT L'AJOUTER ICI — ou dans un
# drop-in /etc/systemd/system/air-mail-server.service.d/*.conf. Sans cela,
# ProtectSystem=strict le rend illisible et le serveur refuse de démarrer :
# « boîte de … : Read-only file system ». Trouvé le 2026-09-22, au démarrage
# de la bascule de narro.ch, Postfix déjà arrêté : le serveur n'avait jamais été
# lancé PAR L'UNITÉ sur ce chemin, seulement à la main, qui n'a pas de
# cloisonnement. (Sans accent grave : ce texte traverse un heredoc du script.)

# Ce serveur n'a besoin d'AUCUNE capacité, et l'unité le DIT au noyau plutôt
# que de l'affirmer en commentaire.
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
RemoveIPC=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid

# Les appels système d'un service ordinaire, et rien de plus.
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

> **Cette unité a été éprouvée, et voici comment.** Elle a été installée telle
> qu'elle est écrite ci-dessus, avec un compte `air-mail` système, une racine en
> `0700` et les binaires sous `/usr/local/bin`. Le service démarre, sert le SMTP
> et l'IMAP sous `STARTTLS`, écrit son Maildir sous `ReadWritePaths`, et
> `systemctl` le relance après un `kill -9` — `Restart=on-failure` fait ce qu'il
> annonce. `systemd-analyze security` la note **1.5 (OK)**.
>
> **Les onze dernières directives ont été ajoutées à cette occasion**, parce que
> l'unité d'avant AFFIRMAIT en commentaire que « ce serveur n'a besoin d'aucun
> privilège » sans le faire respecter : ni capacités vidées, ni filtre d'appels
> système. Sa note était 5.6 (MEDIUM). Une intention écrite qu'aucun réglage
> n'applique n'est pas une intention.
>
> Le filtre d'appels système a été éprouvé AVEC le reste : un durcissement qui
> empêcherait le serveur de servir ne vaudrait rien. La remise, la lecture et les
> deux `STARTTLS` fonctionnent sous `@system-service`.

---

## 8. Ce qui s'ajoute ensuite

Chacune de ces fonctions est éteinte tant qu'on ne la demande pas, et le serveur
dit à chaque démarrage laquelle manque.

### SPF, DMARC — il faut un résolveur

```sh
    --resolver 127.0.0.1:53 \
    --public-suffix-list /var/lib/air-mail/public_suffix_list.dat
```

**SPF est vérifié dès qu'un résolveur est nommé.** DMARC exige les **deux** : la
liste des suffixes publics, pour savoir si deux domaines s'alignent, et le
résolveur, pour aller lire la politique. L'outil refuse une configuration qui
demanderait un travail à DMARC sans les avoir.

Ces résolveurs sont **crus sur parole** : ce serveur ne valide pas DNSSEC
lui-même, il lit le bit `AD` de la réponse. Un résolveur validant sur la machine
même est donc le bon choix — DANE en dépend entièrement.

### Émettre du courrier

```sh
    --relay --queue-spool /var/lib/air-mail/file
```

Éteinte par défaut : ce serveur reçoit, il n'émet pas. **Tout ce qui sort passe
par la file** — le relais, mais aussi les rapports DMARC et TLS —, si bien que
`--queue-spool` est exigé dès que quelque chose sort.

### Signer en DKIM

```sh
openssl genpkey -algorithm ed25519 -out /var/lib/air-mail/dkim.pem
chmod 600 /var/lib/air-mail/dkim.pem
```

puis `--dkim-selector s1 --dkim-key /var/lib/air-mail/dkim.pem`.

**Le serveur imprime au démarrage l'enregistrement à publier**, prêt à coller :

```
    s1._domainkey.example.com. IN TXT "v=DKIM1; k=ed25519; p=…"
```

Il vérifie ensuite ce qui est publié, et distingue quatre issues : conforme,
différente, absente, DNS injoignable. Une clé **différente** est la seule qui
appelle une correction immédiate — tout ce qu'on émet échoue déjà.

### L'API REST d'administration

```sh
    --listen-http 127.0.0.1:8443
```

Elle **exige un certificat** : elle porte des jetons porteurs, et un jeton qui
traverse un réseau en clair est un jeton volé. `--listen-h3` ajoute HTTP/3, et
exige `--listen-http` — `Alt-Svc`, seul moyen par lequel un client découvre un
port HTTP/3, s'annonce depuis les réponses HTTP/2.

Le secret qui scelle les jetons est **tiré du noyau** à la première écriture qui
ouvre l'API, puis repris à chaque écriture suivante. Personne n'a besoin de le
connaître, donc personne n'a à le garder.

```sh
air-mail-admin token /var/lib/air-mail/air-mail.conf --login thierry
```

Quinze minutes par défaut, douze heures au plus. **Aucun mot de passe n'ouvre
l'administration** : c'est ce qui fait qu'un compte compromis ne devient jamais
le serveur entier.

---

## 9. Vérifier que tout est en place

```sh
air-mail-admin config show /var/lib/air-mail/air-mail.conf
sudo -u air-mail air-mail-server --config /var/lib/air-mail/air-mail.conf
```

Lisez les lignes de démarrage jusqu'au bout. Elles disent, une par une, ce qui
est servi et ce qui ne l'est pas — et **ce qui manque y est écrit en clair**,
avec l'option qui le fournirait.

Pour regarder une boîte sans client :

```sh
air-mail-admin summary /var/lib/air-mail/maildir/jean
```

### Le journal : une ligne par connexion, à sa fermeture

Le serveur écrit sur la sortie d'erreur, que `systemd` verse dans `journald` :
aucune configuration de journalisation n'est à poser.

```sh
journalctl -u air-mail-server -f
journalctl -u air-mail-server --since today | grep 'AUTH PLAIN'
```

Chaque connexion servie laisse **une seule ligne, écrite quand elle se ferme** :

```
air-mail-server : SMTP 178.197.196.110 — TLS1.3 (TLS13_AES_256_GCM_SHA384), AUTH PLAIN `ofrou-sierre`, 1 message accepté, 6 commande(s), 3 s
air-mail-server : IMAP 2001:db8::42 — TLS1.2 (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384), AUTH LOGIN `contact`, session ouverte, 24 commande(s), 41 s
air-mail-server : SMTP 192.0.2.7 — EN CLAIR, sans authentification, aucun message, 2 commande(s), 0 s
air-mail-server : SMTP 192.0.2.7 — connexion interrompue : le pair n'a rien envoyé dans le délai imparti, 300 s
```

Elle porte, dans cet ordre : le protocole, **d'où vient le pair**, ce que TLS a
négocié — version ET suite —, **sous quel mécanisme il s'est authentifié** et au
nom de quel compte, ce que la connexion a produit, combien de commandes, et
combien de temps.

**Une ligne, et à la fin.** Écrire à l'ouverture ne dirait rien encore : ni ce
qui a été négocié, ni qui s'est authentifié. Il faudrait deux lignes à recoller
soi-même, et elles s'entrelaceraient, puisque le serveur sert des milliers de
connexions à la fois.

**Le mécanisme est ce qu'on vient y chercher.** `PLAIN` dit que le mot de passe
a traversé le tunnel tel quel ; `SCRAM-SHA-256` qu'il est resté chez le client ;
`SCRAM-SHA-256-PLUS` que la preuve était en plus LIÉE à ce canal TLS. Un
exploitant qui croit SCRAM posé chez tous ses clients n'apprend que là qu'un
seul d'entre eux ne le fait pas. IMAP ajoute `LOGIN` — sa commande d'origine,
qui n'est pas un mécanisme SASL —, et POP3 n'offre que `USER/PASS`.

### Une soumission authentifiée n'est pas du courrier entrant

SPF, DKIM et DMARC répondent à une question : **ce message vient-il bien de qui
il prétend ?** Elle ne se pose que pour un inconnu. Quand le pair s'est
authentifié, ce serveur n'est pas le destinataire du message — il en est
l'ORIGINE, et il sait déjà qui parle.

Le serveur ne les évalue donc plus sur une soumission authentifiée. Il écrit à
la place ce qu'il a réellement vérifié, et au nom de qui (RFC 8601 §2.7.4) :

```
Authentication-Results: mail.narro.ch;
	auth=pass smtp.auth=ofrou-sierre
```

**Pourquoi ce n'est pas un affaiblissement.** Ce qui empêche un compte
d'usurper une autre adresse n'est pas DMARC : c'est la règle « un compte
n'écrit qu'en son nom », que la remise vérifie sur chaque soumission
authentifiée et qui, elle, n'a pas bougé. Un `From:` qui n'appartient pas au
compte est refusé, et l'incident nommé.

**Ce que cela corrige.** Une passerelle qui se présente en `HELO 127.0.0.1` —
ce qu'on lui accorde — n'a rien d'aligné en SPF et n'est pas signée à la
soumission : elle recevait `dmarc=fail`, c'est-à-dire un verdict d'usurpation
contre un client qui venait de prouver son identité. Sans dossier de
quarantaine configuré, rien n'était écarté ; avec, ses alertes auraient été
mises de côté en silence.

### Ce qu'une soumission dépose ici est signé

**Depuis la 0.2.5, une soumission authentifiée est signée en DKIM même quand
elle ne sort pas.** Jusque-là, seul ce qui partait en file l'était : un message
déposé dans une boîte d'ici n'était signé par personne, et rien ne permettait
d'établir qu'il venait de nous si on l'exportait ou le faisait suivre.

```
DKIM-Signature: v=1; a=ed25519-sha256; d=narro.ch; s=ams202609; ...
Authentication-Results: mail.narro.ch;
	auth=pass smtp.auth=ofrou-sierre
```

**Rien n'est rassemblé en mémoire pour autant** (C3) : le condensat du corps se
calcule au fil de l'eau pendant qu'il part vers le disque, et seul l'en-tête —
borné — est retenu. La place des deux en-têtes est réservée avant le premier
octet, comme elle l'était déjà pour l'`Authentication-Results` seul.

**On ne signe que pour un domaine dont on tient la zone.** Une signature pour
un domaine qui n'est pas le nôtre échoue partout, et son échec se lit dans les
rapports DMARC du domaine usurpé : c'est pire que pas de signature. Et un
message qu'on ne sait pas signer **part quand même** — refuser serait punir le
déposant d'une faute qui n'est pas la sienne.

#### Ce que le journal ne porte pas, et c'est délibéré

- **Aucun secret** : ni mot de passe, ni preuve SCRAM, ni octets de liaison. Le
  mécanisme se nomme ; ce qu'il a transporté, non.
- **Aucune adresse d'enveloppe, aucun objet de message.** Un journal
  d'exploitation dit QUI s'est connecté et CE QU'IL A OBTENU. Le laisser devenir
  une copie du courrier ferait des sauvegardes de `journald` un second magasin
  de messages que personne n'a décidé.
- **Rien que le pair ait écrit**, à une exception : le nom du compte, et
  seulement APRÈS que la politique l'a reconnu et canonisé. Il est en outre
  filtré à l'ASCII imprimable — un octet de contrôle y couperait la ligne en
  deux, et une fausse ligne se lit comme une vraie.
- **Rien d'un pair banni.** Il n'a rien reçu, pas même une bannière ; consigner
  chacune de ses tentatives donnerait à qui frappe le moyen de remplir le disque
  de celui qui l'a banni.

---

## Ce que ce document ne couvre pas

- **L'interopérabilité a été éprouvée contre Postfix, Exim et OpenSMTPD**, dans
  les deux sens et sous `STARTTLS` de part et d'autre : ils remettent chez nous, nous
  remettons chez eux, la signature DKIM arrive intacte et un message de plusieurs
  centaines de kibioctets revient identique octet pour octet. Les deux n'ont pas
  emprunté le même chemin — Postfix envoie `DATA`, Exim prend `BDAT` —, et leurs
  conversations sont désormais rejouées par les essais, sans qu'aucun des deux
  n'ait à être installé.

  **Ce que cela ne dit pas** : aucun service commercial n'a été confronté, ni un
  envoi en masse. Et la première remise de production reste à faire.
- **La table `nftables` du §6 a été éprouvée**, dans deux espaces de noms réseau,
  et le §6 dit ce qui en est sorti. Ce qui n'a PAS été éprouvé : la même table
  sur une machine qui porte déjà d'autres règles, où l'ordre des priorités
  compte.
- **Les six ports se servent ensemble** depuis le 2026-09-06 : 25, 587 et 465 en
  SMTP, 143 et 993 en IMAP, 110 et 995 en POP3. Chaque écoute porte son mode.
- **Il n'y a pas de PAQUET** — ni `.deb`, ni `.rpm`. Il y a un script
  d'installation, `scripts/installer.sh`, qui tourne à chaque poussée dans un
  arbre jetable. Ce qu'un paquet ferait de plus : les dépendances, la mise à
  jour, la désinstallation.
- **La durée de vie des jetons ne se règle pas** : quinze minutes par défaut,
  douze heures au plus, gravées dans le code.
