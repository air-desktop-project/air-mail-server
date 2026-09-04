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

Le serveur écoute sur des ports hauts ; le pare-feu y redirige les ports
attendus. Avec `nftables` :

```
table inet mail {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        tcp dport 25  redirect to :2525
        tcp dport 587 redirect to :2525
        tcp dport 143 redirect to :1143
        tcp dport 993 redirect to :1143
        tcp dport 110 redirect to :1110
        tcp dport 995 redirect to :1110
    }
}
```

> **Cette table n'a pas été éprouvée par ce projet.** Elle est donnée comme point
> de départ ; c'est le seul endroit de ce document qui ne soit pas vérifié contre
> le binaire. Vérifiez-la sur votre machine avant de vous y fier.
>
> Deux remarques qui valent quand même : `redirect` ne s'applique qu'au trafic
> ARRIVANT, et le serveur voit alors le port haut — c'est normal. Et 465, 993 et
> 995 sont des ports « TLS implicite » : ce serveur ne sert que le `STARTTLS`
> explicite, donc les y rediriger ne fera pas ce que leurs clients attendent.

---

## 7. L'unité systemd

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

---

## Ce que ce document ne couvre pas

- **L'interopérabilité a été éprouvée contre Postfix et contre Exim**, dans les
  deux sens et sous `STARTTLS` de part et d'autre : ils remettent chez nous, nous
  remettons chez eux, la signature DKIM arrive intacte et un message de plusieurs
  centaines de kibioctets revient identique octet pour octet. Les deux n'ont pas
  emprunté le même chemin — Postfix envoie `DATA`, Exim prend `BDAT` —, et leurs
  conversations sont désormais rejouées par les essais, sans qu'aucun des deux
  n'ait à être installé.

  **Ce que cela ne dit pas** : aucun service commercial n'a été confronté, ni
  OpenSMTPD, ni un envoi en masse. Et la première remise de production reste à
  faire.
- **La table `nftables` ci-dessus n'est pas éprouvée**, et elle seule : personne
  ne l'a fait tourner. L'unité systemd, elle, l'a été — voir le §7.
- **Il n'y a pas de paquet**, ni de script d'installation. Ce document décrit
  des gestes à faire, pas une commande à lancer.
- **La durée de vie des jetons ne se règle pas** : quinze minutes par défaut,
  douze heures au plus, gravées dans le code.
