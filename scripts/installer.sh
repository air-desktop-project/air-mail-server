#!/usr/bin/env bash
#
# installer — pose air-mail-server sur une machine, en un geste.
#
# # CE QUE CE SCRIPT FAIT, ET CE QU'IL NE FERA JAMAIS
#
# `docs/installation.md` décrivait des gestes à faire, et le disait lui-même :
# « il n'y a pas de paquet, ni de script d'installation ». Une suite de gestes
# qu'on recopie à la main est une suite de gestes qu'on rate une fois sur dix, et
# dont personne ne sait, trois mois plus tard, lesquels ont été faits.
#
# Ce script fait les gestes MÉCANIQUES : le compte Unix, l'arborescence et ses
# permissions, les binaires, l'unité systemd.
#
# **Il n'écrit PAS la configuration, et n'ajoute AUCUN compte.** Ces deux-là
# demandent un domaine et des mots de passe, c'est-à-dire des décisions ; un
# script qui les inventerait poserait un serveur qui ne sert pas ce qu'on croit.
# Il imprime les commandes exactes, à la fin.
#
# **Il n'applique AUCUNE règle de pare-feu.** Il écrit la table dans un fichier
# et donne la commande qui la charge. Poser des règles sur la machine de
# quelqu'un est précisément ce qui peut le couper de ce dont il dépend — y
# compris de la session par laquelle il vous parle.
#
# # POURQUOI `--racine`, ET POURQUOI C'EST CE QUI REND CE SCRIPT ÉPROUVABLE
#
# Tout chemin qu'il écrit est préfixé par `--racine`, à la façon d'un `DESTDIR`.
# Avec `--racine /tmp/essai`, il pose l'arborescence entière dans un répertoire
# jetable, sans superutilisateur et sans toucher à la machine.
#
# C'est ce qui permet à `check-installation.sh` de le FAIRE TOURNER à chaque
# commit, plutôt que de le relire. Ce dépôt vient de reprocher à sa propre table
# `nftables` d'avoir été documentée sans jamais tourner ; un script
# d'installation qu'on ne lancerait qu'en production serait la même faute, en
# pire.
#
# # IDEMPOTENT, PARCE QU'UNE INSTALLATION SE REJOUE
#
# On le relance après une mise à jour, après un échec à mi-chemin, après avoir
# corrigé une faute de frappe. Chaque geste vérifie donc d'abord ce qui est déjà
# là, et ne le refait pas. Rien de ce qui existe n'est écrasé sans le dire.
set -euo pipefail

# ── CE QUI SE RÈGLE ─────────────────────────────────────────────────────────
racine=""
compte="air-mail"
prefixe="/usr/local/bin"
etat="/var/lib/air-mail"
unite="/etc/systemd/system/air-mail-server.service"
construire=1

usage() {
    cat >&2 <<'AIDE'
usage : installer.sh [OPTIONS]

    --racine <dir>    préfixe TOUT chemin écrit, à la façon d'un `DESTDIR`.
                      Avec lui, ni superutilisateur ni compte système : le
                      script pose une arborescence jetable et s'arrête là.
                      C'est ainsi qu'il s'éprouve.
    --compte <nom>    le compte Unix qui portera le service (air-mail)
    --prefixe <dir>   où poser les binaires (/usr/local/bin)
    --etat <dir>      où vivent configuration, comptes et courrier
                      (/var/lib/air-mail)
    --sans-construire ne pas lancer `cargo build --release` ; les binaires
                      doivent alors se trouver dans `target/release/`
    --aide            ceci

CE QU'IL NE FAIT PAS, ET QUI RESTE À FAIRE APRÈS LUI :
    la configuration, les comptes, le certificat, le pare-feu. Il imprime les
    commandes exactes en terminant.
AIDE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --racine) racine="${2-}"; shift 2 ;;
        --compte) compte="${2-}"; shift 2 ;;
        --prefixe) prefixe="${2-}"; shift 2 ;;
        --etat) etat="${2-}"; shift 2 ;;
        --sans-construire) construire=0; shift ;;
        --aide|-h) usage; exit 0 ;;
        *) echo "installer.sh : option inconnue : $1" >&2; usage; exit 2 ;;
    esac
done

# **UNE RACINE VIDE EST LA MACHINE ELLE-MÊME**, et c'est le seul cas qui demande
# des privilèges. La distinction se fait ici, une fois, et tout le reste s'écrit
# pareil dans les deux cas.
sur_la_machine=0
if [ -z "$racine" ]; then
    sur_la_machine=1
fi

# Le répertoire du dépôt, quel que soit l'endroit d'où on lance le script.
depot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

dit() { printf '  %s\n' "$*"; }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

# ── 0. CE QU'IL FAUT AVANT DE COMMENCER ─────────────────────────────────────
titre "contrôles préalables"

if [ "$sur_la_machine" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    cat >&2 <<'REFUS'
installer.sh : sans `--racine`, ce script installe sur CETTE machine, et il lui
faut le superutilisateur pour créer un compte système et écrire sous /etc.

    sudo ./scripts/installer.sh

Pour l'éprouver sans rien toucher, donnez-lui une racine jetable :

    ./scripts/installer.sh --racine /tmp/essai-air-mail
REFUS
    exit 1
fi

# **LE SERVEUR, LUI, REFUSE DE TOURNER EN SUPERUTILISATEUR** (C10). Ce script
# l'est le temps de poser les fichiers, et le service ne le sera jamais : c'est
# précisément pourquoi il crée un compte dédié.
dit "dépôt          $depot"
dit "racine         ${racine:-(la machine elle-même)}"
dit "compte         $compte"
dit "binaires       ${racine}${prefixe}"
dit "état           ${racine}${etat}"

# ── 1. CONSTRUIRE ───────────────────────────────────────────────────────────
titre "construire"

if [ "$construire" -eq 1 ]; then
    dit "cargo build --release (chaîne épinglée par rust-toolchain.toml)"
    (cd "$depot" && cargo build --release --locked)
else
    dit "ignoré (--sans-construire)"
fi

for binaire in air-mail-server air-mail-admin; do
    if [ ! -x "$depot/target/release/$binaire" ]; then
        echo "installer.sh : $depot/target/release/$binaire est absent." >&2
        echo "Construisez d'abord, ou retirez --sans-construire." >&2
        exit 1
    fi
done
dit "les deux binaires sont là"

# ── 2. LE COMPTE UNIX ───────────────────────────────────────────────────────
titre "compte Unix"

if [ "$sur_la_machine" -eq 1 ]; then
    if id "$compte" >/dev/null 2>&1; then
        dit "`$compte` existe déjà — inchangé"
    else
        # SANS INTERPRÉTEUR ET SANS MOT DE PASSE : ce compte n'est pas fait pour
        # qu'on s'y connecte, seulement pour porter un service.
        useradd --system --home-dir "$etat" --shell /usr/sbin/nologin "$compte"
        dit "`$compte` créé (système, sans interpréteur)"
    fi
else
    dit "ignoré : une racine jetable n'a pas de compte système"
fi

# ── 3. L'ARBORESCENCE ───────────────────────────────────────────────────────
titre "arborescence"

# **0700 DÈS LA CRÉATION**, et non resserré après coup. Un répertoire qui naît
# ouvert l'est pendant l'intervalle, et cet intervalle suffit.
install -d -m 0700 "${racine}${etat}"
install -d -m 0700 "${racine}${etat}/maildir"
dit "${etat}/ et ${etat}/maildir/ en 0700"

if [ "$sur_la_machine" -eq 1 ]; then
    chown -R "$compte:$compte" "$etat"
    dit "appartiennent à $compte"
fi

# ── 4. LES BINAIRES ─────────────────────────────────────────────────────────
titre "binaires"

install -d -m 0755 "${racine}${prefixe}"
for binaire in air-mail-server air-mail-admin; do
    install -m 0755 "$depot/target/release/$binaire" "${racine}${prefixe}/$binaire"
    dit "${prefixe}/$binaire"
done

# ── 5. L'UNITÉ SYSTEMD ──────────────────────────────────────────────────────
titre "unité systemd"

install -d -m 0755 "${racine}$(dirname "$unite")"

# **CETTE UNITÉ EST CELLE DU §7 DE `docs/installation.md`**, au caractère près.
# Deux copies d'un même texte divergent ; celle-ci est la copie qui TOURNE, et le
# document renvoie désormais ici.
cat > "${racine}${unite}" <<UNITE
[Unit]
Description=air-mail-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${compte}
Group=${compte}
ExecStart=${prefixe}/air-mail-server --config ${etat}/air-mail.conf
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

ReadWritePaths=${etat}

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
UNITE
chmod 0644 "${racine}${unite}"
dit "${unite}"

# ── 6. LA TABLE DU PARE-FEU, ÉCRITE ET NON APPLIQUÉE ────────────────────────
titre "pare-feu (écrit, JAMAIS appliqué)"

table="${etat}/nftables-air-mail.conf"
cat > "${racine}${table}" <<'TABLE'
# Redirige les ports privilégiés vers les ports hauts que le serveur écoute.
#
# CETTE TABLE N'EST PAS CHARGÉE PAR L'INSTALLATEUR. Relisez-la, adaptez les
# ports hauts à votre configuration, puis :
#
#     sudo nft -f /var/lib/air-mail/nftables-air-mail.conf
#
# Un port redirigé n'est joignable QUE DU DEHORS : depuis la machine elle-même,
# `127.0.0.1:25` et son adresse publique sur le 25 sont refusés. Un contrôle
# local doit viser le port haut. N'ajoutez pas de chaîne `output` pour corriger
# cela — elle détournerait AUSSI le courrier destiné à un MTA extérieur.
table inet mail {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        tcp dport 25  redirect to :2525
        tcp dport 587 redirect to :2525
        tcp dport 465 redirect to :4465
        tcp dport 993 redirect to :9993
        tcp dport 110 redirect to :1110
    }
}
TABLE
chmod 0600 "${racine}${table}"
if [ "$sur_la_machine" -eq 1 ]; then
    chown "$compte:$compte" "${racine}${table}"
fi
dit "${table} — À RELIRE, puis à charger vous-même"

# ── CE QUI RESTE À FAIRE ────────────────────────────────────────────────────
titre "ce qui reste, et que ce script ne décidera pas pour vous"

cat <<SUITE

  1. La configuration. Remplacez le domaine et les adresses :

     ${prefixe}/air-mail-admin config write ${etat}/air-mail.conf \\
         --domain mail.example.com --hosted example.com \\
         --maildir ${etat}/maildir --accounts ${etat}/comptes.bin \\
         --listen 0.0.0.0:2525 --listen-smtps 0.0.0.0:4465 \\
         --listen-imaps 0.0.0.0:9993 \\
         --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \\
         --tls-key  /etc/letsencrypt/live/example.com/privkey.pem

  2. Un compte. LE MOT DE PASSE SE LIT SUR L'ENTRÉE STANDARD, jamais en
     argument — ce que \`ps\` affiche, tout le monde le lit :

     printf %s "\$MOT_DE_PASSE" | ${prefixe}/air-mail-admin account add \\
         ${etat}/comptes.bin --login jean --address jean@example.com

  3. Relisez ce que vous venez d'écrire. Cette sortie DIT AUSSI CE QUI MANQUE :

     ${prefixe}/air-mail-admin config show ${etat}/air-mail.conf

  4. Le pare-feu, après l'avoir relu :

     sudo nft -f ${table}

  5. Le service :

     sudo systemctl daemon-reload
     sudo systemctl enable --now air-mail-server

SUITE

titre "fait"
dit "rien n'a été démarré, et aucune règle n'a été posée."
