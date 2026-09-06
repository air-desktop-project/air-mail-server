#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Construit le paquet Debian d'air-mail-server.
#
# **LA CIBLE DE DÉPLOIEMENT EST UBUNTU**, et c'est elle qui décide du format.
# Debian et Ubuntu partagent `dpkg`, la charte et l'emplacement des unités
# systemd ; ce paquet vaut donc pour les deux, mais c'est la seconde qu'il vise —
# et c'est sur elle qu'il est éprouvé, l'intégration continue tournant sur
# `ubuntu-latest`.
#
# ── CE QU'UN PAQUET FAIT QUE `installer.sh` NE FAIT PAS ─────────────────────
#
# Trois choses, et la troisième est celle qui manquait vraiment :
#
#   — les DÉPENDANCES, calculées et non devinées (`dpkg-shlibdeps`) ;
#   — la MISE À JOUR, que `dpkg` conduit sans qu'on relise quoi que ce soit ;
#   — la DÉSINSTALLATION, qu'`installer.sh` ne sait pas faire. Un script qui
#     pose et ne sait pas défaire laisse l'exploitant retirer des fichiers à la
#     main, en espérant n'en oublier aucun.
#
# ── L'UNITÉ N'EST PAS RÉÉCRITE ICI ──────────────────────────────────────────
#
# Ce script APPELLE `installer.sh` pour poser l'arborescence, puis l'empaquette.
# En écrire une seconde copie donnerait deux textes à maintenir, et la leçon du
# 2026-09-06 est fraîche : la table `nftables` du document avait divergé de
# celle du script parce que deux copies existaient. Il n'y en a qu'une, et c'est
# `installer.sh` qui la porte.
#
# ── CE QUE CE PAQUET NE FAIT DÉLIBÉRÉMENT PAS ───────────────────────────────
#
# Il n'active ni ne démarre le service. Le serveur REFUSE de démarrer sans
# configuration, et le paquet n'en écrit aucune — c'est une décision, pas un
# défaut : le domaine, les boîtes et le certificat ne se devinent pas. Un paquet
# qui démarrerait un service voué à échouer apprendrait à l'exploitant que les
# échecs de ce service sont normaux.
#
# **ET IL N'EFFACE JAMAIS LE COURRIER.** Voir `postrm` : même `dpkg --purge`
# laisse `/var/lib/air-mail` en place. Un paquet qui supprime des boîtes aux
# lettres sur une commande de nettoyage est un paquet qui perd du courrier.
set -euo pipefail

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
sortie="."
construire=1
architecture=$(dpkg --print-architecture 2>/dev/null || echo amd64)

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2-}"; shift 2 ;;
        --sortie) sortie="${2-}"; shift 2 ;;
        --sans-construire) construire=0; shift ;;
        --aide|-h)
            sed -n '6,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "paquet.sh : option inconnue : $1" >&2; exit 2 ;;
    esac
done

depot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dit() { printf '  %s\n' "$*"; }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

titre "contrôles préalables"
# **ON REFUSE PLUTÔT QUE DE BRICOLER.** Un `.deb` se fabrique aussi à la main
# avec `ar` et `tar` ; le résultat serait subtilement différent de ce que `dpkg`
# attend, et le défaut se découvrirait sur la machine de quelqu'un.
for outil in dpkg-deb dpkg-shlibdeps; do
    if ! command -v "$outil" > /dev/null 2>&1; then
        echo "paquet.sh : \`$outil\` est absent — il vient du paquet \`dpkg-dev\`" >&2
        exit 1
    fi
done
dit "dpkg-deb et dpkg-shlibdeps sont là"

if [ "$construire" -eq 1 ]; then
    titre "construction"
    (cd "$depot" && cargo build --release --bin air-mail-server --bin air-mail-admin)
    dit "binaires construits en release"
fi

arbre=$(mktemp -d)
# LE RÉPERTOIRE JETABLE PART AVEC NOUS, quoi qu'il arrive.
trap 'rm -rf "$arbre"' EXIT

titre "arborescence, posée par installer.sh"
# `--prefixe /usr/bin` : un paquet n'a RIEN à faire dans `/usr/local`, qui
# appartient à l'administrateur (§9.1.2 de la charte Debian).
"$depot/scripts/installer.sh" --racine "$arbre" --prefixe /usr/bin --sans-construire \
    > "$arbre/.pose" 2>&1 || { cat "$arbre/.pose"; exit 1; }
rm -f "$arbre/.pose"
dit "posée"

titre "ce qu'un paquet range ailleurs"
# L'unité d'un PAQUET va sous `/lib/systemd/system` ; `/etc/systemd/system` est
# réservé à ce que l'administrateur écrit lui-même, et y poser un fichier de
# paquet lui retirerait l'endroit où il peut passer devant.
# **`/usr/lib` ET NON `/lib`** : sur un système à `/usr` fusionné — c'est le cas
# de toute Debian depuis bookworm — `/lib` EST un lien vers `/usr/lib`, et un
# paquet qui expédie sous l'un des deux noms oblige `dpkg` à démêler l'alias.
# Les paquets neufs prennent le vrai chemin.
install -d -m 0755 "$arbre/usr/lib/systemd/system"
mv "$arbre/etc/systemd/system/air-mail-server.service" "$arbre/usr/lib/systemd/system/"
chmod 0644 "$arbre/usr/lib/systemd/system/air-mail-server.service"
rmdir "$arbre/etc/systemd/system" "$arbre/etc/systemd" "$arbre/etc"
dit "unité sous /usr/lib/systemd/system"

# La table `nftables` est un EXEMPLE à relire, pas une configuration : elle va
# dans la documentation, d'où personne ne la chargera par mégarde.
install -d -m 0755 "$arbre/usr/share/doc/air-mail-server"
mv "$arbre/var/lib/air-mail/nftables-air-mail.conf" \
   "$arbre/usr/share/doc/air-mail-server/nftables-air-mail.conf.exemple"
# `installer.sh` l'écrit en 0600 parce qu'elle vit alors dans le répertoire du
# service ; ici c'est une lecture pour tout le monde, et rien n'y est secret.
chmod 0644 "$arbre/usr/share/doc/air-mail-server/nftables-air-mail.conf.exemple"
install -m 0644 "$depot/LICENSE" "$arbre/usr/share/doc/air-mail-server/copyright"
dit "table d'exemple et licence dans /usr/share/doc"

# Le maildir se crée au premier courrier, pas à l'installation : l'expédier vide
# ferait croire que le paquet décide de son emplacement, alors que c'est la
# configuration qui le dit.
rmdir "$arbre/var/lib/air-mail/maildir"
dit "maildir non expédié — la configuration en décide"

titre "dépendances, calculées et non devinées"
# **`dpkg-shlibdeps` LIT LE BINAIRE.** Écrire `libc6 (>= 2.34)` à la main serait
# vrai le jour où on l'écrit, et faux à la première mise à jour de la chaîne de
# compilation — exactement la dérive que ce dépôt passe son temps à traquer.
# `dpkg-shlibdeps` veut un `debian/control` pour savoir DE QUEL paquet il parle.
# Le nôtre n'existe qu'ici, le temps du calcul : le paquet, lui, porte le
# `DEBIAN/control` écrit plus bas.
install -d -m 0755 "$arbre/debian"
printf 'Source: air-mail-server\n\nPackage: air-mail-server\nArchitecture: any\n' \
    > "$arbre/debian/control"
if ! depends=$(cd "$arbre" && dpkg-shlibdeps -O --ignore-missing-info \
    usr/bin/air-mail-server usr/bin/air-mail-admin 2>"$arbre/debian/plainte" \
    | sed 's/^shlibs:[A-Za-z]*=//'); then
    echo "paquet.sh : \`dpkg-shlibdeps\` a refusé :" >&2
    sed 's/^/    /' "$arbre/debian/plainte" >&2
    exit 1
fi
rm -rf "$arbre/debian"
if [ -z "$depends" ]; then
    echo "paquet.sh : aucune dépendance calculée — c'est invraisemblable" >&2
    exit 1
fi
dit "$depends"

titre "métadonnées et scripts de mainteneur"
install -d -m 0755 "$arbre/DEBIAN"
taille=$(du -sk --exclude=DEBIAN "$arbre" | cut -f1)
cat > "$arbre/DEBIAN/control" <<CONTROL
Package: air-mail-server
Version: $version
Section: mail
Priority: optional
Architecture: $architecture
Depends: $depends
Installed-Size: $taille
Maintainer: Thierry Delhaise <thierry.delhaise@gmail.com>
Homepage: https://github.com/air-desktop-project/air-mail-server
Description: serveur de courrier autonome, écrit en Rust
 SMTP, IMAP4rev2 et POP3, avec SPF, DKIM, DMARC, DANE et MTA-STS. Aucune
 dépendance C : ni OpenSSL, ni bibliothèque système de chiffrement.
 .
 Le paquet n'écrit AUCUNE configuration et ne démarre PAS le service : le
 domaine, les boîtes et le certificat sont des décisions. Voir
 /usr/share/doc/air-mail-server/ et \`air-mail-admin config write --help\`.
CONTROL

cat > "$arbre/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

case "$1" in
    configure)
        # LE COMPTE EST SYSTÈME, SANS INTERPRÉTEUR ET SANS MOT DE PASSE : rien
        # ne doit pouvoir s'y connecter, il n'existe que pour porter le service.
        if ! getent passwd air-mail > /dev/null 2>&1; then
            adduser --system --group --no-create-home \
                --home /var/lib/air-mail --shell /usr/sbin/nologin \
                --quiet air-mail || true
        fi
        # **LE COURRIER N'APPARTIENT QU'À CE COMPTE.** 0700, et le `chown` porte
        # sur ce qui est DÉJÀ là : une mise à jour ne doit pas déposséder les
        # boîtes existantes.
        chown -R air-mail:air-mail /var/lib/air-mail
        chmod 0700 /var/lib/air-mail
        ;;
esac

#DEBHELPER#

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi

# ON N'ACTIVE RIEN, ET ON DIT POURQUOI. Le serveur refuse de démarrer sans
# configuration ; l'activer ici ferait échouer le service à chaque démarrage de
# la machine, et apprendrait à l'exploitant que cet échec est normal.
if [ "$1" = "configure" ] && [ -z "${2-}" ]; then
    cat <<'SUITE'

air-mail-server est installé, mais NI ACTIVÉ NI DÉMARRÉ : il lui faut d'abord
une configuration, qui n'est pas devinable.

  1. écrivez-la :   air-mail-admin config write /var/lib/air-mail/air-mail.conf \
                        --domain … --hosted … --tls-cert … --tls-key … …
  2. un compte :    air-mail-admin account add /var/lib/air-mail/comptes.bin \
                        --login … --address …
  3. la table :     /usr/share/doc/air-mail-server/nftables-air-mail.conf.exemple
                    — À RELIRE, puis à charger vous-même
  4. démarrez :     systemctl enable --now air-mail-server

SUITE
fi

exit 0
POSTINST

cat > "$arbre/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e

# ON ARRÊTE AVANT DE RETIRER LES FICHIERS. Sans cela, le service tournerait sur
# un binaire effacé jusqu'au prochain redémarrage — et son journal parlerait
# d'une version qui n'est plus là.
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl stop air-mail-server > /dev/null 2>&1 || true
fi

#DEBHELPER#

exit 0
PRERM

cat > "$arbre/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi

#DEBHELPER#

# ── LE COURRIER SURVIT AU PURGE, ET C'EST DÉLIBÉRÉ ──────────────────────────
#
# `dpkg --purge` efface la configuration d'un paquet. Ici, le même répertoire
# porte AUSSI les boîtes aux lettres : les effacer perdrait du courrier que
# personne n'a demandé à perdre, sur une commande dont ce n'est pas l'objet.
#
# On ne retire donc RIEN de /var/lib/air-mail — pas même la configuration, qui
# y vit à côté des boîtes. L'exploitant qui veut tout effacer le fait lui-même,
# et le dire est plus honnête que de le faire à sa place.
if [ "$1" = "purge" ] && [ -d /var/lib/air-mail ]; then
    cat <<'RESTE'

air-mail-server : /var/lib/air-mail A ÉTÉ LAISSÉ EN PLACE.

Il porte les boîtes aux lettres en plus de la configuration, et un `purge` n'est
pas une raison de perdre du courrier. Pour l'effacer vous-même, en sachant ce
que vous effacez :

    rm -rf /var/lib/air-mail
    deluser --system air-mail

RESTE
fi

exit 0
POSTRM

chmod 0755 "$arbre/DEBIAN/postinst" "$arbre/DEBIAN/prerm" "$arbre/DEBIAN/postrm"
dit "control, postinst, prerm, postrm"

titre "assemblage"
# **LA RACINE DU PAQUET EST `/`**, et son mode s'appliquerait à `/`.
# `installer.sh` a créé le répertoire jetable en 0700, ce qui est juste pour un
# répertoire jetable et catastrophique pour la racine d'un système.
chmod 0755 "$arbre"
mkdir -p "$sortie"
nom="$sortie/air-mail-server_${version}_${architecture}.deb"
# `--root-owner-group` : sans lui, les fichiers du paquet appartiendraient au
# compte qui l'a construit, dont le numéro ne veut rien dire ailleurs.
dpkg-deb --root-owner-group --build "$arbre" "$nom" > /dev/null
dit "$nom"

printf '\nOK : %s (%s)\n' "$nom" "$(du -h "$nom" | cut -f1)"
