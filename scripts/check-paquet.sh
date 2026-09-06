#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Éprouve le paquet Debian que `scripts/paquet.sh` construit.
#
# ── CE QU'ON ÉPROUVE, ET POURQUOI CHAQUE POINT ──────────────────────────────
#
# Un paquet s'installe sur la machine de quelqu'un d'autre, avec les privilèges
# du superutilisateur, et ses scripts de mainteneur tournent SANS que personne
# les relise. C'est la seule chose de ce dépôt dont un défaut s'exécute en root
# chez un inconnu.
set -euo pipefail

racine=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$racine"

fautes=0
rate() { printf '\nÉCHEC : %s\n' "$*" >&2; fautes=$((fautes + 1)); }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

# **CE QU'UN SCRIPT IMPRIME N'EST PAS CE QU'IL FAIT.** Les scripts de mainteneur
# CITENT les commandes qu'ils recommandent à l'exploitant — `systemctl enable`,
# `rm -rf` — dans des « here-documents ». Chercher ces mots sans distinguer le
# dire du faire condamnerait précisément la bonne conduite : dire au lieu de
# faire. On retire donc les corps de here-document avant de chercher.
denuder() {
    awk '
        /<<'"'"'[A-Z]+'"'"'$/ { fin = $NF; gsub(/[<'"'"']/, "", fin); dedans = 1; next }
        dedans && $0 == fin   { dedans = 0; next }
        !dedans               { print }
    ' "$1"
}

# Chaque contrôle dit SON verdict, et non celui de la somme : un `OK` qui
# disparaît parce qu'un contrôle précédent a échoué cache ce qu'on vient
# d'éprouver.
avant=0
commencer() { avant=$fautes; }
conclure() { [ "$fautes" -eq "$avant" ] && echo "OK — $1"; return 0; }

# **UNE MACHINE SANS `dpkg` NE PEUT PAS ÉPROUVER UN `.deb`**, et le prétendre
# serait pire que de s'abstenir. On le DIT, fort, plutôt que de rendre un OK qui
# ne veut rien dire.
if ! command -v dpkg-deb > /dev/null 2>&1 || ! command -v dpkg-shlibdeps > /dev/null 2>&1; then
    cat >&2 <<'ABSENT'

IGNORÉ : `dpkg-deb` ou `dpkg-shlibdeps` est absent de cette machine.

Ce contrôle ne peut pas s'exécuter, et n'a donc RIEN éprouvé. Il tourne en
intégration continue, où `dpkg-dev` est présent — c'est là que son verdict
compte.

ABSENT
    exit 0
fi

essai=$(mktemp -d)
trap 'rm -rf "$essai"' EXIT

titre "1. le paquet se construit"
if ! ./scripts/paquet.sh --sans-construire --sortie "$essai" > "$essai/journal" 2>&1; then
    cat "$essai/journal" >&2
    rate "paquet.sh n'a pas abouti"
    exit 1
fi
deb=$(find "$essai" -maxdepth 1 -name '*.deb' | head -1)
[ -n "$deb" ] || { rate "aucun .deb produit"; exit 1; }
echo "OK — $(basename "$deb")"

titre "2. dpkg le relit, et ses dépendances sont CALCULÉES"
dpkg-deb --info "$deb" > "$essai/info" 2>&1 || rate "dpkg-deb refuse de le relire"
depends=$(sed -n 's/^ Depends: //p' "$essai/info")
if [ -z "$depends" ]; then
    rate "aucune dépendance déclarée"
elif ! printf '%s' "$depends" | grep -q 'libc6 (>='; then
    # Une dépendance sans BORNE DE VERSION ne protège de rien : le paquet
    # s'installerait sur une glibc trop ancienne, et le binaire échouerait au
    # chargement avec un message que personne ne rattache au paquet.
    rate "les dépendances ne portent pas de borne de version : $depends"
else
    echo "OK — $depends"
fi

titre "3. rien dans /usr/local, et la racine n'est pas resserrée"
dpkg-deb --contents "$deb" > "$essai/contenu" 2>&1
if grep -q './usr/local/' "$essai/contenu"; then
    # §9.1.2 de la charte : `/usr/local` appartient à l'administrateur, et un
    # paquet qui y écrit lui reprend l'endroit où il peut passer devant.
    rate "le paquet écrit dans /usr/local"
else
    echo "OK — rien dans /usr/local"
fi
mode_racine=$(awk '$6 == "./" {print $1}' "$essai/contenu")
if [ "$mode_racine" != "drwxr-xr-x" ]; then
    # **LE MODE DE `./` S'APPLIQUERAIT À `/`.** Un paquet qui l'expédie en 0700
    # rend la machine inutilisable pour tout compte qui n'est pas root.
    rate "la racine du paquet est en \`$mode_racine\` et non \`drwxr-xr-x\`"
else
    echo "OK — racine en drwxr-xr-x"
fi
mode_etat=$(awk '$6 == "./var/lib/air-mail/" {print $1}' "$essai/contenu")
if [ "$mode_etat" != "drwx------" ]; then
    rate "/var/lib/air-mail est en \`$mode_etat\` : le courrier serait lisible"
else
    echo "OK — /var/lib/air-mail en drwx------"
fi

titre "4. l'unité du paquet est CELLE de l'installateur"
# **DEUX COPIES D'UN MÊME TEXTE DIVERGENT** — c'est le §8 de
# `check-installation.sh`, et la table `nftables` a prouvé le 2026-09-06 que le
# dire ne suffit pas. `paquet.sh` fait poser l'arborescence par `installer.sh`
# au lieu d'en écrire une seconde ; ce contrôle vérifie que c'est bien resté le
# cas.
pose=$(mktemp -d); trap 'rm -rf "$essai" "$pose"' EXIT
./scripts/installer.sh --racine "$pose" --prefixe /usr/bin --sans-construire > /dev/null 2>&1
dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/lib/systemd/system/air-mail-server.service \
    > "$essai/unite-paquet" 2>/dev/null
if ! diff -u "$pose/etc/systemd/system/air-mail-server.service" "$essai/unite-paquet" \
        > "$essai/ecart" 2>&1; then
    rate "l'unité du paquet et celle de l'installateur diffèrent :
$(cat "$essai/ecart")"
else
    echo "OK — au caractère près"
fi

titre "5. les scripts de mainteneur sont du shell valide"
commencer
dpkg-deb --control "$deb" "$essai/CONTROLE" 2>/dev/null
for script in postinst prerm postrm; do
    if [ ! -x "$essai/CONTROLE/$script" ]; then
        rate "\`$script\` manque ou n'est pas exécutable"
    elif ! sh -n "$essai/CONTROLE/$script" 2>"$essai/plainte"; then
        rate "\`$script\` n'est pas du shell valide :
$(cat "$essai/plainte")"
    fi
done
conclure "postinst, prerm et postrm passent \`sh -n\`"

titre "6. LE PURGE N'EFFACE PAS LE COURRIER"
# **C'EST LE CONTRÔLE QUI COMPTE LE PLUS.** `dpkg --purge` efface la
# configuration d'un paquet ; ici, le même répertoire porte les BOÎTES. Un
# `postrm` qui les effacerait perdrait du courrier sur une commande dont ce
# n'est pas l'objet — et il l'effacerait en root, sans que personne l'ait relu.
#
# On retire les corps de « here-document » avant de chercher : le `postrm` CITE
# la commande d'effacement dans le texte qu'il imprime à l'exploitant, et cette
# citation-là est justement ce qu'on veut qu'il fasse — dire au lieu de faire.
denuder "$essai/CONTROLE/postrm" > "$essai/postrm-nu"
if grep -qE '^[^#]*(rm|deluser|userdel|shred)[^|]*/var/lib/air-mail' "$essai/postrm-nu"; then
    rate "le \`postrm\` EFFACE /var/lib/air-mail — il perdrait du courrier :
$(grep -nE '^[^#]*(rm|deluser|userdel|shred)' "$essai/postrm-nu")"
else
    echo "OK — le courrier survit au purge"
fi

titre "7. le paquet n'active ni ne démarre le service"
# Le serveur REFUSE de démarrer sans configuration, que le paquet n'écrit pas.
# L'activer ferait échouer le service à chaque démarrage de la machine, et
# apprendrait à l'exploitant que cet échec est normal.
denuder "$essai/CONTROLE/postinst" > "$essai/postinst-nu"
if grep -qE '^[^#]*systemctl[^|]*(enable|start|restart)' "$essai/postinst-nu"; then
    rate "le \`postinst\` active ou démarre le service :
$(grep -nE '^[^#]*systemctl' "$essai/postinst-nu")"
else
    echo "OK — il pose, il n'allume pas ; il IMPRIME la marche à suivre"
fi

titre "8. ce qu'on déballe s'exécute"
commencer
# UN PAQUET QUI S'INSTALLE ET DONT LE BINAIRE NE PART PAS n'a rien installé.
dpkg-deb -x "$deb" "$essai/deballe" 2>/dev/null
for binaire in air-mail-server air-mail-admin; do
    if [ ! -x "$essai/deballe/usr/bin/$binaire" ]; then
        rate "\`$binaire\` manque ou n'est pas exécutable"
    elif ! "$essai/deballe/usr/bin/$binaire" --version > /dev/null 2>&1; then
        rate "\`$binaire --version\` ne répond pas"
    fi
done
conclure "les deux binaires répondent à \`--version\`"

titre "9. la marche à suivre imprimée existe vraiment"
commencer
# CE QU'UN SCRIPT IMPRIME EST CE QUE L'EXPLOITANT RECOPIE.
for option in --domain --hosted --tls-cert --tls-key; do
    grep -q -- "$option" "$essai/CONTROLE/postinst" \
        || rate "le \`postinst\` ne montre pas \`$option\`"
    "$essai/deballe/usr/bin/air-mail-admin" config write --help 2>&1 \
        | grep -q -- "$option" || rate "\`$option\` n'existe pas dans \`config write\`"
done
conclure "les options imprimées sont reconnues"

titre "10. le postinst S'EXÉCUTE, sous des doublures"
commencer
# **`sh -n` DIT QUE LA GRAMMAIRE EST BONNE, PAS QUE LE SCRIPT MARCHE.** Celui-ci
# tourne en root sur la machine de quelqu'un d'autre : c'est le seul de ce dépôt
# dont un défaut s'exécute avec tous les privilèges chez un inconnu.
#
# On le lance donc pour de vrai, mais chaque commande qui TOUCHE au système est
# remplacée par une doublure qui note son passage. Ce qu'on éprouve est le
# CHEMINEMENT — l'ordre des étapes, le code de sortie, et le fait que la marche
# à suivre s'imprime à l'installation SANS s'imprimer à la mise à jour.
doublures="$essai/doublures"
install -d -m 0755 "$doublures"
for commande in adduser chown chmod systemctl; do
    cat > "$doublures/$commande" <<DOUBLURE
#!/bin/sh
echo "$commande \$*" >> "$essai/journal-doublures"
exit 0
DOUBLURE
    chmod 0755 "$doublures/$commande"
done
# `getent passwd air-mail` doit dire QUE LE COMPTE N'EXISTE PAS, sans quoi la
# branche qui le crée ne serait jamais parcourue.
cat > "$doublures/getent" <<DOUBLURE
#!/bin/sh
echo "getent \$*" >> "$essai/journal-doublures"
exit 2
DOUBLURE
chmod 0755 "$doublures/getent"

: > "$essai/journal-doublures"
if ! PATH="$doublures:$PATH" sh "$essai/CONTROLE/postinst" configure \
        > "$essai/dit-installation" 2>&1; then
    rate "le \`postinst\` échoue à l'installation :
$(cat "$essai/dit-installation")"
fi
for attendu in "adduser --system" "chown -R air-mail:air-mail /var/lib/air-mail" \
               "chmod 0700 /var/lib/air-mail" "systemctl daemon-reload"; do
    grep -qF "$attendu" "$essai/journal-doublures" \
        || rate "le \`postinst\` n'a pas fait : $attendu"
done
grep -q "air-mail-admin config write" "$essai/dit-installation" \
    || rate "le \`postinst\` n'imprime pas la marche à suivre à l'installation"

# **UNE MISE À JOUR NE RÉPÈTE PAS LA LEÇON.** `dpkg` passe l'ancienne version en
# second argument ; un paquet qui redonnerait les quatre étapes à chaque montée
# de version apprendrait à l'exploitant à ne plus lire ce qu'il imprime.
: > "$essai/journal-doublures"
if ! PATH="$doublures:$PATH" sh "$essai/CONTROLE/postinst" configure 0.0.9 \
        > "$essai/dit-montee" 2>&1; then
    rate "le \`postinst\` échoue à la mise à jour :
$(cat "$essai/dit-montee")"
fi
if grep -q "air-mail-admin config write" "$essai/dit-montee"; then
    rate "le \`postinst\` répète la marche à suivre à chaque mise à jour"
fi
grep -qF "chown -R air-mail:air-mail /var/lib/air-mail" "$essai/journal-doublures" \
    || rate "la mise à jour ne reprend pas la propriété du répertoire d'état"
conclure "installation et mise à jour, sans rien toucher"

if [ "$fautes" -ne 0 ]; then
    printf '\nÉCHEC : %s contrôle(s) du paquet n'"'"'ont pas passé.\n' "$fautes" >&2
    exit 1
fi
printf '\nOK : le paquet pose ce qu'"'"'il dit poser, et le purge ne perd rien.\n'
