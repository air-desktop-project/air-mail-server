#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Pose un paquet `air-mail-server` sur un MX en service, et DIT si le serveur
# sert encore — ce qui n'est pas la même chose que de dire s'il est installé.
#
# Usage, SUR la machine :
#     poser-un-paquet.sh <paquet.deb> [port-imaps] [port-smtps]
#
# ── CE SCRIPT EXISTE À CAUSE D'UNE COUPURE ─────────────────────────────────
#
# Le 2026-10-08, la pose de la 0.2.53 sur `mail.narro.ch` a coupé le courrier
# pendant que la vérification annonçait « service : active, ports idem ». Les
# deux mesures étaient fausses, et la raison vaut pour TOUTE pose ici.
#
# **L'UNITÉ EST EN `Type=simple`.** systemd déclare le service `active` dès que
# le processus est LANCÉ, sans attendre aucun signal de disponibilité. Un
# serveur qui démarre, écrit tout son journal, puis meurt sur sa dernière ligne
# est `active` le temps de mourir — et l'écouteur qu'il a ouvert répond encore
# quand on compte les ports. Ce jour-là, il est mort 421 fois de suite.
#
# Ce script mesure donc TROIS choses que `is-active` ne dit pas :
#
#   1. `NRestarts` — un compteur qui grimpe dit la boucle que l'état cache ;
#   2. une poignée de main TLS complète sur IMAPS et SMTPS, depuis la machine ;
#   3. LA MÊME MESURE, répétée après un délai : une pose qui tient dix secondes
#      ne tient pas forcément une minute.
#
# Il ne connaît aucun secret et n'ouvre aucune session : prouver qu'un compte
# s'authentifie demande un mot de passe, et cela se fait DEPUIS LE POSTE, après.
set -uo pipefail
export LC_ALL=C

DEB="${1:?usage : poser-un-paquet.sh <paquet.deb> [port-imaps] [port-smtps]}"
IMAPS="${2:-9993}"
SMTPS="${3:-4465}"
ETAT=/var/lib/air-mail
CONF="$ETAT/air-mail.conf"

[ -f "$DEB" ] || { echo "poser-un-paquet : \`$DEB\` est introuvable." >&2; exit 1; }
command -v openssl >/dev/null || { echo "poser-un-paquet : \`openssl\` manque." >&2; exit 1; }

# Une poignée de main TLS complète, et la bannière du serveur. C'est le seul
# contrôle qui traverse l'écouteur, TLS, et la boucle de session.
salue() {  # $1 = port, $2 = ce que la bannière doit contenir
    # **ON ÉCOUTE AVANT DE PARLER.** Envoyer `QUIT` aussitôt ferme la connexion
    # avant que la bannière ne sorte : le serveur note « 0 commande(s) » et le
    # contrôle rend NON un essai sur deux. Deux secondes suffisent sur la
    # boucle locale, et le `timeout` borne l'attente de toute façon.
    { sleep 2; printf 'QUIT\r\n'; sleep 1; } \
        | timeout 20 openssl s_client -quiet -verify_quiet \
            -connect "127.0.0.1:$1" 2>/dev/null \
        | grep -qm1 "$2"
}

etat_vrai() {  # imprime « <état> <NRestarts> <ports> <imaps> <smtps> »
    printf '%s %s %s %s %s' \
        "$(systemctl is-active air-mail-server)" \
        "$(systemctl show air-mail-server -p NRestarts --value)" \
        "$(ss -tlnH | awk '{print $4}' | grep -cE ":($IMAPS|$SMTPS)$")" \
        "$(salue "$IMAPS" 'OK' && echo oui || echo NON)" \
        "$(salue "$SMTPS" '220' && echo oui || echo NON)"
}

echo "=== AVANT ==="
AV_VER=$(air-mail-server --version 2>/dev/null | awk '{print $2}')
AV_EMPREINTE=$(sha256sum "$CONF" | cut -c1-16)
sudo -u air-mail air-mail-admin config show "$CONF" > /tmp/conf.avant 2>&1
AV_RESTARTS=$(systemctl show air-mail-server -p NRestarts --value)
echo "  version $AV_VER | conf $AV_EMPREINTE ($(wc -l < /tmp/conf.avant) lignes) | $AV_RESTARTS redémarrage(s)"
echo "  état vrai : $(etat_vrai)"

echo "=== POSE ==="
dpkg -i "$DEB" 2>&1 | grep -iE "^Setting up|^Unpacking|error|erreur" | sed 's/^/  /'

# ── LES DEUX MESURES, ESPACÉES ──────────────────────────────────────────────
# La seconde n'est pas une précaution de style : entre deux redémarrages, un
# service qui boucle est `active` une partie du temps. Deux mesures à trente
# secondes d'écart avec le MÊME `NRestarts` disent qu'il ne boucle pas.
echo "=== APRÈS, deux mesures à 30 s d'écart ==="
sleep 8
read -r E1 R1 P1 I1 S1 <<< "$(etat_vrai)"
echo "  t+8s   : état $E1 | $R1 redémarrage(s) | $P1 port(s) | IMAPS $I1 | SMTPS $S1"
sleep 30
read -r E2 R2 P2 I2 S2 <<< "$(etat_vrai)"
echo "  t+38s  : état $E2 | $R2 redémarrage(s) | $P2 port(s) | IMAPS $I2 | SMTPS $S2"

echo "=== VERDICT ==="
mal=0
[ "$E2" = "active" ]   || { echo "  le service n'est pas actif"; mal=1; }
[ "$R2" = "$R1" ]      || { echo "  IL BOUCLE : $R1 puis $R2 redémarrages"; mal=1; }
[ "$R2" = "$AV_RESTARTS" ] || echo "  (note : $AV_RESTARTS redémarrage(s) avant la pose, $R2 après)"
[ "$I2" = "oui" ]      || { echo "  IMAPS ne salue pas sur $IMAPS"; mal=1; }
[ "$S2" = "oui" ]      || { echo "  SMTPS ne salue pas sur $SMTPS"; mal=1; }
AP_EMPREINTE=$(sha256sum "$CONF" | cut -c1-16)
[ "$AV_EMPREINTE" = "$AP_EMPREINTE" ] || { echo "  LA CONFIGURATION A CHANGÉ : $AV_EMPREINTE -> $AP_EMPREINTE"; mal=1; }
sudo -u air-mail air-mail-admin config show "$CONF" > /tmp/conf.apres 2>&1
diff -q /tmp/conf.avant /tmp/conf.apres >/dev/null || { echo "  \`config show\` a changé :"; diff /tmp/conf.avant /tmp/conf.apres | head -8 | sed 's/^/    /'; mal=1; }

if [ "$mal" -ne 0 ]; then
    echo
    echo "ÉCHEC — le journal des deux dernières minutes :"
    journalctl -u air-mail-server --since '2 minutes ago' --no-pager | tail -12 | sed 's/^/    /'
    echo
    echo "  Le paquet RESTE POSÉ : revenir en arrière demande le .deb précédent."
    exit 1
fi

echo "  version $(air-mail-server --version | awk '{print $2}') | configuration intacte | IMAPS et SMTPS saluent, deux fois"
echo "=== les pages de manuel ==="
for f in /usr/share/man/man8/air-mail-server.8 /usr/share/man/man8/air-mail-admin.8 \
         /usr/share/doc/air-mail-server/air-mail-server.8.html \
         /usr/share/doc/air-mail-server/air-mail-admin.8.html; do
    [ -f "$f" ] && printf "  %s %7s  %s\n" "$(stat -c %a "$f")" "$(stat -c %s "$f")" "$f" \
                || { echo "  MANQUE : $f"; mal=1; }
done
for p in air-mail-server air-mail-admin; do
    man 8 "$p" >/dev/null 2>&1 || { echo "  \`man 8 $p\` ne la trouve pas"; mal=1; }
done
[ "$mal" -eq 0 ] && echo "  \`man 8 air-mail-server\` et \`man 8 air-mail-admin\` répondent"

echo
echo "IL RESTE À PROUVER CE QUE CE SCRIPT NE PEUT PAS PROUVER :"
echo "  une connexion AUTHENTIFIÉE depuis le poste, sur chaque protocole servi."
echo "  Le garde bannit par adresse source : espacez les essais, ou une rafale"
echo "  fera répondre \`421 4.3.2 Service not available\` à tout, y compris au"
echo "  client de messagerie du même réseau."
[ "$mal" -eq 0 ] && echo "FINI_OK" || exit 1
