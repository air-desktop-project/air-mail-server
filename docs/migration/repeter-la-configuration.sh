#!/usr/bin/env bash
#
# repeter-la-configuration.sh — LA COMMANDE DU MANUEL EST-ELLE ENCORE VALABLE ?
#
# Il EXTRAIT de `bascule.md` la commande `config write` de la phase 0.4, remplace
# les chemins de production par un arbre jetable, et la joue. Puis il relit la
# configuration écrite et vérifie qu'elle porte bien ce que le manuel promet.
#
# Il ne touche NI à la machine de production, NI à `/etc`, NI au courrier.
#
# USAGE
#     bash docs/migration/repeter-la-configuration.sh
#
# POURQUOI CE SCRIPT EXISTE
#
# `bascule.md` a été FAUX quatre fois, et chaque fois d'une façon qui ne se
# serait vue que le jour J, Postfix déjà arrêté :
#
#   1. `rsync` de racine à racine — le serveur n'aurait trouvé aucune boîte ;
#   2. le retour en arrière qui dupliquait tout message dont un drapeau avait
#      bougé ;
#   3. un vérificateur qui coûtait quatre minutes de coupure ;
#   4. `--resolver 127.0.0.53` sans port — la commande aurait été REFUSÉE.
#
# Le quatrième a été trouvé en JOUANT la commande, pas en la relisant. Une
# procédure écrite n'est pas une procédure éprouvée, et une prose qui vieillit ne
# prévient pas.
#
# **IL EXTRAIT PLUTÔT QU'IL NE RECOPIE**, et c'est tout ce qui le rend utile :
# une copie de la commande dériverait du manuel sans que rien ne le dise, et l'on
# éprouverait alors une commande que personne ne tapera.

set -uo pipefail
export LC_ALL=C

racine=$(cd "$(dirname "$0")/../.." && pwd)
manuel="$racine/docs/migration/bascule.md"
outil="$racine/target/release/air-mail-admin"

[ -r "$manuel" ] || { echo "ÉCHEC : \`$manuel\` est illisible." >&2; exit 1; }
if [ ! -x "$outil" ]; then
    echo "ÉCHEC : \`$outil\` n'est pas là. \`cargo build --release\` d'abord." >&2
    exit 1
fi

banc=$(mktemp -d) || exit 1
trap 'rm -rf "$banc"' EXIT
for fichier in cert.pem cle.pem dkim.key psl.dat anchors.pem; do
    : > "$banc/$fichier"
done

# ── L'EXTRACTION ────────────────────────────────────────────────────────────
#
# Le bloc va de la ligne qui porte `config write` jusqu'à la première qui ne se
# termine PAS par une barre oblique inverse. On ôte l'indentation du manuel, le
# `printf` qui donne le secret, et le `sudo`.
commande=$(awk '
    /air-mail-admin config write \\$/ { dans = 1 }
    dans { print; if ($0 !~ /\\$/) exit }
' "$manuel")

if [ -z "$commande" ]; then
    echo "ÉCHEC : aucune commande \`config write\` trouvée dans \`bascule.md\`." >&2
    echo "        Le manuel a changé de forme, ou la commande a disparu." >&2
    exit 1
fi

# ── LES SUBSTITUTIONS, ET CHACUNE EST NOMMÉE ────────────────────────────────
#
# On ne remplace QUE ce qui désigne la machine de production. Toute autre
# différence entre ce qu'on joue et ce que le manuel dit serait une divergence
# qu'on ne verrait pas.
jouable=$(printf '%s\n' "$commande" \
    | sed -e 's|^ *||' \
          -e 's#^printf %s "$SECRET_RESEND" | ##' \
          -e 's|sudo -u ams air-mail-admin|«OUTIL»|' \
          -e "s|/etc/ams/essai.conf|$banc/essai.conf|" \
          -e "s|/etc/ams/comptes.bin|$banc/comptes.bin|" \
          -e "s|/var/vmail-ams|$banc/vmail|" \
          -e "s|/var/spool/ams/file|$banc/file|" \
          -e "s|/var/cache/ams/mtasts|$banc/mtasts|" \
          -e "s|/etc/letsencrypt/live/mail.narro.ch/fullchain.pem|$banc/cert.pem|" \
          -e "s|/etc/letsencrypt/live/mail.narro.ch/privkey.pem|$banc/cle.pem|" \
          -e "s|/var/lib/rspamd/dkim/narro.ch.mail.key|$banc/dkim.key|" \
          -e "s|/usr/share/publicsuffix/public_suffix_list.dat|$banc/psl.dat|" \
          -e "s|/etc/ssl/certs/ca-certificates.crt|$banc/anchors.pem|" \
          -e 's|«le compte Resend, dans /etc/postfix/sasl_passwd»|compte@narro.ch|')
jouable=${jouable//«OUTIL»/$outil}

echo "── la commande jouée ────────────────────────────────────────────────────"
printf '%s\n' "$jouable"
echo

# ── ON LA JOUE ──────────────────────────────────────────────────────────────
sortie=$(printf %s 'un-secret-de-banc' | eval "$jouable" 2>&1)
issue=$?
printf '%s\n' "$sortie"
if [ "$issue" -ne 0 ] || printf '%s' "$sortie" | grep -q "^air-mail-admin : "; then
    echo
    echo "ÉCHEC : la commande de \`bascule.md\` est REFUSÉE." >&2
    echo "        Elle le serait aussi le jour de la bascule." >&2
    exit 1
fi

# ── ET ON RELIT CE QU'ELLE A ÉCRIT ──────────────────────────────────────────
#
# Une commande acceptée n'est pas une commande qui fait ce qu'on croit : une
# option retirée du produit deviendrait « option inconnue », mais une option
# RENOMMÉE qui ne s'appliquerait plus passerait sans un mot. On relit donc.
relu=$(mktemp) || exit 1
trap 'rm -rf "$banc" "$relu"' EXIT
"$outil" config show "$banc/essai.conf" > "$relu" 2>&1

manques=0
verifier() {
    if ! grep -qiE "$2" "$relu"; then
        echo "ÉCHEC : la configuration écrite ne porte pas $1." >&2
        manques=$((manques + 1))
    fi
}
verifier "le domaine annoncé"          '^domaine +mail\.narro\.ch'
verifier "les 50 Mio de message"       '^message max +52428800'
verifier "l'exigence de HELO qualifié" '^.HELO. qualifié +EXIGÉ'
verifier "les deux exigences d'enveloppe" '^enveloppe +EXPÉDITEUR et DESTINATAIRE'
verifier "l'existence du domaine"      '^domaine expéditeur +doit EXISTER'
verifier "le relais Resend"            'smtp\.resend\.com:465'
verifier "l'API REST"                  '^API REST +0\.0\.0\.0:8443'

echo
if [ "$manques" -ne 0 ]; then
    echo "ÉCHEC : $manques promesse(s) du manuel ne se relisent pas." >&2
    exit 1
fi
echo "OK : la commande de \`bascule.md\` est acceptée, et tout ce qu'elle promet se relit."
