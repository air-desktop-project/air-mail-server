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
# Un bloc va de la ligne qui porte `config write` jusqu'à la première qui ne se
# termine PAS par une barre oblique inverse. On ôte l'indentation du manuel, le
# `printf` qui donne le secret, et le `sudo`.
#
# **IL Y A DEUX COMMANDES DANS LE MANUEL, ET CE SCRIPT N'EN JOUAIT QU'UNE.**
# Celle de la phase 0.4 — la répétition, en `127.0.0.1` — et celle de l'étape 6
# de la phase 1 — la vraie, celle que Postfix arrêté attend. La seconde a dit
# `--listen [::]:25` pendant des jours : un port que le serveur ne peut PAS lier
# (C10, unité sans capacité), donc un « Permission denied » à l'étape 8, en
# pleine coupure. Elle n'était pas jouée ; elle n'était pas non plus jouable,
# écrite comme « les mêmes options qu'en 0.4, mais ». Elle l'est désormais, et
# elle passe ici comme la première — trouvé le 2026-09-16, sur la machine
# `mail.air-desktop.org` où la même idée avait été essayée.
extraire() {  # $1 = rang du bloc (1 = phase 0.4, 2 = phase 1 étape 6)
    awk -v voulu="$1" '
        /air-mail-admin config write \\$/ { rang++; dans = (rang == voulu) }
        dans { print; if ($0 !~ /\\$/) exit }
    ' "$manuel"
}

commande_essai=$(extraire 1)
commande_jour_j=$(extraire 2)

if [ -z "$commande_essai" ]; then
    echo "ÉCHEC : aucune commande \`config write\` trouvée dans \`bascule.md\`." >&2
    echo "        Le manuel a changé de forme, ou la commande a disparu." >&2
    exit 1
fi
if [ -z "$commande_jour_j" ]; then
    echo "ÉCHEC : la commande du JOUR J (phase 1, étape 6) n'est plus dans \`bascule.md\`," >&2
    echo "        ou n'est plus écrite comme une commande jouable." >&2
    exit 1
fi

# ── LE COMPTE DE SERVICE EST-IL CELUI DU PRODUIT ? ──────────────────────────
#
# **CE CONTRÔLE MANQUAIT, ET SON ABSENCE A LAISSÉ PASSER LE CINQUIÈME DÉFAUT.**
# Ce script substituait `sudo -u ams air-mail-admin` par un jeton avant de jouer
# la commande : il était donc AVEUGLE au nom du compte, précisément parce qu'il
# le remplaçait. Le manuel a nommé `ams` pendant des semaines quand
# l'installateur et le paquet créent `air-mail` — trouvé le 2026-09-08 en posant
# le paquet sur la machine, à onze jours de la bascule. La première commande de
# la §0.4 aurait échoué par « sudo: unknown user ams », Postfix déjà arrêté.
#
# On ne peut pas éprouver le compte en le jouant : il n'existe pas sur une
# machine de développement. On peut, en revanche, vérifier que le manuel et
# l'installateur nomment LE MÊME — c'est ce qui aurait suffi.
compte_du_produit=$(sed -n 's/^compte="\([^"]*\)".*/\1/p' "$racine/scripts/installer.sh" | head -1)
for commande in "$commande_essai" "$commande_jour_j"; do
    compte_du_manuel=$(printf '%s\n' "$commande" \
        | sed -n 's/.*sudo -u \([A-Za-z0-9_-]*\) air-mail-admin.*/\1/p' | head -1)
    if [ -z "$compte_du_manuel" ] || [ -z "$compte_du_produit" ]; then
        echo "ECHEC : compte de service introuvable — manuel «$compte_du_manuel», produit «$compte_du_produit»." >&2
        exit 1
    fi
    if [ "$compte_du_manuel" != "$compte_du_produit" ]; then
        echo "ECHEC : le manuel dit «$compte_du_manuel», l installateur cree «$compte_du_produit»." >&2
        echo "        La premiere commande de la phase 0 echouerait sur la machine." >&2
        exit 1
    fi
done
echo "compte de service : «$compte_du_manuel» — le meme que l installateur cree"

# ── LE CERTIFICAT EST-IL LISIBLE PAR LE COMPTE QUI SERT ? ───────────────────
#
# **CE CONTRÔLE MANQUAIT, ET LES DEUX COMMANDES ONT NOMMÉ LE MAUVAIS CHEMIN
# PENDANT DEUX SEMAINES.** `/etc/letsencrypt/live` et `/etc/letsencrypt/archive`
# sont en `0700 root` : un `fullchain.pem` en 0644 dans un répertoire qui ne se
# traverse pas est un fichier ILLISIBLE. Le manuel l'expliquait — en prose, deux
# paragraphes au-dessus de commandes qui nommaient ce chemin-là. Le serveur
# aurait refusé de démarrer à l'étape 8, Postfix déjà arrêté.
#
# Le `deploy-hook` recopie les deux fichiers sous `/var/lib/air-mail/tls`, et
# c'est CE chemin que la configuration doit porter. Trouvé le 2026-09-21.
#
# On ne peut pas l'éprouver en jouant la commande : sur une machine de
# développement, les deux chemins sont également absents et `config write` les
# accepte tous les deux. On lit donc le TEXTE de la commande, comme pour le
# compte de service — c'est le même genre de faute, et le même genre de garde.
for commande in "$commande_essai" "$commande_jour_j"; do
    if printf '%s\n' "$commande" | grep -q '/etc/letsencrypt/live'; then
        echo "ECHEC : une commande de \`bascule.md\` nomme /etc/letsencrypt/live." >&2
        echo "        Ce repertoire est en 0700 root : \`$compte_du_manuel\` ne peut pas" >&2
        echo "        le traverser, et le serveur refuserait de demarrer a l etape 8." >&2
        echo "        Le deploy-hook recopie les deux fichiers sous /var/lib/air-mail/tls." >&2
        exit 1
    fi
done
echo "certificat : aucune commande ne nomme un chemin que «$compte_du_manuel» ne peut pas lire"

# ── LES SUBSTITUTIONS, ET CHACUNE EST NOMMÉE ────────────────────────────────
#
# On ne remplace QUE ce qui désigne la machine de production. Toute autre
# différence entre ce qu'on joue et ce que le manuel dit serait une divergence
# qu'on ne verrait pas.
rendre_jouable() {  # lit la commande sur l'entrée standard
    sed -e 's|^ *||' \
        -e 's#^printf %s "$SECRET_RESEND" | ##' \
        -e "s|sudo -u $compte_du_manuel air-mail-admin|«OUTIL»|" \
        -e "s|/var/lib/air-mail/essai.conf|$banc/essai.conf|" \
        -e "s|/var/lib/air-mail/air-mail.conf|$banc/air-mail.conf|" \
        -e "s|/var/lib/air-mail/comptes.bin|$banc/comptes.bin|" \
        -e "s|/var/vmail-ams|$banc/vmail|" \
        -e "s|/var/lib/air-mail/file|$banc/file|" \
        -e "s|/var/lib/air-mail/mtasts|$banc/mtasts|" \
        -e "s|/etc/letsencrypt/live/mail.narro.ch/fullchain.pem|$banc/cert.pem|" \
        -e "s|/etc/letsencrypt/live/mail.narro.ch/privkey.pem|$banc/cle.pem|" \
        -e "s|/var/lib/air-mail/tls/fullchain.pem|$banc/cert.pem|" \
        -e "s|/var/lib/air-mail/tls/privkey.pem|$banc/cle.pem|" \
        -e "s|/var/lib/rspamd/dkim/narro.ch.ams202609.key|$banc/dkim.key|" \
        -e "s|/usr/share/publicsuffix/public_suffix_list.dat|$banc/psl.dat|" \
        -e "s|/etc/ssl/certs/ca-certificates.crt|$banc/anchors.pem|" \
        -e 's|«le compte Resend, dans /etc/postfix/sasl_passwd»|compte@narro.ch|'
}

# ── ON LES JOUE, PUIS ON RELIT CE QU'ELLES ONT ÉCRIT ────────────────────────
#
# Une commande acceptée n'est pas une commande qui fait ce qu'on croit : une
# option retirée du produit deviendrait « option inconnue », mais une option
# RENOMMÉE qui ne s'appliquerait plus passerait sans un mot. On relit donc.
relu=$(mktemp) || exit 1
trap 'rm -rf "$banc" "$relu"' EXIT
manques=0
verifier() {  # $1 = ce qu'on attend, en mots ; $2 = le motif qui doit se relire
    if ! grep -qiE "$2" "$relu"; then
        echo "ÉCHEC : la configuration écrite ne porte pas $1." >&2
        manques=$((manques + 1))
    fi
}
interdire_ecoute() {  # $1 = ce qu'on refuse, en mots ; $2 = le motif qu'AUCUNE ligne d'écoute ne doit porter
    # Seules les lignes d'écoute : `écoute …` et leurs suites indentées. Le
    # relais, lui, a le droit de dire `smtp.resend.com:465`.
    if grep -E '^(écoute| )' "$relu" | grep -qiE "$2"; then
        echo "ÉCHEC : la configuration écrite porte $1." >&2
        manques=$((manques + 1))
    fi
}

jouer() {  # $1 = le nom de la commande ; $2 = la commande ; $3 = le fichier écrit
    local jouable sortie issue
    jouable=$(printf '%s\n' "$2" | rendre_jouable)
    jouable=${jouable//«OUTIL»/$outil}

    echo "── la commande jouée ($1) ──────────────────────────────────────────────"
    printf '%s\n' "$jouable"
    echo

    sortie=$(printf %s 'un-secret-de-banc' | eval "$jouable" 2>&1)
    issue=$?
    printf '%s\n' "$sortie"
    if [ "$issue" -ne 0 ] || printf '%s' "$sortie" | grep -q "^air-mail-admin : "; then
        echo
        echo "ÉCHEC : la commande de \`bascule.md\` ($1) est REFUSÉE." >&2
        echo "        Elle le serait aussi le jour de la bascule." >&2
        exit 1
    fi
    "$outil" config show "$3" > "$relu" 2>&1
}

# Ce que LES DEUX commandes promettent — l'inventaire, valeur par valeur.
promesses_communes() {
    verifier "le domaine annoncé"          '^domaine +mail\.narro\.ch'
    verifier "les 50 Mio de message"       '^message max +52428800'
    verifier "l'exigence de HELO qualifié" '^.HELO. qualifié +EXIGÉ'
    verifier "les deux exigences d'enveloppe" '^enveloppe +EXPÉDITEUR et DESTINATAIRE'
    verifier "l'existence du domaine"      '^domaine expéditeur +doit EXISTER'
    verifier "le relais Resend"            'smtp\.resend\.com:465'
    # **`[::]` ET NON `0.0.0.0`** : le premier couvre les deux familles d'adresses,
    # le second l'IPv4 SEULEMENT. `mail.narro.ch` a une AAAA et Dovecot écoute
    # aujourd'hui sur les deux ; s'en tenir à `0.0.0.0` ferait de la bascule une
    # régression. Mesuré le 2026-09-08 : `401` en IPv4, RIEN en IPv6.
    verifier "l'API REST sur les deux familles" '^API REST +\[::\]:8443'
}

jouer "phase 0.4, la répétition" "$commande_essai" "$banc/essai.conf"
promesses_communes
# La répétition n'est PAS jointe du dehors, et c'est voulu : Postfix sert encore.
verifier "l'écoute SMTP d'essai sur la boucle locale" '^écoute +127\.0\.0\.1:2525'

echo
jouer "phase 1 étape 6, le jour J" "$commande_jour_j" "$banc/air-mail.conf"
promesses_communes
# Le jour J, on veut être joint — par les deux familles — et sur des PORTS
# HAUTS, les seuls que le serveur puisse lier : le pare-feu y ramène le 25, le
# 587, le 465 et le 993 (§0.3bis et étape 6ter).
verifier "l'écoute SMTP du jour J en \`[::]:2525\`"      '^écoute +\[::\]:2525'
verifier "l'écoute SMTPS du jour J en \`[::]:4465\`"     '^ +\[::\]:4465 '
verifier "l'écoute IMAPS du jour J en \`[::]:9993\`"     '^écoute IMAP +\[::\]:9993'
interdire_ecoute "une écoute sur la boucle locale — c'est la configuration d'essai, pas celle du jour J" '127\.0\.0\.1:'
interdire_ecoute "une écoute en \`0.0.0.0\` — l'IPv4 seule" '0\.0\.0\.0:'
interdire_ecoute "un port sous 1024 — que le serveur ne peut pas lier (C10)" ':(25|110|143|465|587|993|995)( |$)'

echo
if [ "$manques" -ne 0 ]; then
    echo "ÉCHEC : $manques promesse(s) du manuel ne se relisent pas." >&2
    exit 1
fi
echo "OK : les DEUX commandes de \`bascule.md\` sont acceptées, et tout ce qu'elles promettent se relit."
