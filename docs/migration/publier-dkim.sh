#!/usr/bin/env bash
#
# publier-dkim.sh — LE SÉLECTEUR ams202609, ENGENDRÉ PUIS VÉRIFIÉ
#
# # POURQUOI CE SCRIPT EXISTE
#
# Le manuel de bascule dit, en §0.1bis :
#
#     Un découpage mal fait casse TOUTES les signatures sans rien dire.
#
# C'est vrai, et c'est insuffisant : un avertissement dans un document ne
# vérifie rien. Une clé publique de 2048 bits fait 392 caractères en base64,
# au-delà des 255 octets qu'une chaîne de caractères DNS peut porter. Elle doit
# donc être publiée en PLUSIEURS CHAÎNES QUI SE CONCATÈNENT, à l'intérieur d'UNE
# SEULE ressource TXT — et les panneaux d'hébergeurs se partagent en deux
# familles qui ne s'annoncent pas :
#
#   * ceux qui prennent la valeur entière et découpent eux-mêmes ;
#   * ceux qui prennent ce qu'on leur donne, mot pour mot.
#
# Entre les deux se cache la faute la plus coûteuse de toute la bascule : DEUX
# ressources TXT au lieu d'une. La zone se charge, le panneau affiche deux
# lignes vertes, `dig` répond — et tout vérificateur DKIM lit `permerror`,
# parce que la RFC 6376 §3.6.2 lui interdit de choisir entre deux clés. Le
# courrier part, il est accepté, il tombe dans les indésirables. Chez les
# autres. Une semaine plus tard.
#
# AUCUN JOURNAL LOCAL NE S'EN ÉMEUT. C'est pourquoi la vérification ne peut pas
# regarder ce qu'on a saisi : elle doit relire ce que le DNS SERT VRAIMENT, le
# recomposer, et le comparer octet pour octet à la clé privée qui signera.
#
# # USAGE
#
#     # 1. sur mail.narro.ch, une seule fois :
#     sudo bash publier-dkim.sh --engendrer
#
#     # 2. on publie chez Gandi ce que l'étape 1 a imprimé.
#
#     # 3. on vérifie — sur le serveur, sans rien recopier :
#     sudo bash publier-dkim.sh --verifier
#
#     # ... ou depuis n'importe quelle machine, avec la seule empreinte que
#     #     l'étape 1 a imprimée. Elle ne porte aucun secret.
#     bash publier-dkim.sh --verifier --empreinte 3f2a...
#
#     # 4. et le banc, qui ne touche ni au DNS ni au serveur :
#     bash publier-dkim.sh --essais
#
# # OPTIONS
#
#     --selecteur <nom>     défaut : ams202609
#     --domaine <nom>       défaut : narro.ch
#     --cle <fichier>       la clé privée ; défaut : le chemin rspamd
#     --empreinte <sha256>  vérifier sans la clé privée
#     --serveur <hôte>      interroger CE serveur de noms plutôt que le résolveur
#                           du système — pour ne pas attendre l'expiration d'un
#                           cache après publication
#     --depuis <fichier>    lire une capture de `dig +short` au lieu d'interroger
#                           le DNS ; pour les essais, et pour rejouer un incident
#
# Il ne touche JAMAIS au DNS : personne ne lui confie de mot de passe
# d'hébergeur, et il ne recharge pas rspamd. Publier reste un geste humain.

set -uo pipefail
export LC_ALL=C

selecteur=ams202609
domaine=narro.ch
cle=""
empreinte_attendue=""
serveur=""
depuis=""
mode=""
bits=2048

# ── CE QUE LE DNS PEUT PORTER ───────────────────────────────────────────────
#
# 255 est la limite d'UNE chaîne (RFC 1035 §3.3.14). On découpe à 200 : la marge
# ne coûte rien, et elle évite d'avoir à réfléchir le jour où le préambule
# `v=DKIM1; k=rsa; ` s'allonge d'un `t=s;` ou d'un `h=sha256;`.
TAILLE_MORCEAU=200

rate() { echo "ÉCHEC : $*" >&2; fautes=$((fautes + 1)); }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((68 - ${#1}))))"; }

# ── DÉCOUPER, ET C'EST LA FONCTION QUE LE BANC ÉPROUVE ──────────────────────
#
# Rend la suite de chaînes citées, séparées par un espace, telle qu'un fichier
# de zone l'attend. Une SEULE ressource, plusieurs chaînes.
decouper() { # <chaîne>
    local reste=$1 sortie=""
    while [ -n "$reste" ]; do
        sortie="$sortie\"${reste:0:TAILLE_MORCEAU}\" "
        reste=${reste:TAILLE_MORCEAU}
    done
    printf '%s' "${sortie% }"
}

# ── RECOMPOSER CE QUE LE DNS A RENDU ────────────────────────────────────────
#
# `dig +short TXT` imprime UNE LIGNE PAR RESSOURCE, et à l'intérieur d'une
# ligne, les chaînes multiples apparaissent citées et séparées par un espace :
#
#     "v=DKIM1; k=rsa; p=MIIBIjAN" "AQ8AMIIBCgKCAQEA...IDAQAB"
#
# **ON NE PEUT PAS ÉCRIRE `tr -d '" '` ICI.** Ce raccourci — qui est dans le
# manuel, et qui y était de ma main — retire aussi les espaces INTÉRIEURS aux
# chaînes. Il donne la bonne réponse sur `p=`, dont le base64 n'en contient
# jamais, et la mauvaise sur tout le reste. On retire donc exactement les
# frontières `" "`, et rien d'autre.
#
# Renseigne `nb_ressources` et `valeur_recomposee`.
recomposer() { # lit sur l'entrée standard
    local ligne
    nb_ressources=0
    valeur_recomposee=""
    while IFS= read -r ligne; do
        [ -n "$ligne" ] || continue
        nb_ressources=$((nb_ressources + 1))
        ligne=${ligne#\"}
        ligne=${ligne%\"}
        ligne=${ligne//\" \"/}
        valeur_recomposee=$ligne
    done
}

# ── EXTRAIRE UNE ÉTIQUETTE DKIM ─────────────────────────────────────────────
#
# La RFC 6376 §3.2 autorise des espaces autour des étiquettes ET À L'INTÉRIEUR
# de la valeur de `p=`, qu'un vérificateur DOIT ignorer. Certains panneaux en
# insèrent en repliant la valeur ; le nôtre n'en met pas, mais un jour un autre
# le fera, et une clé refusée pour un espace serait une nuit perdue.
etiquette() { # <valeur-recomposée> <nom-d-étiquette>
    local morceau nom val
    local IFS=';'
    for morceau in $1; do
        morceau=${morceau#"${morceau%%[![:space:]]*}"}
        nom=${morceau%%=*}
        nom=${nom%"${nom##*[![:space:]]}"}
        [ "$nom" = "$2" ] || continue
        val=${morceau#*=}
        val=${val//[[:space:]]/}
        printf '%s' "$val"
        return 0
    done
    return 1
}

# La partie publique, en base64 de DER — exactement ce que `p=` doit porter.
publique_de() { # <clé-privée>
    openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | base64 -w0
}

# **L'EMPREINTE PORTE SUR LES OCTETS, PAS SUR LEUR ÉCRITURE.** On l'établit sur
# le DER décodé et non sur le base64 : deux outils qui replient différemment le
# même base64 donneraient deux empreintes pour une seule clé, et on chercherait
# un défaut qui n'existe pas.
empreinte_de() { # <base64>
    printf '%s' "$1" | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1
}

interroger() { # <nom>
    if [ -n "$depuis" ]; then
        cat "$depuis"
    elif [ -n "$serveur" ]; then
        dig +short TXT "$1" "@$serveur"
    else
        dig +short TXT "$1"
    fi
}

# ════════════════════════════════════════════════════════════════════════════
#   ENGENDRER
# ════════════════════════════════════════════════════════════════════════════
engendrer() {
    local defaut=/var/lib/rspamd/dkim/$domaine.$selecteur.key
    [ -n "$cle" ] || cle=$defaut

    if [ -e "$cle" ]; then
        echo "ÉCHEC : $cle existe déjà." >&2
        echo "       Une clé qu'on écrase est une clé qui signait peut-être." >&2
        echo "       Choisissez un autre sélecteur, ou déplacez celle-ci." >&2
        return 1
    fi

    mkdir -p "$(dirname "$cle")" || return 1

    # **LE MASQUE AVANT L'ÉCRITURE, ET NON LE `chmod` APRÈS.** Entre un
    # `openssl genrsa` qui pose un fichier en 0644 et le `chmod 600` qui suit,
    # il y a un intervalle — court, réel — où la clé de signature du domaine est
    # lisible par tous les comptes de la machine.
    ( umask 077 && openssl genrsa -out "$cle" "$bits" 2>/dev/null ) || {
        echo "ÉCHEC : openssl genrsa a refusé." >&2
        return 1
    }
    chmod 600 "$cle"
    if id _rspamd > /dev/null 2>&1; then
        chown _rspamd "$cle"
    else
        echo "note : le compte _rspamd est absent ; le propriétaire est inchangé."
    fi

    local pub; pub=$(publique_de "$cle")
    local valeur="v=DKIM1; k=rsa; p=$pub"
    local nom="$selecteur._domainkey.$domaine"

    echo "clé engendrée : $cle  ($bits bits, 0600)"
    echo

    titre 'A. FICHIER DE ZONE, ou tout panneau qui prend du BIND'
    printf '%s. IN TXT ( %s )\n' "$nom" "$(decouper "$valeur")"

    titre 'B. GANDI, panneau — UNE ligne, plusieurs chaînes citées'
    #
    # **LA VALEUR ENTIÈRE VA DANS UN SEUL CHAMP.** Le piège de Gandi est là :
    # son panneau et son API acceptent une LISTE de valeurs, et cette liste veut
    # dire « plusieurs ressources », jamais « plusieurs morceaux d'une seule ».
    # Mettre les deux moitiés dans deux entrées de la liste publie DEUX clés
    # incomplètes, et fait tomber toute signature en permerror.
    decouper "$valeur"
    echo

    titre 'C. GANDI, API — un SEUL élément dans rrset_values'
    #
    # **L'ÉCHAPPEMENT EST LE PIÈGE DANS LE PIÈGE.** La valeur JSON porte des
    # guillemets — ceux qui séparent les morceaux — et ils doivent y entrer
    # échappés une fois, pas deux. Un \\" au lieu d'un \" rend le corps
    # invalide, et Gandi répond 400 : celui-là, au moins, se voit tout de suite.
    echo 'Le corps, à mettre dans un fichier dkim.json :'
    echo
    printf '{\n'
    printf '  "rrset_name": "%s._domainkey",\n' "$selecteur"
    printf '  "rrset_type": "TXT",\n'
    printf '  "rrset_ttl": 3600,\n'
    printf '  "rrset_values": ["%s"]\n' "$(decouper "$valeur" | sed 's/"/\\"/g')"
    printf '}\n'
    echo
    echo 'puis, avec un jeton personnel Gandi dans $GANDI_PAT :'
    echo
    echo '    curl -X POST --fail-with-body \\'
    echo '         -H "Authorization: Bearer $GANDI_PAT" \\'
    echo '         -H "Content-Type: application/json" \\'
    echo "         --data @dkim.json \\"
    echo "         https://api.gandi.net/v5/livedns/domains/$domaine/records"

    titre "D. L'EMPREINTE, à emporter — elle ne porte aucun secret"
    echo "$(empreinte_de "$pub")"
    echo
    echo "Vérifiez ensuite, depuis n'importe où :"
    echo "    bash publier-dkim.sh --verifier --empreinte $(empreinte_de "$pub")"
    echo
    echo "RSPAMD NE SIGNE PAS ENCORE : le manuel §0.1bis dit quoi mettre dans"
    echo "dkim_signing.conf, et pourquoi l'ancien sélecteur RESTE publié."
    return 0
}

# ════════════════════════════════════════════════════════════════════════════
#   VÉRIFIER
# ════════════════════════════════════════════════════════════════════════════
verifier() {
    local fautes=0
    local nom="$selecteur._domainkey.$domaine"
    local nb_ressources valeur_recomposee

    local attendu=""
    if [ -n "$empreinte_attendue" ]; then
        attendu=$empreinte_attendue
    else
        [ -n "$cle" ] || cle=/var/lib/rspamd/dkim/$domaine.$selecteur.key
        if [ ! -r "$cle" ]; then
            echo "ÉCHEC : ni --empreinte, ni clé lisible en $cle" >&2
            echo "       Sur le serveur, mettez sudo. Ailleurs, passez --empreinte." >&2
            return 1
        fi
        local pub; pub=$(publique_de "$cle")
        if [ -z "$pub" ]; then
            echo "ÉCHEC : $cle ne se lit pas comme une clé privée." >&2
            return 1
        fi
        attendu=$(empreinte_de "$pub")
    fi

    echo "publier-dkim — $nom"
    [ -n "$depuis" ] && echo "  (capture rejouée : $depuis)"
    [ -n "$serveur" ] && echo "  (interrogé chez $serveur)"

    local reponse
    reponse=$(interroger "$nom") || {
        echo "ÉCHEC : l'interrogation DNS a échoué." >&2
        return 1
    }
    recomposer <<< "$reponse"

    # ── 1. UNE SEULE RESSOURCE ──────────────────────────────────────────────
    #
    # LE CONTRÔLE POUR LEQUEL CE SCRIPT EXISTE. RFC 6376 §3.6.2 : plusieurs
    # ressources au même nom, et le vérificateur abandonne — il n'a pas le droit
    # d'en choisir une.
    if [ "$nb_ressources" -eq 0 ]; then
        rate "aucune ressource TXT à ce nom — rien n'est publié, ou le cache n'a pas expiré"
        echo
        echo "  Si vous venez de publier, réessayez avec --serveur ns-133-c.gandi.net"
        echo "  pour interroger la source plutôt qu'un cache."
        return 1
    elif [ "$nb_ressources" -gt 1 ]; then
        rate "$nb_ressources ressources TXT au même nom — un vérificateur DKIM abandonne"
        echo
        echo "  C'est le découpage mis dans la LISTE de valeurs de l'hébergeur."
        echo "  Les morceaux vont dans UNE valeur, séparés par un espace :"
        echo '      "premier morceau" "second morceau"'
        return 1
    fi
    echo "OK — une seule ressource TXT"

    # ── 2. LA GRAMMAIRE ─────────────────────────────────────────────────────
    local v k p
    v=$(etiquette "$valeur_recomposee" v) || v=""
    k=$(etiquette "$valeur_recomposee" k) || k=""
    p=$(etiquette "$valeur_recomposee" p) || p=""

    if [ "$v" != "DKIM1" ]; then
        rate "l'étiquette v= vaut '$v' au lieu de DKIM1"
    elif [ -z "$p" ]; then
        # Une valeur `p=` vide n'est pas une faute de frappe : la RFC 6376 §3.6.1
        # en fait la RÉVOCATION de la clé. On ne la confond pas avec un oubli.
        rate "p= est VIDE — c'est une clé RÉVOQUÉE, pas une clé absente"
    else
        echo "OK — v=DKIM1, et p= est renseignée"
    fi
    if [ -n "$k" ] && [ "$k" != "rsa" ]; then
        rate "k= vaut '$k' alors que la clé engendrée est du RSA"
    fi

    # ── 3. ELLE SE DÉCODE, ET ELLE FAIT LA BONNE TAILLE ─────────────────────
    if [ -n "$p" ]; then
        local taille
        taille=$(printf '%s' "$p" | base64 -d 2>/dev/null \
            | openssl pkey -pubin -inform DER -noout -text 2>/dev/null \
            | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
        if [ -z "$taille" ]; then
            rate "p= ne se décode pas en clé publique — le découpage a perdu des octets"
        elif [ "$taille" -lt 2048 ]; then
            rate "la clé publiée fait $taille bits ; on en voulait $bits"
        else
            echo "OK — la clé publiée se décode, $taille bits"
        fi
    fi

    # ── 4. C'EST LA MÊME QUE CELLE QUI SIGNERA ──────────────────────────────
    #
    # Tout le reste peut passer et la signature tomber quand même : une clé
    # valide, bien découpée, mais d'un AUTRE sélecteur recopié par mégarde.
    if [ -n "$p" ]; then
        local vue; vue=$(empreinte_de "$p")
        if [ "$vue" != "$attendu" ]; then
            rate "la clé publiée n'est PAS celle qui signera"
            echo "       publiée : $vue" >&2
            echo "       attendue : $attendu" >&2
        else
            echo "OK — c'est bien la clé qui signera"
        fi
    fi

    echo
    if [ "$fautes" -eq 0 ]; then
        echo "OK : $nom est publiable en l'état."
        echo
        echo "IL RESTE LE SEUL CONTRÔLE QUI COMPTE, et il ne se fait pas ici :"
        echo "envoyez-vous un message vers Gmail et vers Outlook, et lisez"
        echo "Authentication-Results chez le destinataire. Il doit dire"
        echo "dkim=pass header.d=$domaine."
    else
        echo "$fautes défaut(s) — NE PAS faire signer rspamd avec ce sélecteur."
    fi
    return "$fautes"
}

# ════════════════════════════════════════════════════════════════════════════
#   ESSAIS
# ════════════════════════════════════════════════════════════════════════════
#
# Le banc n'interroge aucun DNS et ne touche à rien : il fabrique de vraies clés
# dans un répertoire jetable, et rejoue par --depuis les réponses que le DNS
# rendrait. Les cinq façons de se tromper sont montées à la main, parce qu'aucune
# ne se serait vue autrement qu'en production, une semaine plus tard.
essais() {
    local banc; banc=$(mktemp -d) || return 1
    trap 'rm -rf "$banc"' RETURN
    local fautes=0

    openssl genrsa -out "$banc/bonne.key" 2048 2>/dev/null
    openssl genrsa -out "$banc/autre.key" 2048 2>/dev/null
    openssl genrsa -out "$banc/courte.key" 1024 2>/dev/null

    local pub; pub=$(publique_de "$banc/bonne.key")
    local valeur="v=DKIM1; k=rsa; p=$pub"

    # **UN CODE DE RETOUR NE SUFFIT PAS, ET C'EST UNE CORRECTION.**
    #
    # La première écriture de ce banc n'exigeait qu'un refus. Elle passait — et
    # deux mutants la passaient aussi : en supprimant le comptage des ressources,
    # puis en supprimant le contrôle de taille. Les cas refusaient toujours, mais
    # POUR UNE AUTRE RAISON, en aval. Le contrôle que ce script existe pour
    # rendre n'était donc éprouvé par rien.
    #
    # Chaque cas nomme désormais le motif qu'il attend dans le rapport, et
    # plusieurs sont montés pour qu'AUCUN autre contrôle ne puisse les rattraper.
    attendu() { # <code> <motif> <étiquette> <capture> [options de vérification...]
        local code=$1 motif=$2 quoi=$3 capture=$4; shift 4
        printf '%s\n' "$capture" > "$banc/capture.txt"
        local args=(--verifier --depuis "$banc/capture.txt")
        if [ $# -gt 0 ]; then args+=("$@"); else args+=(--cle "$banc/bonne.key"); fi
        bash "$0" "${args[@]}" > "$banc/sortie.txt" 2>&1
        local vu=$? mal=""
        if [ "$code" -eq 0 ] && [ "$vu" -ne 0 ]; then
            mal="refusé alors qu'il fallait accepter (code $vu)"
        elif [ "$code" -ne 0 ] && [ "$vu" -eq 0 ]; then
            mal="ACCEPTÉ alors qu'il fallait refuser"
        elif [ -n "$motif" ] && ! grep -qF "$motif" "$banc/sortie.txt"; then
            mal="refusé, mais PAS pour la bonne raison — «$motif» absent du rapport"
        fi
        if [ -n "$mal" ]; then
            echo "FAUTE : $quoi — $mal" >&2
            sed 's/^/       /' "$banc/sortie.txt" >&2
            fautes=$((fautes + 1))
        fi
    }

    local decoupee; decoupee=$(decouper "$valeur")

    # ── A. LE CAS SAIN ──────────────────────────────────────────────────────
    attendu 0 "" "une ressource, deux chaînes, la bonne clé" "$decoupee"

    # ── B. DEUX RESSOURCES — LA FAUTE QUE CE SCRIPT EXISTE POUR VOIR ────────
    #
    # **LES DEUX SONT COMPLÈTES ET JUSTES.** C'est délibéré : la clé recomposée
    # est alors parfaite, l'empreinte concorde, la taille est bonne — plus AUCUN
    # autre contrôle ne peut faire échouer ce cas. Seul le comptage le voit.
    # C'est aussi le cas réel le plus banal : la ressource saisie deux fois.
    attendu 1 "ressources TXT au même nom" "DEUX ressources complètes" \
        "$decoupee
$decoupee"

    # ── B bis. LE MÊME DÉFAUT, PAR LA LISTE DE VALEURS DE L'HÉBERGEUR ───────
    #
    # Chaque morceau dans une entrée séparée : deux ressources INCOMPLÈTES.
    local premier=${decoupee%% \"*} second="\"${decoupee#* \"}"
    attendu 1 "ressources TXT au même nom" "les morceaux dans DEUX entrées" \
        "$premier
$second"

    # ── C. UN DÉCOUPAGE QUI PERD UN CARACTÈRE ───────────────────────────────
    #
    # Une clé recopiée à la main d'un terminal qui a replié la ligne. Elle a la
    # bonne allure, elle se recompose, et elle ne vaut rien.
    attendu 1 "ne se décode pas en clé publique" "un caractère perdu à la frontière" \
        "${decoupee:0:120}${decoupee:121}"

    # ── D. LA CLÉ D'UN AUTRE SÉLECTEUR ──────────────────────────────────────
    #
    # Tout est bien formé. C'est simplement l'autre clé — celle du sélecteur
    # qu'on remplace, recopiée par habitude.
    attendu 1 "n'est PAS celle qui signera" "une clé bien formée, mais pas la bonne" \
        "$(decouper "v=DKIM1; k=rsa; p=$(publique_de "$banc/autre.key")")"

    # ── E. UNE CLÉ DE 1024 BITS ─────────────────────────────────────────────
    #
    # Celle que narro.ch publie AUJOURD'HUI sous le sélecteur `mail`. Republier
    # la courte sous le nouveau nom rendrait la rotation sans objet.
    #
    # **ON VÉRIFIE CONTRE L'EMPREINTE DE LA COURTE**, pour que la comparaison
    # concorde et que la taille soit le SEUL contrôle qui puisse refuser.
    attendu 1 "on en voulait" "une clé de 1024 bits sous le nouveau sélecteur" \
        "$(decouper "v=DKIM1; k=rsa; p=$(publique_de "$banc/courte.key")")" \
        --empreinte "$(empreinte_de "$(publique_de "$banc/courte.key")")"

    # ── F. RIEN DU TOUT ─────────────────────────────────────────────────────
    attendu 1 "aucune ressource TXT" "aucune ressource publiée" ""

    # ── G. UNE CLÉ RÉVOQUÉE ─────────────────────────────────────────────────
    attendu 1 "RÉVOQUÉE" "p= vide, donc révoquée" '"v=DKIM1; k=rsa; p="'

    # ── G bis. UN v= ABSENT ─────────────────────────────────────────────────
    attendu 1 "au lieu de DKIM1" "l'étiquette v= oubliée" \
        "$(decouper "k=rsa; p=$pub")"

    # ── H. DES ESPACES DANS p=, QUI DOIVENT ÊTRE IGNORÉS ────────────────────
    #
    # **CELUI-CI DOIT PASSER.** RFC 6376 §3.2 : un vérificateur DOIT ignorer les
    # espaces à l'intérieur de la valeur de `p=`. Un panneau qui replie la clé
    # est agaçant, il n'est pas fautif — et refuser sa sortie ferait chercher un
    # défaut là où il n'y en a pas.
    attendu 0 "" "des espaces à l'intérieur de p=" \
        "$(decouper "v=DKIM1; k=rsa; p=${pub:0:40} ${pub:40}")"

    # ── I. LA VÉRIFICATION SANS LA CLÉ PRIVÉE ───────────────────────────────
    #
    # Le chemin que Thierry emprunte depuis son poste : il n'a que l'empreinte.
    attendu 0 "" "l'empreinte seule accepte la bonne clé" "$decoupee" \
        --empreinte "$(empreinte_de "$pub")"
    attendu 1 "n'est PAS celle qui signera" "l'empreinte seule refuse une fausse" \
        "$decoupee" \
        --empreinte 0000000000000000000000000000000000000000000000000000000000000000

    # ── L. CE QU'ON IMPRIME EST CE QU'ON ACCEPTE ────────────────────────────
    #
    # **LE SEUL CAS DE BOUT EN BOUT.** Tous les autres partent d'une capture
    # fabriquée par le banc ; celui-ci part de la sortie RÉELLE de --engendrer,
    # celle que Thierry recopiera dans le panneau. Sans lui, --engendrer pourrait
    # imprimer une chose et --verifier en attendre une autre, chacun se tenant
    # pour juste — et le banc entier resterait vert.
    #
    # On prend la section B, qui est déjà à la forme que `dig +short` rend.
    bash "$0" --engendrer --cle "$banc/neuve.key" --domaine exemple.test \
        > "$banc/engendre.txt" 2>&1
    grep -m1 '^"v=DKIM1' "$banc/engendre.txt" > "$banc/capture.txt"
    if ! bash "$0" --verifier --cle "$banc/neuve.key" --domaine exemple.test \
        --depuis "$banc/capture.txt" > "$banc/sortie.txt" 2>&1; then
        echo "FAUTE : --verifier REFUSE ce que --engendrer vient d'imprimer" >&2
        sed 's/^/       /' "$banc/sortie.txt" >&2
        fautes=$((fautes + 1))
    fi

    # Et le corps JSON de la section C est du JSON.
    if command -v python3 > /dev/null 2>&1; then
        sed -n '/^{$/,/^}$/p' "$banc/engendre.txt" > "$banc/corps.json"
        if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' \
            "$banc/corps.json" 2>/dev/null; then
            echo "FAUTE : le corps JSON imprimé n'est pas du JSON valide" >&2
            sed 's/^/       /' "$banc/corps.json" >&2
            fautes=$((fautes + 1))
        fi
    fi

    # **ET --engendrer REFUSE D'ÉCRASER.** Une clé qu'on écrase est une clé qui
    # signait peut-être ; le second appel doit buter, pas obéir.
    if bash "$0" --engendrer --cle "$banc/neuve.key" --domaine exemple.test \
        > /dev/null 2>&1; then
        echo "FAUTE : --engendrer a ÉCRASÉ une clé existante" >&2
        fautes=$((fautes + 1))
    fi

    # ── J. LE DÉCOUPAGE TIENT LA LIMITE DU DNS ──────────────────────────────
    #
    # Le contrôle qui empêche de « corriger » TAILLE_MORCEAU en le montant à 300
    # un jour où l'on trouvera la sortie moins jolie.
    local morceau
    for morceau in $decoupee; do
        morceau=${morceau#\"}; morceau=${morceau%\"}
        if [ "${#morceau}" -gt 255 ]; then
            echo "FAUTE : une chaîne de ${#morceau} caractères, au-delà des 255 du DNS" >&2
            fautes=$((fautes + 1))
        fi
    done

    # ── K. ET LA RECOMPOSITION GARDE LES ESPACES INTÉRIEURS ─────────────────
    #
    # Le défaut du manuel, mis en banc : `tr -d '" '` passerait tout le reste et
    # échouerait ici. Sans ce cas, rien n'empêcherait d'y revenir.
    local nb_ressources valeur_recomposee
    recomposer <<< '"un deux" "trois quatre"'
    if [ "$valeur_recomposee" != "un deuxtrois quatre" ]; then
        echo "FAUTE : recomposition — obtenu '$valeur_recomposee'" >&2
        fautes=$((fautes + 1))
    fi

    if [ "$fautes" -eq 0 ]; then
        echo "OK : le sain passe, et les huit façons de se tromper échouent"
        echo "     TOUTES, et chacune en le disant."
    fi
    return "$fautes"
}

# ── LIGNE DE COMMANDE ───────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --engendrer) mode=engendrer ;;
        --verifier) mode=verifier ;;
        --essais) mode=essais ;;
        --selecteur) selecteur=${2:?}; shift ;;
        --domaine) domaine=${2:?}; shift ;;
        --cle) cle=${2:?}; shift ;;
        --empreinte) empreinte_attendue=${2:?}; shift ;;
        --serveur) serveur=${2:?}; shift ;;
        --depuis) depuis=${2:?}; shift ;;
        *) echo "option inconnue : $1" >&2; exit 2 ;;
    esac
    shift
done

case "$mode" in
    engendrer) engendrer ;;
    verifier) verifier ;;
    essais) essais ;;
    *)
        sed -n '2,60p' "$0" | sed 's/^#\{0,1\} \{0,1\}//'
        exit 2
        ;;
esac
