#!/usr/bin/env bash
#
# check-doublons — une crate que NOUS déclarons entre-t-elle deux fois ?
#
# # LE DÉFAUT QUE CETTE BARRIÈRE FERME, ET IL A VÉCU SIX SEMAINES
#
# Le manifeste écrit, à propos de `rsa` : « en prendre une autre mettrait DEUX
# `rsa` dans le binaire — deux implémentations de la même arithmétique, dont une
# seule serait revue le jour d'un avis de sécurité ». La règle était juste, et
# rien ne la vérifiait.
#
# Le 2026-08-28, le commit `b7e53e902` a posé l'échange de clés hybride et, avec
# lui, `rustls-rustcrypto` épinglé sur un commit. Cette crate-là demande
# `x25519-dalek = "3"` ; notre manifeste demandait `"2"`. Le binaire a donc porté
# **deux X25519** — la 2.0.1 pour notre moitié classique du KEX, la 3.0.0 pour
# TLS — pendant six semaines, sans qu'une ligne le dise. C'est tombé le
# 2026-10-08, en relisant le graphe pour une autre raison.
#
# Deux copies d'une crate de cryptographie, ce n'est pas de l'embonpoint : c'est
# une version qu'on croit avoir mise à jour et qui tourne encore, et un avis de
# sécurité qu'on lit en pensant être couvert.
#
# # LA LISTE NE S'ÉCRIT PAS, ELLE SE DÉRIVE
#
# Une liste de crates « sensibles » tenue à la main aurait le sort de toutes les
# listes tenues à la main. Celle-ci se lit dans `[workspace.dependencies]` du
# manifeste, et c'est le bon périmètre — pas par commodité, mais parce que
# **c'est exactement la classe du défaut** : une crate que nous déclarons
# nous-mêmes, et dont une AUTRE version entre par une dépendance transitive.
# C'est notre exigence qui a divergé de celle d'amont ; le gate juge donc nos
# déclarations.
#
# Ce qu'elle laisse donc passer, et c'est assumé : un doublon entre deux crates
# que nous ne déclarons ni l'une ni l'autre. `syn` en est un (2 et 3, par deux
# macros de procédure), et il n'entre pas dans le binaire.
#
# # LES DEUX VERROUS, ET NON LE SEUL
#
# `fuzz/Cargo.lock` est un second graphe, résolu à part (`fuzz/` est hors du
# workspace). Il peut donc diverger seul — et une campagne de fuzz qui éprouve
# une autre version que celle qu'on sert n'éprouve pas ce qu'on sert.
#
# # LE RENOMMAGE EST LU
#
# `webpki = { package = "rustls-webpki", … }` se déclare sous un nom et se
# verrouille sous l'autre. Chercher `webpki` dans le verrou ne rendrait rien, et
# la barrière conclurait « une seule copie » sans en avoir compté aucune.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "check-doublons — nos propres déclarations, comptées dans les deux verrous"
echo

# ── Ce que nous déclarons, sous le nom que le verrou emploie ─────────────────
#
# Les crates internes (`path = …`) sont écartées : elles sont uniques par
# construction, et leur version suit le workspace.
declarees=$(
    sed -n '/^\[workspace.dependencies\]/,/^\[workspace.lints/p' Cargo.toml |
        grep -v '^[[:space:]]*#' |
        grep -E '^[a-z0-9_-]+ *=' |
        grep -v 'path *=' |
        while IFS= read -r ligne; do
            nom=${ligne%%=*}
            nom=${nom// /}
            # Un `package = "autre-nom"` l'emporte : c'est lui qui est verrouillé.
            reel=$(printf '%s' "$ligne" | sed -n 's/.*package *= *"\([^"]*\)".*/\1/p')
            printf '%s\n' "${reel:-$nom}"
        done | sort -u
)

if [ -z "$declarees" ]; then
    echo "ÉCHEC : aucune déclaration lue dans \`[workspace.dependencies]\`."
    echo "Ce contrôle n'a RIEN examiné ; il ne prétend pas le contraire."
    exit 1
fi

combien=$(printf '%s\n' "$declarees" | wc -l | tr -d ' ')
echo "périmètre : $combien dépendances déclarées en direct (hors crates internes)"

# ── Le compte, verrou par verrou ────────────────────────────────────────────
violations=0

for verrou in Cargo.lock fuzz/Cargo.lock; do
    [ -f "$verrou" ] || {
        echo "ÉCHEC : \`$verrou\` manque."
        violations=$((violations + 1))
        continue
    }

    while IFS= read -r crate; do
        # `awk` plutôt que `grep -A1` : il faut la version qui SUIT le nom, et
        # seulement celle-là. Un `-A1` rendrait aussi la ligne qui suit une
        # mention du nom ailleurs dans le fichier.
        versions=$(
            awk -v cible="name = \"$crate\"" '
                $0 == cible { attend = 1; next }
                attend && /^version = / { gsub(/version = |"/, ""); print; attend = 0 }
            ' "$verrou"
        )
        nombre=$(printf '%s' "$versions" | grep -c . || true)

        if [ "$nombre" -gt 1 ]; then
            echo
            echo "ÉCHEC : \`$crate\` est $nombre fois dans \`$verrou\` :"
            printf '%s\n' "$versions" | sed 's/^/    /'
            echo "    Notre déclaration a divergé de celle d'une dépendance qui la tire"
            echo "    aussi. Alignez la version dans \`Cargo.toml\`, puis :"
            echo "        cargo update -p $crate      # ici ET dans fuzz/"
            violations=$((violations + 1))
        fi
    done <<< "$declarees"
done

echo

if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations doublon(s). Une crate en double, c'est une version"
    echo "qu'on croit avoir montée et qui tourne encore."
    exit 1
fi

echo "OK : chacune de nos déclarations n'a qu'une version, dans les deux verrous."
