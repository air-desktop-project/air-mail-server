#!/usr/bin/env bash
#
# poser-secrets-air-desktop.sh — Pose les secrets initiaux pour air-desktop.org
#
# # POURQUOI CE SCRIPT EXISTE
#
# Ce script est adapté de poser-les-secrets.sh utilisé pour narro.ch.
# Il génère des mots de passe sécurisés pour chaque compte utilisateur
# et les pose dans le magasin air-mail-server.
#
# # PRINCIPES
#
# 1. Tous les secrets sont DISTINCTS (vérifié)
# 2. Les secrets sont générés avec un alphabet sûr (pas de 0/O, 1/l/I)
# 3. Les secrets ne s'affichent JAMAIS sur la sortie standard
# 4. Les secrets sont écrits dans un fichier 0600
# 5. Un secret commun laisserait chacun ouvrir la boîte des autres
#
# # USAGE
#
#     # 1. Afficher ce que le script ferait (mode test)
#     bash poser-secrets-air-desktop.sh
#
#     # 2. Poser les secrets pour de vrai
#     sudo bash poser-secrets-air-desktop.sh --pour-de-vrai
#
#     # 3. Poser les secrets avec un magasin personnalisé
#     sudo bash poser-secrets-air-desktop.sh --pour-de-vrai --magasin /chemin/vers/comptes.bin
#
#     # 4. Afficher l'aide
#     bash poser-secrets-air-desktop.sh --aide
#
# # DÉPENDANCES
#
#     - air-mail-admin (dans le PATH)
#     - od (pour la génération aléatoire)
#

set -euo pipefail
export LC_ALL=C

# ── Configuration par défaut ─────────────────────────────────────────────────

# Liste des comptes pour air-desktop.org
# À adapter selon vos besoins
COMPTES=(
    "postmaster"
    "admin"
    "thierry"
)

# Domaine
DOMAINE="air-desktop.org"

# Magasin des comptes
MAGASIN="/var/lib/air-mail/comptes.bin"

# Fichier de sortie pour les secrets
SORTIE="${SECRETS_SORTIE:-$HOME/secrets-air-desktop-$(date +%Y%m%d).txt}"

# Mode d'exécution
POUR_DE_VRAI=0
VERBOSE=0

# ── Fonctions utilitaires ───────────────────────────────────────────────────

dit() {
    printf '  %s\n' "$*"
}

titre() {
    printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((66 - ${#1}))))"
}

erreur() {
    echo "poser-secrets-air-desktop: $*" >&2
}

# ── Génération des secrets ─────────────────────────────────────────────────

# Alphabet sûr : pas de 0/O, 1/l/I qui se confondent
ALPHABET='abcdefghjkmnpqrstuvwxyz23456789'

# Générer un secret de 16 caractères
un_secret() {
    local secret=''
    local i
    
    for ((i = 0; i < 16; i++)); do
        # Générer un nombre aléatoire entre 0 et 255
        local tirage
        tirage=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
        
        # Rejeter les valeurs qui introduiraient un biais
        local seuil=$((256 - 256 % ${#ALPHABET}))
        while [ "$tirage" -ge "$seuil" ]; do
            tirage=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
        done
        
        # Ajouter le caractère correspondant
        secret="${secret}${ALPHABET:$((tirage % ${#ALPHABET})):1}"
        
        # Ajouter un tiret tous les 4 caractères (sauf à la fin)
        if [ $(((i + 1) % 4)) -eq 0 ] && [ "$i" -lt 15 ]; then
            secret="${secret}-"
        fi
    done
    
    printf '%s' "$secret"
}

# ── Vérifications préalables ───────────────────────────────────────────────

verifier_dependances() {
    command -v air-mail-admin >/dev/null 2>&1 || {
        erreur "air-mail-admin introuvable dans le PATH"
        return 1
    }
    command -v od >/dev/null 2>&1 || {
        erreur "od introuvable"
        return 1
    }
    return 0
}

verifier_magasin() {
    local magasin="$1"
    
    if [ ! -f "$magasin" ]; then
        erreur "Magasin introuvable : $magasin"
        return 1
    fi
    
    if ! sudo -u air-mail test -f "$magasin" 2>/dev/null; then
        erreur "Le compte air-mail ne peut pas lire $magasin"
        return 1
    fi
    
    local connus
    connus=$(sudo -u air-mail air-mail-admin account list "$magasin" 2>/dev/null | awk '{print $1}')
    
    local manquants=0
    for compte in "${COMPTES[@]}"; do
        if ! grep -qx "$compte" <<< "$connus"; then
            echo "  ABSENT du magasin : $compte" >&2
            manquants=1
        fi
    done
    
    [ "$manquants" -eq 0 ] || {
        erreur "Un ou plusieurs comptes manquent dans le magasin"
        echo "Créez d'abord les comptes avec :" >&2
        echo "  printf %s \"MOT_DE_PASSE_TEMPORAIRE\" | air-mail-admin account add $magasin --login <compte> --address <compte>@$DOMAINE" >&2
        return 1
    }
    
    return 0
}

# ── Fonctions principales ───────────────────────────────────────────────────

generer_et_poser_secrets() {
    titre "Génération des secrets"
    
    verifier_dependances || exit 1
    verifier_magasin "$MAGASIN" || exit 1
    
    if [ -e "$SORTIE" ]; then
        erreur "Le fichier de sortie existe déjà : $SORTIE"
        erreur "Écartez-le d'abord pour éviter d'écraser les secrets précédents"
        exit 1
    fi
    
    dit "Magasin : $MAGASIN"
    dit "Sortie : $SORTIE"
    dit "Nombre de comptes : ${#COMPTES[@]}"
    
    titre "Génération"
    
    declare -A secrets
    for compte in "${COMPTES[@]}"; do
        secrets["$compte"]=$(un_secret)
        dit "Généré pour $compte"
    done
    
    titre "Vérification de l'unicité"
    
    local secrets_tries
    secrets_tries=$(printf '%s\n' "${secrets[@]}" | sort -u)
    local nb_distincts
    nb_distincts=$(echo "$secrets_tries" | wc -l)
    
    if [ "$nb_distincts" -ne "${#COMPTES[@]}" ]; then
        erreur "Certains secrets ne sont pas distincts !"
        erreur "Génération annulée pour éviter les conflits"
        exit 1
    fi
    
    dit "Tous les secrets sont distincts (${#COMPTES[@]} secrets, $nb_distincts uniques)"
    
    titre "Pose des secrets"
    
    for compte in "${COMPTES[@]}"; do
        printf %s "${secrets[$compte]}" | \
            sudo -u air-mail air-mail-admin account passwd "$MAGASIN" --login "$compte"
        dit "Secret posé pour $compte"
    done
    
    titre "Écriture du fichier de sortie"
    
    umask 077
    {
        printf 'Secrets initiaux pour air-desktop.org — posés le %s\n' "$(date -Is)"
        printf '\n'
        printf 'Ces secrets sont DE PASSAGE.\n'
        printf 'Chaque utilisateur doit changer son mot de passe après la première connexion.\n'
        printf '\n'
        printf 'À transmettre par un canal sécurisé (pas par email).\n'
        printf '\n'
        printf 'Configuration serveur :\n'
        printf '  Domaine : mail.air-desktop.org\n'
        printf '  Serveur IMAP : mail.air-desktop.org:993 (SSL/TLS)\n'
        printf '  Serveur SMTP : mail.air-desktop.org:587 (STARTTLS) ou 465 (SSL/TLS)\n'
        printf '  Identifiant : <compte> (SANS @air-desktop.org)\n'
        printf '  Méthode auth : Mot de passe normal (PLAIN)\n'
        printf '\n'
        printf 'Secrets :\n'
        printf '\n'
        
        for compte in "${COMPTES[@]}"; do
            printf '  %-20s %s\n' "$compte" "${secrets[$compte]}"
        done
        
        printf '\n'
        printf 'Instructions pour changer de mot de passe :\n'
        printf '\n'
        printf '1. Obtenir un jeton avec votre mot de passe actuel :\n'
        printf '   curl -X POST https://mail.air-desktop.org:8443/v1/tokens\n'
        printf '   -H \'Content-Type: application/json\'\n'
        printf '   -d \'{\"login\":\"<compte>\",\"password\":\"<mot-de-passe-actuel>\"}\'\n'
        printf '\n'
        printf '2. Changer le mot de passe avec le jeton :\n'
        printf '   curl -X PUT https://mail.air-desktop.org:8443/v1/me/password\n'
        printf '   -H \'Authorization: Bearer <jeton>\'\n'
        printf '   -H \'Content-Type: application/json\'\n'
        printf '   -d \'{\"current_password\":\"<ancien>\",\"password\":\"<nouveau>\"}\'\n'
        printf '\n'
        printf 'Note : Les mots de passe ne sont JAMAIS stockés en clair.\n'
        printf '      Seules des empreintes (argon2id) sont conservées.\n'
    } > "$SORTIE"
    
    chmod 600 "$SORTIE"
    dit "Fichier écrit : $SORTIE (permissions 0600)"
    
    echo ""
    echo "OK : les ${#COMPTES[@]} secrets ont été posés, tous distincts."
    echo "     Ils sont dans $SORTIE — effacez ce fichier après distribution !"
}

# ── Analyse des arguments ───────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --pour-de-vrai)
            POUR_DE_VRAI=1
            shift
            ;;
        --magasin)
            MAGASIN="$2"
            shift 2
            ;;
        --sortie)
            SORTIE="$2"
            shift 2
            ;;
        --domaine)
            DOMAINE="$2"
            shift 2
            ;;
        --compte)
            COMPTES+=("$2")
            shift 2
            ;;
        --aide|-h)
            cat <<'AIDE'
Usage: poser-secrets-air-desktop.sh [OPTIONS]

OPTIONS:
    --pour-de-vrai       Poser les secrets pour de vrai (sinon mode test)
    --magasin <fichier>  Chemin vers le magasin des comptes (défaut: /var/lib/air-mail/comptes.bin)
    --sortie <fichier>   Chemin vers le fichier de sortie (défaut: ~/secrets-air-desktop-YYYYMMDD.txt)
    --domaine <domaine>  Domaine principal (défaut: air-desktop.org)
    --compte <nom>       Ajouter un compte à la liste (peut être répété)
    --aide, -h           Afficher cette aide

EXEMPLES:
    # Mode test (ne pose rien)
    bash poser-secrets-air-desktop.sh

    # Poser les secrets pour de vrai
    sudo bash poser-secrets-air-desktop.sh --pour-de-vrai

    # Avec des comptes personnalisés
    sudo bash poser-secrets-air-desktop.sh --pour-de-vrai \
        --compte alice --compte bob --compte charlie

    # Avec un magasin personnalisé
    sudo bash poser-secrets-air-desktop.sh --pour-de-vrai \
        --magasin /chemin/vers/mon-magasin.bin
AIDE
            exit 0
            ;;
        *)
            erreur "Option inconnue : $1"
            exit 1
            ;;
    esac
done

# ── Exécution ───────────────────────────────────────────────────────────────

if [ "$POUR_DE_VRAI" -eq 0 ]; then
    titre "Mode test"
    dit "RIEN n'a été posé, et aucun secret n'a été généré."
    dit "Pour poser les secrets pour de vrai :"
    dit "  sudo bash $0 --pour-de-vrai"
    exit 0
fi

generer_et_poser_secrets
