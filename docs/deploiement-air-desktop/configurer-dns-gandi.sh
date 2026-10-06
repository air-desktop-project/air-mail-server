#!/usr/bin/env bash
#
# configurer-dns-gandi.sh — Configuration complète du DNS pour air-desktop.org via API Gandi
#
# # POURQUOI CE SCRIPT EXISTE
#
# La configuration DNS pour air-mail-server est critique et doit être exacte.
# Ce script automatise la création de tous les enregistrements nécessaires via
# l'API Gandi LiveDNS, en s'inspirant de la configuration éprouvée de narro.ch.
#
# # USAGE
#
#     # 1. Vérifier la configuration actuelle
#     bash configurer-dns-gandi.sh --verifier
#
#     # 2. Créer tous les enregistrements (nécessite GANDI_API_KEY)
#     bash configurer-dns-gandi.sh --creer --api-key $GANDI_API_KEY
#
#     # 3. Supprimer les enregistrements (pour nettoyage)
#     bash configurer-dns-gandi.sh --supprimer --api-key $GANDI_API_KEY
#
#     # 4. Afficher la configuration JSON à publier
#     bash configurer-dns-gandi.sh --json
#
#     # 5. Afficher la configuration pour bind/named
#     bash configurer-dns-gandi.sh --bind
#
# # DÉPENDANCES
#
#     - curl (pour les requêtes API)
#     - jq (pour le traitement JSON)
#     - openssl (pour la génération DKIM)
#     - dig (pour la vérification)
#
# # VARIABLES D'ENVIRONNEMENT
#
#     GANDI_API_KEY : Clé API Gandi (peut aussi être passée via --api-key)
#     GANDI_API_URL : URL de l'API (par défaut: https://api.gandi.net/v5)
#

set -uo pipefail
export LC_ALL=C

# ── Configuration par défaut ─────────────────────────────────────────────────
DOMAINE="air-desktop.org"
SOUS_DOMAINE="mail"
DOMAINE_COMPLET="$SOUS_DOMAINE.$DOMAINE"

# Sélecteur DKIM (date de création)
SELECTEUR_DKIM="ams202610"

# TTL par défaut (en secondes)
TTL_DEFAULT=3600

# Chemin vers la clé DKIM (si génération locale)
CHEMIN_CLE_DKIM="/var/lib/air-mail/dkim.pem"

# Mode d'exécution
MODE=""
API_KEY=""
API_URL="${GANDI_API_URL:-https://api.gandi.net/v5}"
VERBOSE=0

# Variables pour les IP (à passer en arguments ou via environnement)
IPV4=""
IPV6=""

# ── Fonctions utilitaires ───────────────────────────────────────────────────

log() {
    [ "$VERBOSE" -eq 1 ] && echo "[INFO] $*"
}

erreur() {
    echo "[ERREUR] $*" >&2
}

titre() {
    printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((68 - ${#1}))))"
}

# Vérifier les dépendances
verifier_dependances() {
    local outils=(curl jq openssl dig)
    for outil in "${outils[@]}"; do
        command -v "$outil" >/dev/null 2>&1 || {
            erreur "Outils manquant : $outil"
            return 1
        }
    done
    return 0
}

# Générer une clé DKIM Ed25519
generer_cle_dkim() {
    local chemin="${1:-$CHEMIN_CLE_DKIM}"
    
    if [ -f "$chemin" ]; then
        log "Clé DKIM existe déjà : $chemin"
        return 0
    fi
    
    log "Génération de la clé DKIM RSA-2048 : $chemin"
    mkdir -p "$(dirname "$chemin")"
    
    # Générer la clé privée
    # RSA-2048 ET NON Ed25519 : RFC 8463 est facultative, et Gmail comme
    # Outlook ignorent encore `k=rsa` — une signature qu'ils ne savent pas
    # lire ne vaut pas mieux qu'aucune.
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$chemin" 2>/dev/null || {
        erreur "Échec de la génération de la clé DKIM"
        return 1
    }
    
    chmod 600 "$chemin"
    log "Clé DKIM générée avec succès"
    return 0
}

# Extraire la partie publique de la clé DKIM en base64
obtenir_clé_publique_dkim() {
    local chemin="${1:-$CHEMIN_CLE_DKIM}"
    openssl pkey -in "$chemin" -pubout -outform DER 2>/dev/null | base64 -w0
}

# Calculer l'empreinte SHA-256 de la clé publique
calculer_empreinte_dkim() {
    local base64="$1"
    printf '%s' "$base64" | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1
}

# Découper une valeur TXT pour le DNS (max 255 caractères par chaîne)
decouper_valeur_txt() {
    local valeur="$1"
    local taille_max=200  # Marge de sécurité pour éviter les problèmes
    local sortie=""
    
    while [ -n "$valeur" ]; do
        sortie="$sortie\"${valeur:0:$taille_max}\" "
        valeur="${valeur:$taille_max}"
    done
    
    # Supprimer le dernier espace
    printf '%s' "${sortie% }"
}

# ── Fonctions API Gandi ────────────────────────────────────────────────────

# Obtenir l'ID de la zone DNS pour un domaine
obtenir_id_zone() {
    local domaine="$1"
    local url="${API_URL}/livedns/domains/$domaine"
    
    local response
    response=$(curl -s -f -H "Authorization: Bearer $API_KEY" "$url" 2>/dev/null) || {
        erreur "Impossible de récupérer l'ID de zone pour $domaine"
        echo "$response" >&2
        return 1
    }
    
    local zone_id
    zone_id=$(echo "$response" | jq -r '.id' 2>/dev/null)
    
    if [ -z "$zone_id" ] || [ "$zone_id" = "null" ]; then
        erreur "ID de zone non trouvé pour $domaine"
        return 1
    fi
    
    echo "$zone_id"
    return 0
}

# Créer un enregistrement DNS
creer_enregistrement() {
    local zone_id="$1"
    local nom="$2"
    local type="$3"
    local valeur="$4"
    local ttl="${5:-$TTL_DEFAULT}"
    
    # PUT ET NON POST : `POST /records` refuse un rrset qui existe déjà (409),
    # et ce script doit pouvoir se rejouer. `PUT /records/<nom>/<type>` REMPLACE
    # le rrset, ce qui est précisément ce qu'on veut dire.
    local url="${API_URL}/livedns/domains/$zone_id/records/$nom/$type"
    local data
    
    # Construire le JSON en fonction du type
    case "$type" in
        TXT)
            # Pour TXT, la valeur doit être un tableau
            data=$(jq -n --arg name "$nom" --arg type "$type" --argjson ttl "$ttl" --arg values "$valeur" \
                '{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}')
            ;;
        MX|A|AAAA|CNAME|PTR)
            data=$(jq -n --arg name "$nom" --arg type "$type" --argjson ttl "$ttl" --arg values "$valeur" \
                '{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}')
            ;;
        *)
            erreur "Type d'enregistrement non supporté : $type"
            return 1
            ;;
    esac
    
    log "Création de l'enregistrement : $nom $type $valeur"
    
    local response
    response=$(curl -s -f -X PUT \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$data" \
        "$url" 2>/dev/null) || {
        erreur "Échec de la création de l'enregistrement $nom.$type"
        echo "Réponse API :" >&2
        echo "$response" | jq . >&2
        return 1
    }
    
    log "Enregistrement créé avec succès : $nom.$type"
    return 0
}

# Supprimer un enregistrement DNS
supprimer_enregistrement() {
    local zone_id="$1"
    local nom="$2"
    local type="$3"
    
    local url="${API_URL}/livedns/domains/$zone_id/records/$nom/$type"
    
    log "Suppression de l'enregistrement : $nom $type"
    
    local response
    response=$(curl -s -f -X DELETE \
        -H "Authorization: Bearer $API_KEY" \
        "$url" 2>/dev/null) || {
        erreur "Échec de la suppression de l'enregistrement $nom.$type"
        echo "Réponse API : $response" >&2
        return 1
    }
    
    log "Enregistrement supprimé avec succès : $nom.$type"
    return 0
}

# Lister les enregistrements DNS existants
lister_enregistrements() {
    local zone_id="$1"
    local url="${API_URL}/livedns/domains/$zone_id/records"
    
    curl -s -f -H "Authorization: Bearer $API_KEY" "$url" 2>/dev/null
}

# Vérifier un enregistrement DNS
verifier_enregistrement() {
    local nom="$1"
    local type="$2"
    local valeur_attendue="$3"
    
    local valeur_trouvee
    valeur_trouvee=$(dig +short "$type" "$nom" 2>/dev/null | tr -d '"')
    
    if [ "$valeur_trouvee" = "$valeur_attendue" ]; then
        echo "✓ OK"
        return 0
    else
        echo "✗ ÉCHEC"
        echo "  Attendu : $valeur_attendue"
        echo "  Trouvé  : $valeur_trouvee"
        return 1
    fi
}

# ── Génération de la configuration ──────────────────────────────────────────

# Générer la configuration DNS complète
generer_configuration() {
    local domaine="$1"
    local sous_domaine="$2"
    local ipv4="$3"
    local ipv6="$4"
    local selecteur_dkim="$5"
    local chemin_cle_dkim="$6"
    
    # Générer la clé DKIM si nécessaire
    if [ ! -f "$chemin_cle_dkim" ]; then
        generer_cle_dkim "$chemin_cle_dkim" || return 1
    fi
    
    local cle_publique
    cle_publique=$(obtenir_clé_publique_dkim "$chemin_cle_dkim")
    local valeur_dkim="v=DKIM1; k=rsa; p=$cle_publique"
    
    # Découper la valeur DKIM pour le DNS
    local valeur_dkim_decoupee
    valeur_dkim_decoupee=$(decouper_valeur_txt "$valeur_dkim")
    
    # Générer le nom complet pour DKIM
    local nom_dkim="$selecteur_dkim._domainkey.$domaine"
    local date_id=$(date +%Y%m%d)000000
    
    # Afficher la configuration
    titre "Configuration DNS pour $domaine"
    
    echo ""
    echo "=== Enregistrements MX ==="
    echo "$domaine.  IN  MX  10 $sous_domaine.$domaine."
    
    echo ""
    echo "=== Enregistrements A/AAAA ==="
    echo "$sous_domaine.$domaine.  IN  A      $ipv4"
    echo "$sous_domaine.$domaine.  IN  AAAA   $ipv6"
    
    echo ""
    echo "=== Enregistrement PTR (à configurer chez OVH) ==="
    echo "; Pour IPv4 : $ipv4 -> mail.air-desktop.org"
    echo "; Pour IPv6 : $ipv6 -> mail.air-desktop.org"
    
    echo ""
    echo "=== Enregistrement SPF ==="
    echo "$domaine.  IN  TXT  \"v=spf1 mx ~all\""
    
    echo ""
    echo "=== Enregistrement DKIM ==="
    echo "$nom_dkim.  IN  TXT  ($valeur_dkim_decoupee)"
    
    echo ""
    echo "=== Enregistrement DMARC ==="
    echo "_dmarc.$domaine.  IN  TXT  \"v=DMARC1; p=none; rua=mailto:postmaster@$domaine\""
    
    echo ""
    echo "=== Enregistrement MTA-STS (optionnel) ==="
    echo "mta-sts.$domaine.  IN  A      $ipv4"
    echo "mta-sts.$domaine.  IN  AAAA   $ipv6"
    echo "_mta-sts.$domaine.  IN  TXT  \"v=STSv1; id=$date_id;\""
    
    echo ""
    echo "=== Empreinte DKIM (pour vérification) ==="
    local empreinte
    empreinte=$(calculer_empreinte_dkim "$cle_publique")
    echo "$empreinte"
    
    # Retourner les informations pour l'API
    echo "DOMAINE=$domaine"
    echo "SOUS_DOMAINE=$sous_domaine"
    echo "IPV4=$ipv4"
    echo "IPV6=$ipv6"
    echo "SELECTEUR_DKIM=$selecteur_dkim"
    echo "VALEUR_DKIM=$valeur_dkim_decoupee"
    echo "NOM_DKIM=$nom_dkim"
    echo "EMPREINTE_DKIM=$empreinte"
}

# Générer le JSON pour l'API Gandi
generer_json() {
    local domaine="$1"
    local sous_domaine="$2"
    local ipv4="$3"
    local ipv6="$4"
    local selecteur_dkim="$5"
    local chemin_cle_dkim="$6"
    
    # Générer la clé DKIM si nécessaire
    if [ ! -f "$chemin_cle_dkim" ]; then
        generer_cle_dkim "$chemin_cle_dkim" || return 1
    fi
    
    local cle_publique
    cle_publique=$(obtenir_clé_publique_dkim "$chemin_cle_dkim")
    local valeur_dkim="v=DKIM1; k=rsa; p=$cle_publique"
    local valeur_dkim_decoupee
    valeur_dkim_decoupee=$(decouper_valeur_txt "$valeur_dkim")
    
    local nom_dkim="$selecteur_dkim._domainkey"
    local date_id=$(date +%Y%m%d)000000
    
    # Créer le JSON pour chaque enregistrement
    local json="[]"
    
    # MX
    json=$(echo "$json" | jq --arg name "@" --arg type "MX" --argjson ttl $TTL_DEFAULT --arg values "10 $sous_domaine.$domaine." \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # A
    json=$(echo "$json" | jq --arg name "$sous_domaine" --arg type "A" --argjson ttl $TTL_DEFAULT --arg values "$ipv4" \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # AAAA
    json=$(echo "$json" | jq --arg name "$sous_domaine" --arg type "AAAA" --argjson ttl $TTL_DEFAULT --arg values "$ipv6" \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # SPF
    json=$(echo "$json" | jq --arg name "$domaine" --arg type "TXT" --argjson ttl $TTL_DEFAULT --arg values '"v=spf1 mx ~all"' \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # DKIM
    json=$(echo "$json" | jq --arg name "$nom_dkim" --arg type "TXT" --argjson ttl $TTL_DEFAULT --arg values "$valeur_dkim_decoupee" \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # DMARC
    json=$(echo "$json" | jq --arg name "_dmarc" --arg type "TXT" --argjson ttl $TTL_DEFAULT --arg values "\"v=DMARC1; p=none; rua=mailto:postmaster@$domaine\"" \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # MTA-STS A
    json=$(echo "$json" | jq --arg name "mta-sts" --arg type "A" --argjson ttl $TTL_DEFAULT --arg values "$ipv4" \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    # MTA-STS TXT
    json=$(echo "$json" | jq --arg name "_mta-sts" --arg type "TXT" --argjson ttl $TTL_DEFAULT --arg values "\"v=STSv1; id=$date_id;\"" \
        '. + [{rrset_name: $name, rrset_type: $type, rrset_ttl: $ttl, rrset_values: [$values]}]')
    
    echo "$json" | jq .
}

# ── Fonctions principales ───────────────────────────────────────────────────

# Créer tous les enregistrements DNS
creer_tous_enregistrements() {
    titre "Création des enregistrements DNS pour $DOMAINE"
    
    # Vérifier que nous avons une clé API
    if [ -z "$API_KEY" ]; then
        erreur "Clé API Gandi requise. Passez-la via --api-key ou GANDI_API_KEY"
        return 1
    fi
    
    # Vérifier que nous avons les IP
    if [ -z "$IPV4" ] || [ -z "$IPV6" ]; then
        erreur "Les adresses IP sont requises. Passez-les via --ipv4 et --ipv6"
        return 1
    fi
    
    # Obtenir l'ID de zone
    local zone_id
    zone_id=$(obtenir_id_zone "$DOMAINE") || return 1
    log "ID de zone : $zone_id"
    
    # Générer la clé DKIM
    generer_cle_dkim "$CHEMIN_CLE_DKIM" || return 1
    
    local cle_publique
    cle_publique=$(obtenir_clé_publique_dkim "$CHEMIN_CLE_DKIM")
    local valeur_dkim="v=DKIM1; k=rsa; p=$cle_publique"
    local valeur_dkim_decoupee
    valeur_dkim_decoupee=$(decouper_valeur_txt "$valeur_dkim")
    
    local nom_dkim="$SELECTEUR_DKIM._domainkey"
    local date_id=$(date +%Y%m%d)000000
    
    # Créer chaque enregistrement
    local erreurs=0
    
    # MX
    creer_enregistrement "$zone_id" "@" "MX" "10 $SOUS_DOMAINE.$DOMAINE." || erreurs=$((erreurs + 1))
    
    # A
    creer_enregistrement "$zone_id" "$SOUS_DOMAINE" "A" "$IPV4" || erreurs=$((erreurs + 1))
    
    # AAAA
    creer_enregistrement "$zone_id" "$SOUS_DOMAINE" "AAAA" "$IPV6" || erreurs=$((erreurs + 1))
    
    # SPF
    creer_enregistrement "$zone_id" "@" "TXT" '"v=spf1 mx ~all"' || erreurs=$((erreurs + 1))
    
    # DKIM
    creer_enregistrement "$zone_id" "$nom_dkim" "TXT" "$valeur_dkim_decoupee" || erreurs=$((erreurs + 1))
    
    # DMARC
    creer_enregistrement "$zone_id" "_dmarc" "TXT" "\"v=DMARC1; p=none; rua=mailto:postmaster@$DOMAINE\"" || erreurs=$((erreurs + 1))
    
    # MTA-STS A
    creer_enregistrement "$zone_id" "mta-sts" "A" "$IPV4" || erreurs=$((erreurs + 1))
    
    # MTA-STS AAAA
    creer_enregistrement "$zone_id" "mta-sts" "AAAA" "$IPV6" || erreurs=$((erreurs + 1))
    
    # MTA-STS TXT
    creer_enregistrement "$zone_id" "_mta-sts" "TXT" "\"v=STSv1; id=$date_id;\"" || erreurs=$((erreurs + 1))
    
    if [ "$erreurs" -eq 0 ]; then
        echo ""
        echo "✓ Tous les enregistrements DNS ont été créés avec succès"
        echo ""
        echo "Empreinte DKIM pour vérification :"
        calculer_empreinte_dkim "$cle_publique"
        echo ""
        echo "Vérifiez la configuration avec :"
        echo "  bash $0 --verifier"
        return 0
    else
        erreur "$erreurs erreur(s) lors de la création des enregistrements"
        return 1
    fi
}

# Supprimer tous les enregistrements DNS
supprimer_tous_enregistrements() {
    titre "Suppression des enregistrements DNS pour $DOMAINE"
    
    # Vérifier que nous avons une clé API
    if [ -z "$API_KEY" ]; then
        erreur "Clé API Gandi requise. Passez-la via --api-key ou GANDI_API_KEY"
        return 1
    fi
    
    # Obtenir l'ID de zone
    local zone_id
    zone_id=$(obtenir_id_zone "$DOMAINE") || return 1
    log "ID de zone : $zone_id"
    
    # Lister les enregistrements existants
    local enregistrements
    enregistrements=$(lister_enregistrements "$zone_id") || return 1
    
    # Supprimer chaque enregistrement lié à notre configuration
    local erreurs=0
    # RELATIFS À LA ZONE, comme à la création : `$DOMAINE` seul s'écrit `@`.
    local noms=(
        "$SOUS_DOMAINE"
        "@"
        "$SELECTEUR_DKIM._domainkey"
        "_dmarc"
        "mta-sts"
        "_mta-sts"
    )
    
    for nom in "${noms[@]}"; do
        # Supprimer MX
        supprimer_enregistrement "$zone_id" "$nom" "MX" || log "MX $nom non trouvé ou déjà supprimé"
        # Supprimer A
        supprimer_enregistrement "$zone_id" "$nom" "A" || log "A $nom non trouvé ou déjà supprimé"
        # Supprimer AAAA
        supprimer_enregistrement "$zone_id" "$nom" "AAAA" || log "AAAA $nom non trouvé ou déjà supprimé"
        # Supprimer TXT
        supprimer_enregistrement "$zone_id" "$nom" "TXT" || log "TXT $nom non trouvé ou déjà supprimé"
    done
    
    echo ""
    echo "✓ Suppression terminée"
    return 0
}

# Vérifier la configuration DNS existante
verifier_configuration() {
    titre "Vérification de la configuration DNS pour $DOMAINE"
    
    local erreurs=0
    
    # Vérifier MX
    echo -n "MX : "
    verifier_enregistrement "$DOMAINE" "MX" "10 $SOUS_DOMAINE.$DOMAINE." || erreurs=$((erreurs + 1))
    
    # Vérifier A
    echo -n "A : "
    verifier_enregistrement "$SOUS_DOMAINE.$DOMAINE" "A" "$IPV4" || erreurs=$((erreurs + 1))
    
    # Vérifier AAAA
    echo -n "AAAA : "
    verifier_enregistrement "$SOUS_DOMAINE.$DOMAINE" "AAAA" "$IPV6" || erreurs=$((erreurs + 1))
    
    # Vérifier SPF
    echo -n "SPF : "
    verifier_enregistrement "$DOMAINE" "TXT" '"v=spf1 mx ~all"' || erreurs=$((erreurs + 1))
    
    # Vérifier DKIM (on vérifie juste que l'enregistrement existe)
    echo -n "DKIM : "
    # `dig` interroge le DNS : ici le nom est PLEINEMENT QUALIFIÉ.
    local nom_dkim="$SELECTEUR_DKIM._domainkey.$DOMAINE"
    local valeur_dkim
    valeur_dkim=$(dig +short TXT "$nom_dkim" 2>/dev/null)
    if [ -n "$valeur_dkim" ]; then
        echo "✓ OK (trouvé)"
    else
        echo "✗ ÉCHEC (non trouvé)"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier DMARC
    echo -n "DMARC : "
    verifier_enregistrement "_dmarc.$DOMAINE" "TXT" "\"v=DMARC1; p=none; rua=mailto:postmaster@$DOMAINE\"" || erreurs=$((erreurs + 1))
    
    # Vérifier MTA-STS
    echo -n "MTA-STS A : "
    verifier_enregistrement "mta-sts.$DOMAINE" "A" "$IPV4" || erreurs=$((erreurs + 1))
    
    echo -n "MTA-STS TXT : "
    local valeur_mta_sts
    valeur_mta_sts=$(dig +short TXT "_mta-sts.$DOMAINE" 2>/dev/null | tr -d '"')
    if [[ "$valeur_mta_sts" == v=STSv1* ]]; then
        echo "✓ OK (trouvé)"
    else
        echo "✗ ÉCHEC (non trouvé ou incorrect)"
        erreurs=$((erreurs + 1))
    fi
    
    echo ""
    if [ "$erreurs" -eq 0 ]; then
        echo "✓ Tous les enregistrements DNS sont correctement configurés"
        return 0
    else
        erreur "$erreurs enregistrement(s) DNS incorrect(s) ou manquant(s)"
        return 1
    fi
}

# ── Analyse des arguments ───────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --creer)
            MODE="creer"
            shift
            ;;
        --supprimer)
            MODE="supprimer"
            shift
            ;;
        --verifier)
            MODE="verifier"
            shift
            ;;
        --json)
            MODE="json"
            shift
            ;;
        --bind)
            MODE="bind"
            shift
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --ipv4)
            IPV4="$2"
            shift 2
            ;;
        --ipv6)
            IPV6="$2"
            shift 2
            ;;
        --domaine)
            DOMAINE="$2"
            shift 2
            ;;
        --sous-domaine)
            SOUS_DOMAINE="$2"
            shift 2
            ;;
        --selecteur-dkim)
            SELECTEUR_DKIM="$2"
            shift 2
            ;;
        --chemin-cle-dkim)
            CHEMIN_CLE_DKIM="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --aide|-h)
            cat <<'AIDE'
Usage: configurer-dns-gandi.sh [OPTIONS] [COMMANDE]

COMMANDES:
    --creer              Créer tous les enregistrements DNS
    --supprimer          Supprimer tous les enregistrements DNS
    --verifier           Vérifier la configuration DNS existante
    --json              Afficher la configuration au format JSON
    --bind              Afficher la configuration au format bind/named

OPTIONS:
    --api-key <clé>      Clé API Gandi (ou via GANDI_API_KEY)
    --ipv4 <adresse>     Adresse IPv4 du serveur
    --ipv6 <adresse>     Adresse IPv6 du serveur
    --domaine <domaine>  Domaine principal (défaut: air-desktop.org)
    --sous-domaine <sd>  Sous-domaine pour mail (défaut: mail)
    --selecteur-dkim <s> Sélecteur DKIM (défaut: ams202610)
    --chemin-cle-dkim <c> Chemin vers la clé DKIM (défaut: /var/lib/air-mail/dkim.pem)
    --verbose, -v        Mode verbeux
    --aide, -h          Afficher cette aide

EXEMPLES:
    # Créer tous les enregistrements
    bash configurer-dns-gandi.sh --creer --api-key $GANDI_API_KEY --ipv4 1.2.3.4 --ipv6 2001:db8::1

    # Vérifier la configuration
    bash configurer-dns-gandi.sh --verifier --ipv4 1.2.3.4 --ipv6 2001:db8::1

    # Afficher la configuration bind
    bash configurer-dns-gandi.sh --bind --ipv4 1.2.3.4 --ipv6 2001:db8::1
AIDE
            exit 0
            ;;
        *)
            erreur "Option inconnue : $1"
            exit 1
            ;;
    esac
done

# Vérifier les dépendances
verifier_dependances || exit 1

# Si API_KEY n'est pas passé en argument, essayer la variable d'environnement
[ -z "$API_KEY" ] && API_KEY="${GANDI_API_KEY:-}"

# ── Exécution ───────────────────────────────────────────────────────────────

case "$MODE" in
    creer)
        creer_tous_enregistrements
        exit $?
        ;;
    supprimer)
        supprimer_tous_enregistrements
        exit $?
        ;;
    verifier)
        verifier_configuration
        exit $?
        ;;
    json)
        titre "Configuration DNS au format JSON"
        generer_json "$DOMAINE" "$SOUS_DOMAINE" "$IPV4" "$IPV6" "$SELECTEUR_DKIM" "$CHEMIN_CLE_DKIM"
        ;;
    bind)
        # Le `> /dev/null` qui était ici rendait `--bind` muet : le mode n'a
        # jamais rien affiché depuis qu'il existe.
        generer_configuration "$DOMAINE" "$SOUS_DOMAINE" "$IPV4" "$IPV6" "$SELECTEUR_DKIM" "$CHEMIN_CLE_DKIM"
        ;;
    "")
        # Mode par défaut : afficher l'aide
        erreur "Aucune commande spécifiée. Utilisez --aide pour voir les options."
        exit 1
        ;;
    *)
        erreur "Mode inconnu : $MODE"
        exit 1
        ;;
esac
