#!/usr/bin/env bash
#
# deploy-air-desktop.sh — Déploiement complet de air-mail-server pour air-desktop.org
#
# # POURQUOI CE SCRIPT EXISTE
#
# Ce script automatise le déploiement complet de air-mail-server sur un VPS OVH
# pour le domaine air-desktop.org, en s'inspirant de la configuration éprouvée
# de narro.ch (vps-9d275e3a.vps.ovh.net).
#
# Il orchestrer toutes les étapes :
#   1. Installation des dépendances
#   2. Construction du projet
#   3. Configuration du système
#   4. Configuration DNS (via API Gandi)
#   5. Configuration du serveur
#   6. Création des comptes
#   7. Pose des secrets
#   8. Activation du service
#
# # USAGE
#
#     # 1. Déploiement complet (interactif)
#     sudo bash deploy-air-desktop.sh
#
#     # 2. Déploiement avec toutes les options
#     sudo bash deploy-air-desktop.sh \
#         --ipv4 1.2.3.4 \
#         --ipv6 2001:db8::1 \
#         --api-key $GANDI_API_KEY \
#         --comptes alice,bob,charlie \
#         --relais smtp.resend.com \
#         --relais-user monuser \
#         --relais-password monpassword
#
#     # 3. Vérification du déploiement
#     sudo bash deploy-air-desktop.sh --verifier
#
#     # 4. Nettoyage
#     sudo bash deploy-air-desktop.sh --nettoyer
#
# # DÉPENDANCES EXTERNES
#
#     - git
#     - curl
#     - jq
#     - openssl
#     - cargo (Rust)
#     - systemd
#     - nftables
#     - certbot (optionnel, pour Let's Encrypt)
#

set -uo pipefail
export LC_ALL=C

# ── Configuration par défaut ─────────────────────────────────────────────────

# Domaine
DOMAINE="air-desktop.org"
SOUS_DOMAINE="mail"
DOMAINE_COMPLET="$SOUS_DOMAINE.$DOMAINE"

# Sélecteur DKIM
SELECTEUR_DKIM="ams202610"

# Répertoire d'installation
REPO_DIR="/opt/air-mail-server"
INSTALL_DIR="/usr/local/bin"
ETAT_DIR="/var/lib/air-mail"

# Compte système
COMPTE_SYSTEME="air-mail"

# IP (à fournir)
IPV4=""
IPV6=""

# Clé API Gandi (à fournir)
GANDI_API_KEY=""

# Configuration relais (optionnelle)
RELAIS_HOST=""
RELAIS_USER=""
RELAIS_PASSWORD=""
USE_RELAIS=0

# Liste des comptes (séparés par des virgules)
COMPTES_LIST="postmaster,admin,thierry"

# Mode d'exécution
MODE="deploy"
VERBOSE=0
FORCE=0

# ── Variables dérivées ───────────────────────────────────────────────────────

COMPTES_ARRAY=()
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Fonctions utilitaires ───────────────────────────────────────────────────

dit() {
    [ "$VERBOSE" -eq 1 ] && printf '  [INFO] %s\n' "$*"
}

titre() {
    printf '\n═══════════════════════════════════════════════════════════════\n'
    printf '  %s\n' "$1"
    printf '═══════════════════════════════════════════════════════════════\n'
}

sous_titre() {
    printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((66 - ${#1}))))"
}

erreur() {
    echo "[ERREUR] $*" >&2
}

avertissement() {
    echo "[AVERTISSEMENT] $*" >&2
}

succes() {
    echo "[OK] $*"
}

# Vérifier si on est root
est_root() {
    [ "$(id -u)" -eq 0 ]
}

# Vérifier les dépendances
verifier_dependances() {
    local outils=(git curl jq openssl cargo systemctl nft)
    local manquants=0
    
    for outil in "${outils[@]}"; do
        command -v "$outil" >/dev/null 2>&1 || {
            erreur "Dépendance manquante : $outil"
            manquants=$((manquants + 1))
        }
    done
    
    [ "$manquants" -eq 0 ] || return 1
    return 0
}

# Demander confirmation
demander_confirmation() {
    local message="$1"
    local defaut="${2:-n}"
    
    if [ "$FORCE" -eq 1 ]; then
        return 0
    fi
    
    read -r -p "$message [O/n] " reponse
    reponse="${reponse:-$defaut}"
    
    case "$reponse" in
        [OoYy]|oui|yes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ── Fonctions de déploiement ───────────────────────────────────────────────

# Étape 0 : Vérifications préalables
etape_verifications() {
    titre "Étape 0 : Vérifications préalables"
    
    # Vérifier qu'on est root
    est_root || {
        erreur "Ce script doit être exécuté en tant que root"
        return 1
    }
    
    # Vérifier les dépendances
    verifier_dependances || return 1
    
    # Vérifier que les IP sont fournies
    if [ -z "$IPV4" ] || [ -z "$IPV6" ]; then
        erreur "Les adresses IP sont requises"
        erreur "Passez --ipv4 et --ipv6"
        return 1
    fi
    
    # Vérifier la clé API Gandi
    if [ -z "$GANDI_API_KEY" ]; then
        avertissement "Aucune clé API Gandi fournie"
        avertissement "La configuration DNS devra être faite manuellement"
        read -r -p "Continuer sans configuration DNS automatique ? [O/n] " reponse
        reponse="${reponse:-O}"
        case "$reponse" in
            [Nn]|non)
                return 1
                ;;
        esac
    fi
    
    # Vérifier que le domaine est valide
    if ! [[ "$DOMAINE" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
        erreur "Domaine invalide : $DOMAINE"
        return 1
    fi
    
    succes "Toutes les vérifications ont réussi"
    return 0
}

# Étape 1 : Installation des dépendances système
etape_dependances_systeme() {
    titre "Étape 1 : Installation des dépendances système"
    
    # Détecter la distribution
    local distro
    distro=$(lsb_release -is 2>/dev/null || echo "unknown")
    
    case "$distro" in
        Ubuntu|Debian)
            dit "Détection : $distro"
            
            # Mettre à jour les paquets
            dit "Mise à jour des paquets..."
            apt-get update -qq || return 1
            
            # Installer les dépendances
            dit "Installation des dépendances..."
            apt-get install -y -qq \
                git \
                curl \
                jq \
                openssl \
                build-essential \
                pkg-config \
                libssl-dev \
                systemd \
                nftables \
                certbot \
                ufw \
                || return 1
            
            # Installer Rust
            dit "Installation de Rust..."
            if ! command -v cargo >/dev/null 2>&1; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || return 1
                source "$HOME/.cargo/env"
            fi
            
            ;;
        *)
            erreur "Distribution non supportée : $distro"
            erreur "Seul Ubuntu/Debian est supporté pour le moment"
            return 1
            ;;
    esac
    
    succes "Dépendances système installées"
    return 0
}

# Étape 2 : Clonage et construction du projet
etape_construire_projet() {
    titre "Étape 2 : Clonage et construction du projet"
    
    # Cloner le dépôt
    if [ ! -d "$REPO_DIR" ]; then
        dit "Clonage du dépôt..."
        git clone https://github.com/air-desktop-project/air-mail-server "$REPO_DIR" || return 1
    else
        dit "Mise à jour du dépôt..."
        cd "$REPO_DIR" || return 1
        git pull || return 1
    fi
    
    # Construire le projet
    dit "Construction du projet (cela peut prendre plusieurs minutes)..."
    cd "$REPO_DIR" || return 1
    cargo build --release --locked || return 1
    
    succes "Projet construit avec succès"
    return 0
}

# Étape 3 : Configuration du système
etape_configurer_systeme() {
    titre "Étape 3 : Configuration du système"
    
    # Créer le compte système
    dit "Création du compte système $COMPTE_SYSTEME..."
    if id "$COMPTE_SYSTEME" >/dev/null 2>&1; then
        dit "Compte $COMPTE_SYSTEME existe déjà"
    else
        useradd --system --home-dir "$ETAT_DIR" --shell /usr/sbin/nologin "$COMPTE_SYSTEME" || return 1
    fi
    
    # Créer les répertoires
    dit "Création des répertoires..."
    mkdir -p "$ETAT_DIR/maildir" || return 1
    mkdir -p "$ETAT_DIR/file" || return 1
    mkdir -p "$ETAT_DIR/tls" || return 1
    mkdir -p "$ETAT_DIR/mtasts" || return 1
    # Les quatre que la configuration nomme désormais. Le registre et l'audit
    # ne sont pas du confort : sans registre, la réception refuse par `451`.
    mkdir -p "$ETAT_DIR/registre" || return 1
    mkdir -p "$ETAT_DIR/audit" || return 1
    mkdir -p "$ETAT_DIR/brouillons" || return 1
    mkdir -p "$ETAT_DIR/rapports-dmarc" || return 1
    
    # Définir les permissions
    chown -R "$COMPTE_SYSTEME:$COMPTE_SYSTEME" "$ETAT_DIR" || return 1
    chmod 0700 "$ETAT_DIR" || return 1
    chmod 0700 "$ETAT_DIR/maildir" || return 1
    chmod 0700 "$ETAT_DIR/file" || return 1
    # **LE SERVEUR EXIGE `0700` SUR LE REGISTRE DEPUIS 0.2.47** : il REFUSE de
    # démarrer sur un registre accessible aux autres comptes, ou qu'il ne
    # pourrait pas écrire. Il ne l'élargit plus en silence, ce qu'il faisait
    # avant. Les trois autres suivent la même règle, par cohérence.
    chmod 0700 "$ETAT_DIR/registre" || return 1
    chmod 0700 "$ETAT_DIR/audit" || return 1
    chmod 0700 "$ETAT_DIR/brouillons" || return 1
    chmod 0700 "$ETAT_DIR/rapports-dmarc" || return 1
    
    # Installer les binaires
    dit "Installation des binaires..."
    install -d -m 0755 "$INSTALL_DIR" || return 1
    install -m 0755 "$REPO_DIR/target/release/air-mail-server" "$INSTALL_DIR/" || return 1
    install -m 0755 "$REPO_DIR/target/release/air-mail-admin" "$INSTALL_DIR/" || return 1
    
    # Installer l'unité systemd
    dit "Installation de l'unité systemd..."
    install -d -m 0755 /etc/systemd/system || return 1
    
    # Générer l'unité systemd (basée sur installer.sh)
    cat > /etc/systemd/system/air-mail-server.service <<'UNITE'
[Unit]
Description=air-mail-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=air-mail
Group=air-mail
ExecStart=/usr/local/bin/air-mail-server --config /var/lib/air-mail/air-mail.conf
Restart=on-failure
RestartSec=5s

UMask=0077

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

ReadWritePaths=/var/lib/air-mail

CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
RemoveIPC=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid

SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
UNITE
    
    chmod 0644 /etc/systemd/system/air-mail-server.service || return 1
    
    # Recharger systemd
    systemctl daemon-reload || return 1
    
    succes "Système configuré"
    return 0
}

# Étape 4 : Configuration DNS via API Gandi
etape_configurer_dns() {
    titre "Étape 4 : Configuration DNS"
    
    if [ -z "$GANDI_API_KEY" ]; then
        avertissement "Pas de clé API Gandi fournie"
        avertissement "Configuration DNS à faire manuellement"
        echo ""
        echo "Exécutez manuellement :"
        echo "  bash $SCRIPT_DIR/configurer-dns-gandi.sh --creer --api-key \$GANDI_API_KEY --ipv4 $IPV4 --ipv6 $IPV6"
        return 0
    fi
    
    dit "Configuration DNS via API Gandi..."
    
    # Exécuter le script de configuration DNS
    bash "$SCRIPT_DIR/configurer-dns-gandi.sh" \
        --creer \
        --api-key "$GANDI_API_KEY" \
        --ipv4 "$IPV4" \
        --ipv6 "$IPV6" \
        --domaine "$DOMAINE" \
        --sous-domaine "$SOUS_DOMAINE" \
        --selecteur-dkim "$SELECTEUR_DKIM" \
        --chemin-cle-dkim "$ETAT_DIR/dkim.pem" || return 1
    
    succes "DNS configuré"
    return 0
}

# Étape 5 : Configuration du serveur
etape_configurer_serveur() {
    titre "Étape 5 : Configuration du serveur"
    
    # Générer la clé DKIM si elle n'existe pas
    #
    # **RSA 2048, ET NON ed25519.** La zone publie `k=rsa` et la clé en place
    # est une RSA 2048 (vérifié le 2026-10-07) ; ce script tirait de l'ed25519,
    # si bien que sur une machine neuve la clé et le DNS n'auraient pas
    # correspondu — DKIM aurait échoué sans que rien ne le dise, l'émission
    # passant par Resend qui re-signe de son côté. RFC 8463 permet l'ed25519,
    # mais il se décide AVEC la zone, pas contre elle.
    if [ ! -f "$ETAT_DIR/dkim.pem" ]; then
        dit "Génération de la clé DKIM (RSA 2048, comme la zone l'annonce)..."
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
            -out "$ETAT_DIR/dkim.pem" || return 1
        chmod 600 "$ETAT_DIR/dkim.pem" || return 1
        chown "$COMPTE_SYSTEME:$COMPTE_SYSTEME" "$ETAT_DIR/dkim.pem" || return 1
    fi
    
    # Configurer le serveur
    dit "Configuration du serveur..."
    
    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  `config write` REMPLACE LE FICHIER ENTIER, ET CELUI-CI EST CELUI DE  ║
    # ║  LA PRODUCTION. Toute option retirée d'ici est EFFACÉE de la machine. ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    #
    # Remis à niveau le 2026-10-07 : il manquait DOUZE options que la
    # production porte, dont `--registre` — sans lui la réception refuse par
    # `451` — et les trois écoutes IMAP STARTTLS et POP3, qui SONT servies.
    # Avant de modifier cette liste, lisez ce que la machine porte vraiment :
    #   air-mail-admin config show /var/lib/air-mail/air-mail.conf
    # et comparez les deux `config show` après écriture. La procédure sûre est
    # au bas de `docs/arc/feuille-de-route.md`.
    local cmd_config=(
        "$INSTALL_DIR/air-mail-admin" "config" "write" "$ETAT_DIR/air-mail.conf"
        "--domain" "$DOMAINE_COMPLET"
        "--hosted" "$DOMAINE"
        # Le sous-domaine du MX est hébergé lui aussi : `postmaster@mail.…`
        # est une adresse du compte `thierry`.
        "--hosted" "$DOMAINE_COMPLET"
        "--maildir" "$ETAT_DIR/maildir"
        "--accounts" "$ETAT_DIR/comptes.bin"
        "--listen" "[::]:2525"
        "--listen-smtps" "[::]:4465"
        # LES SIX ÉCOUTES, et non trois : le pare-feu ramène 143 sur 1143,
        # 110 sur 1110 et 995 sur 9995, et ces écouteurs doivent exister.
        "--listen-imap" "[::]:1143"
        "--listen-imaps" "[::]:9993"
        "--listen-pop3" "[::]:1110"
        "--listen-pop3s" "[::]:9995"
        # 10 Mio, ce que la machine porte — et non les 50 Mio de narro.ch.
        "--max-message" "10485760"
        "--tls-cert" "$ETAT_DIR/tls/fullchain.pem"
        "--tls-key" "$ETAT_DIR/tls/privkey.pem"
        "--dkim-selector" "$SELECTEUR_DKIM"
        "--dkim-key" "$ETAT_DIR/dkim.pem"
        "--resolver" "127.0.0.53:53"
        "--public-suffix-list" "/usr/share/publicsuffix/public_suffix_list.dat"
        "--listen-http" "[::]:8443"
        "--mta-sts-anchors" "/etc/ssl/certs/ca-certificates.crt"
        "--mta-sts-cache" "$ETAT_DIR/mtasts"
        "--require-fqdn-helo"
        "--require-fqdn-sender"
        "--require-fqdn-recipient"
        "--require-sender-domain"
        # ── CE QUI MANQUAIT, ET QUI SERAIT EFFACÉ SANS CES LIGNES ──────────
        # SANS LUI, LA RÉCEPTION REFUSE PAR `451` : le registre n'est pas une
        # option de confort, le serveur n'accepte un message qu'une fois son
        # constat scellé.
        "--registre" "$ETAT_DIR/registre"
        "--audit" "$ETAT_DIR/audit"
        "--drafts" "$ETAT_DIR/brouillons"
        "--app-passwords" "$ETAT_DIR/applicatifs.bin"
        "--spf" "observe"
        "--dmarc" "observe"
        # Un `p=quarantine` est MIS DE CÔTÉ au lieu d'être remis en boîte.
        "--dmarc-quarantine-folder" "Junk"
        # Les rapports agrégés se composent et se DÉPOSENT ; `--dmarc-send`
        # n'est PAS posé — envoyer est un engagement envers les autres
        # domaines, et c'est une décision à part.
        "--dmarc-report-dir" "$ETAT_DIR/rapports-dmarc"
        "--about" "on"
    )
    
    # Ajouter le relais si configuré
    if [ "$USE_RELAIS" -eq 1 ] && [ -n "$RELAIS_HOST" ]; then
        cmd_config+=(
            "--relay"
            "--queue-spool" "$ETAT_DIR/file"
            "--queue-expire-seconds" "86400"
            "--relayhost" "$RELAIS_HOST:465"
            "--relayhost-implicit-tls"
        )
        
        if [ -n "$RELAIS_USER" ]; then
            cmd_config+=("--relayhost-user" "$RELAIS_USER")
        fi
    fi
    
    # Exécuter la commande
    "${cmd_config[@]}" || return 1
    
    # Vérifier la configuration
    dit "Vérification de la configuration..."
    "$INSTALL_DIR/air-mail-admin" config show "$ETAT_DIR/air-mail.conf" || return 1
    
    succes "Serveur configuré"
    return 0
}

# Étape 6 : Création des comptes
etape_creer_comptes() {
    titre "Étape 6 : Création des comptes"
    
    # Convertir COMPTES_LIST en tableau
    IFS=',' read -ra COMPTES_ARRAY <<< "$COMPTES_LIST"
    
    dit "Création des comptes : ${COMPTES_ARRAY[*]}"
    
    for compte in "${COMPTES_ARRAY[@]}"; do
        # Nettoyer les espaces
        compte=$(echo "$compte" | xargs)
        [ -z "$compte" ] && continue
        
        dit "Création du compte : $compte"
        
        # Mot de passe temporaire (sera remplacé par poser-secrets)
        local mot_de_passe_temp
        mot_de_passe_temp=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
        
        printf %s "$mot_de_passe_temp" | \
            sudo -u "$COMPTE_SYSTEME" "$INSTALL_DIR/air-mail-admin" account add \
                "$ETAT_DIR/comptes.bin" \
                --login "$compte" \
                --address "$compte@$DOMAINE" || return 1
        
        # Ajouter l'alias postmaster si nécessaire
        if [ "$compte" = "postmaster" ]; then
            printf %s "$mot_de_passe_temp" | \
                sudo -u "$COMPTE_SYSTEME" "$INSTALL_DIR/air-mail-admin" account add \
                    "$ETAT_DIR/comptes.bin" \
                    --login "$compte" \
                    --address "abuse@$DOMAINE" \
                    --address "root@$DOMAINE" || return 1
        fi
    done
    
    succes "Comptes créés"
    return 0
}

# Étape 7 : Pose des secrets
etape_poser_secrets() {
    titre "Étape 7 : Pose des secrets"
    
    # Convertir COMPTES_LIST en tableau
    IFS=',' read -ra COMPTES_ARRAY <<< "$COMPTES_LIST"
    
    # Créer un fichier temporaire pour les comptes
    local comptes_temp_file
    comptes_temp_file=$(mktemp)
    
    # Écrire les comptes dans le fichier temporaire
    for compte in "${COMPTES_ARRAY[@]}"; do
        compte=$(echo "$compte" | xargs)
        [ -z "$compte" ] && continue
        echo "$compte" >> "$comptes_temp_file"
    done
    
    # Exécuter le script de pose des secrets
    dit "Pose des secrets..."
    sudo bash "$SCRIPT_DIR/poser-secrets-air-desktop.sh" \
        --pour-de-vrai \
        --magasin "$ETAT_DIR/comptes.bin" \
        --domaine "$DOMAINE" || return 1
    
    # Nettoyer
    rm -f "$comptes_temp_file"
    
    succes "Secrets posés"
    return 0
}

# Étape 8 : Configuration du pare-feu
etape_configurer_parefeu() {
    titre "Étape 8 : Configuration du pare-feu"
    
    dit "Configuration de nftables..."
    
    # Créer le fichier de configuration nftables
    cat > "$ETAT_DIR/nftables-air-mail.conf" <<TABLE
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
    }
}
TABLE
    
    chmod 0600 "$ETAT_DIR/nftables-air-mail.conf" || return 1
    chown "$COMPTE_SYSTEME:$COMPTE_SYSTEME" "$ETAT_DIR/nftables-air-mail.conf" || return 1
    
    # Charger la configuration
    dit "Chargement de la configuration nftables..."
    nft -f "$ETAT_DIR/nftables-air-mail.conf" || return 1
    
    # Ouvrir le port 8443 (API) dans ufw si activé
    if systemctl is-active --quiet ufw 2>/dev/null; then
        dit "Ouverture du port 8443 dans ufw..."
        ufw allow 8443/tcp || return 1
    fi
    
    succes "Pare-feu configuré"
    return 0
}

# Étape 9 : Configuration des certificats TLS
etape_configurer_certificats() {
    titre "Étape 9 : Configuration des certificats TLS"
    
    # Vérifier si certbot est disponible
    if ! command -v certbot >/dev/null 2>&1; then
        avertissement "certbot non installé, saut de la configuration TLS automatique"
        avertissement "Installez certbot et configurez manuellement les certificats"
        return 0
    fi
    
    dit "Configuration des certificats avec certbot..."
    
    # Obtenir le certificat
    certbot certonly --standalone -d "$DOMAINE_COMPLET" --non-interactive --agree-tos -m "admin@$DOMAINE" || {
        avertissement "Échec de l'obtention du certificat"
        avertissement "Configurez manuellement les certificats"
        return 0
    }
    
    # Créer le hook de déploiement
    dit "Création du hook de déploiement certbot..."
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy || return 1
    
    cat > /etc/letsencrypt/renewal-hooks/deploy/air-mail-server <<'HOOK'
#!/bin/sh
set -eu

CIBLE=/var/lib/air-mail/tls
LIGNEE="${RENEWED_LINEAGE:-/etc/letsencrypt/live/mail.air-desktop.org}"

case "$LIGNEE" in
    *mail.air-desktop.org) ;;
    *) exit 0 ;;
esac

install -d -o air-mail -g air-mail -m 0700 "$CIBLE"
install -o air-mail -g air-mail -m 0600 "$LIGNEE/fullchain.pem" "$CIBLE/fullchain.pem"
install -o air-mail -g air-mail -m 0600 "$LIGNEE/privkey.pem" "$CIBLE/privkey.pem"
chmod 600 "$CIBLE/privkey.pem"

# Recharger le serveur
systemctl reload air-mail-server
HOOK
    
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/air-mail-server || return 1
    
    # Copier les certificats initiaux
    dit "Copie des certificats initiaux..."
    install -d -o "$COMPTE_SYSTEME" -g "$COMPTE_SYSTEME" -m 0700 "$ETAT_DIR/tls" || return 1
    install -o "$COMPTE_SYSTEME" -g "$COMPTE_SYSTEME" -m 0600 \
        /etc/letsencrypt/live/"$DOMAINE_COMPLET"/fullchain.pem \
        "$ETAT_DIR/tls/fullchain.pem" || return 1
    install -o "$COMPTE_SYSTEME" -g "$COMPTE_SYSTEME" -m 0600 \
        /etc/letsencrypt/live/"$DOMAINE_COMPLET"/privkey.pem \
        "$ETAT_DIR/tls/privkey.pem" || return 1
    
    succes "Certificats TLS configurés"
    return 0
}

# Étape 10 : Activation du service
etape_activer_service() {
    titre "Étape 10 : Activation du service"
    
    dit "Activation du service air-mail-server..."
    
    # Recharger systemd
    systemctl daemon-reload || return 1
    
    # Activer et démarrer le service
    systemctl enable air-mail-server || return 1
    systemctl start air-mail-server || return 1
    
    # Vérifier le statut
    sleep 3
    systemctl status air-mail-server --no-pager || return 1
    
    succes "Service activé"
    return 0
}

# Étape 11 : Vérification finale
etape_verification() {
    titre "Étape 11 : Vérification finale"
    
    local erreurs=0
    
    # Vérifier que le service est actif
    dit "Vérification du service..."
    if systemctl is-active --quiet air-mail-server 2>/dev/null; then
        succes "Service actif"
    else
        erreur "Service non actif"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier les ports
    dit "Vérification des ports..."
    local ports=(2525 4465 9993 8443)
    for port in "${ports[@]}"; do
        if ss -tlnp | grep -q ":$port "; then
            succes "Port $port en écoute"
        else
            erreur "Port $port non en écoute"
            erreurs=$((erreurs + 1))
        fi
    done
    
    # Vérifier la configuration
    dit "Vérification de la configuration..."
    if [ -f "$ETAT_DIR/air-mail.conf" ]; then
        succes "Fichier de configuration présent"
    else
        erreur "Fichier de configuration manquant"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier les comptes
    dit "Vérification des comptes..."
    local nb_comptes
    nb_comptes=$(sudo -u "$COMPTE_SYSTEME" "$INSTALL_DIR/air-mail-admin" account list "$ETAT_DIR/comptes.bin" 2>/dev/null | wc -l)
    if [ "$nb_comptes" -gt 0 ]; then
        succes "$nb_comptes compte(s) configuré(s)"
    else
        erreur "Aucun compte trouvé"
        erreurs=$((erreurs + 1))
    fi
    
    echo ""
    if [ "$erreurs" -eq 0 ]; then
        titre "Déploiement terminé avec succès !"
        echo ""
        echo "Le serveur air-mail-server est maintenant opérationnel pour $DOMAINE"
        echo ""
        echo "Configuration :"
        echo "  Domaine : $DOMAINE_COMPLET"
        echo "  IP : $IPV4 (IPv4), $IPV6 (IPv6)"
        echo "  Ports : 25, 587, 465, 993"
        echo "  API : https://$DOMAINE_COMPLET:8443"
        echo ""
        echo "Prochaines étapes :"
        echo "  1. Configurer le PTR chez OVH : $IPV4 -> $DOMAINE_COMPLET"
        echo "  2. Tester l'envoi/réception de mails"
        echo "  3. Vérifier les logs : journalctl -u air-mail-server -f"
        return 0
    else
        erreur "Déploiement terminé avec $erreurs erreur(s)"
        return 1
    fi
}

# Étape : Nettoyage
etape_nettoyer() {
    titre "Nettoyage"
    
    dit "Arrêt du service..."
    systemctl stop air-mail-server 2>/dev/null || true
    systemctl disable air-mail-server 2>/dev/null || true
    
    dit "Suppression des fichiers..."
    rm -f "$INSTALL_DIR/air-mail-server" "$INSTALL_DIR/air-mail-admin"
    rm -rf "$ETAT_DIR"
    rm -f /etc/systemd/system/air-mail-server.service
    
    dit "Suppression du dépôt..."
    rm -rf "$REPO_DIR"
    
    systemctl daemon-reload 2>/dev/null || true
    
    succes "Nettoyage terminé"
    return 0
}

# Étape : Vérification du déploiement existant
etape_verifier() {
    titre "Vérification du déploiement"
    
    local erreurs=0
    
    # Vérifier le service
    if systemctl is-active --quiet air-mail-server 2>/dev/null; then
        succes "Service actif"
    else
        erreur "Service non actif"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier la configuration
    if [ -f "$ETAT_DIR/air-mail.conf" ]; then
        succes "Configuration présente"
        dit "Affichage de la configuration :"
        "$INSTALL_DIR/air-mail-admin" config show "$ETAT_DIR/air-mail.conf" || erreurs=$((erreurs + 1))
    else
        erreur "Configuration manquante"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier les comptes
    if [ -f "$ETAT_DIR/comptes.bin" ]; then
        local nb_comptes
        nb_comptes=$(sudo -u "$COMPTE_SYSTEME" "$INSTALL_DIR/air-mail-admin" account list "$ETAT_DIR/comptes.bin" 2>/dev/null | wc -l)
        succes "$nb_comptes compte(s) configuré(s)"
    else
        erreur "Magasin des comptes manquant"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier les certificats
    if [ -f "$ETAT_DIR/tls/fullchain.pem" ] && [ -f "$ETAT_DIR/tls/privkey.pem" ]; then
        succes "Certificats TLS présents"
    else
        erreur "Certificats TLS manquants"
        erreurs=$((erreurs + 1))
    fi
    
    # Vérifier le DNS
    if [ -n "$GANDI_API_KEY" ]; then
        dit "Vérification du DNS..."
        bash "$SCRIPT_DIR/configurer-dns-gandi.sh" --verifier --api-key "$GANDI_API_KEY" || erreurs=$((erreurs + 1))
    else
        avertissement "Vérification DNS sautée (pas de clé API)"
    fi
    
    echo ""
    if [ "$erreurs" -eq 0 ]; then
        succes "Vérification terminée : tout est correct"
        return 0
    else
        erreur "Vérification terminée avec $erreurs erreur(s)"
        return 1
    fi
}

# ── Analyse des arguments ───────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --ipv4)
            IPV4="$2"
            shift 2
            ;;
        --ipv6)
            IPV6="$2"
            shift 2
            ;;
        --api-key)
            GANDI_API_KEY="$2"
            shift 2
            ;;
        --domaine)
            DOMAINE="$2"
            SOUS_DOMAINE="mail"
            DOMAINE_COMPLET="$SOUS_DOMAINE.$DOMAINE"
            shift 2
            ;;
        --sous-domaine)
            SOUS_DOMAINE="$2"
            DOMAINE_COMPLET="$SOUS_DOMAINE.$DOMAINE"
            shift 2
            ;;
        --comptes)
            COMPTES_LIST="$2"
            shift 2
            ;;
        --relais)
            RELAIS_HOST="$2"
            USE_RELAIS=1
            shift 2
            ;;
        --relais-user)
            RELAIS_USER="$2"
            shift 2
            ;;
        --relais-password)
            RELAIS_PASSWORD="$2"
            shift 2
            ;;
        --selecteur-dkim)
            SELECTEUR_DKIM="$2"
            shift 2
            ;;
        --deploy)
            MODE="deploy"
            shift
            ;;
        --verifier)
            MODE="verifier"
            shift
            ;;
        --nettoyer)
            MODE="nettoyer"
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --aide|-h)
            cat <<'AIDE'
Usage: deploy-air-desktop.sh [OPTIONS] [COMMANDE]

COMMANDES:
    --deploy       Déploiement complet (par défaut)
    --verifier     Vérifier le déploiement existant
    --nettoyer     Nettoyer le déploiement

OPTIONS:
    --ipv4 <adresse>         Adresse IPv4 du serveur
    --ipv6 <adresse>         Adresse IPv6 du serveur
    --api-key <clé>          Clé API Gandi pour la configuration DNS
    --domaine <domaine>      Domaine principal (défaut: air-desktop.org)
    --sous-domaine <sd>      Sous-domaine pour mail (défaut: mail)
    --comptes <liste>        Liste des comptes (séparés par des virgules)
    --relais <hôte>          Hôte du relais SMTP (active le relais)
    --relais-user <user>     Utilisateur du relais SMTP
    --relais-password <pass> Mot de passe du relais SMTP
    --selecteur-dkim <s>     Sélecteur DKIM (défaut: ams202610)
    --force                 Forcer sans confirmation
    --verbose, -v           Mode verbeux
    --aide, -h             Afficher cette aide

EXEMPLES:
    # Déploiement complet
    sudo bash deploy-air-desktop.sh \
        --ipv4 1.2.3.4 \
        --ipv6 2001:db8::1 \
        --api-key $GANDI_API_KEY \
        --comptes alice,bob,charlie

    # Déploiement avec relais
    sudo bash deploy-air-desktop.sh \
        --ipv4 1.2.3.4 \
        --ipv6 2001:db8::1 \
        --api-key $GANDI_API_KEY \
        --relais smtp.resend.com \
        --relais-user monuser \
        --relais-password monpassword

    # Vérification
    sudo bash deploy-air-desktop.sh --verifier

    # Nettoyage
    sudo bash deploy-air-desktop.sh --nettoyer
AIDE
            exit 0
            ;;
        *)
            erreur "Option inconnue : $1"
            exit 1
            ;;
    esac
done

# Si GANDI_API_KEY n'est pas passé en argument, essayer la variable d'environnement
[ -z "$GANDI_API_KEY" ] && GANDI_API_KEY="${GANDI_API_KEY:-}"

# ── Exécution ───────────────────────────────────────────────────────────────

case "$MODE" in
    deploy)
        # Afficher le résumé
        titre "Déploiement de air-mail-server pour $DOMAINE"
        echo ""
        echo "Configuration :"
        echo "  Domaine : $DOMAINE_COMPLET"
        echo "  IPv4 : $IPV4"
        echo "  IPv6 : $IPV6"
        echo "  Comptes : $COMPTES_LIST"
        echo "  Sélecteur DKIM : $SELECTEUR_DKIM"
        if [ "$USE_RELAIS" -eq 1 ]; then
            echo "  Relais : $RELAIS_HOST"
        else
            echo "  Relais : Aucun"
        fi
        echo ""
        
        # Demander confirmation
        demander_confirmation "Démarrer le déploiement ?" "n" || exit 0
        
        # Exécuter les étapes
        etape_verifications || exit 1
        etape_dependances_systeme || exit 1
        etape_construire_projet || exit 1
        etape_configurer_systeme || exit 1
        etape_configurer_dns || exit 1
        etape_configurer_serveur || exit 1
        etape_creer_comptes || exit 1
        etape_poser_secrets || exit 1
        etape_configurer_parefeu || exit 1
        etape_configurer_certificats || exit 1
        etape_activer_service || exit 1
        etape_verification || exit 1
        
        ;;
    verifier)
        etape_verifications || exit 1
        etape_verifier || exit 1
        ;;
    nettoyer)
        demander_confirmation "Voulez-vous vraiment nettoyer le déploiement ?" "n" || exit 0
        etape_nettoyer || exit 1
        ;;
    *)
        erreur "Mode inconnu : $MODE"
        exit 1
        ;;
esac

exit 0
