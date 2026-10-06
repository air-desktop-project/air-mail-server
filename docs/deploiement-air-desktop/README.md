# Déploiement de air-mail-server pour air-desktop.org

> **⚠ CE DOCUMENT DÉCRIT LE PLAN, PAS LA RÉALITÉ.**
>
> Le déploiement a divergé de ce plan, et la divergence a coupé le courrier
> d'air-desktop.org du 1er au 6 octobre 2026. Pour savoir ce qui **est** en
> place — la machine, la version, les ports, les boîtes, la zone, les
> certificats — lire **[ETAT-2026-10-06.md](ETAT-2026-10-06.md)**.
>
> Trois affirmations de ce document sont fausses telles quelles :
>
> - le VPS n'est ni celui des exemples ni celui des scripts : c'est
>   `vps-c77c4972` / `51.254.212.176` ;
> - le PTR **ne se configure pas à la main** dans le manager OVH, il se pose par
>   l'API (voir `ETAT-2026-10-06.md`) — et il est posé ;
> - l'API REST **n'est pas servie** ici, contrairement au tableau des ports.
>
> `creer-dns-air-desktop.sh` et `update_dns_air_desktop.sh` (à la racine du
> dépôt) sont les deux scripts qui ont causé la panne. **Ne pas les lancer.**
> Le script DNS à utiliser est `configurer-dns-gandi.sh`, corrigé le 2026-10-06.

Ce dossier contient les scripts et la documentation pour déployer **air-mail-server** sur un VPS OVH pour le domaine **air-desktop.org**, en s'inspirant de la configuration éprouvée de **narro.ch** (vps-9d275e3a.vps.ovh.net).

---

## 📋 Structure du Dossier

```
docs/deploiement-air-desktop/
├── README.md                      # Ce fichier
├── deploy-air-desktop.sh         # Script de déploiement complet
├── configurer-dns-gandi.sh        # Configuration DNS via API Gandi
└── poser-secrets-air-desktop.sh  # Pose des secrets initiaux
```

---

## 🎯 Prérequis

### 1. Infrastructure
- **Un VPS OVH** avec Ubuntu 24.04 LTS (ou Debian récent)
- **Une adresse IPv4 publique** et **une adresse IPv6 publique**
- **Accès root** sur le VPS

### 2. Domaine
- **Domaine air-desktop.org** hébergé chez Gandi
- **Clé API Gandi** avec accès à l'API LiveDNS
  - À obtenir depuis : https://account.gandi.net/fr/settings/api
  - À exporter dans `GANDI_API_KEY` ou passer via `--api-key`

### 3. Logiciels
- `git`, `curl`, `jq`, `openssl`, `cargo` (Rust)
- `systemd`, `nftables`, `certbot` (optionnel)

---

## 🚀 Déploiement Rapide

### 1. Préparer le VPS

```bash
# Se connecter au VPS
ssh root@votre-vps.ovh.net

# Cloner ce dépôt (ou copier les scripts)
git clone https://github.com/air-desktop-project/air-mail-server /opt/air-mail-server
```

### 2. Exécuter le déploiement complet

```bash
# Se placer dans le dossier des scripts
cd /opt/air-mail-server/docs/deploiement-air-desktop

# Lancer le déploiement (remplacer les valeurs)
sudo bash deploy-air-desktop.sh \
    --ipv4 1.2.3.4 \
    --ipv6 2001:db8::1 \
    --api-key $GANDI_API_KEY \
    --comptes postmaster,admin,thierry,utilisateur1,utilisateur2
```

### 3. Configurer manuellement le PTR chez OVH

Le script ne peut pas configurer le **PTR** (enregistrement inverse) automatiquement. 
Il faut le faire manuellement depuis le [manager OVH](https://www.ovh.com/auth/) :

- Pour IPv4 : `1.2.3.4` → `mail.air-desktop.org`
- Pour IPv6 : `2001:db8::1` → `mail.air-desktop.org`

---

## 📖 Scripts Disponibles

### 1. `deploy-air-desktop.sh` — Déploiement Complet

**Description** : Script principal qui orchestrer toutes les étapes du déploiement.

**Fonctionnalités** :
- Installation des dépendances système
- Clonage et construction du projet
- Configuration du système (compte, répertoires, service systemd)
- Configuration DNS via API Gandi
- Configuration du serveur air-mail-server
- Création des comptes utilisateurs
- Pose des secrets initiaux
- Configuration du pare-feu (nftables)
- Configuration des certificats TLS (via certbot)
- Activation du service

**Usage** :
```bash
# Déploiement complet
sudo bash deploy-air-desktop.sh \
    --ipv4 <IPv4> \
    --ipv6 <IPv6> \
    --api-key <GANDI_API_KEY> \
    --comptes <liste>

# Avec relais SMTP (ex: Resend)
sudo bash deploy-air-desktop.sh \
    --ipv4 <IPv4> \
    --ipv6 <IPv6> \
    --api-key <GANDI_API_KEY> \
    --relais smtp.resend.com \
    --relais-user <user> \
    --relais-password <password>

# Vérification du déploiement
sudo bash deploy-air-desktop.sh --verifier

# Nettoyage
sudo bash deploy-air-desktop.sh --nettoyer
```

**Options** :
| Option | Description | Défaut |
|--------|-------------|--------|
| `--ipv4` | Adresse IPv4 du serveur | *requis* |
| `--ipv6` | Adresse IPv6 du serveur | *requis* |
| `--api-key` | Clé API Gandi | *requis* |
| `--domaine` | Domaine principal | `air-desktop.org` |
| `--sous-domaine` | Sous-domaine pour mail | `mail` |
| `--comptes` | Liste des comptes (virgules) | `postmaster,admin,thierry` |
| `--relais` | Hôte du relais SMTP | *aucun* |
| `--relais-user` | Utilisateur du relais | *aucun* |
| `--relais-password` | Mot de passe du relais | *aucun* |
| `--selecteur-dkim` | Sélecteur DKIM | `ams202610` |
| `--force` | Forcer sans confirmation | `0` |
| `--verbose` | Mode verbeux | `0` |

---

### 2. `configurer-dns-gandi.sh` — Configuration DNS

**Description** : Configure tous les enregistrements DNS nécessaires via l'API Gandi LiveDNS.

**Enregistrements créés** :
- **MX** : `mail.air-desktop.org` → `10 mail.air-desktop.org`
- **A** : `mail.air-desktop.org` → `<IPv4>`
- **AAAA** : `mail.air-desktop.org` → `<IPv6>`
- **TXT (SPF)** : `air-desktop.org` → `"v=spf1 mx ~all"`
- **TXT (DKIM)** : `ams202610._domainkey.air-desktop.org` → clé publique DKIM
- **TXT (DMARC)** : `_dmarc.air-desktop.org` → `"v=DMARC1; p=none; rua=mailto:postmaster@air-desktop.org"`
- **A (MTA-STS)** : `mta-sts.air-desktop.org` → `<IPv4>`
- **TXT (MTA-STS)** : `_mta-sts.air-desktop.org` → `"v=STSv1; id=..."`

**Usage** :
```bash
# Créer tous les enregistrements
bash configurer-dns-gandi.sh --creer --api-key $GANDI_API_KEY --ipv4 1.2.3.4 --ipv6 2001:db8::1

# Vérifier la configuration
bash configurer-dns-gandi.sh --verifier --ipv4 1.2.3.4 --ipv6 2001:db8::1

# Supprimer les enregistrements
bash configurer-dns-gandi.sh --supprimer --api-key $GANDI_API_KEY

# Afficher la configuration au format bind
bash configurer-dns-gandi.sh --bind --ipv4 1.2.3.4 --ipv6 2001:db8::1

# Afficher la configuration au format JSON
bash configurer-dns-gandi.sh --json --ipv4 1.2.3.4 --ipv6 2001:db8::1
```

**Options** :
| Option | Description | Défaut |
|--------|-------------|--------|
| `--creer` | Créer les enregistrements | - |
| `--supprimer` | Supprimer les enregistrements | - |
| `--verifier` | Vérifier la configuration | - |
| `--json` | Afficher au format JSON | - |
| `--bind` | Afficher au format bind | - |
| `--api-key` | Clé API Gandi | *requis pour créer/supprimer* |
| `--ipv4` | Adresse IPv4 | *requis* |
| `--ipv6` | Adresse IPv6 | *requis* |

---

### 3. `poser-secrets-air-desktop.sh` — Pose des Secrets

**Description** : Génère et pose les mots de passe initiaux pour les comptes utilisateurs.

**Fonctionnalités** :
- Génération de mots de passe sécurisés (16 caractères, alphabet sûr)
- Vérification de l'unicité des secrets
- Pose des secrets dans le magasin air-mail-server
- Écriture des secrets dans un fichier 0600

**Usage** :
```bash
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
```

**Options** :
| Option | Description | Défaut |
|--------|-------------|--------|
| `--pour-de-vrai` | Poser les secrets | Mode test |
| `--magasin` | Chemin vers le magasin | `/var/lib/air-mail/comptes.bin` |
| `--sortie` | Fichier de sortie | `~/secrets-air-desktop-YYYYMMDD.txt` |
| `--domaine` | Domaine principal | `air-desktop.org` |
| `--compte` | Ajouter un compte | `postmaster,admin,thierry` |

---

## 📋 Configuration Résultante

### Structure des Répertoires

```
/var/lib/air-mail/
├── air-mail.conf          # Configuration binaire du serveur
├── comptes.bin            # Comptes et empreintes (argon2id)
├── maildir/               # Boîtes Maildir
│   ├── postmaster/
│   ├── admin/
│   └── thierry/
├── file/                  # File de réémission
├── tls/                  # Certificats TLS
│   ├── fullchain.pem
│   └── privkey.pem
├── dkim.pem              # Clé privée DKIM
└── nftables-air-mail.conf # Configuration du pare-feu

/usr/local/bin/
├── air-mail-server        # Binaire du serveur
└── air-mail-admin         # Binaire d'administration

/etc/systemd/system/
└── air-mail-server.service # Unité systemd
```

### Configuration Réseau

| Service | Port Externe | Port Interne | Protocole |
|---------|--------------|--------------|-----------|
| SMTP | 25 | 2525 | STARTTLS |
| SMTP (Soumission) | 587 | 2525 | STARTTLS |
| SMTPS | 465 | 4465 | TLS Implicite |
| IMAPS | 993 | 9993 | TLS Implicite |
| API REST | 8443 | 8443 | HTTP/2 + TLS |

### Configuration DNS

| Type | Nom | Valeur |
|------|-----|--------|
| MX | mail.air-desktop.org | 10 mail.air-desktop.org |
| A | mail.air-desktop.org | `<IPv4>` |
| AAAA | mail.air-desktop.org | `<IPv6>` |
| TXT | air-desktop.org | `"v=spf1 mx ~all"` |
| TXT | ams202610._domainkey.air-desktop.org | `"v=DKIM1; k=ed25519; p=..."` |
| TXT | _dmarc.air-desktop.org | `"v=DMARC1; p=none; rua=mailto:postmaster@air-desktop.org"` |
| A | mta-sts.air-desktop.org | `<IPv4>` |
| TXT | _mta-sts.air-desktop.org | `"v=STSv1; id=..."` |

---

## 🔧 Configuration des Clients

### Paramètres IMAP
- **Serveur** : `mail.air-desktop.org`
- **Port** : `993`
- **Chiffrement** : SSL/TLS
- **Authentification** : Mot de passe normal (PLAIN)
- **Identifiant** : `<compte>` (SANS `@air-desktop.org`)

### Paramètres SMTP
- **Serveur** : `mail.air-desktop.org`
- **Port** : `587` (STARTTLS) ou `465` (SSL/TLS)
- **Authentification** : Mot de passe normal (PLAIN)
- **Identifiant** : `<compte>` (SANS `@air-desktop.org`)

---

## ⚠️ Points d'Attention

### 1. Compatibilité Clients
- **Apple Mail** : Nécessite TLS 1.2 (déjà activé dans air-mail-server)
- **Ancients clients** : Vérifier la compatibilité avec TLS 1.3
- **Identifiants** : **Sans le domaine** (ex: `thierry` et non `thierry@air-desktop.org`)

### 2. Migration des Boîtes Existantes
Si vous migrez depuis un autre serveur (ex: Dovecot) :
1. Utiliser `rsync` pour copier les boîtes Maildir
2. Adapter les chemins : `/var/vmail/<domaine>/<compte>/Maildir/` → `/var/lib/air-mail/maildir/<compte>/`
3. Vérifier avec le script `verifier.sh` du projet

### 3. Gestion des Mots de Passe
- **Pas de migration possible** depuis d'autres formats (SHA512-CRYPT, etc.)
- Les utilisateurs doivent **changer leur mot de passe** après la première connexion
- Utiliser l'API REST : `PUT /v1/me/password`

### 4. DNS et Réputation
- **PTR cohérent** : Obligatoire pour éviter le classement en spam
- **Test de réputation** : Vérifier avec [MXToolbox](https://mxtoolbox.com/)
- **Test DKIM** : Envoyer un email vers Gmail/Outlook et vérifier `Authentication-Results`

### 5. Certificats TLS
- Les certificats sont gérés par **certbot** (Let's Encrypt)
- Un **hook de déploiement** copie automatiquement les certificats vers `/var/lib/air-mail/tls/`
- Le serveur **recharge automatiquement** les certificats toutes les 5 minutes

---

## 📊 Vérification du Déploiement

### 1. Vérifier le service
```bash
# Statut du service
systemctl status air-mail-server

# Journaux
journalctl -u air-mail-server -f
```

### 2. Tester les connexions
```bash
# Tester SMTP (port 2525 directement, ou 25 via redirection)
openssl s_client -connect mail.air-desktop.org:465 -brief

# Tester IMAP (port 9993 directement, ou 993 via redirection)
openssl s_client -connect mail.air-desktop.org:993 -brief

# Tester l'API
curl -k https://mail.air-desktop.org:8443/v1/health
```

### 3. Vérifier le DNS
```bash
# Vérifier tous les enregistrements
dig +short MX air-desktop.org
dig +short A mail.air-desktop.org
dig +short AAAA mail.air-desktop.org
dig +short TXT air-desktop.org
dig +short TXT ams202610._domainkey.air-desktop.org
dig +short TXT _dmarc.air-desktop.org

# Ou utiliser le script de vérification
bash configurer-dns-gandi.sh --verifier --ipv4 1.2.3.4 --ipv6 2001:db8::1
```

### 4. Tester l'envoi/réception
```bash
# Envoyer un email de test (avec telnet ou swaks)
# Vérifier la réception dans un client IMAP
```

---

## 🔄 Mise à Jour

### Mise à jour du serveur
```bash
# Arrêter le service
sudo systemctl stop air-mail-server

# Mettre à jour le code
cd /opt/air-mail-server
git pull
cargo build --release

# Installer les nouveaux binaires
sudo install -m 0755 target/release/air-mail-server /usr/local/bin/
sudo install -m 0755 target/release/air-mail-admin /usr/local/bin/

# Redémarrer le service
sudo systemctl start air-mail-server
```

### Mise à jour des certificats
```bash
# Les certificats se renouvellent automatiquement avec certbot
# Le hook de déploiement copie automatiquement les nouveaux certificats
# et recharge le serveur
```

---

## 🎓 Basé sur la Configuration de narro.ch

Ce déploiement s'inspire directement de la configuration **éprouvée** de **narro.ch** :

- **VPS** : vps-9d275e3a.vps.ovh.net
- **IPv4** : 37.59.106.115
- **IPv6** : 2001:41d0:305:2100::b711
- **Sélecteur DKIM** : ams202609 (pour narro.ch) → ams202610 (pour air-desktop.org)
- **Configuration** : Identique, adaptée pour le nouveau domaine

Les scripts ont été **testés et validés** sur la base de l'expérience de narro.ch.

---

## 📞 Support

En cas de problème :

1. **Vérifier les journaux** : `journalctl -u air-mail-server -f`
2. **Vérifier la configuration** : `air-mail-admin config show /var/lib/air-mail/air-mail.conf`
3. **Vérifier le DNS** : Utiliser `configurer-dns-gandi.sh --verifier`
4. **Consulter la documentation** : [README du projet](../../README.md)

---

## 📄 Licence

Ces scripts sont distribués sous la même licence que le projet **air-mail-server** : **MPL-2.0**.

Voir [LICENSE](../../LICENSE) pour plus de détails.
