#!/usr/bin/env bash
#
# inventaire.sh — ce qu'il faut savoir d'un MX Postfix + Dovecot avant de le
# remplacer par air-mail-server.
#
# # IL NE MODIFIE RIEN, ET NE DIVULGUE AUCUN SECRET
#
# Aucune commande d'écriture, aucun redémarrage, aucun `doveadm` qui touche une
# boîte. Les empreintes de mots de passe ne sont PAS recopiées — seul le nom du
# SCHÉMA l'est (`{SHA512-CRYPT}`, `{BLF-CRYPT}`, …), qui est ce dont dépend la
# migration. Les clés privées ne sont jamais lues : on n'imprime que le chemin
# et les permissions.
#
# Lisez sa sortie avant de la transmettre : c'est un inventaire de votre
# serveur de courrier, et il nomme vos comptes.
#
# USAGE
#     sudo bash inventaire.sh > inventaire-$(hostname)-$(date +%F).txt

set -uo pipefail

titre() {
    printf '\n══════════════════════════════════════════════════════════════\n'
    printf '  %s\n' "$1"
    printf '══════════════════════════════════════════════════════════════\n'
}

absent() { printf '  (absent : %s)\n' "$1"; }

essayer() {
    # Lance une commande, ou dit poliment qu'elle n'existe pas.
    if command -v "$1" > /dev/null 2>&1; then
        "$@" 2>&1
    else
        absent "$1"
    fi
}

titre "0. La machine"
echo "date       : $(date -Is)"
echo "hôte       : $(hostname -f 2>/dev/null || hostname)"
essayer lsb_release -ds
uname -srm
echo "espace libre sur / et sur le stockage du courrier :"
df -h / /var /home 2>/dev/null | sort -u

titre "1. Ce qui écoute, et ce qui tourne"
essayer ss -lntp
echo
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    | grep -iE 'postfix|dovecot|opendkim|rspamd|spamassassin|amavis|clamav|redis|mysql|maria|postgres|nginx|apache|certbot' \
    || echo "  (aucun service de courrier reconnu dans les services actifs)"

titre "2. Postfix — la configuration qui n'est PAS le défaut"
essayer postconf -n
titre "2b. Postfix — les services de master.cf"
essayer postconf -M
titre "2c. Postfix — la file d'attente"
essayer postqueue -p | tail -5

titre "3. Les tables de Postfix (domaines, alias, boîtes)"
# On imprime le CONTENU des tables : c'est ce qu'il faut recréer.
for cle in virtual_alias_maps virtual_mailbox_maps virtual_mailbox_domains \
           alias_maps mydestination relay_domains transport_maps; do
    valeur=$(postconf -h "$cle" 2>/dev/null)
    [ -z "$valeur" ] && continue
    printf '\n── %s = %s\n' "$cle" "$valeur"
    # Chaque table peut être `hash:/chemin`, `texthash:…`, `mysql:…`, etc.
    for morceau in $valeur; do
        chemin=${morceau#*:}
        case "$morceau" in
            hash:*|texthash:*|cidr:*|regexp:*|pcre:*|lmdb:*|btree:*)
                if [ -r "$chemin" ]; then
                    printf '   contenu de %s :\n' "$chemin"
                    grep -vE '^\s*(#|$)' "$chemin" | sed 's/^/     /'
                else
                    printf '   %s : illisible\n' "$chemin"
                fi
                ;;
            mysql:*|pgsql:*|ldap:*|sqlite:*)
                printf '   %s : base de données — la requête est dans %s\n' "$morceau" "$chemin"
                if [ -r "$chemin" ]; then
                    # On masque le mot de passe de la base.
                    grep -vE '^\s*(#|$)' "$chemin" \
                        | sed -E 's/^(password[[:space:]]*=).*/\1 «masqué»/I' | sed 's/^/     /'
                fi
                ;;
        esac
    done
done

titre "4. Dovecot — la configuration qui n'est PAS le défaut"
essayer doveconf -n

titre "5. Dovecot — LE FORMAT DES BOÎTES, qui décide de tout"
echo "mail_location : $(doveconf -h mail_location 2>/dev/null || echo '(inconnu)')"
echo "mail_home     : $(doveconf -h mail_home 2>/dev/null || echo '(inconnu)')"
echo "mail_plugins  : $(doveconf -h mail_plugins 2>/dev/null || echo '(inconnu)')"
echo
# Les accents graves seraient des SUBSTITUTIONS DE COMMANDE entre guillemets
# doubles : `bash -n` les accepte, et le script exécuterait `maildirfolder`.
echo 'Ce que le disque montre — maildirfolder / cur / new / tmp disent Maildir,'
echo 'dovecot.map.index ou m.1 disent mdbox, dbox-Mails dit sdbox :'
for racine in /var/mail /var/vmail /var/spool/mail /home/vmail /srv/vmail /var/mail/vhosts; do
    [ -d "$racine" ] || continue
    printf '\n  %s :\n' "$racine"
    find "$racine" -maxdepth 4 \
        \( -name cur -o -name new -o -name 'dovecot.map.index*' -o -name 'dbox-Mails' \
           -o -name 'maildirfolder' -o -name 'dovecot-uidlist' \) \
        -printf '    %y %p\n' 2>/dev/null | head -25
done

titre "6. Les comptes, et LE SCHÉMA de leurs empreintes"
echo "ATTENTION : aucune empreinte n'est imprimée. Seul le schéma l'est."
echo "default_pass_scheme : $(doveconf -h auth_default_pass_scheme 2>/dev/null || echo '(non défini)')"
echo
for base in /etc/dovecot/users /etc/dovecot/passwd /etc/dovecot/passwd.db \
            /etc/dovecot/users.db /etc/dovecot/private/passwd; do
    [ -r "$base" ] || continue
    printf '\n  %s — %s ligne(s) :\n' "$base" "$(grep -cvE '^\s*(#|$)' "$base")"
    # login:{SCHÉMA}empreinte:… → on garde le login et le schéma, rien d'autre.
    grep -vE '^\s*(#|$)' "$base" \
        | awk -F: '{
            schema = "(sans préfixe — c'"'"'est alors default_pass_scheme)";
            if (match($2, /^\{[A-Za-z0-9.-]+\}/)) schema = substr($2, RSTART, RLENGTH);
            printf "    %-32s %s\n", $1, schema;
          }'
done

titre "6b. Les boîtes vues par Dovecot"
essayer doveadm user '*' 2>/dev/null | head -60
echo
echo "── Nombre de messages et taille, par compte ──"
essayer doveadm -f table quota get -A 2>/dev/null | head -60

titre "7. Les dossiers IMAP de chaque compte"
essayer doveadm -f table mailbox list -A 2>/dev/null | head -120

titre "8. TLS — les certificats, sans les clés"
for cle in smtpd_tls_cert_file smtpd_tls_key_file smtpd_tls_chain_files \
           smtpd_tls_CAfile smtp_tls_CAfile; do
    valeur=$(postconf -h "$cle" 2>/dev/null)
    [ -n "$valeur" ] && printf '  postfix %-24s = %s\n' "$cle" "$valeur"
done
for cle in ssl_cert ssl_key ssl_ca; do
    valeur=$(doveconf -h "$cle" 2>/dev/null)
    [ -n "$valeur" ] && printf '  dovecot %-24s = %s\n' "$cle" "$valeur"
done
echo
echo "── Ce que les certificats contiennent ──"
for chemin in $(postconf -h smtpd_tls_cert_file 2>/dev/null) \
              $(doveconf -h ssl_cert 2>/dev/null | tr -d '<') \
              /etc/letsencrypt/live/*/fullchain.pem; do
    [ -r "$chemin" ] || continue
    printf '\n  %s\n' "$chemin"
    ls -l "$chemin" | sed 's/^/    /'
    openssl x509 -in "$chemin" -noout -subject -issuer -dates \
        -ext subjectAltName 2>/dev/null | sed 's/^/    /'
done
echo
echo "── Les clés privées : chemin et PERMISSIONS seulement ──"
for chemin in $(postconf -h smtpd_tls_key_file 2>/dev/null) \
              $(doveconf -h ssl_key 2>/dev/null | tr -d '<') \
              /etc/letsencrypt/live/*/privkey.pem; do
    [ -e "$chemin" ] && ls -lL "$chemin" 2>/dev/null | sed 's/^/    /'
done
echo
echo "── Renouvellement automatique ──"
essayer systemctl list-timers --no-pager --no-legend 2>/dev/null | grep -i certbot
ls -l /etc/letsencrypt/renewal/ 2>/dev/null | sed 's/^/    /'

titre "9. DKIM, et ce qui signe"
essayer opendkim-testkey -v 2>&1 | head -5
for f in /etc/opendkim.conf /etc/opendkim/KeyTable /etc/opendkim/SigningTable /etc/opendkim/TrustedHosts; do
    [ -r "$f" ] && { printf '\n  %s :\n' "$f"; grep -vE '^\s*(#|$)' "$f" | sed 's/^/    /'; }
done
echo
echo "  Clés DKIM (chemin et permissions, jamais le contenu) :"
find /etc/opendkim /etc/dkimkeys /var/db/dkim -name '*.private' -o -name '*.key' 2>/dev/null \
    | while read -r k; do ls -l "$k" | sed 's/^/    /'; done

titre "10. Ce qui filtre — et qu'air-mail-server ne sait PAS reprendre"
echo "── Milters déclarés ──"
postconf -h smtpd_milters non_smtpd_milters 2>/dev/null | sed 's/^/    /'
echo "── Sieve ──"
echo "  plugins : $(doveconf -h mail_plugins 2>/dev/null)"
echo "  protocol lda/lmtp mail_plugins : $(doveconf -h protocol/lda/mail_plugins 2>/dev/null) $(doveconf -h protocol/lmtp/mail_plugins 2>/dev/null)"
echo "  sieve_dir : $(doveconf -h plugin/sieve 2>/dev/null)"
echo "  scripts trouvés :"
find /var/vmail /home/vmail /var/mail -maxdepth 4 -name '*.sieve' 2>/dev/null | head -20 | sed 's/^/    /'
echo "── Quotas ──"
echo "  quota : $(doveconf -h plugin/quota 2>/dev/null) $(doveconf -h plugin/quota_rule 2>/dev/null)"

titre "11. Volumétrie du courrier"
for racine in /var/mail /var/vmail /var/spool/mail /home/vmail /srv/vmail; do
    [ -d "$racine" ] || continue
    printf '  %s : %s\n' "$racine" "$(du -sh "$racine" 2>/dev/null | cut -f1)"
    printf '    fichiers : %s\n' "$(find "$racine" -type f 2>/dev/null | wc -l)"
    printf '    par compte :\n'
    du -sh "$racine"/* 2>/dev/null | sort -h | tail -30 | sed 's/^/      /'
done

titre "12. Sauvegardes existantes"
essayer systemctl list-timers --no-pager --no-legend 2>/dev/null | head -20
ls -la /etc/cron.d/ 2>/dev/null | sed 's/^/    /'

titre "FIN"
echo "Relisez ce fichier avant de le transmettre : il nomme vos comptes."
