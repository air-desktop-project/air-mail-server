#!/usr/bin/env bash
#
# repetition-generale.sh — LA SÉQUENCE ENTIÈRE, JOUÉE D'UN BOUT À L'AUTRE.
#
# Monte un magasin de forme DOVECOT — celle que `mail.narro.ch` porte
# réellement —, déroule les phases 0.4 à 1 de `bascule.md`, puis vérifie que le
# serveur SERT ce que Dovecot rangeait. Il finit par le retour en arrière.
#
# Il ne touche à rien d'autre qu'un répertoire jetable.
#
#     bash docs/migration/repetition-generale.sh
#
# ── POURQUOI ELLE EXISTE ────────────────────────────────────────────────────
#
# Chaque pièce de cette migration a désormais son banc : la commande du manuel,
# le décodeur de noms de dossiers, le retour en arrière, l'audit. Leur
# ENCHAÎNEMENT, lui, n'avait jamais été joué.
#
# Or c'est là que les quatre défauts du manuel se logeaient : le `rsync` de
# racine à racine, le retour en arrière qui dupliquait, le vérificateur qui
# coûtait quatre minutes, le résolveur sans port. Aucun ne vivait DANS une
# pièce ; tous vivaient entre deux.
set -uo pipefail
export LC_ALL=C

racine=$(cd "$(dirname "$0")/../.." && pwd)
banc=$(mktemp -d) || exit 1
comptes=(contact thierry.delhaise vincent.delhaise support kelly.garro ofrou-sierre)
# **UNE BOÎTE SANS SOUS-DOSSIER, ET C'EST UN CAS À PART ENTIÈRE.**
# `ofrou-sierre` est la passerelle Milesight : une `INBOX`, rien d'autre, aucun
# abonnement. Elle ne reçoit donc ni traduction de noms, ni rôles — et la
# séquence doit tenir avec elle, puisque la machine la porte depuis le
# 2026-09-15. Toutes les boucles ci-dessous la sautent là où un sous-dossier est
# attendu ; aucune ne la saute là où un message l'est.
machines=(ofrou-sierre)
est_une_machine() {
    local nom
    for nom in "${machines[@]}"; do [ "$nom" = "$1" ] && return 0; done
    return 1
}
fautes=0
port_imap=9996
port_smtp=2527

nettoyer() {
    [ -n "${pid_serveur-}" ] && kill "$pid_serveur" 2>/dev/null
    rm -rf "$banc"
}
trap nettoyer EXIT

rate() { echo "ÉCHEC : $*" >&2; fautes=$((fautes + 1)); }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((68 - ${#1}))))"; }

for binaire in air-mail-server air-mail-admin; do
    [ -x "$racine/target/release/$binaire" ] || {
        echo "ÉCHEC : \`target/release/$binaire\` manque (\`cargo build --release\`)." >&2
        exit 1
    }
done

# ── LE MAGASIN DE DÉPART, DE FORME DOVECOT ──────────────────────────────────
#
# `mail_location = maildir:/var/vmail/%d/%n/Maildir`, ce que l'inventaire a
# relevé. Les dossiers y sont en UTF-7 MODIFIÉ, et les abonnements dans un
# fichier `subscriptions` à séparateur `.`.
titre "0. un magasin de forme Dovecot"
ancien="$banc/vmail"
numero=0
poser() { # <chemin-boîte> <sous> <drapeaux>
    numero=$((numero + 1))
    mkdir -p "$1/$2"
    printf 'From: anne@exemple.test\r\nSubject: message %d\r\n\r\ncorps\r\n' "$numero" \
        > "$1/$2/17250000$numero.M1.dovecot,S=64,W=66${3-}"
}
for compte in "${comptes[@]}"; do
    boite="$ancien/narro.ch/$compte/Maildir"
    mkdir -p "$boite"/{cur,new,tmp}
    poser "$boite" cur ":2,S"      # lu
    poser "$boite" cur ":2,RS"     # lu ET répondu
    poser "$boite" new ""          # non lu
    # La passerelle s'arrête là : une `INBOX`, et pas un dossier de plus. C'est
    # exactement ce que `/var/vmail/narro.ch/ofrou-sierre` porte sur la machine.
    est_une_machine "$compte" && continue
    # `.&AMk-t&AOk--2025` est `Été-2025` : le cas courant d'un domaine
    # francophone, et celui que `renommer-dossiers.py` traduit.
    for dossier in .Sent .Drafts '.&AMk-t&AOk--2025'; do
        mkdir -p "$boite/$dossier"/{cur,new,tmp}
        poser "$boite/$dossier" cur ":2,S"
    done
    printf '.Sent\n.Drafts\n.&AMk-t&AOk--2025\n' > "$boite/subscriptions"
done
attendus=$numero
echo "OK — ${#comptes[@]} comptes, $attendus messages, dossiers en UTF-7 modifié"

# ── PHASE 0.4 : LA COPIE, COMPTE PAR COMPTE ─────────────────────────────────
#
# **PAS DE RACINE À RACINE.** Dovecot range `<racine>/<domaine>/<compte>/Maildir`
# et air-mail-server attend `<racine>/<compte>` : un `rsync` de racine à racine
# donnerait une arborescence où le serveur ne trouverait AUCUNE boîte — et il
# démarrerait sans rien dire.
titre "0.4 la copie, compte par compte"
neuf="$banc/vmail-ams"
mkdir -p "$neuf"
for compte in "${comptes[@]}"; do
    rsync -aH --delete "$ancien/narro.ch/$compte/Maildir/" "$neuf/$compte/" || {
        rate "la copie de $compte a échoué"; break; }
done
copies=$(find "$neuf" -type f \( -path '*/cur/*' -o -path '*/new/*' \) | wc -l)
[ "$copies" -eq "$attendus" ] || rate "$attendus messages copiés attendus, $copies trouvés"
echo "OK — $copies messages, $(find "$neuf" -mindepth 1 -maxdepth 1 -type d | wc -l) boîtes"

# ── PHASE 0.4bis : LES NOMS DE DOSSIERS, ET LES ABONNEMENTS ─────────────────
titre "0.4bis les noms de dossiers"
python3 "$racine/docs/migration/renommer-dossiers.py" --essais > /dev/null \
    || rate "le décodeur d'UTF-7 modifié ne passe pas ses propres essais"
python3 "$racine/docs/migration/renommer-dossiers.py" "$neuf" --pour-de-vrai > /dev/null \
    || rate "la traduction des dossiers a échoué"
for compte in "${comptes[@]}"; do
    if est_une_machine "$compte"; then
        # **RIEN À TRADUIRE N'EST PAS UNE ERREUR, ET NE DOIT RIEN INVENTER.**
        # Un `ams-abonnements` posé sur une boîte qui n'a aucun abonnement
        # ferait rendre `LSUB` vide à un client réglé pour n'afficher que les
        # dossiers abonnés — il ne verrait plus sa propre `INBOX`.
        [ -e "$neuf/$compte/ams-abonnements" ] \
            && rate "$compte : un fichier d'abonnements est apparu là où il n'y en a aucun"
        continue
    fi
    [ -d "$neuf/$compte/.Été-2025" ] \
        || rate "$compte : \`.Été-2025\` n'a pas été traduit"
    [ -d "$neuf/$compte/.&AMk-t&AOk--2025" ] \
        && rate "$compte : le nom encodé est resté"
    [ -f "$neuf/$compte/ams-abonnements" ] \
        || rate "$compte : les abonnements n'ont pas été traduits"
done
echo "OK — dossiers en UTF-8, abonnements en \`ams-abonnements\`"

# ── PHASE 0.4bis-2 : LES RÔLES, ET CE QUE LE DELTA LEUR FAIT ────────────────
#
# **CETTE ÉTAPE N'ÉTAIT PAS JOUÉE, ET C'EST POURQUOI LE DÉFAUT A TENU.** Le
# manuel posait `ams-usages` en §0.4bis-2 et le delta de l'étape 3 l'effaçait :
# `rsync --delete` synchronise `Maildir/` SUR LA RACINE DU COMPTE, où ce fichier
# vit, et il n'a aucun équivalent côté Dovecot — donc il est surnuméraire, donc
# il saute. Le manuel avait vu le cas pour les noms de dossiers (étape 3bis) et
# pas pour les rôles. Trouvé le 2026-09-21 ; l'étape 3ter le répare, et ce banc
# l'éprouve des deux côtés : posé en 0.4bis-2, EFFACÉ par le delta, REPOSÉ par
# 3ter.
titre "0.4bis-2 les rôles de dossiers"
poser_les_roles() {
    for compte in "${comptes[@]}"; do
        est_une_machine "$compte" && continue
        printf '\\Archive\tArchive\n\\Drafts\tDrafts\n\\Junk\tJunk\n\\Sent\tSent\n\\Trash\tTrash\n' \
            > "$neuf/$compte/ams-usages"
        chmod 600 "$neuf/$compte/ams-usages"
    done
}
poser_les_roles
for compte in "${comptes[@]}"; do
    if est_une_machine "$compte"; then
        # **UN RÔLE NE SE POSE QUE SUR UN DOSSIER QUI EXISTE.** Sinon le jour où
        # un client voudra créer son `Sent`, le serveur le refusera par
        # `UsageDejaPris` (RFC 6154 §3) — un refus incompréhensible pour qui
        # n'a jamais vu ce fichier.
        [ -e "$neuf/$compte/ams-usages" ] \
            && rate "$compte : des rôles posés sur une boîte qui n'a aucun dossier"
        continue
    fi
    [ -f "$neuf/$compte/ams-usages" ] || rate "$compte : les rôles ne sont pas posés"
done
echo "OK — rôles posés sur $((${#comptes[@]} - ${#machines[@]})) boîtes, aucune sur la passerelle"

# ── PHASE 0.5 : L'AUDIT QUI DÉCIDE ──────────────────────────────────────────
#
# Il compare le neuf à une VUE de l'ancien, qui a la même forme : sans elle il
# comparerait deux arborescences différentes et trouverait zéro des deux côtés.
titre "0.5 l'audit qui décide"
bash "$racine/docs/migration/verifier.sh" --essais > /dev/null \
    || rate "l'audit ne passe pas ses propres essais"
vue="$banc/vmail-vue"
mkdir -p "$vue"
for compte in "${comptes[@]}"; do
    ln -sfn "$ancien/narro.ch/$compte/Maildir" "$vue/$compte"
done
if bash "$racine/docs/migration/verifier.sh" "$neuf" "$vue" > "$banc/audit.txt" 2>&1; then
    echo "OK — l'audit accepte la copie"
else
    rate "l'audit REFUSE la copie :"
    sed 's/^/       /' "$banc/audit.txt" >&2
fi

# ── LA CONFIGURATION, TIRÉE DU MANUEL LUI-MÊME ──────────────────────────────
titre "0.4 la configuration"
bash "$racine/docs/migration/repeter-la-configuration.sh" > "$banc/config.txt" 2>&1 \
    || { rate "la commande de \`bascule.md\` est refusée :"; tail -3 "$banc/config.txt" >&2; }
echo "OK — la commande du manuel est acceptée"

# ── PHASE 0.6 : LE SERVEUR SERT-IL CE QUE DOVECOT RANGEAIT ? ────────────────
titre "0.6 éprouver la copie, pour de bon"
openssl req -x509 -newkey rsa:2048 -keyout "$banc/cle.pem" -out "$banc/cert.pem" \
    -days 2 -nodes -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1 \
    || { echo "ÉCHEC : openssl." >&2; exit 1; }
for compte in "${comptes[@]}"; do
    printf %s 'ouvre-toi' | "$racine/target/release/air-mail-admin" account add \
        "$banc/comptes.bin" --login "$compte" --address "$compte@narro.ch" >/dev/null \
        || rate "le compte $compte ne s'écrit pas"
done
chmod 600 "$banc/comptes.bin"
"$racine/target/release/air-mail-admin" config write "$banc/ams.conf" \
    --domain mail.narro.ch --hosted narro.ch \
    --maildir "$neuf" --accounts "$banc/comptes.bin" \
    --listen "127.0.0.1:$port_smtp" --listen-imaps "127.0.0.1:$port_imap" \
    --tls-cert "$banc/cert.pem" --tls-key "$banc/cle.pem" \
    --require-fqdn-helo --require-fqdn-sender --require-fqdn-recipient >/dev/null \
    || rate "la configuration du banc ne s'écrit pas"

"$racine/target/release/air-mail-server" --config "$banc/ams.conf" > "$banc/serveur.log" 2>&1 &
pid_serveur=$!
sleep 2
grep -q 'IMAP écoute' "$banc/serveur.log" || {
    rate "le serveur n'a pas ouvert l'IMAP :"
    sed 's/^/       /' "$banc/serveur.log" >&2
}

python3 - "$port_imap" "$attendus" "${machines[*]}" "${comptes[@]}" <<'IMAP'
import base64, socket, ssl, sys

port, attendus = int(sys.argv[1]), int(sys.argv[2])
machines, comptes = set(sys.argv[3].split()), sys.argv[4:]
contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
contexte.check_hostname = False
contexte.verify_mode = ssl.CERT_NONE
fautes = 0

def session(compte):
    prise = contexte.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                                 server_hostname="localhost")
    fichier = prise.makefile("rwb")
    fichier.readline()
    return prise, fichier

def dire(fichier, etiquette, commande):
    fichier.write(f"{etiquette} {commande}\r\n".encode()); fichier.flush()
    lignes = []
    while True:
        ligne = fichier.readline()
        if not ligne:
            break
        lignes.append(ligne.decode("utf-8", "replace").rstrip())
        if lignes[-1].startswith(f"{etiquette} "):
            break
    return lignes

vus = 0
for compte in comptes:
    prise, fichier = session(compte)
    jeton = base64.b64encode(f"\0{compte}\0ouvre-toi".encode()).decode()
    if " OK " not in dire(fichier, "a1", f"AUTHENTICATE PLAIN {jeton}")[-1]:
        print(f"FAUTE : {compte} ne se connecte pas", file=sys.stderr); fautes += 1; continue
    # **LES DOSSIERS, EN UTF-7 MODIFIÉ SUR LE FIL** — c'est ce qu'IMAP exige, et
    # ce que le client retraduira pour l'afficher.
    liste = dire(fichier, "a2", 'LIST "" "*"')
    # La passerelle n'a qu'une `INBOX` : lui demander un `Sent` serait exiger du
    # banc ce que la machine ne porte pas.
    dossiers = ("INBOX",) if compte in machines \
        else ("INBOX", "Sent", "Drafts", "&AMk-t&AOk--2025")
    for attendu in dossiers:
        if not any(f'"{attendu}"' in l for l in liste):
            print(f"FAUTE : {compte} — dossier {attendu} absent de LIST",
                  file=sys.stderr)
            fautes += 1
    for boite in dossiers:
        select = dire(fichier, "a3", f'SELECT "{boite}"')
        combien = next((int(l.split()[1]) for l in select if l.endswith(" EXISTS")), -1)
        if combien < 0:
            print(f"FAUTE : {compte}/{boite} — pas d'EXISTS", file=sys.stderr); fautes += 1
            continue
        vus += combien
        # **LES DRAPEAUX ONT-ILS SURVÉCU ?** C'est la question de la case
        # « les drapeaux \Seen / \Answered ont survécu » du manuel.
        if boite == "INBOX":
            drapeaux = dire(fichier, "a4", "FETCH 1:* (FLAGS)")
            texte = " ".join(drapeaux)
            for drapeau in ("\\Seen", "\\Answered"):
                if drapeau not in texte:
                    print(f"FAUTE : {compte} — {drapeau} perdu", file=sys.stderr)
                    fautes += 1
    prise.close()

if vus != attendus:
    print(f"FAUTE : {attendus} messages attendus au total, {vus} servis", file=sys.stderr)
    fautes += 1
print(f"{vus} messages servis sur {attendus}, {fautes} faute(s)")
sys.exit(1 if fautes else 0)
IMAP
[ $? -eq 0 ] || rate "le serveur ne sert pas ce que Dovecot rangeait"

# ── PHASE 1 : LE DELTA, PUIS LE RETOUR EN ARRIÈRE ───────────────────────────
# ── L'ÉTAPE 3 DU MANUEL, ET CE QU'ELLE EMPORTE ──────────────────────────────
#
# On rejoue ici le delta tel que la phase 1 l'écrit — `--delete` compris — et
# l'on vérifie DEUX choses que personne ne vérifiait : qu'il efface bien les
# rôles (sans quoi ce banc ne prouverait rien), et que l'étape 3ter les repose.
titre "1. le delta, et les rôles qu'il emporte"
for compte in "${comptes[@]}"; do
    rsync -aH --delete "$ancien/narro.ch/$compte/Maildir/" "$neuf/$compte/" \
        || rate "le delta de $compte a échoué"
done
emportes=0
for compte in "${comptes[@]}"; do
    est_une_machine "$compte" && continue
    [ -e "$neuf/$compte/ams-usages" ] || emportes=$((emportes + 1))
done
[ "$emportes" -eq $((${#comptes[@]} - ${#machines[@]})) ] || rate \
    "le delta n'a pas emporté les rôles — ce banc ne prouve plus rien sur l'étape 3ter"
python3 "$racine/docs/migration/renommer-dossiers.py" "$neuf" --pour-de-vrai > /dev/null \
    || rate "3bis : la retraduction des dossiers a échoué"
poser_les_roles   # l'étape 3ter
for compte in "${comptes[@]}"; do
    est_une_machine "$compte" && continue
    [ -f "$neuf/$compte/ams-usages" ] \
        || rate "$compte : 3ter n'a pas reposé les rôles que le delta a emportés"
    [ -d "$neuf/$compte/.Été-2025" ] \
        || rate "$compte : 3bis n'a pas retraduit les dossiers que le delta a remis"
done
echo "OK — le delta emporte les rôles, 3bis retraduit, 3ter repose"

# **ET LA FENÊTRE VIENT APRÈS LE DELTA, JAMAIS AVANT.** C'est l'ordre de la
# phase 1 — on synchronise, PUIS le serveur neuf reçoit. Joué dans l'autre sens,
# le `--delete` ci-dessus effacerait les deux messages arrivés pendant la
# fenêtre, c'est-à-dire précisément ceux que le rapatriement doit retrouver : le
# banc rendrait alors un « aucun doublon » qui ne prouverait rien.
titre "1. la fenêtre, et le retour en arrière (suite)"
# Deux messages arrivent dans le NEUF pendant la fenêtre, et un est lu.
poser "$neuf/contact" new ""
poser "$neuf/contact" new ""
mv "$neuf/contact/cur/172500001.M1.dovecot,S=64,W=66:2,S" \
   "$neuf/contact/cur/172500001.M1.dovecot,S=64,W=66:2,RS" 2>/dev/null

avant=$(find "$vue/contact/" -type f \( -path '*/cur/*' -o -path '*/new/*' \) | wc -l)
bash "$racine/docs/migration/rapatrier.sh" --essais > /dev/null \
    || rate "le retour en arrière ne passe pas ses propres essais"
bash "$racine/docs/migration/rapatrier.sh" "$neuf" "$vue" --pour-de-vrai > "$banc/retour.txt" 2>&1 \
    || rate "le rapatriement a échoué"
apres=$(find "$vue/contact/" -type f \( -path '*/cur/*' -o -path '*/new/*' \) | wc -l)
if [ "$apres" -ne $((avant + 2)) ]; then
    rate "$((avant + 2)) messages attendus dans l'ancien, $apres trouvés — rapatriés :"
    grep '^  +' "$banc/retour.txt" | sed 's/^/       /' >&2
fi

# **`find -printf` EST UNE EXTENSION GNU, ET CE BANC TOURNE AUSSI SUR LE MAC.**
# Là, `find` refuse l'option, n'imprime RIEN, et `uniq -d` ne trouve donc aucun
# doublon — « OK — aucun doublon » était rendu par un contrôle qui n'avait ouvert
# aucun fichier. C'est la même faute que celle de `verifier.sh` le 2026-09-10, au
# même endroit : un feu vert qui ne vient pas d'un examen. Trouvé le 2026-09-21,
# en jouant ce banc sur le Mac de développement.
#
# Le chemin complet porte déjà ce que `%h %f` donnait : on le découpe soi-même,
# et l'on REFUSE de conclure si rien n'a été lu.
#
# **ET `-L`, PARCE QUE LA VUE EST FAITE DE LIENS.** `$vue/<compte>` est un lien
# symbolique vers le `Maildir` de l'ancien magasin — c'est ce que §0.5 du manuel
# prescrit —, et `find` ne traverse pas un lien qu'il n'a pas reçu en argument.
# Sans `-L`, ce contrôle ne voyait que six liens et zéro message, sur le Mac
# comme sous Linux. Les deux causes se cachaient l'une l'autre.
messages=$(find -L "$vue/" -type f \( -path '*/cur/*' -o -path '*/new/*' \) \
    | sed -E 's#^(.*)/(cur|new)/([^/]*)$#\1 \3#; s#(,|:)[^ ]*$##')
if [ -z "$messages" ]; then
    rate "le contrôle des doublons n'a lu aucun message — il ne conclut rien"
else
    doublons=$(printf '%s\n' "$messages" | sort | uniq -d)
    [ -z "$doublons" ] || { rate "doublons après rapatriement :"; printf '%s\n' "$doublons" >&2; }
fi
echo "OK — $((apres - avant)) rapatriés, aucun doublon"

printf '\n'
if [ "$fautes" -ne 0 ]; then
    echo "ÉCHEC : $fautes faute(s). LA SÉQUENCE DU MANUEL NE TIENT PAS."
    exit 1
fi
echo "OK : la séquence entière tient — copie, noms, audit, service, retour."
