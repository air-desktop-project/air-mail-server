#!/usr/bin/env bash
#
# capture-client.sh — CE QU'UN VRAI CLIENT ENVOIE, ET CE QU'ON LUI RÉPOND.
#
# Monte une boîte d'essai, lance le serveur, met un mandataire qui note tout,
# puis fait parler THUNDERBIRD au serveur et rend la conversation.
#
# USAGE
#     bash scripts/capture-client.sh            # capture, et dit les refus
#     bash scripts/capture-client.sh --montrer  # affiche toute la conversation
#
# ── POURQUOI CE BANC EXISTE ─────────────────────────────────────────────────
#
# `imaplib`, avec lequel B5ter avait été levé, n'emploie AUCUNE des dix-huit
# capacités que ce serveur annonce. Le défaut qu'il ne pouvait pas voir :
#
#     C> list (subscribed) "" "*" return (special-use)
#     S> BAD LIST arguments are not well formed
#
# C'est la PREMIÈRE commande de liste de Thunderbird, sur chacune de ses
# connexions. Après ce refus il n'a listé que `INBOX` et `Trash` : les dossiers
# de l'utilisateur n'apparaissaient nulle part.
#
# ── CE QUE LE BANC DEMANDE À LA MACHINE, ET POURQUOI ────────────────────────
#
# Thunderbird est un SNAP, donc confiné. Quatre détours en découlent :
#
#   1. un compte Unix à part — il ne lit pas `/tmp`, et son profil doit vivre
#      dans un répertoire personnel. Celui de l'exploitant porte son courrier
#      RÉEL, auquel ce banc ne touche jamais ;
#   2. `loginctl enable-linger` — sans session, snap refuse de démarrer ;
#   3. `systemd-run --uid` avec `XDG_RUNTIME_DIR` et `DBUS_SESSION_BUS_ADDRESS`
#      — snap exige un cgroup à lui, et `sudo -u` seul ne le lui donne pas ;
#   4. `xdotool` pour saisir le mot de passe UNE fois sous `Xvfb`. Thunderbird
#      le garde ensuite, mais `--headless` seul ne sait pas le relire.
#
# Le montage se fait par `--preparer`, et une seule fois par machine.
set -uo pipefail
export LC_ALL=C

racine=$(cd "$(dirname "$0")/.." && pwd)
banc=${TMPDIR:-/tmp}/capture-client-$$
compte=banc-ams
port_serveur=9994
port_mandataire=9995

nettoyer() {
    [ -n "${pid_serveur-}" ] && kill "$pid_serveur" 2>/dev/null
    [ -n "${pid_mandataire-}" ] && kill "$pid_mandataire" 2>/dev/null
    [ -n "${pid_xvfb-}" ] && kill "$pid_xvfb" 2>/dev/null
    sudo systemctl stop capture-client 2>/dev/null
    rm -rf "$banc"
}
trap nettoyer EXIT

# ── LE MONTAGE, UNE FOIS PAR MACHINE ────────────────────────────────────────
if [ "${1-}" = "--preparer" ]; then
    id "$compte" >/dev/null 2>&1 || sudo useradd --create-home --shell /bin/bash "$compte"
    sudo loginctl enable-linger "$compte"
    command -v xdotool >/dev/null || sudo apt-get install -y -q xdotool
    uid=$(id -u "$compte")
    sudo systemd-run --uid="$compte" --gid="$compte" \
        --setenv=HOME="/home/$compte" --setenv=XDG_RUNTIME_DIR="/run/user/$uid" \
        --setenv=DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        --collect --pipe --wait --quiet \
        /snap/bin/thunderbird --headless -CreateProfile banc
    echo "OK : le compte \`$compte\` est prêt. Relancez sans \`--preparer\`."
    exit 0
fi

id "$compte" >/dev/null 2>&1 || {
    echo "ÉCHEC : le compte \`$compte\` manque. \`$0 --preparer\` d'abord." >&2
    exit 1
}
uid=$(id -u "$compte")
profil=$(sudo find "/home/$compte/snap/thunderbird" -maxdepth 4 -type d -name '*.banc' 2>/dev/null | head -1)
[ -n "$profil" ] || { echo "ÉCHEC : aucun profil \`banc\`. \`$0 --preparer\`." >&2; exit 1; }

for binaire in air-mail-server air-mail-admin; do
    [ -x "$racine/target/release/$binaire" ] || {
        echo "ÉCHEC : \`target/release/$binaire\` manque (\`cargo build --release\`)." >&2
        exit 1
    }
done

# ── LA BOÎTE D'ESSAI ────────────────────────────────────────────────────────
#
# Quatre messages et trois dossiers, dont un ACCENTUÉ : c'est là qu'un client
# bronche, et c'est le cas courant d'un domaine francophone.
mkdir -p "$banc/vmail/jean"/{cur,new,tmp}
for dossier in .Sent .Drafts .Été-2025; do
    mkdir -p "$banc/vmail/jean/$dossier"/{cur,new,tmp}
done
printf 'Sent\nDrafts\nÉté-2025\n' > "$banc/vmail/jean/ams-abonnements"

numero=0
poser() { # <dossier> <sujet> <corps>
    numero=$((numero + 1))
    {
        printf 'Return-Path: <anne@exemple.test>\r\n'
        printf 'From: Anne <anne@exemple.test>\r\n'
        printf 'To: jean@example.com\r\nSubject: %s\r\n' "$2"
        printf 'Date: Mon, 07 Sep 2026 09:00:0%d +0200\r\n' "$numero"
        printf 'Message-ID: <%d.banc@exemple.test>\r\nMIME-Version: 1.0\r\n' "$numero"
        printf 'Content-Type: text/plain; charset=utf-8\r\n'
        printf 'Content-Transfer-Encoding: 8bit\r\n\r\n%s\r\n' "$3"
    } > "$banc/vmail/jean/$1/cur/172500000$numero.M1.banc,S=$((200 + numero)):2,S"
}
poser "" "Bonjour" "Un message tout simple."
poser "" "=?UTF-8?Q?R=C3=A9union_de_pr=C3=A9paration?=" "Sujet encodé, corps accentué."
poser ".Sent" "Ce que j'ai envoyé" "Dans le dossier Envoyés."
poser ".Drafts" "Brouillon" "Pas fini."

openssl req -x509 -newkey rsa:2048 -keyout "$banc/cle.pem" -out "$banc/cert.pem" \
    -days 2 -nodes -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1 \
    || { echo "ÉCHEC : openssl n'a pas produit de certificat." >&2; exit 1; }

printf %s 'ouvre-toi' | "$racine/target/release/air-mail-admin" account add \
    "$banc/comptes.bin" --login jean --address jean@example.com >/dev/null || exit 1
chmod 600 "$banc/comptes.bin"
"$racine/target/release/air-mail-admin" config write "$banc/ams.conf" \
    --domain mail.example.com --hosted example.com \
    --maildir "$banc/vmail" --accounts "$banc/comptes.bin" \
    --listen 127.0.0.1:2526 --listen-imaps "127.0.0.1:$port_serveur" \
    --tls-cert "$banc/cert.pem" --tls-key "$banc/cle.pem" >/dev/null || exit 1
# **PAS DE `chmod o+rX` ICI**, et le serveur l'a rappelé : il REFUSE de démarrer
# sur un magasin lisible par les autres comptes de la machine. Une première
# écriture de ce script ouvrait le banc « pour que le compte jetable puisse
# lire » — il n'a rien à y lire. Il ne joint qu'un port.

"$racine/target/release/air-mail-server" --config "$banc/ams.conf" > "$banc/serveur.log" 2>&1 &
pid_serveur=$!
sleep 2
grep -q 'IMAP écoute' "$banc/serveur.log" || {
    echo "ÉCHEC : le serveur n'a pas ouvert l'IMAP :" >&2
    sed 's/^/       /' "$banc/serveur.log" >&2
    exit 1
}

# ── LE MANDATAIRE : EN CLAIR CÔTÉ CLIENT, EN TLS CÔTÉ SERVEUR ───────────────
#
# Cela évite de faire accepter un certificat auto-signé à un client qui a de
# bonnes raisons de le refuser, sans rien changer à ce qu'on mesure : le serveur
# voit bien une session TLS, et les commandes sont celles de Thunderbird.
python3 "$racine/scripts/capture-client/mandataire.py" \
    "$port_mandataire" "$port_serveur" "$banc/conversation.log" > /dev/null 2>&1 &
pid_mandataire=$!
sleep 1

# ── LE PROFIL, ET LA COURSE ─────────────────────────────────────────────────
sed -e "s/@PORT@/$port_mandataire/" "$racine/scripts/capture-client/prefs.js" \
    > "$banc/prefs.js"
sudo cp "$banc/prefs.js" "$profil/prefs.js"
sudo chown "$compte:$compte" "$profil/prefs.js"

export DISPLAY=:77
Xvfb :77 -screen 0 1280x1024x24 > /dev/null 2>&1 &
pid_xvfb=$!
sleep 2
sudo systemd-run --uid="$compte" --gid="$compte" \
    --setenv=HOME="/home/$compte" --setenv=XDG_RUNTIME_DIR="/run/user/$uid" \
    --setenv=DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    --setenv=DISPLAY=:77 --collect --pipe --quiet --unit=capture-client \
    /snap/bin/thunderbird -P banc > /dev/null 2>&1 &

# La boîte du mot de passe n'apparaît que la PREMIÈRE fois : ensuite Thunderbird
# le garde. On la cherche sans exiger qu'elle vienne.
for essai in $(seq 1 12); do
    sleep 4
    fenetre=$(xdotool search --name 'mot de passe|Password|Saisissez' 2>/dev/null | head -1)
    [ -z "$fenetre" ] && continue
    xdotool windowactivate "$fenetre" 2>/dev/null
    sleep 1
    xdotool type --delay 60 'ouvre-toi'
    xdotool key Return
    echo "mot de passe saisi (première fois sur cette machine)"
    break
done
sleep 30

# ── CE QU'ON EN TIRE ────────────────────────────────────────────────────────
python3 - "$banc/conversation.log" "${1-}" <<'PY'
import sys

chemin, mode = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
commandes, refus, oks = [], [], 0
for ligne in open(chemin, encoding="utf-8", errors="replace"):
    if not ligne.startswith(("C> ", "S> ")):
        continue
    try:
        octets = eval(ligne[3:].strip())
    except Exception:
        continue
    for texte in octets.decode("utf-8", "replace").split("\r\n"):
        if not texte:
            continue
        if ligne.startswith("C> "):
            # Le jeton SASL porte le secret : il ne se journalise pas.
            if not texte.startswith("AGpl"):
                commandes.append(texte)
                if mode == "--montrer":
                    print("C>", texte)
        else:
            if mode == "--montrer":
                print("  ", texte[:120])
            if " BAD " in texte or " NO " in texte:
                refus.append(texte)
            elif texte[:1].isdigit() and " OK " in texte:
                oks += 1

print()
print(f"commandes du client : {len(commandes)}")
print(f"réponses OK         : {oks}")
print(f"refus (BAD ou NO)   : {len(refus)}")
for r in refus:
    print("   ", r[:120])

if not commandes:
    print()
    print("ÉCHEC : le client n'a envoyé AUCUNE commande — il attend sans doute")
    print("        son mot de passe. Relancez : la saisie n'a lieu qu'une fois.")
    sys.exit(1)
# **UN REFUS N'EST PAS FORCÉMENT UNE FAUTE**, et c'est pourquoi ce script les
# MONTRE au lieu d'échouer : `NO [ALREADYEXISTS]` sur un `CREATE "Trash"` que
# deux connexions demandent en même temps est la bonne réponse. C'est à qui lit
# de juger — mais il faut qu'il les voie.
PY
