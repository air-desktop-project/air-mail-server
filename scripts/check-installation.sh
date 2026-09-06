#!/usr/bin/env bash
#
# check-installation — l'installateur pose-t-il ce qu'il dit poser ?
#
# # POURQUOI CETTE BARRIÈRE EXISTE
#
# Ce dépôt vient de reprocher à sa propre table `nftables` d'avoir été
# documentée pendant des mois sans jamais tourner. Un script d'installation
# qu'on ne lancerait qu'en production serait la même faute, en pire : on ne le
# découvrirait pas en relisant un document, mais un soir, sur la machine de
# quelqu'un, à mi-chemin.
#
# `installer.sh --racine` pose son arborescence dans un répertoire jetable, sans
# superutilisateur. Il n'y a donc aucune raison de ne pas l'exécuter à chaque
# commit — et ce script est cette raison-là, retournée.
#
# # CE QU'IL VÉRIFIE, ET POURQUOI CHACUN
#
# 1. Le script s'analyse (`bash -n`) : une faute de frappe dans une branche
#    rarement prise ne se voit pas autrement.
# 2. Il REFUSE de s'exécuter sans racine et sans privilège, plutôt que de poser
#    la moitié d'une installation avant de buter.
# 3. L'arborescence est celle qu'il annonce, aux PERMISSIONS PRÈS. C'est le seul
#    contrôle qui protège du défaut le plus coûteux : un répertoire de courrier
#    lisible par tous les comptes de la machine.
# 4. L'unité systemd est syntaxiquement valide — vérifiée par systemd lui-même,
#    quand il est là.
# 5. Il est IDEMPOTENT : on relance une installation après une mise à jour ou un
#    échec à mi-chemin, et le second passage ne doit rien changer.
# 6. La table du pare-feu est ÉCRITE ET NON CHARGÉE, et l'hôte n'a pas reçu une
#    seule règle.
set -euo pipefail

racine=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$racine"

essai=$(mktemp -d)
# LE RÉPERTOIRE JETABLE PART AVEC NOUS, quoi qu'il arrive — y compris si une
# assertion échoue au milieu.
nettoyer() { rm -rf "$essai"; }
trap nettoyer EXIT

echec=0
rate() {
    echo "ÉCHEC : $*" >&2
    echec=1
}

echo "── 1. le script s'analyse ───────────────────────────────────────────────"
bash -n scripts/installer.sh || rate "scripts/installer.sh ne s'analyse pas"
echo "OK"

echo
echo "── 2. sans racine et sans privilège, il refuse ──────────────────────────"
if [ "$(id -u)" -eq 0 ]; then
    echo "ignoré : ce contrôle demande de NE PAS être superutilisateur"
else
    if scripts/installer.sh --sans-construire > "$essai/refus" 2>&1; then
        rate "il a accepté d'installer sur la machine sans privilège"
    elif ! grep -q 'racine' "$essai/refus"; then
        rate "le refus ne dit pas comment l'éprouver sans rien toucher"
    else
        echo "OK — il refuse, et dit quoi faire à la place"
    fi
fi

echo
echo "── 3. les binaires doivent être là, ET À JOUR ───────────────────────────"
# **« PRÉSENT » N'EST PAS « À JOUR ».** Ce contrôle ne construisait que si les
# binaires MANQUAIENT. Le 2026-09-06, on a découvert qu'il éprouvait depuis
# plusieurs tranches un `release` vieux de plusieurs heures : `--resolver-trusted`
# avait été ajoutée, documentée, poussée — et le contrôle interrogeait un binaire
# qui ne la connaissait pas.
#
# C'est pire qu'un contrôle absent : celui-ci rendait un verdict, sur autre chose
# que ce qu'on lui demandait. `cargo` est incrémental — quand rien n'a changé,
# cette ligne ne coûte qu'une seconde.
#
# **`check-paquet.sh` EMPAQUETTE CE MÊME `target/release`**, et son
# `--sans-construire` s'y fiait : un paquet pouvait donc être bâti, éprouvé et
# déclaré bon en portant un binaire qui ne correspondait à aucune source.
cargo build --release --locked
echo "OK — construits, et à jour"

echo
echo "── 4. l'installation dans un arbre jetable ──────────────────────────────"
arbre="$essai/arbre"
scripts/installer.sh --racine "$arbre" --sans-construire > "$essai/pose" 2>&1 \
    || { cat "$essai/pose" >&2; rate "l'installateur a échoué"; }

# **LES PERMISSIONS SONT LE CŒUR DU CONTRÔLE.** Tout ce que ce serveur pose sur
# le disque est soit un secret, soit le courrier de quelqu'un.
attendu="drwx------ var/lib/air-mail
drwx------ var/lib/air-mail/maildir
-rw------- var/lib/air-mail/nftables-air-mail.conf
-rw-r--r-- etc/systemd/system/air-mail-server.service
-rwxr-xr-x usr/local/bin/air-mail-admin
-rwxr-xr-x usr/local/bin/air-mail-server"

while read -r mode chemin; do
    [ -n "$chemin" ] || continue
    vu=$(find "$arbre" -path "$arbre/$chemin" -printf '%M' 2>/dev/null || true)
    if [ -z "$vu" ]; then
        rate "$chemin n'a pas été posé"
    elif [ "$vu" != "$mode" ]; then
        rate "$chemin est en $vu, attendu $mode"
    fi
done <<< "$attendu"
echo "OK — six chemins, aux permissions attendues"

echo
echo "── 5. l'unité systemd est valide ────────────────────────────────────────"
unite="$arbre/etc/systemd/system/air-mail-server.service"
if command -v systemd-analyze > /dev/null 2>&1; then
    # `ExecStart` NOMME LE CHEMIN RÉEL, non celui de l'arbre jetable : systemd se
    # plaint donc que le binaire soit absent, et c'est attendu. Toute AUTRE
    # plainte est une faute de l'unité.
    autres=$(systemd-analyze verify "$unite" 2>&1 \
        | grep -v 'is not executable' \
        | grep -v '^$' || true)
    if [ -n "$autres" ]; then
        rate "systemd se plaint de l'unité : $autres"
    else
        echo "OK — systemd ne lui reproche que le binaire absent de CETTE machine"
    fi
else
    echo "ignoré : systemd-analyze n'est pas là"
fi

# CE QUE L'UNITÉ DOIT DIRE, et que personne ne doit pouvoir retirer sans le
# vouloir : le service ne tourne pas en superutilisateur (C10), et n'a AUCUNE
# capacité.
for exigence in 'User=' 'NoNewPrivileges=yes' 'CapabilityBoundingSet=$' \
                'ProtectSystem=strict' 'UMask=0077'; do
    grep -qE "^$exigence" "$unite" || rate "l'unité ne porte pas \`$exigence\`"
done
echo "OK — elle porte les garanties que C10 exige"

echo
echo "── 6. il est idempotent ─────────────────────────────────────────────────"
avant=$(find "$arbre" -printf '%M %P\n' | sort -k2)
scripts/installer.sh --racine "$arbre" --sans-construire > /dev/null 2>&1 \
    || rate "le second passage a échoué"
apres=$(find "$arbre" -printf '%M %P\n' | sort -k2)
if [ "$avant" != "$apres" ]; then
    rate "le second passage a changé l'arborescence"
else
    echo "OK — relancer ne change rien"
fi

echo
echo "── 7. aucune règle de pare-feu n'a été posée ────────────────────────────"
table="$arbre/var/lib/air-mail/nftables-air-mail.conf"
if [ ! -s "$table" ]; then
    rate "la table du pare-feu n'a pas été écrite"
elif ! grep -q 'redirect to :2525' "$table"; then
    rate "la table n'est pas celle du §6"
else
    echo "OK — écrite, et pas chargée"
fi
# **ON NE REGARDE PAS `nft list ruleset`** : le faire demanderait le
# superutilisateur, que ce contrôle n'a pas et ne veut pas. Ce qui garantit
# qu'aucune règle n'est posée est plus simple à établir : l'installateur
# n'appelle jamais `nft`.
if grep -nE '^[^#]*\bnft\b' scripts/installer.sh | grep -qv 'sudo nft -f'; then
    rate "l'installateur appelle \`nft\` ailleurs que dans le texte qu'il imprime"
else
    echo "OK — il ne lance jamais \`nft\`"
fi

echo
echo "── 8. le document et le script posent LA MÊME unité ─────────────────────"
# **DEUX COPIES D'UN MÊME TEXTE DIVERGENT**, et celle qu'on relit n'est pas celle
# qui tourne. `docs/installation.md` §7 montre l'unité ; le script l'écrit. Les
# comparer ici est le seul moyen que la première reste vraie.
#
# **LA TABLE `nftables` ÉTAIT CITÉE ICI COMME L'EXEMPLE À NE PAS SUIVRE** —
# « exacte le jour où elle a été écrite » — et elle n'était pas contrôlée. Elle
# a donc redérivé, le 2026-09-06 : le serveur s'est mis à servir le 143 et le
# 995, le document a gagné une SECONDE table qui les redirigeait, et
# l'installateur a continué d'en écrire cinq. Un document qui se contredit
# lui-même est pire qu'un document qui vieillit. Le contrôle 8bis existe pour
# cela.
sed -n '/^## 7. L.unité systemd/,/^```$/p' docs/installation.md \
    | sed -n '/^\[Unit\]/,$p' | head -n -1 > "$essai/unite-doc"
if [ ! -s "$essai/unite-doc" ]; then
    rate "le §7 de docs/installation.md ne montre plus d'unité"
elif ! diff -u "$essai/unite-doc" "$unite" > "$essai/ecart" 2>&1; then
    rate "le §7 et le script ne posent pas la même unité :
$(cat "$essai/ecart")"
else
    echo "OK — au caractère près"
fi

echo
echo "── 8bis. le document et le script posent LA MÊME table ──────────────────"
# **UNE SEULE TABLE DANS LE DOCUMENT**, et c'est celle que le script écrit. Deux
# tables dans un même document se contredisent dès que l'une bouge, et le
# lecteur n'a aucun moyen de savoir laquelle est vraie.
regles_doc=$(grep -cE '^ *tcp dport [0-9]+ +redirect to :[0-9]+$' docs/installation.md)
grep -E '^ *tcp dport [0-9]+ +redirect to :[0-9]+$' docs/installation.md \
    | sed 's/^ *//' > "$essai/table-doc"
grep -E '^ *tcp dport [0-9]+ +redirect to :[0-9]+$' scripts/installer.sh \
    | sed 's/^ *//' > "$essai/table-script"
if [ ! -s "$essai/table-doc" ]; then
    rate "docs/installation.md ne montre plus de redirection"
elif [ "$regles_doc" -ne "$(wc -l < "$essai/table-script")" ] \
    || ! diff -u "$essai/table-doc" "$essai/table-script" > "$essai/ecart" 2>&1; then
    rate "le document et le script ne redirigent pas les mêmes ports :
$(cat "$essai/ecart" 2>/dev/null)"
else
    echo "OK — $regles_doc redirections, les mêmes des deux côtés"
fi

echo
echo "── 9. les commandes imprimées à la fin sont celles qui existent ─────────"
# CE QU'UN SCRIPT IMPRIME EST CE QUE L'EXPLOITANT RECOPIE. Une option qui aurait
# changé de nom se découvrirait sur sa machine, pas ici.
for option in --domain --hosted --maildir --accounts --listen --listen-smtps \
              --listen-imaps --tls-cert --tls-key; do
    grep -q -- "$option" "$essai/pose" || rate "la marche à suivre ne montre pas \`$option\`"
    "$racine/target/release/air-mail-admin" config write --help 2>&1 \
        | grep -q -- "$option" || rate "\`$option\` est imprimée et n'existe pas"
done
grep -q 'account add' "$essai/pose" || rate "la marche à suivre n'ajoute aucun compte"
echo "OK — neuf options imprimées, et toutes reconnues par \`config write --help\`"

echo
echo "── 10. les options que LE SERVEUR imprime existent aussi ────────────────"
# **LE SERVEUR EN CITE BIEN PLUS QUE L'INSTALLATEUR.** Chacune de ses lignes de
# démarrage qui dit ce qui MANQUE nomme l'option qui le fournirait — `--resolver`
# pour SPF, `--public-suffix-list` pour DMARC, `--queue-spool` pour la file. Ce
# sont ces commandes-là que l'exploitant recopie, et une seule qui aurait changé
# de nom se découvrirait sur sa machine.
#
# On les tire de la SOURCE plutôt que d'une exécution : le serveur n'imprime que
# les manques de SA configuration, si bien qu'un seul démarrage n'en montrerait
# qu'une poignée.
# `--address` appartient à `account add` ; `--config`, `--help` et `--version`
# sont les options du SERVEUR lui-même, pas de `config write`.
ailleurs=" --address --config --help --version "
manquantes=0
for option in $(grep -ohE '\-\-[a-z][a-z0-9-]+' crates/ams-server/src/main.rs | sort -u); do
    case "$ailleurs" in *" $option "*) continue ;; esac
    "$racine/target/release/air-mail-admin" config write --help 2>&1 \
        | grep -q -- "$option" || {
            rate "le serveur imprime \`$option\`, que \`config write\` ne connaît pas"
            manquantes=$((manquantes + 1))
        }
done
[ "$manquantes" -eq 0 ] && echo "OK — toutes reconnues par \`config write --help\`"

echo
if [ "$echec" -ne 0 ]; then
    echo "ÉCHEC : l'installateur ne pose pas ce qu'il dit poser." >&2
    exit 1
fi
echo "OK : l'installateur pose ce qu'il dit poser, et rien d'autre."
