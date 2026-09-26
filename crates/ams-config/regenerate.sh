#!/usr/bin/env bash
#
# Régénère le code Rust COMMITTÉ à partir du schéma `.capnp`.
#
# # Pourquoi le code généré est committé
#
# Le build normal et la CI consomment le `.rs` : ils n'ont besoin **d'aucun outil
# C++**. Faire dépendre chaque compilation du `capnp` C++ ferait entrer dans le
# chemin de build un programme que ce projet ne construit pas, ne vérifie pas, et
# ne saurait pas porter sur la cible Air.
#
# Régénérer est donc une opération de MAINTENEUR, rare, et hors CI.
#
# # Pré-requis
#
#   - greffon Rust       = capnpc **0.26.0** (`cargo install capnpc --version 0.26.0`)
#   - crate d'exécution  = capnp **0.26.0**  (pin strict dans le Cargo.toml)
#   - outil C++ `capnp`  = n'importe quelle version récente (`brew install capnp`)
#
# Les deux premières sont exactes ; la troisième ne l'est pas, et c'est une
# correction du 2026-09-22 : cette liste disait « capnp = 1.1.0 » et ce chiffre
# a failli faire renoncer à régénérer un schéma, faute de cette version-là.
#
# **CE QUI DOIT S'ACCORDER, C'EST LE GREFFON ET LA CRATE `capnp`** : un greffon
# plus récent émet du code qu'une ancienne crate ne compile pas, et l'inverse est
# pire — il compile et ne dit rien. L'outil C++, lui, ne fait que transmettre le
# schéma analysé : sa version n'apparaît que dans un commentaire. Vérifié le
# 2026-09-22 en régénérant les trois schémas avec capnp 1.1.0 puis 1.5.0 (greffon
# 0.26.0) : code identique à l'octet près, hors cette ligne de commentaire.
#
# Usage, depuis `crates/ams-config/` :  ./regenerate.sh

set -euo pipefail

cd "$(dirname "$0")"
SORTIE="$(mktemp -d)"
trap 'rm -rf "$SORTIE"' EXIT

capnp compile -I schema --src-prefix schema \
  -o "$(command -v capnpc-rust):$SORTIE" \
  schema/ams-config.capnp schema/ams-accounts.capnp schema/ams-index.capnp \
  schema/ams-scram.capnp schema/ams-devices.capnp schema/ams-app-passwords.capnp || {
    echo 'échec de la compilation des schémas (capnp + capnpc-rust 0.26.0 requis)' >&2
    exit 1
  }

# Aucun attribut `#![...]` ici : le fichier est inclus par `include!`, qui ne
# tolère pas d'attribut interne. Les `#[allow(...)]` nécessaires sont posés en
# ATTRIBUT EXTERNE sur le module englobant, dans `lib.rs`.
#
# L'en-tête passe par un heredoc QUOTÉ et non par une chaîne entre apostrophes :
# une apostrophe française y fermerait la chaîne, et le reste deviendrait des
# commandes. C'est arrivé.
# Les deux schémas passent par le même en-tête et le même traitement : une
# boucle plutôt que deux copies, parce que la seconde copie est celle qu'on
# oublie de corriger.
for schema in ams_config ams_accounts ams_index ams_scram ams_devices ams_app_passwords; do
cat > "src/${schema}_capnp.rs" <<'ENTETE'
// CODE GÉNÉRÉ — NE PAS ÉDITER À LA MAIN.
//
// Régénérer via `crates/ams-config/regenerate.sh` (outil C++ capnp + greffon
// capnpc-rust 0.26.0). Le build normal et la CI consomment ce fichier SANS
// aucun outil C++ : voilà pourquoi il est committé.
//
// C'EST LE GREFFON QUI ÉCRIT CE RUST, pas l'outil C++ : sa version à lui est ce
// qui doit s'accorder avec la crate `capnp`. Mesuré le 2026-09-22 — régénérer
// avec capnp 1.1.0 puis 1.5.0, greffon 0.26.0 dans les deux cas, donne un code
// IDENTIQUE À L'OCTET PRÈS, à la seule ligne `// capnp binary version:` près,
// que le greffon recopie. La version de l'outil C++ n'est donc plus épinglée
// ici : ce serait épingler ce qui ne décide de rien.
//
// Inclus par `include!` dans `lib.rs`, qui porte les `#[allow(...)]`.

ENTETE

cat "$SORTIE/${schema}_capnp.rs" >> "src/${schema}_capnp.rs"
echo "régénéré : src/${schema}_capnp.rs"
done
