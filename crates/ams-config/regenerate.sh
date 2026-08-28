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
# # Pré-requis, en versions exactes
#
#   - outil C++ `capnp`  = 1.1.0   (`capnp --version`)
#   - greffon Rust       = capnpc 0.26.0 (`cargo install capnpc --version 0.26.0`)
#   - crate d'exécution  = capnp 0.26.0  (pin strict dans le Cargo.toml)
#
# Les trois doivent s'accorder : un greffon plus récent émet du code qu'une
# ancienne crate ne compile pas, et l'inverse est pire — il compile et ne dit rien.
#
# Usage, depuis `crates/ams-config/` :  ./regenerate.sh

set -euo pipefail

cd "$(dirname "$0")"
SORTIE="$(mktemp -d)"
trap 'rm -rf "$SORTIE"' EXIT

capnp compile -I schema --src-prefix schema \
  -o "$(command -v capnpc-rust):$SORTIE" \
  schema/ams-config.capnp schema/ams-accounts.capnp || {
    echo 'échec de la compilation des schémas (capnp 1.1.0 + capnpc-rust requis)' >&2
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
for schema in ams_config ams_accounts; do
cat > "src/${schema}_capnp.rs" <<'ENTETE'
// CODE GÉNÉRÉ — NE PAS ÉDITER À LA MAIN.
//
// Régénérer via `crates/ams-config/regenerate.sh` (outil C++ capnp 1.1.0 +
// greffon capnpc-rust 0.26.0). Le build normal et la CI consomment ce fichier
// SANS aucun outil C++ : voilà pourquoi il est committé.
//
// Inclus par `include!` dans `lib.rs`, qui porte les `#[allow(...)]`.

ENTETE

cat "$SORTIE/${schema}_capnp.rs" >> "src/${schema}_capnp.rs"
echo "régénéré : src/${schema}_capnp.rs"
done
