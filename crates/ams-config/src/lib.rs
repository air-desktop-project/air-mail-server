//! Schéma Cap'n Proto de la configuration, lecture et écriture (C11).
//!
//! La configuration d'air-mail-server est un fichier **binaire** : pas de TOML,
//! pas de YAML, pas de JSON. Le schéma `.capnp` est la définition normative de ce
//! qui est configurable ; le fichier en est une instance.
//!
//! Conséquence directe : la configuration **n'est pas éditable à la main**. C'est
//! ce qui rend `air-mail-admin` obligatoire plutôt que confortable (C12).
//!
//! Portent ici, entre autres, les paramètres exigés par C8 : le seuil de trames
//! invalides par minute et la durée de bannissement.
//!
//! # État
//!
//! **Rien n'est implémenté** — pas même le schéma. Emplacement réservé.
