// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le journal des changements d'une boîte, **sur le disque** : le lire, le
//! comparer à ce que le répertoire montre, et le réécrire s'il a bougé.
//!
//! Toute la logique vit dans `ams_config::Journal`, couverte à cent pour cent ;
//! ce module ne fait que ce qu'elle ne peut pas faire — lire, verrouiller,
//! écrire, et donner l'heure.
//!
//! # LE VERROU EST CELUI DU FICHIER, ET IL SUFFIT
//!
//! Deux requêtes qui réconcilient la même boîte en même temps attribueraient
//! deux fois les mêmes points. `ams_fichier::verrouiller` prend un `flock` sur
//! un fichier voisin : il sépare les processus, et aussi deux fils du même
//! processus — chacun ouvre sa propre description de fichier.

use std::path::Path;

use ams_config::Journal;

/// Le nom du journal, dans le répertoire de la boîte.
///
/// À côté de `ams-index.bin`, et pour la même raison : une boîte renommée
/// emporte son journal, une boîte supprimée l'emporte aussi.
pub const NOM: &str = "ams-journal.bin";

/// L'heure, en millisecondes : le point de départ d'un journal neuf.
///
/// **ELLE DÉPASSE TOUT POINT QU'UN JOURNAL PERDU AVAIT ATTRIBUÉ** : un journal
/// n'avance que d'un par changement, et l'heure de mille par seconde.
fn depart() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |depuis| {
            u64::try_from(depuis.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Réconcilie le journal de la boîte qui vit dans `racine` avec ce que son
/// répertoire montre, et le rend.
///
/// # UN JOURNAL ILLISIBLE N'EST PAS UNE PANNE
///
/// Absent, abîmé, refusé par son décodeur : on en recrée un, qui part d'un
/// point plus grand que tout ce qu'un client a pu voir. Chaque client
/// resynchronise alors une fois — c'est le prix, et il est dit dans le journal
/// du serveur.
///
/// # Errors
///
/// Le verrou ne se prend pas, ou le disque refuse d'écrire le journal.
/// **Servir un delta sans l'avoir écrit** ferait attribuer les mêmes points
/// deux fois à la requête suivante : on refuse plutôt.
pub fn reconcilier(
    racine: &Path,
    uid_validity: u32,
    vus: &[(u32, u16)],
) -> Result<Journal, String> {
    let chemin = racine.join(NOM);
    tokio::task::block_in_place(|| {
        let _verrou = ams_fichier::verrouiller(&chemin)
            .map_err(|erreur| format!("`{}` : {erreur}", chemin.display()))?;
        let (journal, a_ecrire) = match std::fs::read(&chemin) {
            Ok(octets) => match ams_config::decode_journal(&octets) {
                Ok(mut journal) => {
                    let change = journal.reconcile(uid_validity, depart(), vus);
                    (journal, change)
                }
                Err(erreur) => {
                    eprintln!(
                        "air-mail-server : journal `{}` illisible ({erreur}) — recréé ; ses \
                         clients resynchroniseront une fois",
                        chemin.display()
                    );
                    (Journal::initial(uid_validity, depart(), vus), true)
                }
            },
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                (Journal::initial(uid_validity, depart(), vus), true)
            }
            Err(erreur) => return Err(format!("`{}` : {erreur}", chemin.display())),
        };
        if a_ecrire {
            let octets = ams_config::encode_journal(&journal)
                .map_err(|erreur| format!("encodage du journal : {erreur}"))?;
            ams_fichier::poser(&chemin, &octets)
                .map_err(|erreur| format!("`{}` : {erreur}", chemin.display()))?;
        }
        Ok(journal)
    })
}

#[cfg(test)]
mod tests;
