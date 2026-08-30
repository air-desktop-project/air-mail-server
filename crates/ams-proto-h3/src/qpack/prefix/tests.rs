// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un préfixe de section de champs a le droit de dire.

use super::{max_entries, read_prefix};
use crate::error::{H3Error, Reason};

/// Une capacité qui porte seize entrées.
const CAPACITE: u64 = 16 * 32;

/// **UNE ENTRÉE COÛTE TRENTE-DEUX OCTETS** (§3.2.2), les mêmes qu'HPACK compte :
/// ils représentent ce qu'une entrée coûte à RETENIR, non ce qu'elle pèse sur le
/// fil.
#[test]
fn le_nombre_d_entrees_vient_de_la_capacite() {
    assert_eq!(max_entries(0), 0);
    assert_eq!(max_entries(31), 0);
    assert_eq!(max_entries(32), 1);
    assert_eq!(max_entries(CAPACITE), 16);
    assert_eq!(max_entries(4_096), 128);
}

/// **ZÉRO VEUT DIRE : CETTE SECTION NE DÉPEND D'AUCUNE INSERTION.** C'est le cas
/// le plus fréquent, et le seul qui ne bloque jamais personne.
#[test]
fn zero_ne_depend_de_rien() {
    let lu = read_prefix(&[0x00, 0x00], 0, CAPACITE).expect("lisible");
    assert_eq!(lu.required_insert_count, 0);
    assert_eq!(lu.base, 0);
    assert_eq!(lu.read, 2);

    // Et cela vaut quel que soit ce qu'on a déjà inséré.
    let lu = read_prefix(&[0x00, 0x00], 1_000, CAPACITE).expect("lisible");
    assert_eq!(lu.required_insert_count, 0);
}

/// **`S` DIT DE QUEL CÔTÉ LE RANG SE COMPTE** (§4.5.1.2). Se tromper de côté
/// ferait lire chaque index relatif à côté de sa cible.
#[test]
fn le_signe_dit_de_quel_cote_le_rang_se_compte() {
    // Seize entrées, quarante insertions reçues : un compte écrit de dix se
    // reconstruit à quarante et un (voir le test qui suit).
    // `S` à zéro : le rang est AU-DESSUS du compte.
    let lu = read_prefix(&[0x0a, 0x05], 40, CAPACITE).expect("lisible");
    assert_eq!(lu.required_insert_count, 41);
    assert_eq!(lu.base, 46, "quarante et un, plus cinq");

    // `S` à un : le rang est EN DESSOUS, d'un de plus que le delta.
    let lu = read_prefix(&[0x0a, 0x80], 40, CAPACITE).expect("lisible");
    assert_eq!(lu.required_insert_count, 41);
    assert_eq!(lu.base, 40, "quarante et un, moins zéro, moins un");
}

/// **LE COMPTE EST ÉCRIT MODULO**, comme un numéro de paquet tronqué : la
/// reconstruction choisit un tour, et se tromper décalerait toute la table.
#[test]
fn le_compte_se_reconstruit_modulo_la_fenetre() {
    // Seize entrées : la fenêtre vaut trente-deux.
    // Avec quarante insertions reçues, le plafond vaut cinquante-six.
    // Le tour vaut floor(56/32) = 1, donc la base vaut trente-deux.
    // Un compte écrit de 10 donne 32 + 10 - 1 = 41.
    let lu = read_prefix(&[0x0a, 0x00], 40, CAPACITE).expect("lisible");
    assert_eq!(lu.required_insert_count, 41);

    // Un compte écrit qui tomberait AU-DESSUS du plafond redescend d'un tour :
    // 32 + 30 - 1 = 61 > 56, donc 61 - 32 = 29.
    let lu = read_prefix(&[0x1e, 0x00], 40, CAPACITE).expect("lisible");
    assert_eq!(lu.required_insert_count, 29);
}

/// **AU-DELÀ DE LA FENÊTRE, LE COMPTE N'EST PAS RECEVABLE** : le pair ne peut
/// pas avoir écrit cela.
#[test]
fn un_compte_hors_fenetre_se_refuse() {
    // La fenêtre vaut trente-deux : trente-trois n'a pas pu être écrit.
    let issue = read_prefix(&[0x21, 0x00], 40, CAPACITE).expect_err("hors fenêtre");
    assert_eq!(issue.reason(), Reason::BadInsertCount);
    assert_eq!(issue.code(), H3Error::QpackDecompressionFailed);

    // Et sans table du tout, tout compte non nul est hors fenêtre.
    let issue = read_prefix(&[0x01, 0x00], 0, 0).expect_err("aucune table");
    assert_eq!(issue.reason(), Reason::BadInsertCount);
}

/// **UNE RECONSTRUCTION QUI RETOMBE À ZÉRO S'EST TROMPÉE DE TOUR** : le zéro
/// écrit a déjà été rendu plus haut.
#[test]
fn une_reconstruction_nulle_se_refuse() {
    // Fenêtre trente-deux, aucune insertion reçue : le plafond vaut seize, le
    // tour vaut zéro, et un compte écrit de un donnerait 0 + 1 - 1 = 0.
    let issue = read_prefix(&[0x01, 0x00], 0, CAPACITE).expect_err("retombe à zéro");
    assert_eq!(issue.reason(), Reason::BadInsertCount);
}

/// Un rang qui descendrait sous zéro n'existe pas.
#[test]
fn un_rang_sous_zero_se_refuse() {
    // Compte reconstruit à 41, delta de cent avec `S` à un : 41 - 100 - 1 < 0.
    let issue = read_prefix(&[0x0a, 0xff, 0x1d], 40, CAPACITE).expect_err("sous zéro");
    assert_eq!(issue.reason(), Reason::BadInsertCount);
}

/// Un préfixe tronqué se refuse.
#[test]
fn un_prefixe_tronque_se_refuse() {
    for octets in [[0_u8; 0].as_slice(), &[0x0a]] {
        let issue = read_prefix(octets, 40, CAPACITE).expect_err("tronqué");
        assert_eq!(issue.reason(), Reason::Truncated, "{octets:02x?}");
        assert_eq!(issue.code(), H3Error::FrameError);
    }
    // Un entier qui annonce une continuation sans la porter.
    let issue = read_prefix(&[0xff, 0x80], 40, CAPACITE).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
}

/// **UN COMPTE QUI DÉPASSE LE PLAFOND SANS AVOIR DE TOUR PRÉCÉDENT** n'est pas
/// recevable : redescendre d'une fenêtre le ferait passer sous zéro, et l'on
/// aurait reconstruit un compte que le pair n'a jamais écrit.
#[test]
fn un_compte_sans_tour_precedent_se_refuse() {
    // Aucune insertion reçue : le plafond vaut seize, le tour vaut zéro. Un
    // compte écrit de vingt donne dix-neuf, au-dessus du plafond — et il n'y a
    // pas de tour d'avant où le ranger.
    let issue = read_prefix(&[0x14, 0x00], 0, CAPACITE).expect_err("sans tour d'avant");
    assert_eq!(issue.reason(), Reason::BadInsertCount);
    assert_eq!(issue.code(), H3Error::QpackDecompressionFailed);
}
