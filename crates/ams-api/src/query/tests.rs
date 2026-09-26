// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la chaîne de requête accepte, et tout ce qu'elle refuse.

use super::{Query, parse_query};
use crate::error::{Error, Reason};

#[test]
fn une_requete_vide_ne_dit_rien() {
    let lue = parse_query(b"").expect("lisible");
    assert_eq!(lue, Query::default());
    assert!(lue.is_empty());
}

#[test]
fn les_trois_parametres_se_lisent() {
    let lue = parse_query(b"before=1201&limit=50&since=0").expect("lisible");
    assert_eq!(
        lue,
        Query {
            before: Some(1201),
            limit: Some(50),
            since: Some(0),
        }
    );
    assert!(!lue.is_empty());
    // Dans n'importe quel ordre, et seuls.
    assert_eq!(parse_query(b"limit=1").expect("lisible").limit, Some(1));
    assert_eq!(
        parse_query(b"since=18446744073709551615")
            .expect("lisible")
            .since,
        Some(u64::MAX)
    );
    assert_eq!(
        parse_query(b"before=4294967295").expect("lisible").before,
        Some(u32::MAX)
    );
    assert!(!parse_query(b"before=1").expect("lisible").is_empty());
    assert!(!parse_query(b"since=1").expect("lisible").is_empty());
}

/// **TOUT CE QUI N'EST PAS COMPRIS EST REFUSÉ**, et non ignoré : un `limt=10`
/// ignoré rendrait cinquante messages, et personne ne saurait pourquoi.
#[test]
fn tout_ce_qui_n_est_pas_compris_est_refuse() {
    for brut in [
        &b"limt=10"[..],
        b"limit",
        b"limit=",
        b"=10",
        b"limit=0",
        b"limit=65536",
        b"limit=010",
        b"limit=1e3",
        b"limit=-1",
        b"limit=10&limit=20",
        b"before=1&before=2",
        b"since=1&since=2",
        b"before=4294967296",
        // Le dépassement par l'ADDITION du dernier chiffre…
        b"since=18446744073709551616",
        // …et par la MULTIPLICATION, avant même lui : deux chemins distincts.
        b"since=99999999999999999999",
        b"limit=10&",
        b"&limit=10",
        b"limit=10&&since=1",
        b"LIMIT=10",
        b"limit=%31",
    ] {
        assert_eq!(
            parse_query(brut).err().map(Error::reason),
            Some(Reason::BadQuery),
            "`{}`",
            std::string::String::from_utf8_lossy(brut)
        );
    }
}
