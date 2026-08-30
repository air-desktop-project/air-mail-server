// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le préfixe d'une section de champs (RFC 9204 §4.5.1).
//!
//! # DEUX NOMBRES QUI DISENT CE QU'IL FAUT AVOIR REÇU AVANT DE LIRE
//!
//! Chaque section de champs commence par deux entiers : combien d'insertions il
//! faut avoir vues pour la lire, et à partir de quel rang ses index relatifs se
//! comptent. **C'est tout ce qui remplace l'ordre que TCP donnait à HPACK.**
//!
//! Un décodeur qui reçoit une section dont le compte d'insertions dépasse ce
//! qu'il a reçu ne la lit pas : il attend. C'est le seul blocage que QPACK
//! admet, il est explicite, et le pair l'a annoncé — `SETTINGS_QPACK_BLOCKED_STREAMS`
//! dit combien on en accepte.
//!
//! # LE COMPTE EST ÉCRIT MODULO, ET LA RECONSTRUCTION EST DÉLICATE
//!
//! §4.5.1.1 n'écrit pas le compte tel quel : il l'écrit modulo deux fois le
//! nombre d'entrées que la table peut porter. C'est ce qui lui permet de tenir
//! sur un octet là où le compte absolu croît sans fin — et c'est la même idée
//! que le numéro de paquet tronqué de QUIC, avec la même conséquence : **une
//! reconstruction fausse ne se voit pas, elle décale simplement toute la
//! table.**

use ams_field_codec::decode_integer;

use crate::error::{Error, Reason};

/// Ce qu'un préfixe de section a dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// Combien d'insertions il faut avoir reçues pour lire cette section.
    pub required_insert_count: u64,
    /// Le rang à partir duquel les index relatifs se comptent.
    pub base: u64,
    /// Ce que le préfixe a occupé.
    pub read: usize,
}

/// Combien d'entrées une table de cette capacité peut porter (§3.2.2).
///
/// Une entrée coûte au moins trente-deux octets — ce sont les mêmes
/// trente-deux qu'HPACK compte, et ils représentent ce qu'une entrée coûte à
/// retenir, non ce qu'elle pèse sur le fil.
#[must_use]
pub const fn max_entries(capacite: u64) -> u64 {
    capacite / 32
}

/// Lit le préfixe d'une section de champs.
///
/// `inserees` est le nombre total d'insertions que le décodeur a reçues,
/// `capacite` la capacité de sa table dynamique.
///
/// # L'ALGORITHME DE §4.5.1.1, À LA LETTRE
///
/// Le compte écrit vaut `(compte mod 2*maxEntries) + 1`, ou zéro s'il n'y a
/// aucune dépendance. Le reconstruire demande de savoir combien d'insertions on
/// a reçues — c'est ce qui borne la fenêtre — puis de choisir entre deux tours
/// possibles. **Les deux gardes de bord ne sont pas décoratives** : sans elles,
/// une section reconstruirait un compte que le pair n'a pas écrit, et lirait
/// toute sa table décalée.
///
/// # Errors
///
/// [`Reason::Truncated`] ; [`Reason::BadInsertCount`] si le compte écrit sort de
/// la fenêtre, ou si la reconstruction ne tombe pas dedans.
pub fn read_prefix(octets: &[u8], inserees: u64, capacite: u64) -> Result<Prefix, Error> {
    let tronque = || Error::new(Reason::Truncated);
    let faute = || Error::new(Reason::BadInsertCount);
    let (ecrit, lus) = decode_integer(octets, 8).map_err(|_| tronque())?;
    let suite = octets.get(lus..).unwrap_or_default();
    let (delta, encore) = decode_integer(suite, 7).map_err(|_| tronque())?;
    // §4.5.1.2 : le bit de tête du second octet dit de quel côté le rang se
    // compte. Il vit sous le préfixe de sept bits, et `decode_integer` l'ignore.
    let signe = suite.first().is_some_and(|premier| premier & 0x80 != 0);

    let required_insert_count = reconstruire(u64::from(ecrit), inserees, capacite)?;
    let delta = u64::from(delta);
    // §4.5.1.2 : `S` à zéro, le rang est AU-DESSUS du compte ; à un, en dessous.
    // Se tromper de côté ferait lire chaque index relatif à côté de sa cible.
    let base = match signe {
        false => required_insert_count.saturating_add(delta),
        true => required_insert_count
            .checked_sub(delta)
            .and_then(|reste| reste.checked_sub(1))
            .ok_or_else(faute)?,
    };
    Ok(Prefix {
        required_insert_count,
        base,
        read: lus.saturating_add(encore),
    })
}

/// Reconstruit le compte d'insertions (§4.5.1.1).
fn reconstruire(ecrit: u64, inserees: u64, capacite: u64) -> Result<u64, Error> {
    let faute = || Error::new(Reason::BadInsertCount);
    // Zéro veut dire : cette section ne dépend d'aucune insertion. C'est le cas
    // le plus fréquent, et le seul qui ne bloque jamais.
    if ecrit == 0 {
        return Ok(0);
    }
    let fenetre = max_entries(capacite).saturating_mul(2);
    if ecrit > fenetre {
        return Err(faute());
    }
    let plafond = inserees.saturating_add(max_entries(capacite));
    // Le multiple de la fenêtre immédiatement sous le plafond.
    // La fenêtre ne peut pas être nulle ici : un compte écrit non nul avec une
    // fenêtre nulle a déjà été refusé deux lignes plus haut. `unwrap_or` porte
    // cette impossibilité dans la bibliothèque plutôt que dans une branche
    // qu'aucune entrée ne peut emprunter.
    let tours = plafond.checked_div(fenetre).unwrap_or(0);
    let base = tours.saturating_mul(fenetre);
    let mut compte = base.saturating_add(ecrit).saturating_sub(1);
    if compte > plafond {
        // Le tour d'avant, alors — mais seulement s'il existe.
        if compte <= fenetre {
            return Err(faute());
        }
        compte = compte.saturating_sub(fenetre);
    }
    // **ZÉRO NE PEUT PAS SORTIR D'ICI** : on a déjà rendu le zéro écrit plus
    // haut, et un compte reconstruit à zéro veut dire que la reconstruction
    // s'est trompée de tour.
    match compte {
        0 => Err(faute()),
        _ => Ok(compte),
    }
}

#[cfg(test)]
mod tests;
