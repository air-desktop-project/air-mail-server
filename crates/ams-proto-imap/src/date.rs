// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La date-heure d'IMAP (RFC 9051 §9, `date-time`).
//!
//! `"29-Aug-2026 07:08:31 +0200"` — le même format que celui qu'`INTERNALDATE`
//! rend, et qu'un `APPEND` peut donner. **Lire ce qu'on écrit** est la moindre
//! des cohérences : un client qui reprend la date qu'on lui a rendue doit
//! pouvoir nous la rendre.

/// Lit une date-heure IMAP, et rend les secondes depuis l'époque.
///
/// Les guillemets sont admis, et attendus : §9 les impose.
#[must_use]
pub fn parse_date_time(texte: &[u8]) -> Option<u64> {
    let texte = texte.trim_ascii();
    let texte = texte.strip_prefix(b"\"")?;
    let texte = texte.strip_suffix(b"\"")?;
    // `d-Mon-yyyy HH:MM:SS +ZZZZ`, le jour pouvant être précédé d'un espace.
    let texte = texte.trim_ascii_start();
    let mut morceaux = texte.split(|octet| *octet == b' ');
    let date = morceaux.next().unwrap_or_default();
    let heure = morceaux.next().unwrap_or_default();
    let zone = morceaux.next().unwrap_or_default();
    if morceaux.next().is_some() {
        return None;
    }

    let mut champs = date.split(|octet| *octet == b'-');
    let jour = nombre(champs.next().unwrap_or_default())?;
    let mois = mois_de(champs.next().unwrap_or_default())?;
    let annee = nombre(champs.next().unwrap_or_default())?;
    if champs.next().is_some() || !(1..=31).contains(&jour) || !(1970..=9999).contains(&annee) {
        return None;
    }

    let mut parts = heure.split(|octet| *octet == b':');
    let heures = nombre(parts.next().unwrap_or_default())?;
    let minutes = nombre(parts.next().unwrap_or_default())?;
    let secondes = nombre(parts.next().unwrap_or_default())?;
    if parts.next().is_some() || heures > 23 || minutes > 59 || secondes > 60 {
        return None;
    }

    // LE DÉCALAGE SE RETRANCHE, il ne s'ajoute pas : `+0200` dit que l'heure
    // écrite est en avance de deux heures sur l'universel. L'ajouter ferait
    // vieillir chaque message de deux heures à chaque passage.
    let (signe, chiffres) = match zone.split_first() {
        Some((b'+', suite)) => (1_i64, suite),
        Some((b'-', suite)) => (-1_i64, suite),
        _ => return None,
    };
    // QUATRE CHIFFRES, ET ON LES LIT COMME DES `i64` : les convertir depuis un
    // `u64` demanderait de se garder d'un débordement que deux chiffres
    // excluent, c'est-à-dire d'écrire une garde qu'aucune entrée n'emprunte.
    let zone_heures = deux_chiffres(chiffres.get(..2).unwrap_or_default())?;
    let zone_minutes = deux_chiffres(chiffres.get(2..).unwrap_or_default())?;
    if chiffres.len() != 4 || zone_heures > 23 || zone_minutes > 59 {
        return None;
    }
    let decalage = signe.saturating_mul(
        zone_heures
            .saturating_mul(3600)
            .saturating_add(zone_minutes.saturating_mul(60)),
    );

    // L'ANNÉE EST BORNÉE À QUATRE CHIFFRES, donc le total tient largement dans
    // un `u64` : les additions ne peuvent pas déborder, et s'en garder serait
    // encore une garde qu'aucune entrée n'emprunte. Seule la SOUSTRACTION du
    // décalage peut passer sous l'époque, et celle-là se vérifie.
    let jours = jours_depuis_l_epoque(annee, mois, jour);
    let local = jours
        .saturating_mul(86_400)
        .saturating_add(heures.saturating_mul(3600))
        .saturating_add(minutes.saturating_mul(60))
        .saturating_add(secondes);
    let universel = i64::try_from(local)
        .unwrap_or(i64::MAX)
        .saturating_sub(decalage);
    u64::try_from(universel).ok()
}

/// Lit un nombre décimal, sans débordement.
fn nombre(mot: &[u8]) -> Option<u64> {
    if mot.is_empty() || !mot.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut valeur = 0_u64;
    for chiffre in mot {
        valeur = valeur
            .checked_mul(10)?
            .checked_add(u64::from(chiffre.saturating_sub(b'0')))?;
    }
    Some(valeur)
}

/// Lit exactement deux chiffres décimaux, en `i64`.
fn deux_chiffres(mot: &[u8]) -> Option<i64> {
    let (dizaines, unites) = match mot {
        [dizaines, unites] => (*dizaines, *unites),
        _ => return None,
    };
    if !dizaines.is_ascii_digit() || !unites.is_ascii_digit() {
        return None;
    }
    Some(
        i64::from(dizaines.saturating_sub(b'0'))
            .saturating_mul(10)
            .saturating_add(i64::from(unites.saturating_sub(b'0'))),
    )
}

/// Le rang d'un mois, à partir de un.
fn mois_de(mot: &[u8]) -> Option<u64> {
    const MOIS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    MOIS.iter()
        .position(|nom| mot.eq_ignore_ascii_case(nom))
        .map(|rang| (rang as u64).saturating_add(1))
}

/// Le nombre de jours entre l'époque et une date civile (Howard Hinnant).
fn jours_depuis_l_epoque(annee: u64, mois: u64, jour: u64) -> u64 {
    let annee = if mois <= 2 {
        annee.saturating_sub(1)
    } else {
        annee
    };
    let ere = annee / 400;
    let an_de_l_ere = annee.saturating_sub(ere.saturating_mul(400));
    let mois_decale = if mois > 2 {
        mois.saturating_sub(3)
    } else {
        mois.saturating_add(9)
    };
    let jour_de_l_an = (mois_decale.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(jour.saturating_sub(1));
    let jour_de_l_ere = an_de_l_ere
        .saturating_mul(365)
        .saturating_add(an_de_l_ere / 4)
        .saturating_sub(an_de_l_ere / 100)
        .saturating_add(jour_de_l_an);
    ere.saturating_mul(146_097)
        .saturating_add(jour_de_l_ere)
        .saturating_sub(719_468)
}

#[cfg(test)]
mod tests;
