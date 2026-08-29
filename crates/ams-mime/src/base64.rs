//! Le base64 d'un CORPS MIME (RFC 2045 §6.8).
//!
//! # Pourquoi c'est le troisième de ce dépôt
//!
//! `ams-sasl` en a un — en décodage seul, strict, sans blancs. `ams-dkim` en a
//! un autre — qui saute les blancs du pliage à la lecture, et qui replie en
//! `CRLF` **suivi d'une espace** à l'écriture, parce qu'une valeur d'étiquette
//! DKIM vit à l'intérieur d'un en-tête.
//!
//! Celui-ci replie en `CRLF` **seul**, parce qu'un corps MIME n'est pas un
//! en-tête : l'espace de continuation ferait partie des données, et le fichier
//! décodé ne serait plus celui qu'on a encodé.
//!
//! Trois usages, trois règles de pliage, trois analyseurs. Les partager ferait
//! qu'un jour, en corrigeant l'un, on casserait les deux autres — et rien ne le
//! dirait avant qu'un rapport ne soit illisible chez son destinataire.

use crate::Error;

/// La longueur d'une ligne de base64 dans un corps (RFC 2045 §6.8).
///
/// Soixante-seize caractères : la RFC borne à 76, et c'est un multiple de
/// quatre — donc un nombre entier de groupes, ce qui évite de couper un
/// quadruplet en deux.
pub const BASE64_LINE: usize = 76;

/// Ce qu'il faut au plus pour encoder `octets`.
///
/// Quatre caractères pour trois octets, arrondi au groupe supérieur, plus deux
/// octets de fin de ligne toutes les 76 colonnes, plus un `CRLF` final.
#[must_use]
pub fn base64_max(octets: usize) -> usize {
    let groupes = octets.div_ceil(3);
    let caracteres = groupes.saturating_mul(4);
    let lignes = caracteres.div_ceil(BASE64_LINE).max(1);
    caracteres.saturating_add(lignes.saturating_mul(2))
}

/// Encode en base64, une ligne tous les [`BASE64_LINE`] caractères.
///
/// Chaque ligne, la dernière comprise, se termine par un `CRLF` : un corps MIME
/// est fait de lignes, et une dernière ligne sans fin serait recollée à ce qui
/// suit — ici, le délimiteur de partie.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas ; voir [`base64_max`].
pub fn encode_base64<'b>(valeur: &[u8], sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut ecrits = 0_usize;
    let mut colonne = 0_usize;

    for groupe in valeur.chunks(3) {
        // `split_at_mut` porte la borne dans le type : `chunks(3)` ne rend
        // jamais plus de trois octets, et le dire ainsi évite une garde
        // qu'aucune entrée ne pourrait emprunter.
        let mut trois = [0_u8; 3];
        let (cible, _) = trois.split_at_mut(groupe.len());
        cible.copy_from_slice(groupe);
        let paquet = (u32::from(trois[0]) << 16) | (u32::from(trois[1]) << 8) | u32::from(trois[2]);
        for rang in 0..4_usize {
            let lettre = if rang > groupe.len() {
                b'='
            } else {
                let decalage =
                    18_u32.saturating_sub(u32::try_from(rang).unwrap_or(0).saturating_mul(6));
                let sextet = usize::try_from((paquet >> decalage) & 0x3F).unwrap_or(0);
                ALPHABET[sextet & 0x3F]
            };
            ecrits = poser(sortie, ecrits, lettre)?;
            colonne = colonne.saturating_add(1);
            if colonne == BASE64_LINE {
                ecrits = poser(sortie, ecrits, b'\r')?;
                ecrits = poser(sortie, ecrits, b'\n')?;
                colonne = 0;
            }
        }
    }
    // La dernière ligne a sa fin, même incomplète — et le corps vide en a une
    // aussi : une partie MIME sans ligne n'est pas une partie sans contenu,
    // c'est une partie qu'on a oublié de terminer.
    if colonne > 0 || ecrits == 0 {
        ecrits = poser(sortie, ecrits, b'\r')?;
        ecrits = poser(sortie, ecrits, b'\n')?;
    }
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Écrit un octet, et rend le nouveau compte.
fn poser(sortie: &mut [u8], ecrits: usize, octet: u8) -> Result<usize, Error> {
    let place = sortie.get_mut(ecrits).ok_or(Error::BufferTooSmall)?;
    *place = octet;
    Ok(ecrits.saturating_add(1))
}

#[cfg(test)]
mod tests;
