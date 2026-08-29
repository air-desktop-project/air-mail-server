//! Le base64 de DKIM (RFC 6376 §3.5), **strict dans les deux sens**.
//!
//! # Une seule écriture par valeur
//!
//! `Zg==` et `Zh==` décodent tous deux vers `f`. Accepter le second donnerait
//! plusieurs formes pour un même condensat — de quoi passer à côté d'une
//! comparaison, ou d'un journal. Les bits de remplissage doivent donc être nuls,
//! et le remplissage présent.
//!
//! C'est la même exigence que celle d'`ams-sasl` sur le base64 de `PLAIN`, et
//! pour la même raison. Les deux ne partagent pas de code : celui-ci saute les
//! blancs du pliage, ce que l'autre doit refuser.

use crate::Error;

/// Décode du base64 **strict**, et rend le nombre d'octets écrits.
///
/// # Une seule écriture par valeur
///
/// Les bits de remplissage doivent être nuls, et le remplissage doit être
/// présent. Sans cela, un même condensat s'écrirait de plusieurs façons — de
/// quoi passer à côté d'une comparaison, ou d'un journal.
///
/// # Errors
///
/// [`Error::MalformedBase64`] ou [`Error::BufferTooSmall`].
pub fn decoder_base64(valeur: &[u8], sortie: &mut [u8]) -> Result<usize, Error> {
    let mut ecrits = 0_usize;
    let mut accumulateur = 0_u32;
    let mut bits = 0_u32;
    let mut remplissage = 0_usize;

    for octet in valeur {
        if octet.is_ascii_whitespace() {
            continue;
        }
        if *octet == b'=' {
            remplissage = remplissage.saturating_add(1);
            continue;
        }
        if remplissage > 0 {
            // Des données APRÈS le remplissage : ce n'est pas un encodage, c'est
            // deux valeurs collées.
            return Err(Error::MalformedBase64);
        }
        let valeur6 = valeur_base64(*octet).ok_or(Error::MalformedBase64)?;
        accumulateur = (accumulateur << 6) | u32::from(valeur6);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            let case = sortie.get_mut(ecrits).ok_or(Error::BufferTooSmall)?;
            *case = u8::try_from((accumulateur >> bits) & 0xFF).unwrap_or(0);
            ecrits = ecrits.saturating_add(1);
        }
    }

    // Les bits qui restent doivent être NULS : `Zg==` et `Zh==` décodent tous
    // deux vers `f`, et accepter le second donnerait plusieurs formes pour un
    // même condensat.
    let masque = 1_u32.checked_shl(bits).unwrap_or(0).saturating_sub(1);
    if bits >= 6 || (accumulateur & masque) != 0 {
        return Err(Error::MalformedBase64);
    }
    // Le remplissage complète le dernier groupe, et pas davantage.
    let attendu = match bits {
        0 => 0,
        _ => 4_usize.saturating_sub((ecrits % 3).saturating_add(1)),
    };
    if remplissage != attendu {
        return Err(Error::MalformedBase64);
    }
    Ok(ecrits)
}

fn valeur_base64(octet: u8) -> Option<u8> {
    match octet {
        b'A'..=b'Z' => Some(octet.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(octet.wrapping_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0').saturating_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Le base64 d'un condensat SHA-256 : **quarante-quatre octets, toujours**.
///
/// # Pourquoi une fonction à part, plutôt qu'un tampon et un `?`
///
/// Trente-deux octets font quarante-quatre caractères, remplissage compris. Ce
/// n'est pas « en général » : c'est arithmétique. Une fonction qui rendrait un
/// `Result` ferait porter à l'appelant une garde qu'aucune entrée ne pourrait
/// emprunter — et une garde inatteignable n'est pas une garde.
pub(crate) fn condensat_en_base64(condensat: &[u8; 32]) -> [u8; 44] {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Le remplissage est déjà là : trente-deux octets n'en laissent qu'un seul,
    // et `zip` s'arrêtera avant de l'écraser.
    let mut sortie = [b'='; 44];
    let lettres = condensat.chunks(3).flat_map(|groupe| {
        let mut trois = [0_u8; 3];
        let (cible, _) = trois.split_at_mut(groupe.len());
        cible.copy_from_slice(groupe);
        let paquet = (u32::from(trois[0]) << 16) | (u32::from(trois[1]) << 8) | u32::from(trois[2]);
        // Un groupe de `n` octets rend `n + 1` caractères.
        [0_u32, 1, 2, 3]
            .map(|rang| {
                let decalage = 18_u32.saturating_sub(rang.saturating_mul(6));
                ALPHABET[usize::try_from((paquet >> decalage) & 0x3F).unwrap_or(0)]
            })
            .into_iter()
            .take(groupe.len().saturating_add(1))
    });
    for (case, lettre) in sortie.iter_mut().zip(lettres) {
        *case = lettre;
    }
    sortie
}

/// Encode en base64, **replié** tous les `largeur` caractères.
///
/// Le pliage écrit un `CRLF` suivi d'une espace : c'est un repli de la RFC 5322
/// §2.2.3, et il vit à l'intérieur d'une valeur d'étiquette, que la
/// canonicalisation traversera sans y toucher.
///
/// `largeur` à zéro n'en insère aucun.
///
/// # Errors
///
/// [`Error::BufferTooSmall`].
pub fn encoder_base64<'b>(
    valeur: &[u8],
    largeur: usize,
    sortie: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut ecrits = 0_usize;
    let mut depuis_le_repli = 0_usize;

    let mut pousser = |octet: u8, ecrits: &mut usize, depuis: &mut usize| -> Result<(), Error> {
        if largeur > 0 && *depuis >= largeur {
            for repli in b"\r\n " {
                let case = sortie.get_mut(*ecrits).ok_or(Error::BufferTooSmall)?;
                *case = *repli;
                *ecrits = ecrits.saturating_add(1);
            }
            *depuis = 0;
        }
        let case = sortie.get_mut(*ecrits).ok_or(Error::BufferTooSmall)?;
        *case = octet;
        *ecrits = ecrits.saturating_add(1);
        *depuis = depuis.saturating_add(1);
        Ok(())
    };

    for groupe in valeur.chunks(3) {
        // Trois octets font quatre sextets ; un groupe incomplet se complète de
        // zéros, et le remplissage dit combien.
        // `split_at_mut` porte la borne dans le type : `chunks(3)` ne rend
        // jamais plus de trois octets, et le dire ainsi évite une garde
        // qu'aucune entrée ne pourrait emprunter.
        let mut trois = [0_u8; 3];
        let (cible, _) = trois.split_at_mut(groupe.len());
        cible.copy_from_slice(groupe);
        let paquet = (u32::from(trois[0]) << 16) | (u32::from(trois[1]) << 8) | u32::from(trois[2]);
        for rang in 0..4_usize {
            if rang > groupe.len() {
                pousser(b'=', &mut ecrits, &mut depuis_le_repli)?;
                continue;
            }
            let decalage =
                18_u32.saturating_sub(u32::try_from(rang).unwrap_or(0).saturating_mul(6));
            // Six bits : le rang est inférieur à soixante-quatre par
            // construction, et l'alphabet en compte soixante-quatre.
            let sextet = usize::try_from((paquet >> decalage) & 0x3F).unwrap_or(0);
            let lettre = ALPHABET[sextet & 0x3F];
            pousser(lettre, &mut ecrits, &mut depuis_le_repli)?;
        }
    }
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

#[cfg(test)]
mod tests;
