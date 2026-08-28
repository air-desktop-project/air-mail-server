//! Base64 (RFC 4648), en **décodage seul** et **strict**.
//!
//! # Pourquoi seulement le décodage
//!
//! Le serveur décode ce qu'un pair lui envoie ; il n'a rien à encoder. Le défi
//! du mécanisme `PLAIN` est vide, et une ligne `334` sans défi ne porte aucun
//! base64. Écrire un encodeur maintenant serait écrire du code que rien
//! n'appelle et que rien n'éprouve.
//!
//! # Pourquoi STRICT, et ce que la tolérance coûterait
//!
//! Refusé : tout caractère hors alphabet (**y compris l'espace et le saut de
//! ligne**), une longueur qui n'est pas un multiple de quatre, un remplissage
//! ailleurs qu'à la fin, et surtout **un remplissage non canonique**.
//!
//! Ce dernier point mérite son explication. `dGVzdA==` et `dGVzdB==` décodent
//! tous deux vers `test` : les bits de poids faible du dernier caractère ne sont
//! pas utilisés. Les accepter donnerait **plusieurs écritures pour un même
//! identifiant** — de quoi passer à côté d'un filtre, d'un journal ou d'un
//! comptage qui compare les formes encodées. Une seule écriture par valeur,
//! c'est une chose de moins à ne pas voir.

/// Ce qui rend une chaîne base64 irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Un caractère hors de l'alphabet — espaces et sauts de ligne compris.
    Character,
    /// La longueur n'est pas un multiple de quatre.
    Length,
    /// Remplissage ailleurs qu'à la fin, trop long, ou non canonique.
    Padding,
    /// Le tampon de sortie est trop petit.
    OutputTooSmall,
}

/// Combien d'octets au plus `encoded_len` caractères peuvent produire.
///
/// Sert à dimensionner un tampon **avant** de décoder, sans allouer.
#[must_use]
pub const fn decoded_len(encoded_len: usize) -> usize {
    // `saturating_mul` plutôt qu'un `*` : une longueur venue du réseau ne
    // multiplie rien sans borne. La division précède, donc le produit ne peut
    // pas déborder en pratique — mais « en pratique » n'est pas un argument
    // qu'on écrit dans du code de décodage (C3).
    (encoded_len / 4).saturating_mul(3)
}

/// La valeur d'un caractère de l'alphabet, s'il en fait partie.
///
/// Les soustractions sont en `wrapping_` : chaque bras garantit déjà que le
/// retrait ne déborde pas, et un `checked_sub` y ouvrirait une branche d'erreur
/// que rien ne peut atteindre — ce que C2 refuse.
const fn valeur(octet: u8) -> Option<u8> {
    match octet {
        b'A'..=b'Z' => Some(octet.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(octet.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Décode `entree` dans `sortie`, et rend le nombre d'octets écrits.
///
/// # Errors
///
/// [`Error`] — caractère hors alphabet, longueur incorrecte, remplissage
/// invalide ou non canonique, tampon de sortie trop petit.
pub fn decode(entree: &[u8], sortie: &mut [u8]) -> Result<usize, Error> {
    if !entree.len().is_multiple_of(4) {
        return Err(Error::Length);
    }
    let groupes = entree.len() / 4;
    let mut ecrits = 0_usize;

    for (rang, groupe) in entree.as_chunks::<4>().0.iter().enumerate() {
        let dernier = rang.saturating_add(1) == groupes;
        let mut valeurs = [0_u8; 4];
        let mut remplissage = 0_usize;

        for (position, &octet) in groupe.iter().enumerate() {
            if octet == b'=' {
                remplissage = remplissage.saturating_add(1);
            } else if remplissage == 0 {
                valeurs[position] = valeur(octet).ok_or(Error::Character)?;
            } else {
                // Un caractère APRÈS un `=` : le remplissage n'est pas en fin.
                return Err(Error::Padding);
            }
        }

        // Le remplissage n'existe qu'au dernier groupe, et au plus deux fois.
        // `====` décoderait sinon vers rien, et `dGVz====` vers un préfixe.
        if remplissage > 2 || (remplissage > 0 && !dernier) {
            return Err(Error::Padding);
        }

        // Les bits que le remplissage rend inutiles doivent être NULS, sans
        // quoi une même valeur aurait plusieurs écritures.
        let bavards = match remplissage {
            1 => valeurs[2] & 0b11,
            2 => valeurs[1] & 0b1111,
            _ => 0,
        };
        if bavards != 0 {
            return Err(Error::Padding);
        }

        let octets = [
            (valeurs[0] << 2) | (valeurs[1] >> 4),
            (valeurs[1] << 4) | (valeurs[2] >> 2),
            (valeurs[2] << 6) | valeurs[3],
        ];
        let utiles = 3_usize.saturating_sub(remplissage);
        for &octet in octets.iter().take(utiles) {
            let case = sortie.get_mut(ecrits).ok_or(Error::OutputTooSmall)?;
            *case = octet;
            ecrits = ecrits.saturating_add(1);
        }
    }
    Ok(ecrits)
}

#[cfg(test)]
mod tests {
    use super::{Error, decode, decoded_len};

    /// Décode dans un tampon confortable, et rend la tranche écrite.
    fn decoder<'t>(entree: &[u8], tampon: &'t mut [u8]) -> Result<&'t [u8], Error> {
        let ecrits = decode(entree, tampon)?;
        Ok(&tampon[..ecrits])
    }

    #[test]
    fn les_vecteurs_de_la_rfc_4648_passent() {
        // §10 de la RFC : la table de référence, dans les deux longueurs de
        // remplissage et sans remplissage du tout.
        let attendus: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"Zg==", b"f"),
            (b"Zm8=", b"fo"),
            (b"Zm9v", b"foo"),
            (b"Zm9vYg==", b"foob"),
            (b"Zm9vYmE=", b"fooba"),
            (b"Zm9vYmFy", b"foobar"),
        ];
        let mut tampon = [0_u8; 16];
        for (encode, clair) in attendus {
            assert_eq!(decoder(encode, &mut tampon), Ok(clair), "{encode:?}");
        }
    }

    #[test]
    fn tout_l_alphabet_est_reconnu() {
        // Les soixante-quatre caractères, `+` et `/` compris — ceux que l'on
        // oublie quand on écrit la table à la main.
        let entree = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut tampon = [0_u8; 48];
        let ecrits = decode(entree, &mut tampon).expect("alphabet complet");
        assert_eq!(ecrits, 48);
        // Le dernier groupe `89+/` porte les valeurs 60, 61, 62 et 63, dont les
        // vingt-quatre bits se répartissent en trois octets.
        assert_eq!(&tampon[45..], &[0b1111_0011, 0b1101_1111, 0b1011_1111]);
    }

    #[test]
    fn un_caractere_hors_alphabet_est_refuse() {
        let mut tampon = [0_u8; 8];
        // TOUTES CES ENTRÉES FONT QUATRE OCTETS, et c'est délibéré : avec cinq,
        // elles échoueraient sur la longueur, et le test passerait sans avoir
        // jamais atteint le contrôle de l'alphabet. L'espace et le saut de ligne
        // en font partie — une réponse SASL est une ligne, et ce qui la coupe
        // n'est pas de la donnée.
        for entree in [&b"Zm9 "[..], b"Zm9\n", b"Zm9-", b"Zm9\0", b"Zm9\xE9"] {
            assert_eq!(
                decoder(entree, &mut tampon),
                Err(Error::Character),
                "{entree:?}"
            );
        }
    }

    #[test]
    fn une_longueur_qui_n_est_pas_un_multiple_de_quatre_est_refusee() {
        let mut tampon = [0_u8; 8];
        for entree in [&b"Z"[..], b"Zm", b"Zm9", b"Zm9vZ"] {
            assert_eq!(decoder(entree, &mut tampon), Err(Error::Length));
        }
    }

    #[test]
    fn un_remplissage_mal_place_ou_trop_long_est_refuse() {
        let mut tampon = [0_u8; 8];
        for entree in [
            &b"Zg==Zg=="[..], // remplissage au milieu
            b"Z===",          // trois signes
            b"====",          // quatre
            b"Zg=A",          // un caractère APRÈS le remplissage
        ] {
            assert_eq!(
                decoder(entree, &mut tampon),
                Err(Error::Padding),
                "{entree:?}"
            );
        }
    }

    #[test]
    fn un_remplissage_non_canonique_est_refuse() {
        // `Zh==` et `Zg==` décodent tous deux vers `f` : les deux bits de poids
        // faible ne servent pas. Deux écritures pour une valeur, c'est une de
        // trop.
        let mut tampon = [0_u8; 8];
        assert_eq!(decoder(b"Zg==", &mut tampon), Ok(&b"f"[..]));
        assert_eq!(decoder(b"Zh==", &mut tampon), Err(Error::Padding));
        assert_eq!(decoder(b"Zm8=", &mut tampon), Ok(&b"fo"[..]));
        assert_eq!(decoder(b"Zm9=", &mut tampon), Err(Error::Padding));
    }

    #[test]
    fn un_tampon_trop_petit_est_dit_et_non_debordé() {
        // C3 : la longueur de sortie vient de l'entrée, jamais l'inverse.
        let mut tampon = [0_u8; 2];
        assert_eq!(decode(b"Zm9v", &mut tampon), Err(Error::OutputTooSmall));
        let mut juste = [0_u8; 3];
        assert_eq!(decode(b"Zm9v", &mut juste), Ok(3));
    }

    #[test]
    fn la_taille_annoncee_suffit_toujours() {
        assert_eq!(decoded_len(0), 0);
        assert_eq!(decoded_len(4), 3);
        assert_eq!(decoded_len(8), 6);
        // Et elle majore : avec remplissage, on écrit moins.
        let mut tampon = [0_u8; decoded_len(8)];
        assert_eq!(decode(b"Zm9vYg==", &mut tampon), Ok(4));
    }

    #[test]
    fn les_erreurs_se_comparent() {
        // Pas d'assertion sur `Debug` : la crate est `no_std` SANS `alloc`, donc
        // sans `format!`. Un formatage vers un tampon fixe serait possible, mais
        // ce serait éprouver `core::fmt`, pas ce décodeur.
        assert_eq!(Error::Length, Error::Length);
        assert_ne!(Error::Length, Error::Padding);
        assert_ne!(Error::Character, Error::OutputTooSmall);
    }
}
