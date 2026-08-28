//! Domaines et littéraux d'adresse (RFC 5321 §4.1.2).

use crate::{Error, Limits};

/// Comment un client s'est nommé dans `EHLO` ou `HELO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientId<'a> {
    /// Un nom de domaine.
    Domain(&'a [u8]),
    /// Un littéral d'adresse, **chevrons carrés compris** : `[192.0.2.1]`.
    AddressLiteral(&'a [u8]),
}

impl<'a> ClientId<'a> {
    /// Valide un domaine ou un littéral d'adresse.
    ///
    /// Exposé parce que le domaine d'un serveur, celui qu'il annonce dans sa
    /// bannière, doit franchir la MÊME grammaire que celui d'un client. Deux
    /// validateurs pour une seule grammaire finissent par diverger.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedDomain`], [`Error::MalformedAddressLiteral`] ou
    /// [`Error::DomainTooLong`].
    pub fn parse(octets: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        parse_client_id(octets, limits)
    }

    /// Les octets tels qu'ils ont été reçus.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            ClientId::Domain(octets) | ClientId::AddressLiteral(octets) => octets,
        }
    }
}

/// Valide un domaine ou un littéral d'adresse.
///
/// # Errors
///
/// [`Error::MalformedDomain`], [`Error::MalformedAddressLiteral`] ou
/// [`Error::DomainTooLong`].
pub fn parse_client_id<'a>(octets: &'a [u8], limits: &Limits) -> Result<ClientId<'a>, Error> {
    if octets.len() > limits.max_domain_octets {
        return Err(Error::DomainTooLong {
            limit: limits.max_domain_octets,
        });
    }
    match octets {
        [b'[', ..] => {
            check_address_literal(octets)?;
            Ok(ClientId::AddressLiteral(octets))
        }
        _ => {
            check_domain(octets)?;
            Ok(ClientId::Domain(octets))
        }
    }
}

/// Un domaine : des étiquettes `let-dig [ldh-str let-dig]` séparées par des points.
///
/// # Errors
///
/// [`Error::MalformedDomain`].
pub fn check_domain(octets: &[u8]) -> Result<(), Error> {
    // Pas de garde sur le vide, pour la même raison qu'en `check_dot_string` :
    // `[].split(p)` rend une tranche vide, dont `first()` est `None`.
    for etiquette in octets.split(|&b| b == b'.') {
        // Une étiquette vide vient d'un point en tête, en queue, ou doublé.
        let (Some(&premier), Some(&dernier)) = (etiquette.first(), etiquette.last()) else {
            return Err(Error::MalformedDomain);
        };
        // RFC 5321 §4.1.2 : une étiquette commence et finit par une lettre ou un
        // chiffre. Le tiret au bord ouvre la porte aux noms qui ressemblent à des
        // options de ligne de commande, et aux confusions d'affichage.
        if !premier.is_ascii_alphanumeric() || !dernier.is_ascii_alphanumeric() {
            return Err(Error::MalformedDomain);
        }
        // RFC 1035 §2.3.4 : 63 octets par étiquette. Le total est borné par
        // l'appelant, qui connaît `max_domain_octets`.
        if etiquette.len() > 63 {
            return Err(Error::MalformedDomain);
        }
        if !etiquette
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::MalformedDomain);
        }
    }
    Ok(())
}

/// Un littéral d'adresse : `[192.0.2.1]` ou `[IPv6:2001:db8::1]`.
///
/// # Ce qui est vérifié, et ce qui ne l'est pas
///
/// IPv4 est validé **entièrement** : quatre nombres décimaux de 0 à 255, sans
/// zéro de tête. Le zéro de tête n'est pas un détail — `[192.0.2.010]` se lit
/// `10` en décimal et `8` en octal selon l'implémentation, et cette divergence-là
/// a déjà servi à contourner des listes d'accès.
///
/// IPv6 n'est validé qu'en **forme** : le préfixe `IPv6:`, puis des chiffres
/// hexadécimaux, des deux-points et des points. La grammaire complète de la
/// RFC 4291 (compression `::`, adresses mixtes) n'est **pas** implémentée, et
/// cette crate ne prétend donc pas rejeter tout ce qui n'est pas une adresse.
///
/// # Errors
///
/// [`Error::MalformedAddressLiteral`].
pub fn check_address_literal(octets: &[u8]) -> Result<(), Error> {
    let [b'[', interieur @ .., b']'] = octets else {
        return Err(Error::MalformedAddressLiteral);
    };
    if let Some(adresse) = strip_prefix_ci(interieur, b"IPv6:") {
        return check_ipv6_shape(adresse);
    }
    check_ipv4(interieur)
}

/// Quatre nombres décimaux de 0 à 255, sans zéro de tête.
fn check_ipv4(octets: &[u8]) -> Result<(), Error> {
    let mut vus = 0_usize;
    for morceau in octets.split(|&b| b == b'.') {
        vus = vus.saturating_add(1);
        if vus > 4 {
            return Err(Error::MalformedAddressLiteral);
        }
        let valide = match morceau {
            [] => false,
            // Un zéro seul est licite ; un zéro DE TÊTE ne l'est pas.
            [b'0'] => true,
            [b'0', ..] => false,
            chiffres if chiffres.len() <= 3 => {
                chiffres.iter().all(u8::is_ascii_digit) && valeur_decimale(chiffres) <= 255
            }
            _ => false,
        };
        if !valide {
            return Err(Error::MalformedAddressLiteral);
        }
    }
    if vus == 4 {
        Ok(())
    } else {
        Err(Error::MalformedAddressLiteral)
    }
}

/// La valeur d'au plus trois chiffres décimaux. Ne peut pas déborder.
fn valeur_decimale(chiffres: &[u8]) -> u32 {
    chiffres.iter().fold(0_u32, |acc, &b| {
        acc.saturating_mul(10)
            .saturating_add(u32::from(b.wrapping_sub(b'0')))
    })
}

/// La **forme** d'une adresse IPv6, et rien de plus (cf. [`check_address_literal`]).
fn check_ipv6_shape(octets: &[u8]) -> Result<(), Error> {
    if octets.is_empty() {
        return Err(Error::MalformedAddressLiteral);
    }
    if octets
        .iter()
        .all(|&b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    {
        Ok(())
    } else {
        Err(Error::MalformedAddressLiteral)
    }
}

/// Retire un préfixe sans tenir compte de la casse.
pub fn strip_prefix_ci<'a>(octets: &'a [u8], prefixe: &[u8]) -> Option<&'a [u8]> {
    let (debut, reste) = octets.split_at_checked(prefixe.len())?;
    if debut.eq_ignore_ascii_case(prefixe) {
        Some(reste)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientId, check_address_literal, check_domain, parse_client_id, strip_prefix_ci};
    use crate::{Error, Limits};

    fn analyser(octets: &[u8]) -> Result<ClientId<'_>, Error> {
        parse_client_id(octets, &Limits::DEFAULT)
    }

    #[test]
    fn la_validation_publique_est_celle_qui_sert_en_interne() {
        assert_eq!(
            ClientId::parse(b"example.com", &Limits::DEFAULT),
            analyser(b"example.com")
        );
    }

    #[test]
    fn un_domaine_ordinaire_passe() {
        let id = analyser(b"mail.example.com").expect("recevable");
        assert_eq!(id, ClientId::Domain(b"mail.example.com"));
        assert_eq!(id.as_bytes(), b"mail.example.com");
    }

    #[test]
    fn un_litteral_ipv4_passe_et_se_distingue_d_un_domaine() {
        let id = analyser(b"[192.0.2.1]").expect("recevable");
        assert_eq!(id, ClientId::AddressLiteral(b"[192.0.2.1]"));
        assert_eq!(id.as_bytes(), b"[192.0.2.1]");
    }

    #[test]
    fn un_domaine_trop_long_est_refuse() {
        let bornes = Limits {
            max_domain_octets: 4,
            ..Limits::DEFAULT
        };
        assert_eq!(
            parse_client_id(b"example.com", &bornes),
            Err(Error::DomainTooLong { limit: 4 })
        );
    }

    #[test]
    fn les_domaines_mal_formes_sont_refuses() {
        for mauvais in [
            b"".as_slice(),
            b".example.com", // point de tête
            b"example.com.", // point de queue
            b"example..com", // point doublé
            b"-example.com", // tiret en tête d'étiquette
            b"example-.com", // tiret en queue d'étiquette
            b"exa_mple.com", // souligné hors de l'alphabet
        ] {
            assert_eq!(
                check_domain(mauvais),
                Err(Error::MalformedDomain),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn une_etiquette_de_plus_de_63_octets_est_refusee() {
        // RFC 1035 §2.3.4.
        let mut nom = std::vec![b'a'; 64];
        nom.extend_from_slice(b".com");
        assert_eq!(check_domain(&nom), Err(Error::MalformedDomain));

        let mut juste = std::vec![b'a'; 63];
        juste.extend_from_slice(b".com");
        assert!(check_domain(&juste).is_ok());
    }

    #[test]
    fn le_zero_de_tete_d_un_litteral_ipv4_est_refuse() {
        // `[192.0.2.010]` vaut 10 en décimal et 8 en octal selon le lecteur.
        assert_eq!(
            check_address_literal(b"[192.0.2.010]"),
            Err(Error::MalformedAddressLiteral)
        );
        // Un zéro SEUL reste licite.
        assert!(check_address_literal(b"[192.0.2.0]").is_ok());
    }

    #[test]
    fn les_litteraux_mal_formes_sont_refuses() {
        for mauvais in [
            b"[192.0.2.1".as_slice(), // crochet fermant manquant
            b"[]",                    // vide
            b"[192.0.2]",             // trois nombres
            b"[192.0.2.1.5]",         // cinq nombres
            b"[192.0.2.]",            // morceau vide
            b"[192.0.2.256]",         // au-delà de 255
            b"[192.0.2.1234]",        // plus de trois chiffres
            b"[192.0.2.x]",           // pas un chiffre
            b"[IPv6:]",               // vide après le préfixe
            b"[IPv6:zzz]",            // hors de l'hexadécimal
        ] {
            assert_eq!(
                check_address_literal(mauvais),
                Err(Error::MalformedAddressLiteral),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn la_forme_ipv6_est_acceptee_le_prefixe_a_la_casse_pres() {
        assert!(check_address_literal(b"[IPv6:2001:db8::1]").is_ok());
        assert!(check_address_literal(b"[ipv6:2001:db8::1]").is_ok());
        // Adresse mixte : les points sont admis par la FORME.
        assert!(check_address_literal(b"[IPv6:::ffff:192.0.2.1]").is_ok());
    }

    #[test]
    fn le_retrait_de_prefixe_ignore_la_casse_et_les_tranches_courtes() {
        assert_eq!(strip_prefix_ci(b"IPv6:x", b"ipv6:"), Some(b"x".as_slice()));
        assert_eq!(strip_prefix_ci(b"IPv4:x", b"ipv6:"), None);
        assert_eq!(strip_prefix_ci(b"ip", b"ipv6:"), None);
    }
}
