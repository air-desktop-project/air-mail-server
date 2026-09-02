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
/// IPv6 est validé **entièrement** depuis le 2026-09-02 : huit groupes de un à
/// quatre chiffres hexadécimaux, une compression `::` au plus, et la forme mixte
/// dont la queue est une adresse IPv4 — celle-ci vérifiée par le MÊME code que
/// `[192.0.2.1]`, zéro de tête compris. Voir [`check_ipv6`].
/// # Errors
///
/// [`Error::MalformedAddressLiteral`].
pub fn check_address_literal(octets: &[u8]) -> Result<(), Error> {
    let [b'[', interieur @ .., b']'] = octets else {
        return Err(Error::MalformedAddressLiteral);
    };
    if let Some(adresse) = strip_prefix_ci(interieur, b"IPv6:") {
        return check_ipv6(adresse);
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

/// Une adresse IPv6 **entière** (RFC 4291 §2.2).
///
/// # POURQUOI VALIDER, ALORS QUE CE SERVEUR NE ROUTE RIEN
///
/// Un littéral d'adresse est ce qu'un pair écrit dans son `EHLO` quand il n'a
/// pas de nom, et il finit dans l'en-tête `Received:` que nous composons. Une
/// chaîne qu'on aurait laissée passer sans la comprendre y serait recopiée
/// telle quelle, et **le prochain lecteur, lui, la comprendra** — journal,
/// filtre, liste d'accès. Deux lecteurs qui ne lisent pas la même adresse dans
/// les mêmes octets, c'est exactement le défaut que le zéro de tête d'IPv4
/// exploite depuis vingt ans.
///
/// La forme seule ne suffisait pas : `[IPv6:2001:db8:::1]`, `[IPv6::::]` et
/// `[IPv6:1:2:3:4:5:6:7:8:9]` passaient, parce que tous leurs octets sont des
/// chiffres hexadécimaux, des deux-points ou des points.
///
/// # LES TROIS FORMES, ET LA SEULE RÈGLE QUI LES TIENT
///
/// Une adresse est **huit groupes** de un à quatre chiffres hexadécimaux. Deux
/// choses peuvent les remplacer :
///
/// - un `::`, **une fois au plus**, qui vaut autant de groupes de zéros qu'il en
///   manque. Deux `::` seraient ambigus — `1::2::3` ne désigne pas une adresse
///   mais plusieurs — et c'est pourquoi il n'y en a qu'un.
/// - une adresse **IPv4** en queue, qui vaut les deux derniers groupes. Elle est
///   vérifiée par [`check_ipv4`], le même code que `[192.0.2.1]` : deux règles
///   pour une même notation finiraient par ne plus dire la même chose, et l'une
///   des deux accepterait le zéro de tête que l'autre refuse.
///
/// # UN ÉCART ASSUMÉ AVEC RFC 5321 §4.1.3
///
/// Son ABNF `IPv6-comp` limite à six groupes autour du `::`, ce qui l'oblige à
/// représenter au moins DEUX groupes de zéros : `1:2:3:4:5:6:7::` y serait
/// interdit. RFC 4291 §2.2 l'autorise, toute pile IP le lit, et le refuser
/// vaudrait un `501` à un pair dont l'adresse est parfaitement valable.
///
/// Contrairement au zéro de tête d'IPv4, **un `::` ne se lit pas de deux
/// façons** : le nombre de groupes manquants est déterminé par ce qui l'entoure.
/// L'écart ne rouvre donc aucune divergence entre lecteurs, et c'est le seul
/// critère qui compte ici.
fn check_ipv6(octets: &[u8]) -> Result<(), Error> {
    // Ni `:` isolé en bordure, ni adresse vide : seul `::` peut border.
    if octets.first() == Some(&b':') && !octets.starts_with(b"::") {
        return Err(Error::MalformedAddressLiteral);
    }
    if octets.last() == Some(&b':') && !octets.ends_with(b"::") {
        return Err(Error::MalformedAddressLiteral);
    }

    // Une queue IPv4 vaut DEUX groupes. On la détache d'abord : ce qui reste est
    // alors une suite de groupes hexadécimaux, et rien d'autre.
    let (hexa, groupes_ipv4) = match derniere_position(octets, b':') {
        Some(rang)
            if octets
                .get(rang.saturating_add(1)..)
                .is_some_and(contient_un_point) =>
        {
            let queue = octets.get(rang.saturating_add(1)..).unwrap_or_default();
            check_ipv4(queue)?;
            // **LA COUPE NE DOIT PAS SCINDER UN `::`.** Dans
            // `64:ff9b::192.0.2.1`, le dernier deux-points est le SECOND de la
            // compression : couper devant lui laisserait un `:` isolé, et
            // l'adresse serait refusée à tort. On garde alors les deux.
            let tete = octets.get(..rang).unwrap_or_default();
            let coupe = if tete.ends_with(b":") {
                rang.saturating_add(1)
            } else {
                rang
            };
            (octets.get(..coupe).unwrap_or_default(), 2_usize)
        }
        // Un point sans deux-points devant n'est pas une adresse IPv6 : c'est
        // une IPv4 qu'on aurait préfixée de `IPv6:`, et la préfixer ne la
        // transforme pas.
        _ if contient_un_point(octets) => return Err(Error::MalformedAddressLiteral),
        _ => (octets, 0_usize),
    };

    // Le `::`, une fois au plus. Deux seraient ambigus.
    let (avant, apres, comprime) = match hexa.windows(2).position(|paire| paire == b"::") {
        Some(rang) => {
            let avant = hexa.get(..rang).unwrap_or_default();
            let apres = hexa.get(rang.saturating_add(2)..).unwrap_or_default();
            if apres.windows(2).any(|paire| paire == b"::") {
                return Err(Error::MalformedAddressLiteral);
            }
            (avant, apres, true)
        }
        None => (hexa, &[][..], false),
    };

    let devant = compter_les_groupes(avant)?;
    let derriere = compter_les_groupes(apres)?;
    let ecrits = devant.saturating_add(derriere).saturating_add(groupes_ipv4);

    if comprime {
        // Le `::` vaut au moins un groupe : il doit rester de la place.
        if ecrits >= 8 {
            return Err(Error::MalformedAddressLiteral);
        }
        return Ok(());
    }
    // Sans compression, le compte doit tomber juste.
    if ecrits == 8 {
        Ok(())
    } else {
        Err(Error::MalformedAddressLiteral)
    }
}

/// Combien de groupes hexadécimaux, ou la faute qui l'en empêche.
///
/// Une suite VIDE ne compte aucun groupe — c'est ce qui borde un `::`. Partout
/// ailleurs, un groupe vide serait un `:` isolé, donc deux-points de trop.
fn compter_les_groupes(octets: &[u8]) -> Result<usize, Error> {
    if octets.is_empty() {
        return Ok(0);
    }
    let mut combien = 0_usize;
    for groupe in octets.split(|octet| *octet == b':') {
        // Un à quatre chiffres hexadécimaux : au-delà, le groupe ne tient pas
        // dans ses seize bits, et le tronquer donnerait une autre adresse.
        if groupe.is_empty() || groupe.len() > 4 || !groupe.iter().all(u8::is_ascii_hexdigit) {
            return Err(Error::MalformedAddressLiteral);
        }
        combien = combien.saturating_add(1);
        if combien > 8 {
            return Err(Error::MalformedAddressLiteral);
        }
    }
    Ok(combien)
}

/// Le rang du dernier `octet` cherché, s'il y en a un.
fn derniere_position(octets: &[u8], cherche: u8) -> Option<usize> {
    octets.iter().rposition(|octet| *octet == cherche)
}

/// Ces octets portent-ils un point ?
fn contient_un_point(octets: &[u8]) -> bool {
    octets.contains(&b'.')
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
    fn les_adresses_ipv6_valables_sont_acceptees() {
        for bonne in [
            b"[IPv6:2001:db8::1]".as_slice(),
            b"[ipv6:2001:db8::1]", // le préfixe à la casse près
            b"[IPv6:2001:0DB8:0000:0000:0000:0000:0000:0001]", // huit groupes écrits
            b"[IPv6:2001:db8:0:0:0:0:0:1]", // huit groupes, sans zéros de tête
            b"[IPv6:::1]",         // la boucle locale
            b"[IPv6:::]",          // l'adresse indéterminée
            b"[IPv6:fe80::1%25]",  // pas de zone : voir plus bas
            b"[IPv6:1:2:3:4:5:6:7::]", // le `::` ne vaut qu'UN groupe
            b"[IPv6:::2:3:4:5:6:7:8]", // et de l'autre côté aussi
            b"[IPv6:::ffff:192.0.2.1]", // la forme mixte
            b"[IPv6:64:ff9b::192.0.2.1]", // NAT64
            b"[IPv6:0:0:0:0:0:ffff:192.0.2.1]", // mixte, sans compression
            b"[IPv6:ABCD:ef01:2345:6789:abcd:EF01:2345:6789]", // la casse hexadécimale
        ] {
            let vu = check_address_literal(bonne);
            // La zone de RFC 6874 n'a pas sa place dans un littéral SMTP : elle
            // ne veut rien dire hors de la machine qui l'écrit.
            if bonne.contains(&b'%') {
                assert_eq!(vu, Err(Error::MalformedAddressLiteral), "{bonne:?}");
                continue;
            }
            assert_eq!(vu, Ok(()), "{bonne:?} aurait dû être acceptée");
        }
    }

    /// **CE QUE LA VALIDATION DE FORME LAISSAIT PASSER.**
    ///
    /// Tous ces octets sont des chiffres hexadécimaux, des deux-points ou des
    /// points : l'ancienne vérification les acceptait tous.
    #[test]
    fn les_adresses_ipv6_mal_formees_sont_refusees() {
        for mauvaise in [
            b"[IPv6:2001:db8:::1]".as_slice(), // trois deux-points
            b"[IPv6:1::2::3]",                 // deux compressions : ambigu
            b"[IPv6:::::]",                    // et davantage
            b"[IPv6:1:2:3:4:5:6:7:8:9]",       // neuf groupes
            b"[IPv6:1:2:3:4:5:6:7]",           // sept groupes, sans compression
            b"[IPv6:12345::1]",                // cinq chiffres dans un groupe
            b"[IPv6::1]",                      // un deux-points isolé en tête
            b"[IPv6:1:]",                      // et en queue
            b"[IPv6:1:2:3:4:5:6:7:8::]",       // le `::` n'a plus de place
            b"[IPv6:::1:2:3:4:5:6:7:8]",       // idem de l'autre côté
            b"[IPv6:192.0.2.1]",               // une IPv4 qu'on aurait préfixée
            b"[IPv6:1:2:3:4:5:6:192.0.2.256]", // la queue IPv4 est vérifiée
            b"[IPv6:1:2:3:4:5:6:192.0.2.010]", // zéro de tête, la même règle qu'IPv4
            b"[IPv6:1:2:3:4:5:6:7:192.0.2.1]", // la queue vaut deux groupes : neuf
            b"[IPv6:1:2:3:4:5:192.0.2.1]",     // sept groupes en tout
            b"[IPv6:1.2.3.4:5]",               // un point avant les deux-points
        ] {
            assert_eq!(
                check_address_literal(mauvaise),
                Err(Error::MalformedAddressLiteral),
                "{mauvaise:?} aurait dû être refusée"
            );
        }
    }

    #[test]
    fn le_retrait_de_prefixe_ignore_la_casse_et_les_tranches_courtes() {
        assert_eq!(strip_prefix_ci(b"IPv6:x", b"ipv6:"), Some(b"x".as_slice()));
        assert_eq!(strip_prefix_ci(b"IPv4:x", b"ipv6:"), None);
        assert_eq!(strip_prefix_ci(b"ip", b"ipv6:"), None);
    }
}
