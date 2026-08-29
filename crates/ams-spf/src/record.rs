//! L'enregistrement `v=spf1 …` : sa lecture, et sa validation d'un seul tenant.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::term::{DomainSpec, prefixe};
use crate::{Error, Limits, Mechanism, Modifier, Qualifier, Term};

/// La version, telle que la RFC 7208 §4.5 l'exige en tête.
const VERSION: &[u8] = b"v=spf1";

/// Un enregistrement SPF **entièrement validé**.
///
/// # La validation a lieu UNE FOIS
///
/// [`Record::parse`] lit tous les termes avant d'en rendre un seul. Un parcours
/// qui s'arrêterait à mi-chemin appliquerait la moitié d'une politique que son
/// auteur n'a pas écrite — et la RFC 7208 §4.6 ne le permet pas : un
/// enregistrement mal formé vaut `permerror`, pas « ce qu'on en a compris ».
///
/// Passé cet appel, [`Record::terms`] ne peut plus échouer, et ne rend donc pas
/// de `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Record<'a> {
    corps: &'a [u8],
}

impl<'a> Record<'a> {
    /// Lit un enregistrement.
    ///
    /// # Errors
    ///
    /// [`Error::NotSpf`] si ce TXT n'est pas du SPF — **ce n'est pas une
    /// faute**, seulement un enregistrement qui parle d'autre chose. Toutes les
    /// autres valent `permerror`.
    pub fn parse(txt: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        if txt.len() > limits.max_record_octets {
            return Err(Error::TooLong);
        }
        // « v=spf1 » suivi de la fin ou d'une espace. RFC 7208 §4.5 : la
        // comparaison est INSENSIBLE À LA CASSE, et `v=spf10` n'est pas du SPF.
        let corps = match txt.split_at_checked(VERSION.len()) {
            Some((tete, reste))
                if tete.eq_ignore_ascii_case(VERSION)
                    && (reste.is_empty() || reste.first() == Some(&b' ')) =>
            {
                reste
            }
            _ => return Err(Error::NotSpf),
        };

        let enregistrement = Self { corps };
        // TOUT VALIDER MAINTENANT, y compris ce qu'on n'emploiera pas : un
        // `permerror` qui ne se déclencherait qu'au terme qu'on atteint
        // dépendrait de l'adresse du pair, et deux pairs verraient deux
        // politiques différentes pour le même domaine.
        let mut combien = 0_usize;
        for brut in enregistrement.mots() {
            combien = combien.saturating_add(1);
            if combien > limits.max_terms {
                return Err(Error::TooManyTerms);
            }
            lire_terme(brut)?;
        }
        // Un `redirect=` ou un `exp=` en double désignerait deux politiques, et
        // rien ne dirait laquelle s'applique (RFC 7208 §6).
        for nom in [&b"redirect="[..], b"exp="] {
            let combien = enregistrement
                .mots()
                .filter(|brut| commence_par_sans_casse(brut, nom))
                .count();
            if combien > 1 {
                return Err(Error::DuplicateModifier);
            }
        }
        Ok(enregistrement)
    }

    /// Les termes, dans l'ordre. **Ce parcours ne peut plus échouer.**
    #[must_use]
    pub fn terms(&self) -> Terms<'a> {
        Terms { corps: self.corps }
    }

    /// L'enregistrement tel qu'il a été lu, sans son `v=spf1`.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.corps
    }

    /// Les mots séparés par des espaces, les vides écartés.
    ///
    /// RFC 7208 §4.5 : les termes sont séparés par une ou plusieurs espaces.
    /// Deux espaces de suite ne font pas un terme vide.
    fn mots(&self) -> impl Iterator<Item = &'a [u8]> {
        self.corps
            .split(|&octet| octet == b' ')
            .filter(|mot| !mot.is_empty())
    }
}

/// Les termes d'un enregistrement validé.
#[derive(Debug, Clone)]
pub struct Terms<'a> {
    corps: &'a [u8],
}

impl<'a> Iterator for Terms<'a> {
    type Item = Term<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (mot, reste) = match self.corps.iter().position(|&octet| octet == b' ') {
                Some(at) => (
                    self.corps.get(..at).unwrap_or_default(),
                    self.corps.get(at.saturating_add(1)..).unwrap_or_default(),
                ),
                None if self.corps.is_empty() => return None,
                None => (self.corps, &[][..]),
            };
            self.corps = reste;
            if mot.is_empty() {
                continue;
            }
            // `Record::parse` a déjà validé chaque mot : `ok()` ne peut pas
            // rendre `None` ici. L'écrire ainsi plutôt qu'avec un `expect` évite
            // une panique dans un chemin que rien ne peut atteindre — et
            // `Option::ok` n'ouvre aucune branche à nous, là où un `if let …
            // else` en ouvrirait une qu'aucun test ne pourrait emprunter.
            return lire_terme(mot).ok();
        }
    }
}

/// Lit un terme : mécanisme qualifié, ou modificateur.
fn lire_terme(brut: &[u8]) -> Result<Term<'_>, Error> {
    // UN MODIFICATEUR SE RECONNAÎT À SON `=`, ET AVANT TOUT LE RESTE. Un
    // `redirect=example.com` commence par `r`, comme aucun mécanisme — mais un
    // modificateur inconnu, lui, peut porter n'importe quel nom, y compris celui
    // d'un mécanisme. Le `=` tranche (RFC 7208 §4.6.1).
    if let Some(at) = position_du_egal(brut) {
        let nom = brut.get(..at).unwrap_or_default();
        let valeur = brut.get(at.saturating_add(1)..).unwrap_or_default();
        return Ok(Term::Modifier(lire_modificateur(nom, valeur)));
    }

    let (qualifier, reste) = Qualifier::split(brut);
    let (nom, argument) = match reste.iter().position(|&octet| octet == b':') {
        Some(at) => (
            reste.get(..at).unwrap_or_default(),
            Some(reste.get(at.saturating_add(1)..).unwrap_or_default()),
        ),
        None => (reste, None),
    };
    // Le préfixe CIDR se lit sur le NOM quand il n'y a pas d'argument — `a/24`
    // est licite — et sur l'argument sinon.
    let mechanism = lire_mecanisme(nom, argument)?;
    Ok(Term::Mechanism {
        qualifier,
        mechanism,
    })
}

/// La position d'un `=` qui fait de ce terme un modificateur.
///
/// Un `=` **après** un `:` ou un `/` appartient à l'argument d'un mécanisme :
/// `exists:%{i}=x` n'est pas un modificateur.
fn position_du_egal(brut: &[u8]) -> Option<usize> {
    brut.iter()
        .position(|&octet| octet == b'=' || octet == b':' || octet == b'/')
        .filter(|&at| brut.get(at) == Some(&b'='))
        // Un `=` en tête ne nomme rien : `=x` n'est pas un modificateur, et le
        // prendre pour tel donnerait un nom vide.
        .filter(|&at| at > 0)
}

fn lire_modificateur<'a>(nom: &'a [u8], valeur: &'a [u8]) -> Modifier<'a> {
    if nom.eq_ignore_ascii_case(b"redirect") {
        Modifier::Redirect(valeur)
    } else if nom.eq_ignore_ascii_case(b"exp") {
        Modifier::Explanation(valeur)
    } else {
        // RFC 7208 §6 : un modificateur inconnu s'IGNORE. C'est ainsi qu'un
        // protocole s'étend sans casser ce qui existe.
        Modifier::Unknown {
            name: nom,
            value: valeur,
        }
    }
}

fn lire_mecanisme<'a>(nom: &'a [u8], argument: Option<&'a [u8]>) -> Result<Mechanism<'a>, Error> {
    // Le nom peut porter le préfixe : `a/24`, `mx//64`.
    let (nom, prefixes_sur_le_nom) = couper_au_slash(nom);

    if nom.eq_ignore_ascii_case(b"all") {
        // `all` n'admet ni argument ni préfixe : en accepter ferait passer pour
        // conforme un enregistrement que d'autres serveurs refuseront.
        if argument.is_some() || prefixes_sur_le_nom.is_some() {
            return Err(Error::MalformedArgument);
        }
        return Ok(Mechanism::All);
    }

    if nom.eq_ignore_ascii_case(b"ip4") || nom.eq_ignore_ascii_case(b"ip6") {
        let argument = argument.ok_or(Error::MalformedArgument)?;
        if prefixes_sur_le_nom.is_some() {
            return Err(Error::MalformedArgument);
        }
        let (adresse, reste) = couper_au_slash(argument);
        let texte = core::str::from_utf8(adresse).map_err(|_| Error::MalformedAddress)?;
        if nom.eq_ignore_ascii_case(b"ip4") {
            let address: Ipv4Addr = texte.parse().map_err(|_| Error::MalformedAddress)?;
            let prefix = lire_prefixe_simple(reste, 32)?;
            return Ok(Mechanism::Ip4 { address, prefix });
        }
        let address: Ipv6Addr = texte.parse().map_err(|_| Error::MalformedAddress)?;
        let prefix = lire_prefixe_simple(reste, 128)?;
        return Ok(Mechanism::Ip6 { address, prefix });
    }

    // Les mécanismes à domaine. `include` et `exists` EXIGENT un argument et
    // n'admettent aucun préfixe (RFC 7208 §5.2, §5.7) ; `a`, `mx` et `ptr` s'en
    // passent, et le domaine courant s'applique alors.
    let (spec, brut_prefixes) = match argument {
        Some(argument) => couper_au_slash(argument),
        None => (&b""[..], prefixes_sur_le_nom),
    };
    let (prefix4, prefix6) = lire_prefixes_doubles(brut_prefixes)?;

    if nom.eq_ignore_ascii_case(b"include") || nom.eq_ignore_ascii_case(b"exists") {
        if spec.is_empty() || brut_prefixes.is_some() {
            return Err(Error::MalformedArgument);
        }
        let domaine = DomainSpec {
            spec,
            prefix4,
            prefix6,
        };
        return Ok(if nom.eq_ignore_ascii_case(b"include") {
            Mechanism::Include(domaine)
        } else {
            Mechanism::Exists(domaine)
        });
    }

    let domaine = DomainSpec {
        spec,
        prefix4,
        prefix6,
    };
    if nom.eq_ignore_ascii_case(b"a") {
        return Ok(Mechanism::A(domaine));
    }
    if nom.eq_ignore_ascii_case(b"mx") {
        return Ok(Mechanism::Mx(domaine));
    }
    if nom.eq_ignore_ascii_case(b"ptr") {
        // `ptr` n'admet pas de préfixe (RFC 7208 §5.5).
        if brut_prefixes.is_some() {
            return Err(Error::MalformedArgument);
        }
        return Ok(Mechanism::Ptr(domaine));
    }
    Err(Error::UnknownTerm)
}

/// Coupe au premier `/`, et rend ce qui suit **sans** son `/`.
///
/// `None` veut dire « aucun `/` », ce qui n'est pas la même chose que « un `/`
/// suivi de rien » — et rendre la barre avec la suite obligeait les appelants à
/// la retrouver, avec un bras d'échec qu'aucun test ne pouvait emprunter.
fn couper_au_slash(brut: &[u8]) -> (&[u8], Option<&[u8]>) {
    match brut.iter().position(|&octet| octet == b'/') {
        Some(at) => (
            brut.get(..at).unwrap_or_default(),
            Some(brut.get(at.saturating_add(1)..).unwrap_or_default()),
        ),
        None => (brut, None),
    }
}

/// `<n>` après un `/`, ou rien du tout.
fn lire_prefixe_simple(brut: Option<&[u8]>, maximum: u8) -> Result<u8, Error> {
    match brut {
        None => Ok(maximum),
        Some(reste) => prefixe(reste, maximum),
    }
}

/// `<n4>`, `/<n6>`, `<n4>//<n6>`, ou rien — après le premier `/` (RFC 7208 §5.3).
fn lire_prefixes_doubles(brut: Option<&[u8]>) -> Result<(u8, u8), Error> {
    let Some(reste) = brut else {
        return Ok((32, 128));
    };
    // Une seconde barre en tête : `//64`, seul le préfixe IPv6 est donné.
    if let Some(six) = reste.strip_prefix(b"/") {
        return Ok((32, prefixe(six, 128)?));
    }
    match reste.iter().position(|&octet| octet == b'/') {
        None => Ok((prefixe(reste, 32)?, 128)),
        Some(at) => {
            let quatre = reste.get(..at).unwrap_or_default();
            let six = reste
                .get(at..)
                .and_then(|suite| suite.strip_prefix(b"//"))
                .ok_or(Error::MalformedPrefix)?;
            Ok((prefixe(quatre, 32)?, prefixe(six, 128)?))
        }
    }
}

/// Ce mot commence-t-il par ce préfixe, casse ignorée ?
fn commence_par_sans_casse(mot: &[u8], prefixe: &[u8]) -> bool {
    mot.split_at_checked(prefixe.len())
        .is_some_and(|(tete, _)| tete.eq_ignore_ascii_case(prefixe))
}

#[cfg(test)]
mod tests;
