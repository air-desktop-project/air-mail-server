//! L'expansion des macros (RFC 7208 §7).
//!
//! # Pourquoi elles existent, et pourquoi elles coûtent cher
//!
//! Un `exists:%{ir}.%{d}._spf.example.com` transforme une liste d'adresses
//! autorisées en **une question DNS par message**. C'est commode pour qui publie
//! ; c'est aussi ce qui fait qu'un enregistrement peut faire travailler le
//! résolveur d'autrui, et c'est pourquoi la RFC borne le nombre de résolutions.
//!
//! # Ce qui est développé, et ce qui ne l'est pas
//!
//! Les macros du §7.2 qui décrivent le message : `s`, `l`, `o`, `d`, `i`, `h`,
//! plus `%%`, `%_` et `%-`. Les transformations `<digits>` et `r` avec leurs
//! délimiteurs le sont aussi — `%{ir}` est de loin la plus employée.
//!
//! `%{p}` — le nom obtenu par résolution inverse — vaut toujours `unknown`. La
//! RFC 7208 §7.3 le prévoit explicitement, et §5.5 déconseille de s'en servir :
//! le résoudre coûterait une résolution inverse par macro, au bénéfice d'une
//! poignée d'enregistrements. Les macros de `exp=` (`c`, `r`, `t`) n'ont pas
//! cours ici : elles ne servent qu'à composer un message d'explication, que
//! cette tranche ne compose pas.

use core::net::IpAddr;

use crate::Error;

/// La plus longue chaîne qu'une expansion puisse produire.
///
/// Un nom de domaine fait au plus 255 octets (RFC 1035 §2.3.4), et une expansion
/// qui le dépasse ne désigne aucun nom interrogeable. La borne est donc celle du
/// DNS, pas une invention.
pub const EXPANDED_MAX: usize = 255;

/// De quoi développer les macros d'un message.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// L'adresse du pair.
    pub client: IpAddr,
    /// L'expéditeur d'enveloppe, `locale@domaine`.
    ///
    /// Pour un `MAIL FROM:<>`, la RFC 7208 §2.4 veut `postmaster@<helo>`, et
    /// c'est à l'appelant de l'avoir composé : lui laisser ce choix évite que
    /// deux endroits le fassent différemment.
    pub sender: &'a [u8],
    /// Le domaine annoncé par `HELO`/`EHLO`.
    pub helo: &'a [u8],
}

impl Context<'_> {
    /// La partie locale de l'expéditeur.
    fn local(&self) -> &[u8] {
        match self.sender.iter().position(|&octet| octet == b'@') {
            Some(at) => self.sender.get(..at).unwrap_or_default(),
            // Un expéditeur sans `@` n'a pas de partie locale nommée ; la RFC
            // 7208 §7.2 veut alors `postmaster`.
            None => b"postmaster",
        }
    }

    /// Le domaine de l'expéditeur.
    fn sender_domain(&self) -> &[u8] {
        match self.sender.iter().position(|&octet| octet == b'@') {
            Some(at) => self.sender.get(at.saturating_add(1)..).unwrap_or_default(),
            None => self.sender,
        }
    }
}

/// Un tampon d'expansion, sans allocation.
#[derive(Debug, Clone, Copy)]
pub struct Expanded {
    octets: [u8; EXPANDED_MAX],
    longueur: usize,
}

impl Expanded {
    /// Un tampon vide.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            octets: [0; EXPANDED_MAX],
            longueur: 0,
        }
    }

    /// Ce qui a été écrit.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.octets.get(..self.longueur).unwrap_or_default()
    }

    /// Ajoute des octets, ou refuse s'ils ne tiennent pas.
    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.longueur.saturating_add(morceau.len());
        let Some(cible) = self.octets.get_mut(self.longueur..fin) else {
            // Plus long qu'un nom de domaine : cette expansion ne désigne aucun
            // nom interrogeable, et la tronquer en désignerait un AUTRE.
            return Err(Error::MacroTooLong);
        };
        cible.copy_from_slice(morceau);
        self.longueur = fin;
        Ok(())
    }
}

impl Default for Expanded {
    fn default() -> Self {
        Self::new()
    }
}

/// Développe une spécification de domaine.
///
/// `domain` est le domaine courant, celui que `%{d}` désigne.
///
/// # Errors
///
/// [`Error::MalformedMacro`] si une macro est mal formée — ce qui vaut
/// `permerror` — ou [`Error::MacroTooLong`] si le résultat dépasse un nom de
/// domaine.
pub fn expand(
    spec: &[u8],
    contexte: &Context<'_>,
    domain: &[u8],
    sortie: &mut Expanded,
) -> Result<(), Error> {
    sortie.longueur = 0;
    let mut reste = spec;
    while let Some((&premier, suite)) = reste.split_first() {
        if premier != b'%' {
            sortie.pousser(&[premier])?;
            reste = suite;
            continue;
        }
        match suite.split_first() {
            // `%%`, `%_` et `%-` : les trois échappements du §7.1.
            Some((b'%', apres)) => {
                sortie.pousser(b"%")?;
                reste = apres;
            }
            Some((b'_', apres)) => {
                sortie.pousser(b" ")?;
                reste = apres;
            }
            Some((b'-', apres)) => {
                sortie.pousser(b"%20")?;
                reste = apres;
            }
            Some((b'{', apres)) => {
                let fin = apres
                    .iter()
                    .position(|&octet| octet == b'}')
                    .ok_or(Error::MalformedMacro)?;
                let corps = apres.get(..fin).unwrap_or_default();
                developper_une(corps, contexte, domain, sortie)?;
                reste = apres.get(fin.saturating_add(1)..).unwrap_or_default();
            }
            // Un `%` suivi d'autre chose — ou de rien — n'est pas une macro.
            // RFC 7208 §7.1 : c'est une erreur de syntaxe, donc `permerror`.
            _ => return Err(Error::MalformedMacro),
        }
    }
    Ok(())
}

/// Développe le corps d'un `%{…}`.
fn developper_une(
    corps: &[u8],
    contexte: &Context<'_>,
    domain: &[u8],
    sortie: &mut Expanded,
) -> Result<(), Error> {
    let (&lettre, reste) = corps.split_first().ok_or(Error::MalformedMacro)?;

    // La valeur brute. `%{p}` vaut TOUJOURS `unknown` : voir la documentation
    // du module.
    let mut adresse = [0_u8; EXPANDED_MAX];
    let valeur: &[u8] = match lettre.to_ascii_lowercase() {
        b's' => contexte.sender,
        b'l' => contexte.local(),
        b'o' => contexte.sender_domain(),
        b'd' => domain,
        b'i' => ecrire_adresse(contexte.client, &mut adresse),
        b'h' => contexte.helo,
        b'p' => b"unknown",
        b'v' => match contexte.client {
            IpAddr::V4(_) => b"in-addr",
            IpAddr::V6(_) => b"ip6",
        },
        _ => return Err(Error::MalformedMacro),
    };

    let (chiffres, inverser, delimiteurs) = lire_transformation(reste)?;
    transformer(valeur, chiffres, inverser, delimiteurs, sortie)
}

/// Lit `<digits><r><délimiteurs>` (RFC 7208 §7.1).
fn lire_transformation(reste: &[u8]) -> Result<(Option<usize>, bool, &[u8]), Error> {
    let fin_chiffres = reste
        .iter()
        .position(|octet| !octet.is_ascii_digit())
        .unwrap_or(reste.len());
    let (bruts, apres) = reste.split_at(fin_chiffres);

    let chiffres = if bruts.is_empty() {
        None
    } else {
        // Au plus trois chiffres : un nom de domaine n'a pas cent vingt-huit
        // étiquettes, et `%{d999999}` n'a pas de sens.
        if bruts.len() > 3 {
            return Err(Error::MalformedMacro);
        }
        let mut valeur = 0_usize;
        for &octet in bruts {
            let chiffre = usize::from(octet.saturating_sub(b'0'));
            valeur = valeur.saturating_mul(10).saturating_add(chiffre);
        }
        // ZÉRO N'EST PAS UN NOMBRE D'ÉTIQUETTES : la RFC 7208 §7.1 l'interdit,
        // et `%{d0}` ne désignerait rien.
        if valeur == 0 {
            return Err(Error::MalformedMacro);
        }
        Some(valeur)
    };

    let (inverser, delimiteurs) = match apres.split_first() {
        Some((octet, suite)) if octet.eq_ignore_ascii_case(&b'r') => (true, suite),
        _ => (false, apres),
    };
    // Les seuls délimiteurs admis (§7.1). Un autre caractère est une faute de
    // syntaxe, pas un délimiteur exotique.
    if delimiteurs
        .iter()
        .any(|octet| !matches!(octet, b'.' | b'-' | b'+' | b',' | b'/' | b'_' | b'='))
    {
        return Err(Error::MalformedMacro);
    }
    Ok((chiffres, inverser, delimiteurs))
}

/// Découpe, inverse, tronque, puis recolle avec des points.
fn transformer(
    valeur: &[u8],
    chiffres: Option<usize>,
    inverser: bool,
    delimiteurs: &[u8],
    sortie: &mut Expanded,
) -> Result<(), Error> {
    let separateurs: &[u8] = if delimiteurs.is_empty() {
        b"."
    } else {
        delimiteurs
    };

    // Les parties, dans un tableau FIXE : un nom de domaine n'a pas plus de
    // cent vingt-huit étiquettes, et une valeur qui en aurait davantage ne
    // désigne rien d'interrogeable.
    let mut parties: [&[u8]; 128] = [b""; 128];
    let mut combien = 0_usize;
    for partie in valeur.split(|octet| separateurs.contains(octet)) {
        let Some(case) = parties.get_mut(combien) else {
            return Err(Error::MacroTooLong);
        };
        *case = partie;
        combien = combien.saturating_add(1);
    }
    let parties = parties.get(..combien).unwrap_or_default();

    // `r` inverse ; `<digits>` ne garde que les N DERNIÈRES — après inversion,
    // ce sont donc les N premières de la valeur d'origine (§7.1).
    let garde = chiffres.map_or(combien, |n| n.min(combien));
    let saute = combien.saturating_sub(garde);

    // À l'envers, ce sont les N PREMIÈRES parties, retournées ; à l'endroit, les
    // N dernières. Prendre la tranche puis choisir le sens évite d'indexer, donc
    // évite une garde sur un indice qui ne peut pas sortir.
    let tranche = if inverser {
        parties.get(..garde)
    } else {
        parties.get(saute..)
    };
    let tranche = tranche.unwrap_or_default();
    let mut a_l_envers;
    let mut a_l_endroit;
    let parcours: &mut dyn Iterator<Item = &&[u8]> = if inverser {
        a_l_envers = tranche.iter().rev();
        &mut a_l_envers
    } else {
        a_l_endroit = tranche.iter();
        &mut a_l_endroit
    };

    let mut premier = true;
    for partie in parcours {
        if !premier {
            sortie.pousser(b".")?;
        }
        premier = false;
        sortie.pousser(partie)?;
    }
    Ok(())
}

/// Écrit une adresse comme `%{i}` la veut (RFC 7208 §7.2).
///
/// IPv4 en quadruplet pointé ; IPv6 en **quartets pointés**, minuscules — c'est
/// ce que `%{ir}` retourne pour composer un nom sous `ip6.arpa`.
fn ecrire_adresse(client: IpAddr, tampon: &mut [u8; EXPANDED_MAX]) -> &[u8] {
    let mut ecrits = 0_usize;
    match client {
        IpAddr::V4(adresse) => {
            for (rang, octet) in adresse.octets().into_iter().enumerate() {
                if rang > 0 {
                    ecrits = pousser_octet(tampon, ecrits, b'.');
                }
                ecrits = pousser_decimal(tampon, ecrits, octet);
            }
        }
        IpAddr::V6(adresse) => {
            for (rang, quartet) in adresse
                .octets()
                .into_iter()
                .flat_map(|octet| [octet >> 4, octet & 0x0F])
                .enumerate()
            {
                if rang > 0 {
                    ecrits = pousser_octet(tampon, ecrits, b'.');
                }
                ecrits = pousser_octet(tampon, ecrits, hexadecimal(quartet));
            }
        }
    }
    tampon.get(..ecrits).unwrap_or_default()
}

fn hexadecimal(quartet: u8) -> u8 {
    // Minuscules : c'est ce que la RFC 7208 §7.2 écrit, et un nom DNS se compare
    // sans casse de toute façon.
    match quartet {
        0..=9 => b'0'.saturating_add(quartet),
        _ => b'a'.saturating_add(quartet.saturating_sub(10)),
    }
}

fn pousser_octet(tampon: &mut [u8; EXPANDED_MAX], position: usize, octet: u8) -> usize {
    // La plus longue écriture est celle d'une IPv6 en quartets pointés :
    // soixante-trois octets, pour un tampon de deux cent cinquante-cinq. `min`
    // rend l'indexation totale sans ouvrir de branche qu'on ne saurait éprouver.
    tampon[position.min(EXPANDED_MAX.saturating_sub(1))] = octet;
    position.saturating_add(1)
}

fn pousser_decimal(tampon: &mut [u8; EXPANDED_MAX], position: usize, valeur: u8) -> usize {
    let mut position = position;
    let centaines = valeur / 100;
    let dizaines = (valeur / 10) % 10;
    if centaines > 0 {
        position = pousser_octet(tampon, position, b'0'.saturating_add(centaines));
    }
    if centaines > 0 || dizaines > 0 {
        position = pousser_octet(tampon, position, b'0'.saturating_add(dizaines));
    }
    pousser_octet(tampon, position, b'0'.saturating_add(valeur % 10))
}

#[cfg(test)]
mod tests;
