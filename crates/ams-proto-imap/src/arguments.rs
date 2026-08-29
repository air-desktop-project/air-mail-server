//! Les arguments d'une commande (RFC 9051 §4 et §9, `astring`).
//!
//! # Trois façons d'écrire la même chose, et il faut les trois
//!
//! Un argument IMAP s'écrit de trois manières, et le client choisit :
//!
//! - un **atome** — `INBOX`, `42`, `NIL` — pour ce qui n'a rien de spécial ;
//! - une **chaîne** — `"Mon dossier"` — dès qu'il y a une espace, avec `\"` et
//!   `\\` pour les deux octets qui ont un sens ;
//! - un **littéral** — `{7}` puis sept octets bruts — pour ce qui ne rentre dans
//!   aucune des deux : un mot de passe avec un guillemet, un nom de boîte en
//!   UTF-8, un message entier.
//!
//! Un serveur qui n'en lit que deux refuse du courrier légitime ; un serveur qui
//! les confond laisse le client décider de ce qu'il lit.
//!
//! # LA VALEUR NE SE REND PAS PAR EMPRUNT, ET C'EST VOULU
//!
//! `"a\"b"` vaut `a"b` : trois octets, là où la source en porte cinq. Rendre une
//! tranche du tampon obligerait donc à mentir, ou à ne rendre que les cas
//! faciles. [`Argument::value`] écrit dans le tampon de l'appelant — comme tout
//! ce qui, dans ce dépôt, doit produire des octets sans allouer.

use crate::{Error, Limits};

/// Un argument, tel qu'il est écrit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argument<'a> {
    /// Un atome, rendu tel quel.
    Atom(&'a [u8]),
    /// Une chaîne, **guillemets retirés et échappements encore là**.
    Quoted(&'a [u8]),
    /// Un littéral, rendu tel quel : il n'y a rien à déséchapper.
    Literal(&'a [u8]),
}

impl<'a> Argument<'a> {
    /// Écrit la valeur de l'argument, échappements défaits.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas — la valeur ne dépasse
    /// jamais la longueur de ce qui l'écrit.
    pub fn value<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let source = match self {
            Self::Atom(octets) | Self::Literal(octets) => {
                let place = out.get_mut(..octets.len()).ok_or(Error::BufferTooSmall {
                    needed: octets.len(),
                })?;
                place.copy_from_slice(octets);
                return out.get(..octets.len()).ok_or(Error::BufferTooSmall {
                    needed: octets.len(),
                });
            }
            Self::Quoted(octets) => *octets,
        };
        let mut ecrits = 0_usize;
        let mut echappe = false;
        for octet in source {
            if !echappe && *octet == b'\\' {
                echappe = true;
                continue;
            }
            echappe = false;
            let place = out.get_mut(ecrits).ok_or(Error::BufferTooSmall {
                needed: source.len(),
            })?;
            *place = *octet;
            ecrits = ecrits.saturating_add(1);
        }
        out.get(..ecrits).ok_or(Error::BufferTooSmall {
            needed: source.len(),
        })
    }

    /// La valeur vaut-elle `attendue`, échappements défaits ?
    ///
    /// Évite un tampon quand il n'y a qu'à comparer — ce qui est le cas de tous
    /// les mots-clés du protocole.
    #[must_use]
    pub fn equals_ignore_case(&self, attendue: &[u8]) -> bool {
        match self {
            Self::Atom(octets) | Self::Literal(octets) => octets.eq_ignore_ascii_case(attendue),
            Self::Quoted(octets) => {
                let mut reste = attendue;
                let mut echappe = false;
                for octet in *octets {
                    if !echappe && *octet == b'\\' {
                        echappe = true;
                        continue;
                    }
                    echappe = false;
                    match reste.split_first() {
                        Some((premier, suite)) if premier.eq_ignore_ascii_case(octet) => {
                            reste = suite;
                        }
                        _ => return false,
                    }
                }
                reste.is_empty()
            }
        }
    }
}

/// Les arguments d'une commande, dans l'ordre.
#[derive(Debug, Clone)]
pub struct Args<'a> {
    reste: &'a [u8],
}

impl<'a> Args<'a> {
    /// Ouvre la lecture des arguments d'une commande.
    #[must_use]
    pub fn new(arguments: &'a [u8]) -> Self {
        Self { reste: arguments }
    }
}

impl<'a> Iterator for Args<'a> {
    type Item = Result<Argument<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // Le rang ET l'octet du même parcours : les chercher en deux fois
        // demanderait au second de se garder d'une absence que le premier vient
        // d'exclure, et une garde inatteignable n'est pas une garde.
        let (debut, premier) = self
            .reste
            .iter()
            .enumerate()
            .find(|(_, octet)| **octet != b' ')
            .map(|(rang, octet)| (rang, *octet))?;
        self.reste = self.reste.get(debut..).unwrap_or_default();
        let lu = match premier {
            b'"' => self.chaine(),
            b'{' => self.litteral(),
            _ => self.atome(),
        };
        // UNE FAUTE ARRÊTE LA LECTURE. Aucune des trois écritures ne sait où
        // reprendre après ce qu'elle n'a pas compris : rendre la faute sans
        // avancer ferait un itérateur qui la répète sans fin, et un appelant qui
        // collecte n'en verrait jamais la fin. Constaté par un test, avant que
        // le fuzz n'ait à le trouver.
        if lu.is_err() {
            self.reste = &[];
        }
        Some(lu)
    }
}

impl<'a> Args<'a> {
    /// Lit un atome : tout jusqu'à l'espace suivant.
    fn atome(&mut self) -> Result<Argument<'a>, Error> {
        let fin = self
            .reste
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(self.reste.len());
        let mot = self.reste.get(..fin).unwrap_or_default();
        self.reste = self.reste.get(fin..).unwrap_or_default();
        Ok(Argument::Atom(mot))
    }

    /// Lit une chaîne, guillemets compris.
    fn chaine(&mut self) -> Result<Argument<'a>, Error> {
        let corps = self.reste.get(1..).unwrap_or_default();
        let mut echappe = false;
        for (rang, octet) in corps.iter().enumerate() {
            if echappe {
                // §9 : seuls `"` et `\` s'échappent. Tout le reste après une
                // contre-oblique est une écriture qu'on ne sait pas lire.
                if !matches!(*octet, b'"' | b'\\') {
                    return Err(Error::MalformedArgument);
                }
                echappe = false;
                continue;
            }
            match *octet {
                b'\\' => echappe = true,
                b'"' => {
                    let valeur = corps.get(..rang).unwrap_or_default();
                    self.reste = corps.get(rang.saturating_add(1)..).unwrap_or_default();
                    return Ok(Argument::Quoted(valeur));
                }
                // Une chaîne ne traverse pas les lignes : ce qui suit un `CRLF`
                // appartient à un littéral, jamais à la chaîne en cours.
                b'\r' | b'\n' => return Err(Error::MalformedArgument),
                _ => {}
            }
        }
        Err(Error::MalformedArgument)
    }

    /// Lit un littéral : `{n}` ou `{n+}`, un `CRLF`, puis `n` octets.
    fn litteral(&mut self) -> Result<Argument<'a>, Error> {
        let corps = self.reste.get(1..).unwrap_or_default();
        let fermante = corps
            .iter()
            .position(|octet| *octet == b'}')
            .ok_or(Error::MalformedLiteral)?;
        let annonce = corps.get(..fermante).unwrap_or_default();
        let chiffres = annonce.strip_suffix(b"+").unwrap_or(annonce);
        if chiffres.is_empty() || !chiffres.iter().all(u8::is_ascii_digit) {
            return Err(Error::MalformedLiteral);
        }
        let mut longueur = 0_usize;
        for octet in chiffres {
            longueur = longueur
                .checked_mul(10)
                .and_then(|dizaines| dizaines.checked_add(usize::from(octet.wrapping_sub(b'0'))))
                .ok_or(Error::MalformedLiteral)?;
        }
        let apres = corps.get(fermante.saturating_add(1)..).unwrap_or_default();
        let octets = apres.strip_prefix(b"\r\n").ok_or(Error::MalformedLiteral)?;
        // LE DÉCOUPAGE A DÉJÀ COMPTÉ CES OCTETS. S'ils manquent ici, ce n'est
        // pas que la commande est incomplète — elle a été délimitée — c'est que
        // l'annonce et le contenu ne s'accordent pas.
        let valeur = octets.get(..longueur).ok_or(Error::MalformedLiteral)?;
        self.reste = octets.get(longueur..).unwrap_or_default();
        Ok(Argument::Literal(valeur))
    }
}

/// La longueur du plus long argument qu'une commande puisse porter.
///
/// C'est celle d'un littéral : voir
/// [`Limits::max_literal_octets`](crate::Limits::max_literal_octets). Cette
/// fonction ne fait que le rappeler à qui dimensionne un tampon.
#[must_use]
pub fn argument_max(limits: &Limits) -> u64 {
    limits.max_literal_octets
}

#[cfg(test)]
mod tests;
