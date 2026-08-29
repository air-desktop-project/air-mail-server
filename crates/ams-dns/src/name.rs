//! Les noms : lecture avec décompression, écriture en étiquettes.

use crate::Error;

/// La longueur d'un nom, forme pointée comprise (RFC 1035 §2.3.4).
pub const MAX_NAME: usize = 255;

/// La longueur d'une étiquette.
const MAX_LABEL: usize = 63;

/// Les deux bits de tête qui signalent un pointeur de compression.
const POINTEUR: u8 = 0xC0;

/// Un nom de domaine, sous sa forme pointée et **sans point final**.
///
/// Il tient dans le type : deux cent cinquante-cinq octets, la longueur qu'un
/// nom ne peut pas dépasser. C'est ce qui permet de le rendre par valeur — donc
/// sans emprunt sur le message, donc sans obliger l'appelant à garder vivante
/// une réponse UDP pendant qu'il en attend une autre.
#[derive(Clone, Copy)]
pub struct Name {
    octets: [u8; MAX_NAME],
    longueur: usize,
}

impl Name {
    /// La racine — le nom vide.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            octets: [0; MAX_NAME],
            longueur: 0,
        }
    }

    /// Les octets du nom, sans point final.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.octets.get(..self.longueur).unwrap_or_default()
    }

    /// Est-ce la racine ?
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.longueur == 0
    }

    /// Ajoute une étiquette, précédée d'un point si ce n'est pas la première.
    ///
    /// **Rien ne vérifie ici les 63 octets d'une étiquette**, et c'est voulu :
    /// l'appelant lit sa longueur dans un octet dont les deux bits de tête sont
    /// nuls, donc au plus 63. La borne est portée par le format, pas par une
    /// garde qu'aucun message ne pourrait franchir.
    fn pousser(&mut self, etiquette: &[u8]) -> Result<(), Error> {
        let separateur = usize::from(self.longueur > 0);
        let fin = self
            .longueur
            .saturating_add(separateur)
            .saturating_add(etiquette.len());
        let Some(place) = self.octets.get_mut(self.longueur..fin) else {
            return Err(Error::NameTooLong);
        };
        let (point, corps) = place.split_at_mut(separateur);
        point.fill(b'.');
        corps.copy_from_slice(etiquette);
        self.longueur = fin;
        Ok(())
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Un nom vient d'ailleurs : on n'écrit dans le journal QUE ce qui est
        // imprimable, sans quoi une réponse hostile écrirait des octets de
        // contrôle dans un terminal d'administrateur.
        // On assainit AVANT d'écrire, et d'un seul tenant : écrire octet par
        // octet ferait autant de chemins d'erreur qu'un nom a de lettres, et
        // aucun de ces chemins ne serait éprouvable.
        let mut propre = [b'?'; MAX_NAME];
        for (case, &octet) in propre.iter_mut().zip(self.as_bytes()) {
            if octet.is_ascii_graphic() {
                *case = octet;
            }
        }
        let lisible =
            core::str::from_utf8(propre.get(..self.longueur).unwrap_or_default()).unwrap_or("?");
        write!(f, "Name({lisible:?})")
    }
}

impl PartialEq for Name {
    /// **La comparaison des noms est insensible à la casse** (RFC 4343). La
    /// faire sensible ferait échouer une correspondance sur la seule fantaisie
    /// d'un serveur qui répond en majuscules — et certains le font exprès.
    fn eq(&self, autre: &Self) -> bool {
        self.as_bytes().eq_ignore_ascii_case(autre.as_bytes())
    }
}

impl Eq for Name {}

/// Lit un nom à partir de `depart`, pointeurs de compression suivis.
///
/// Rend le nom, et **l'offset qui suit le nom dans le flux** — lequel n'est pas
/// l'endroit où la lecture s'est arrêtée : un nom compressé finit sur ses deux
/// octets de pointeur, quoi qu'il ait fallu lire ailleurs pour le reconstituer.
///
/// # Errors
///
/// Voir [`Error`] : troncature, octet réservé, pointeur qui ne recule pas, nom
/// trop long.
pub(crate) fn lire(message: &[u8], depart: usize) -> Result<(Name, usize), Error> {
    let mut nom = Name::root();
    let mut position = depart;
    let mut apres: Option<usize> = None;
    // LE PLAFOND DES POINTEURS. Chaque saut doit viser strictement plus bas que
    // le précédent — au départ, plus bas que le nom lui-même. La suite des
    // cibles décroît donc dans les entiers naturels : la lecture s'arrête, et
    // aucun compteur de sauts n'a besoin d'exister.
    let mut plafond = depart;

    loop {
        let &tete = message.get(position).ok_or(Error::Truncated)?;
        match tete & POINTEUR {
            0x00 => {
                let debut = position.saturating_add(1);
                if tete == 0 {
                    return Ok((nom, apres.unwrap_or(debut)));
                }
                let fin = debut.saturating_add(usize::from(tete));
                let etiquette = message.get(debut..fin).ok_or(Error::Truncated)?;
                nom.pousser(etiquette)?;
                position = fin;
            }
            POINTEUR => {
                let &basse = message
                    .get(position.saturating_add(1))
                    .ok_or(Error::Truncated)?;
                let cible = (usize::from(tete & 0x3F) << 8) | usize::from(basse);
                if apres.is_none() {
                    apres = Some(position.saturating_add(2));
                }
                if cible >= plafond {
                    return Err(Error::BadPointer);
                }
                plafond = cible;
                position = cible;
            }
            // `01` et `10` : réservés en 1987, jamais attribués. Un message qui
            // les emploie ne vient pas d'un serveur qui parle le même protocole.
            _ => return Err(Error::Malformed),
        }
    }
}

/// Saute un nom sans le reconstituer, et rend l'offset qui le suit.
///
/// Marcher les sections coûte un saut de nom par enregistrement ; les
/// reconstituer tous serait payer deux cent cinquante-cinq octets de recopie
/// pour des noms que personne ne regarde.
///
/// # Errors
///
/// Troncature, ou octet de longueur réservé.
pub(crate) fn sauter(message: &[u8], depart: usize) -> Result<usize, Error> {
    let mut position = depart;
    loop {
        let &tete = message.get(position).ok_or(Error::Truncated)?;
        match tete & POINTEUR {
            0x00 => {
                if tete == 0 {
                    return Ok(position.saturating_add(1));
                }
                position = position.saturating_add(1).saturating_add(usize::from(tete));
                // La borne se vérifie ICI : sans elle, une étiquette qui déborde
                // ferait rendre un offset au-delà du message, et l'appelant y
                // lirait la suite d'un enregistrement qui n'existe pas.
                if position > message.len() {
                    return Err(Error::Truncated);
                }
            }
            // Un pointeur TERMINE le nom : il n'y a rien à lire après lui.
            POINTEUR => {
                let fin = position.saturating_add(2);
                if fin > message.len() {
                    return Err(Error::Truncated);
                }
                return Ok(fin);
            }
            _ => return Err(Error::Malformed),
        }
    }
}

/// Écrit un nom sous forme d'étiquettes, terminé par l'octet nul.
///
/// Le nom se donne sous sa forme pointée ; le point final est toléré et ignoré,
/// parce qu'un administrateur en écrit un une fois sur deux.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si le tampon ne suffit pas, [`Error::NameTooLong`]
/// si une étiquette dépasse 63 octets ou le nom 255, [`Error::EmptyLabel`] si
/// deux points se suivent.
pub(crate) fn ecrire(sortie: &mut [u8], nom: &[u8]) -> Result<usize, Error> {
    let nom = nom.strip_suffix(b".").unwrap_or(nom);
    let mut ecrits = 0_usize;
    if !nom.is_empty() {
        for etiquette in nom.split(|&octet| octet == b'.') {
            if etiquette.is_empty() {
                return Err(Error::EmptyLabel);
            }
            if etiquette.len() > MAX_LABEL {
                return Err(Error::NameTooLong);
            }
            let debut = ecrits;
            let fin = debut.saturating_add(1).saturating_add(etiquette.len());
            let Some(place) = sortie.get_mut(debut..fin) else {
                return Err(Error::BufferTooSmall);
            };
            let (longueur, corps) = place.split_at_mut(1);
            longueur.fill(u8::try_from(etiquette.len()).unwrap_or(u8::MAX));
            corps.copy_from_slice(etiquette);
            ecrits = fin;
        }
    }
    let fin = ecrits.saturating_add(1);
    let Some(zero) = sortie.get_mut(ecrits..fin) else {
        return Err(Error::BufferTooSmall);
    };
    zero.fill(0);
    // La longueur d'un nom SUR LE FIL compte les octets de longueur et le zéro
    // final : c'est ce total-là que la RFC borne à 255, pas la forme pointée.
    if fin > MAX_NAME {
        return Err(Error::NameTooLong);
    }
    Ok(fin)
}

#[cfg(test)]
mod tests;
