//! Les ENSEMBLES DE NUMÉROS (RFC 9051 §9, `sequence-set`).
//!
//! # `1:5,8,10:*` désigne des messages, et il faut s'en méfier
//!
//! C'est ce qu'un client écrit pour dire de quels messages il parle, dans
//! `FETCH`, `STORE`, `COPY`, `MOVE` et `SEARCH`. Trois choses en font une
//! surface :
//!
//! 1. **L'étoile veut dire « le plus grand »**, et sa valeur dépend de la boîte.
//!    `1:*` sur une boîte vide ne désigne rien ; sur une boîte de cent mille
//!    messages, il les désigne tous. L'ensemble ne peut donc pas être résolu à
//!    la lecture — il l'est au moment de s'en servir, contre une borne que
//!    l'appelant fournit.
//! 2. **Un intervalle n'est pas ordonné** (§9) : `10:5` désigne exactement ce
//!    que désigne `5:10`. Un serveur qui prendrait `10:5` pour un intervalle
//!    vide répondrait autre chose que ce que le client a demandé.
//! 3. **La liste peut être immense.** `1,1,1,…` cent mille fois est un ensemble
//!    parfaitement valide, et le parcourir pour chaque message d'une boîte
//!    ferait un travail quadratique offert à qui écrit une ligne. Le nombre
//!    d'éléments est donc borné, et la borne est décidée ici.
//!
//! # Zéro n'est pas un numéro de message
//!
//! La grammaire dit `nz-number` : les numéros commencent à un. Zéro n'est pas
//! « le premier message », c'est une écriture qu'on refuse — et la refuser
//! évite qu'un décalage d'indice quelque part ne le transforme en autre chose.

use crate::{Error, Limits};

/// Un ensemble de numéros, vérifié dans sa forme.
///
/// La résolution de l'étoile n'a pas eu lieu : voir [`SequenceSet::ranges`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceSet<'a> {
    texte: &'a [u8],
    /// Est-ce le marqueur `$` plutôt qu'un ensemble écrit ?
    saved: bool,
}

impl SequenceSet<'static> {
    /// Un ensemble qui ne désigne rien.
    ///
    /// Il sert à celui qui a validé un ensemble, l'a recopié, et le relit plus
    /// tard : la relecture ne peut pas échouer, et cette constante lui évite
    /// d'écrire une garde qu'aucune entrée ne pourrait emprunter.
    pub const EMPTY: Self = Self {
        texte: b"",
        saved: false,
    };
}

impl<'a> SequenceSet<'a> {
    /// Lit un ensemble de numéros.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedSequence`] si la forme n'est pas celle de §9 — zéro,
    /// nombre qui déborde, virgule ou deux-points en trop ;
    /// [`Error::TooManySequenceItems`] au-delà de
    /// [`Limits::max_sequence_items`](crate::Limits::max_sequence_items).
    pub fn parse(valeur: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        if valeur.is_empty() {
            return Err(Error::MalformedSequence);
        }
        // §9 : `sequence-set =/ seq-last-command`, et `seq-last-command = "$"`.
        //
        // # CE MARQUEUR NE DÉSIGNE RIEN ICI, ET C'EST VOULU
        //
        // Il renvoie au résultat de la dernière recherche `SAVE` (§6.4.4.1), que
        // la GRAMMAIRE ne connaît pas : elle n'a pas de session, donc pas de
        // résultat retenu. Elle le reconnaît, le nomme, et le rend inoffensif —
        // sans quoi `Ranges` prendrait ce `$` pour une étoile mal lue et
        // désignerait le dernier message de la boîte, c'est-à-dire n'importe
        // lequel plutôt que ceux qu'on a cherchés.
        if valeur == b"$" {
            return Ok(Self {
                texte: valeur,
                saved: true,
            });
        }
        let mut elements = 0_usize;
        for morceau in valeur.split(|octet| *octet == b',') {
            elements = elements.saturating_add(1);
            if elements > limits.max_sequence_items {
                return Err(Error::TooManySequenceItems {
                    limit: limits.max_sequence_items,
                });
            }
            lire_un(morceau)?;
        }
        Ok(Self {
            texte: valeur,
            saved: false,
        })
    }

    /// Est-ce le marqueur `$` — le résultat de la dernière recherche retenue ?
    ///
    /// L'appelant qui tient une session doit y substituer ce qu'il a retenu ;
    /// tant qu'il ne l'a pas fait, l'ensemble ne désigne rien.
    #[must_use]
    pub fn saved(&self) -> bool {
        self.saved
    }

    /// Les intervalles, **résolus et ordonnés**, l'étoile valant `star`.
    ///
    /// `star` est le plus grand numéro en usage — le nombre de messages pour un
    /// ensemble de numéros de séquence, le plus grand UID pour un ensemble
    /// d'UID. **Zéro veut dire « la boîte est vide »**, et rien n'est alors
    /// désigné.
    #[must_use]
    pub fn ranges(&self, star: u32) -> Ranges<'a> {
        Ranges {
            // LE MARQUEUR NON RÉSOLU NE DÉSIGNE RIEN. Voir `parse`.
            reste: match self.saved {
                true => &[],
                false => self.texte,
            },
            star,
        }
    }

    /// Le texte, tel qu'il a été écrit.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.texte
    }

    /// Ce numéro fait-il partie de l'ensemble ?
    #[must_use]
    pub fn contains(&self, number: u32, star: u32) -> bool {
        self.ranges(star)
            .any(|(bas, haut)| number >= bas && number <= haut)
    }
}

/// Les intervalles d'un ensemble, `(bas, haut)` inclus, `bas <= haut`.
#[derive(Debug, Clone)]
pub struct Ranges<'a> {
    reste: &'a [u8],
    star: u32,
}

impl Iterator for Ranges<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.reste.is_empty() {
                return None;
            }
            let (morceau, suite) = match self.reste.iter().position(|octet| *octet == b',') {
                Some(rang) => {
                    let (avant, apres) = self.reste.split_at(rang);
                    (avant, apres.get(1..).unwrap_or_default())
                }
                None => (self.reste, &[][..]),
            };
            self.reste = suite;
            // La forme a été vérifiée à la lecture : `unwrap_or` porte cette
            // impossibilité dans la bibliothèque standard plutôt que d'ouvrir
            // ici une branche qu'aucune entrée n'atteint.
            let (bas, haut) = lire_un(morceau).unwrap_or((Borne::Etoile, Borne::Etoile));
            let bas = bas.resoudre(self.star);
            let haut = haut.resoudre(self.star);
            // UNE BOÎTE VIDE FAIT DE `*` UN ZÉRO, et zéro n'est pas un numéro.
            // On l'examine AVANT de remettre l'intervalle dans l'ordre : après,
            // `1:*` serait devenu `0:1` et désignerait le premier message d'une
            // boîte qui n'en a aucun.
            //
            // Zéro ne peut venir que de là : la lecture refuse le zéro écrit.
            if bas == 0 || haut == 0 {
                continue;
            }
            // UN INTERVALLE N'EST PAS ORDONNÉ (§9) : `10:5` vaut `5:10`.
            return Some(if bas <= haut {
                (bas, haut)
            } else {
                (haut, bas)
            });
        }
    }
}

/// Une borne d'intervalle : un nombre, ou l'étoile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Borne {
    Nombre(u32),
    Etoile,
}

impl Borne {
    fn resoudre(self, star: u32) -> u32 {
        match self {
            Self::Nombre(valeur) => valeur,
            Self::Etoile => star,
        }
    }
}

/// Lit un élément : un numéro, ou un intervalle.
fn lire_un(morceau: &[u8]) -> Result<(Borne, Borne), Error> {
    match morceau.iter().position(|octet| *octet == b':') {
        Some(rang) => {
            let bas = lire_une_borne(morceau.get(..rang).unwrap_or_default())?;
            let haut = lire_une_borne(morceau.get(rang.saturating_add(1)..).unwrap_or_default())?;
            Ok((bas, haut))
        }
        None => {
            let seule = lire_une_borne(morceau)?;
            Ok((seule, seule))
        }
    }
}

/// Lit une borne : `nz-number` ou `*`.
fn lire_une_borne(morceau: &[u8]) -> Result<Borne, Error> {
    if morceau == b"*" {
        return Ok(Borne::Etoile);
    }
    if morceau.is_empty() || !morceau.iter().all(u8::is_ascii_digit) {
        return Err(Error::MalformedSequence);
    }
    let mut valeur = 0_u32;
    for octet in morceau {
        // UN NUMÉRO QUI DÉBORDE N'EST PAS UN GRAND NUMÉRO. Reparti de zéro, il
        // désignerait un message que le client n'a pas demandé.
        valeur = valeur
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(u32::from(octet.wrapping_sub(b'0'))))
            .ok_or(Error::MalformedSequence)?;
    }
    // `nz-number` : zéro n'est pas « le premier message », c'est une écriture
    // qu'on refuse.
    if valeur == 0 {
        return Err(Error::MalformedSequence);
    }
    Ok(Borne::Nombre(valeur))
}

#[cfg(test)]
mod tests;
