// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les ATTRIBUTS D'USAGE d'une boîte (RFC 6154), et rien d'autre.
//!
//! # Ce qu'ils règlent, et pourquoi leur absence se voit
//!
//! Un client qui range un brouillon doit savoir OÙ. Sans ces attributs, il n'a
//! que le nom — et « Drafts », « Brouillons », « Entwürfe » ne se devinent pas.
//! Chaque client invente alors sa boîte, et deux clients du même compte rangent
//! au même endroit sans le savoir, ou à deux endroits en le croyant.
//!
//! # CINQ ATTRIBUTS, ET L'ENSEMBLE EST FERMÉ
//!
//! §2 en définit sept. Ce serveur en sert **cinq** : `\Archive`, `\Drafts`,
//! `\Junk`, `\Sent`, `\Trash`.
//!
//! **`\All` et `\Flagged` sont écartés, et c'est une question d'honnêteté.**
//! Tous deux désignent une boîte VIRTUELLE — « tous les messages du compte »,
//! « ceux qui portent `\Flagged` » — c'est-à-dire une vue que le serveur
//! calcule, et non un répertoire qu'il tient. Ce serveur n'a pas de boîte
//! virtuelle : il n'a que des Maildir. Les annoncer reviendrait à promettre une
//! boîte qui n'existerait qu'à l'instant où quelqu'un l'ouvre, et qui ne
//! s'ouvrirait pas.
//!
//! C'est le même choix que pour les mots-clefs de [`Flags`](crate::Flags), et
//! pour la même raison : **on refuse ce qu'on ne sait pas tenir**, plutôt que
//! d'accepter et de décevoir plus tard.
//!
//! # LE SERVEUR NE DÉSIGNE RIEN TOUT SEUL
//!
//! §3 laisse le choix : le serveur peut désigner ses boîtes lui-même, ou laisser
//! le client le faire par `CREATE … (USE (\Drafts))`. Celui-ci ne crée aucune
//! boîte de son cru — un compte neuf n'a qu'`INBOX` — et **deviner un usage
//! d'après un nom serait une heuristique qui ment** : une boîte nommée
//! « Sent » peut être un dossier d'archive, et rien ne le dit.
//!
//! Le client désigne donc, et le serveur RETIENT. C'est ce que `CREATE-SPECIAL-USE`
//! veut dire.
//!
//! # UN USAGE NE VAUT QUE POUR UNE BOÎTE
//!
//! §3 : un serveur peut refuser un usage déjà attribué, par `NO [USEATTR]`. Ce
//! serveur refuse. Deux boîtes `\Drafts` rendraient un `LIST (SPECIAL-USE)` où
//! le client devrait choisir — et il choisirait au hasard, différemment d'une
//! fois sur l'autre.

use crate::Error;

/// Les usages d'une boîte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpecialUse(u8);

/// Les cinq usages servis, avec leur bit et leur nom.
///
/// **L'ORDRE EST CELUI DE LA RÉPONSE**, et il est alphabétique : rien ne
/// l'exige, mais un ordre stable rend une réponse comparable d'une fois sur
/// l'autre.
const CONNUS: [(u8, &[u8]); 5] = [
    (0b0000_0001, b"\\Archive"),
    (0b0000_0010, b"\\Drafts"),
    (0b0000_0100, b"\\Junk"),
    (0b0000_1000, b"\\Sent"),
    (0b0001_0000, b"\\Trash"),
];

impl SpecialUse {
    /// Aucun usage — une boîte ordinaire.
    pub const NONE: Self = Self(0);
    /// `\Archive` — ce que le compte garde sans le jeter.
    pub const ARCHIVE: Self = Self(0b0000_0001);
    /// `\Drafts` — les messages commencés et non envoyés.
    pub const DRAFTS: Self = Self(0b0000_0010);
    /// `\Junk` — ce que le compte tient pour indésirable.
    pub const JUNK: Self = Self(0b0000_0100);
    /// `\Sent` — ce que le compte a émis.
    pub const SENT: Self = Self(0b0000_1000);
    /// `\Trash` — ce que le compte a jeté sans l'effacer.
    pub const TRASH: Self = Self(0b0001_0000);

    /// Cet usage est-il posé ?
    #[must_use]
    pub const fn contains(self, autre: Self) -> bool {
        self.0 & autre.0 == autre.0
    }

    /// Y a-t-il un usage quelconque ?
    #[must_use]
    pub const fn any(self) -> bool {
        self.0 != 0
    }

    /// Les deux réunis.
    #[must_use]
    pub const fn with(self, autre: Self) -> Self {
        Self(self.0 | autre.0)
    }

    /// Écrit les usages séparés par des espaces, sans parenthèses.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn write(self, out: &mut [u8]) -> Result<&[u8], Error> {
        /// Les cinq, leurs espaces comprises.
        const BESOIN: usize = 40;
        let mut ecrits = 0_usize;
        for (bit, nom) in CONNUS {
            if self.0 & bit == 0 {
                continue;
            }
            if ecrits > 0 {
                ecrits = pousser(out, ecrits, b" ")?;
            }
            ecrits = pousser(out, ecrits, nom)?;
        }
        out.get(..ecrits)
            .ok_or(Error::BufferTooSmall { needed: BESOIN })
    }

    /// Lit un nom d'usage. Rend `None` pour ce qu'on ne sert pas.
    ///
    /// **`\All` et `\Flagged` rendent `None` comme un nom inconnu**, et c'est
    /// voulu : les distinguer apprendrait au client qu'on les connaît, donc
    /// qu'on pourrait les servir. On ne le pourra pas — voir l'en-tête de ce
    /// module.
    #[must_use]
    pub fn parse_one(nom: &[u8]) -> Option<Self> {
        CONNUS
            .iter()
            .find(|(_, connu)| connu.eq_ignore_ascii_case(nom))
            .map(|(bit, _)| Self(*bit))
    }

    /// Lit une liste d'usages séparés par des espaces : le contenu d'un
    /// `USE (…)`.
    ///
    /// # UNE LISTE VIDE EST UNE FAUTE
    ///
    /// `CREATE boite (USE ())` ne demande rien tout en ayant l'air de demander.
    /// L'accepter créerait une boîte ordinaire sous une écriture qui dit le
    /// contraire.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedUse`] pour un `use-attr` bien écrit qu'on ne sert
    /// pas ; [`Error::MalformedList`] pour ce qui n'est pas un `use-attr`, ou
    /// pour une liste vide.
    pub fn parse_list(dedans: &[u8]) -> Result<Self, Error> {
        let mut usages = Self::NONE;
        let mut vu = false;
        for mot in dedans.split(|octet| *octet == b' ') {
            if mot.is_empty() {
                continue;
            }
            let Some(un) = Self::parse_one(mot) else {
                // **DEUX REFUS, ET ILS NE SE DISENT PAS PAREIL.** Ce qui
                // commence par une barre oblique inverse suivie d'un mot est un
                // `use-attr` BIEN ÉCRIT (§2) : s'il n'est pas des nôtres, le
                // client n'a pas fauté, on ne sait simplement pas le servir.
                // Tout le reste — un mot nu, une barre seule — est une faute de
                // grammaire.
                return match mot.starts_with(b"\\") && mot.len() > 1 {
                    true => Err(Error::UnsupportedUse),
                    false => Err(Error::MalformedList),
                };
            };
            usages = usages.with(un);
            vu = true;
        }
        match vu {
            true => Ok(usages),
            false => Err(Error::MalformedList),
        }
    }
}

/// Lit ce qui suit le nom dans un `CREATE` : `(USE (\Drafts))`, ou rien.
///
/// §3 de RFC 6154 :
///
/// ```text
/// create-param      = "(" create-param-item *(SP create-param-item) ")"
/// create-param-item = "USE" SP "(" use-attr *(SP use-attr) ")"
/// ```
///
/// **UN SEUL ITEM EST SERVI, ET C'EST `USE`.** La grammaire en admet plusieurs
/// pour que d'autres extensions s'y greffent ; aucune de celles que ce serveur
/// sert n'en définit un second. En accepter un qu'on ne comprend pas ferait
/// créer une boîte en ignorant ce que le client a demandé d'elle.
///
/// # Errors
///
/// [`Error::MalformedList`] si la forme n'est pas celle de §3, ou si un usage
/// n'est pas servi.
pub fn parse_create_params(reste: &[u8]) -> Result<SpecialUse, Error> {
    let reste = reste.trim_ascii();
    if reste.is_empty() {
        return Ok(SpecialUse::NONE);
    }
    let dedans = reste
        .strip_prefix(b"(")
        .and_then(|corps| corps.strip_suffix(b")"))
        .ok_or(Error::MalformedList)?
        .trim_ascii();
    let usages = dedans
        .get(..3)
        .filter(|mot| mot.eq_ignore_ascii_case(b"USE"))
        .and_then(|_| dedans.get(3..))
        .ok_or(Error::MalformedList)?
        .trim_ascii();
    let liste = usages
        .strip_prefix(b"(")
        .and_then(|corps| corps.strip_suffix(b")"))
        .ok_or(Error::MalformedList)?;
    // **LA LISTE NE PORTE AUCUNE PARENTHÈSE**, et le vérifier n'est pas une
    // précaution de style. Sans cela, `(USE (\Drafts)) (X (1))` — deux items,
    // que ce serveur ne sert pas — laisse `\Drafts))` comme premier mot : la
    // barre oblique inverse en tête le ferait prendre pour un `use-attr` bien
    // écrit qu'on ne sert pas, et le client recevrait `NO [USEATTR]` pour une
    // commande qui est en réalité MAL FORMÉE. Il chercherait alors un autre
    // usage, là où il faut corriger la syntaxe.
    if liste.iter().any(|octet| matches!(*octet, b'(' | b')')) {
        return Err(Error::MalformedList);
    }
    SpecialUse::parse_list(liste)
}

/// Écrit `quoi` à partir de `ecrits`, et rend la nouvelle longueur.
fn pousser(out: &mut [u8], ecrits: usize, quoi: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(quoi.len());
    let place = out
        .get_mut(ecrits..fin)
        .ok_or(Error::BufferTooSmall { needed: fin })?;
    place.copy_from_slice(quoi);
    Ok(fin)
}

#[cfg(test)]
#[path = "special/tests.rs"]
mod tests;
