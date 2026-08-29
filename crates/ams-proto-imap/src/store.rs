// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les arguments d'un `STORE` (RFC 9051 §6.4.6).
//!
//! # Trois verbes qui ne se valent pas
//!
//! `FLAGS` remplace, `+FLAGS` ajoute, `-FLAGS` retire. La distinction n'est pas
//! cosmétique : **deux `+FLAGS` concurrents se composent, deux `FLAGS`
//! concurrents s'écrasent**. Un serveur qui traiterait les trois pareil ferait
//! perdre au client des marques qu'il n'a jamais demandé d'effacer.
//!
//! # `.SILENT` n'est pas une option d'affichage
//!
//! Sans lui, chaque message modifié donne lieu à une réponse `FETCH` non
//! sollicitée qui dit ses nouveaux drapeaux. Avec lui, rien n'est rendu — et
//! c'est le client qui l'a demandé, parce qu'il sait déjà ce qu'il a écrit. Le
//! travail, lui, est fait dans les deux cas.

use crate::error::Error;
use crate::flags::Flags;
use crate::limits::Limits;
use crate::sequence::SequenceSet;

/// Ce qu'un `STORE` fait des drapeaux qu'il porte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    /// `FLAGS` : les drapeaux du message deviennent EXACTEMENT ceux-ci.
    Replace,
    /// `+FLAGS` : ceux-ci s'ajoutent à ceux qui y sont.
    Add,
    /// `-FLAGS` : ceux-ci sont retirés de ceux qui y sont.
    Remove,
}

/// Les arguments d'un `STORE`, une fois lus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Store<'a> {
    set: SequenceSet<'a>,
    mode: StoreMode,
    silent: bool,
    flags: Flags,
}

impl<'a> Store<'a> {
    /// Les messages visés.
    #[must_use]
    pub fn set(&self) -> SequenceSet<'a> {
        self.set
    }

    /// Le texte de l'ensemble, tel qu'il a été écrit.
    #[must_use]
    pub fn set_text(&self) -> &'a [u8] {
        self.set.as_bytes()
    }

    /// Remplacer, ajouter ou retirer.
    #[must_use]
    pub fn mode(&self) -> StoreMode {
        self.mode
    }

    /// Le client demande-t-il qu'on ne lui rende rien ?
    #[must_use]
    pub fn silent(&self) -> bool {
        self.silent
    }

    /// Les drapeaux à écrire.
    #[must_use]
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Lit les arguments d'un `STORE`.
    ///
    /// # Un drapeau inconnu est un REFUS, pas un silence
    ///
    /// La tentation est de laisser tomber ce qu'on ne sait pas écrire. Mais un
    /// client qui pose une étiquette et à qui l'on répond `OK` la croit posée :
    /// il ne la reverra jamais, et ne saura jamais pourquoi. Mieux vaut dire
    /// non.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedStore`] si la forme n'est pas celle de §6.4.6,
    /// [`Error::UnknownFlag`] pour un drapeau qu'on ne sait pas écrire, ou les
    /// erreurs d'ensemble de numéros.
    pub fn parse(arguments: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let arguments = arguments.trim_ascii();
        let rang = arguments
            .iter()
            .position(|octet| *octet == b' ')
            .ok_or(Error::MalformedStore)?;
        let set = SequenceSet::parse(arguments.get(..rang).unwrap_or_default(), limits)?;
        let reste = arguments
            .get(rang.saturating_add(1)..)
            .unwrap_or_default()
            .trim_ascii();
        let rang = reste
            .iter()
            .position(|octet| *octet == b' ')
            .ok_or(Error::MalformedStore)?;
        let verbe = reste.get(..rang).unwrap_or_default();
        let liste = reste
            .get(rang.saturating_add(1)..)
            .unwrap_or_default()
            .trim_ascii();

        let (mode, nom) = match verbe.split_first() {
            Some((b'+', suite)) => (StoreMode::Add, suite),
            Some((b'-', suite)) => (StoreMode::Remove, suite),
            _ => (StoreMode::Replace, verbe),
        };
        let silent = if let Some(court) = raccourcir(nom, b".SILENT") {
            if !court.eq_ignore_ascii_case(b"FLAGS") {
                return Err(Error::MalformedStore);
            }
            true
        } else {
            if !nom.eq_ignore_ascii_case(b"FLAGS") {
                return Err(Error::MalformedStore);
            }
            false
        };

        // Une liste entre parenthèses, ou des drapeaux nus (§6.4.6 admet les
        // deux écritures).
        // UN OCTET NE PEUT PAS ÊTRE À LA FOIS `(` ET `)` : dès que les deux
        // côtés répondent, la liste fait au moins deux octets. Ajouter une garde
        // de longueur ici serait affirmer une impossibilité sans la vérifier —
        // et le compteur de couverture le dirait, puisqu'aucune entrée ne
        // pourrait l'emprunter.
        let liste = match (liste.first(), liste.last()) {
            (Some(b'('), Some(b')')) => liste
                .get(1..liste.len().saturating_sub(1))
                .unwrap_or_default(),
            // Une parenthèse d'un seul côté n'est pas une liste.
            (Some(b'('), _) | (_, Some(b')')) => return Err(Error::MalformedStore),
            _ => liste,
        };

        let mut flags = Flags::NONE;
        for mot in liste.split(|octet| *octet == b' ') {
            if mot.is_empty() {
                continue;
            }
            let Some(drapeau) = Flags::parse_one(mot) else {
                return Err(Error::UnknownFlag);
            };
            flags = flags.with(drapeau);
        }
        // `FLAGS ()` EST LÉGITIME : c'est ainsi qu'on efface tout. `+FLAGS ()`
        // et `-FLAGS ()`, eux, ne demandent rien — et ne sont pas des fautes
        // pour autant : ils ne changent rien, ce qui est exactement ce qu'ils
        // disent.
        Ok(Self {
            set,
            mode,
            silent,
            flags,
        })
    }
}

/// Rend `nom` privé de `suffixe`, si `nom` s'y termine — comparaison sans égard
/// à la casse, que `strip_suffix` ne sait pas faire.
fn raccourcir<'a>(nom: &'a [u8], suffixe: &[u8]) -> Option<&'a [u8]> {
    let coupe = nom.len().checked_sub(suffixe.len())?;
    let (avant, fin) = nom.split_at(coupe);
    fin.eq_ignore_ascii_case(suffixe).then_some(avant)
}

#[cfg(test)]
mod tests;
