// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! De quoi écrire une réponse IMAP dans un tampon fixe, sans jamais déborder.
//!
//! # POURQUOI UN SEUL ENDROIT
//!
//! Une chaîne IMAP ne peut porter ni `CR` ni `LF` : le client lirait la fin de
//! la réponse au milieu d'un texte, puis la suite du dialogue comme du
//! protocole. La garantie ne tient que si TOUT le texte passe par le même
//! entonnoir — l'écrire une fois par composeur, c'est se donner autant
//! d'occasions de l'oublier, et le fuzz a déjà montré qu'on l'oublie.

use crate::error::Error;

/// Ce qu'un texte est, et donc ce qu'il faut en faire avant de le citer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Forme {
    /// Du texte, tel quel.
    Texte,
    /// Le contenu d'une chaîne citée de la RFC 5322 : ses échappements se
    /// défont avant qu'on recite aux règles d'IMAP, faute de quoi le client
    /// recevrait un antislash que le message ne porte pas.
    Source,
    /// Un jeton MIME — type, sous-type, encodage, nom de paramètre. Ils sont
    /// insensibles à la casse : les rendre tous en capitales évite qu'un défaut
    /// d'en-tête ne se voie dans la réponse.
    Jeton,
}

/// De quoi écrire dans un tampon fixe, sans jamais déborder.
pub(crate) struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl<'a> Plume<'a> {
    /// Une plume qui écrit dans `out`, depuis le début.
    pub(crate) fn neuve(out: &'a mut [u8]) -> Self {
        Self { out, ecrits: 0 }
    }

    /// Combien d'octets ont été écrits.
    pub(crate) fn ecrits(&self) -> usize {
        self.ecrits
    }

    /// Écrit `morceau`, ou dit que la place manque.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si le tampon ne suffit pas.
    pub(crate) fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// Écrit un octet, échappé comme une chaîne IMAP l'exige.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si le tampon ne suffit pas.
    pub(crate) fn octet_de_chaine(&mut self, octet: u8) -> Result<(), Error> {
        if matches!(octet, b'"' | b'\\') {
            self.pousser(b"\\")?;
        }
        self.pousser(&[octet])
    }

    /// Écrit un entier décimal.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si le tampon ne suffit pas.
    pub(crate) fn nombre(&mut self, valeur: u64) -> Result<(), Error> {
        // Vingt chiffres majorent tout `u64`, et la boucle les parcourt tous :
        // s'arrêter plus tôt demanderait une borne, donc une garde qu'aucun
        // appel ne peut faire céder.
        let mut chiffres = [b'0'; 20];
        let mut reste = valeur;
        let mut significatifs = 1_usize;
        for (rang, place) in chiffres.iter_mut().rev().enumerate() {
            *place = b'0'.wrapping_add(u8::try_from(reste % 10).unwrap_or_default());
            reste /= 10;
            if reste != 0 {
                significatifs = rang.saturating_add(2);
            }
        }
        let debut = chiffres.len().saturating_sub(significatifs);
        self.pousser(chiffres.get(debut..).unwrap_or_default())
    }

    /// Écrit un texte entre guillemets, aux règles d'IMAP.
    ///
    /// LES FINS DE LIGNE TOMBENT : une chaîne IMAP n'en porte pas, et le pliage
    /// de la RFC 5322 n'est pas du texte. Voir le doc de module.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si le tampon ne suffit pas.
    pub(crate) fn chaine(&mut self, texte: &[u8], forme: Forme) -> Result<(), Error> {
        self.pousser(b"\"")?;
        let mut i = 0_usize;
        while i < texte.len() {
            let octet = texte.get(i).copied().unwrap_or(0);
            let (a_ecrire, saut) = match (forme, octet) {
                (Forme::Source, b'\\') => {
                    (texte.get(i.saturating_add(1)).copied().unwrap_or(b'\\'), 2)
                }
                (Forme::Jeton, _) => (octet.to_ascii_uppercase(), 1),
                _ => (octet, 1),
            };
            if !matches!(a_ecrire, b'\r' | b'\n') {
                self.octet_de_chaine(a_ecrire)?;
            }
            i = i.saturating_add(saut);
        }
        self.pousser(b"\"")
    }

    /// Où en est la plume, pour pouvoir y revenir.
    pub(crate) fn marque(&self) -> usize {
        self.ecrits
    }

    /// Reprend à une marque, oubliant ce qui a été écrit depuis.
    ///
    /// # POURQUOI PLUTÔT QU'UN PRÉ-CONTRÔLE
    ///
    /// Écrire une liste vide demande de savoir, AVANT de l'ouvrir, si elle
    /// portera quelque chose. Un second parcours qui le devine est un second
    /// lecteur du même texte — et deux lecteurs finissent par ne plus dire la
    /// même chose. On écrit donc, et l'on revient : il n'y a qu'un lecteur.
    pub(crate) fn revenir(&mut self, marque: usize) {
        self.ecrits = marque.min(self.ecrits);
    }

    /// Confie le reste du tampon à `ecrivain`, et avance de ce qu'il a écrit.
    ///
    /// # Errors
    ///
    /// Ce que `ecrivain` rend.
    pub(crate) fn deleguer(
        &mut self,
        ecrivain: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        // `split_at_mut` PLUTÔT QU'UN `get_mut` : la plume n'écrit jamais
        // au-delà de son tampon, donc `ecrits` ne peut pas le dépasser. Un
        // `ok_or` ici serait une garde qu'aucun appel ne peut faire céder,
        // c'est-à-dire une affirmation qu'aucun test ne vérifierait.
        let (_, reste) = self.out.split_at_mut(self.ecrits.min(self.out.len()));
        let place = reste.len();
        let ecrits = ecrivain(reste)?;
        self.ecrits = self.ecrits.saturating_add(ecrits.min(place));
        Ok(())
    }
}
