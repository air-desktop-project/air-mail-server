// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui peut faire échouer une poignée de main, et le code qu'on écrit alors.
//!
//! # UNE FAUTE SANS CODE DE FERMETURE EST UNE CONNEXION QUI SE FIGE
//!
//! Chaque refus doit se traduire en `CONNECTION_CLOSE`. §4.8 de RFC 9001 donne
//! la règle pour les alertes TLS ; §20.1 de RFC 9000 pour le reste. Rendre une
//! faute sans code obligerait l'appelant à en inventer un — et il en inventerait
//! un différent à chaque endroit.

use ams_quic::crypto_error;
use rustls::AlertDescription;

use crate::{HANDSHAKE_FAILURE, NO_APPLICATION_PROTOCOL};

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Le fournisseur n'a aucune suite capable de chiffrer un paquet QUIC.
    ///
    /// **C'EST NOTRE FAUTE, PAS CELLE DU PAIR** : il faut monter la poignée de
    /// main sur `ams_tls::provider_quic()`. Le fournisseur ordinaire ne sait pas
    /// le faire, et `rustls` refuse alors de construire la connexion.
    NoQuicSuite,
    /// TLS a refusé ce qu'il a lu, et son alerte dit quoi.
    Tls(u8),
    /// TLS a refusé sans produire d'alerte.
    ///
    /// §4.8 autorise un code générique dans ce cas ; on écrit
    /// `handshake_failure` plutôt qu'un code inventé.
    TlsSansAlerte,
    /// Le protocole applicatif négocié n'est pas celui qu'on sert.
    ///
    /// §3.1 de RFC 9114 : HTTP/3 se choisit par ALPN. Servir autre chose parce
    /// que la négociation a laissé passer autre chose serait servir ce qu'on
    /// n'a pas annoncé.
    WrongAlpn,
    /// Les paramètres de transport du pair ne se lisent pas (§7.4 de RFC 9000).
    ///
    /// « An endpoint MUST treat receipt of transport parameters that it cannot
    /// process as a connection error of type TRANSPORT_PARAMETER_ERROR. » Les
    /// ignorer laisserait la connexion tourner sur des limites qu'on aurait
    /// inventées — et le pair, lui, tiendrait les siennes.
    BadParameters,
    /// Ce que §4.1.3, §8.3 ou §7.5 refusent entre les niveaux.
    Quic(ams_quic::Reason),
    /// On a parlé de flux avant que la poignée de main les rende possibles.
    ///
    /// **C'EST NOTRE FAUTE, ET NON CELLE DU PAIR** : §4.1 et §4.6 se règlent sur
    /// des paramètres que §7.4 ne laisse croire qu'authentifiés. Rendre cette
    /// faute plutôt que de la taire la fait voir en essai, où elle se corrige,
    /// plutôt qu'en production, où l'application croirait ses octets partis.
    PasEncoreDeFlux,
}

/// Une faute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qui a mal tourné.
    reason: Reason,
}

impl Error {
    /// La faute qui va avec cette raison.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Ce qui a mal tourné.
    #[must_use]
    pub const fn reason(self) -> Reason {
        self.reason
    }

    /// Le code qu'on écrit dans le `CONNECTION_CLOSE`.
    ///
    /// **IL Y EN A TOUJOURS UN.** Une poignée de main qui échoue sans le dire
    /// laisse le pair attendre jusqu'à son délai d'inactivité, sans savoir
    /// pourquoi.
    #[must_use]
    pub fn close_code(self) -> u64 {
        match self.reason {
            // §20.1 : `INTERNAL_ERROR`. Le pair n'y est pour rien — et il n'y
            // est pour rien non plus quand c'est nous qui parlons de flux trop
            // tôt.
            Reason::NoQuicSuite | Reason::PasEncoreDeFlux => 0x01,
            Reason::Tls(alerte) => crypto_error(alerte),
            Reason::TlsSansAlerte => crypto_error(HANDSHAKE_FAILURE),
            Reason::WrongAlpn => crypto_error(NO_APPLICATION_PROTOCOL),
            Reason::BadParameters => {
                ams_proto_quic::TransportError::TransportParameterError.value()
            }
            // La raison QUIC porte déjà le sien, et c'est celui-là qu'on écrit.
            Reason::Quic(raison) => raison.code().map_or(0x0a, ams_proto_quic_code),
        }
    }

    /// La faute que ce refus de `rustls` décrit, en cours de poignée de main.
    pub(crate) fn depuis_alerte(_erreur: &rustls::Error, alerte: Option<AlertDescription>) -> Self {
        match alerte {
            Some(alerte) => Self::new(Reason::Tls(u8::from(alerte))),
            None => Self::new(Reason::TlsSansAlerte),
        }
    }

    /// La faute que cette raison QUIC décrit.
    pub(crate) const fn depuis_quic(erreur: ams_quic::Error) -> Self {
        Self::new(Reason::Quic(erreur.reason()))
    }
}

/// Le code sur le fil d'une erreur de transport.
fn ams_proto_quic_code(code: ams_proto_quic::TransportError) -> u64 {
    code.value()
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::NoQuicSuite => {
                "aucune suite ne sait chiffrer un paquet QUIC : il faut provider_quic()"
            }
            Reason::Tls(_) => "TLS a refusé la poignée de main",
            Reason::TlsSansAlerte => "TLS a refusé sans produire d'alerte",
            Reason::WrongAlpn => "le protocole négocié n'est pas h3",
            Reason::BadParameters => "les paramètres de transport du pair ne se lisent pas",
            Reason::Quic(_) => "les niveaux de chiffrement ont été mal employés",
            Reason::PasEncoreDeFlux => "la poignée de main n'a pas encore ouvert les flux",
        };
        write!(f, "{quoi} — on ferme avec {:#06x}", self.close_code())
    }
}

#[cfg(test)]
mod tests;
