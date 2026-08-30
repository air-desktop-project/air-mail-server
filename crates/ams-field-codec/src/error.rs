// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que ce socle peut refuser.
//!
//! # IL NE CONNAÎT PAS LES CODES DE SES APPELANTS, ET C'EST VOULU
//!
//! HPACK ferme la connexion avec `COMPRESSION_ERROR` d'HTTP/2 ;
//! QPACK avec `QPACK_DECOMPRESSION_FAILED` d'HTTP/3. Ce ne sont pas les mêmes
//! espaces de codes, et un socle qui en nommerait un obligerait l'autre à le
//! traduire — ou pire, à s'en accommoder.
//!
//! On rend donc ce qui a mal tourné, et rien de plus. La traduction vers un code
//! de fil est le travail de celui qui a une connexion à fermer.

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Un entier déborde, n'est pas terminé, ou s'écrit trop long.
    BadInteger,
    /// Une chaîne déborde de ce qui reste, ou de ce qu'on retient.
    BadString,
    /// Un code de Huffman inconnu, un remplissage fautif, ou `EOS`.
    BadHuffman,
    /// Le tampon de sortie ne suffit pas. **Notre faute, pas celle du pair.**
    BufferTooSmall,
}

/// Une faute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qui a mal tourné.
    fault: Fault,
}

impl Error {
    /// La faute qui va avec cette raison.
    #[must_use]
    pub const fn new(fault: Fault) -> Self {
        Self { fault }
    }

    /// Ce qui a mal tourné.
    #[must_use]
    pub const fn fault(self) -> Fault {
        self.fault
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.fault {
            Fault::BadInteger => "un entier déborde, ou n'est pas terminé",
            Fault::BadString => "une chaîne déborde de ce qui reste",
            Fault::BadHuffman => "un code de Huffman inconnu, ou un remplissage fautif",
            Fault::BufferTooSmall => "le tampon de sortie ne suffit pas",
        };
        write!(f, "{quoi}")
    }
}

#[cfg(test)]
mod tests;
