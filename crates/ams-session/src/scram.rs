// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une session retient entre les deux allers-retours de SCRAM.
//!
//! # POURQUOI CE MODULE EST SI PETIT, ET CE QU'IL NE FAIT PAS
//!
//! La session **encadre**, elle ne calcule pas. SCRAM tient en deux échanges :
//! le pair envoie son `client-first`, le serveur répond un `server-first`, le
//! pair envoie son `client-final`, le serveur conclut. Entre les deux, il faut
//! se souvenir de DEUX choses — le `client-first-bare` et le `server-first` —
//! parce que le `AuthMessage` de §3 est leur concaténation avec le
//! `client-final` amputé de sa preuve.
//!
//! Tout le reste — le sel, les itérations, PBKDF2, la comparaison — appartient
//! à la politique, qui seule a le magasin et la clé de scellement. Ce module ne
//! sait même pas si un compte existe.
//!
//! # POURQUOI DES TAMPONS FIXES, ET CES TAILLES-LÀ
//!
//! C3 : pas d'allocation. Une session vit par connexion, et un pair non
//! authentifié ne doit pas pouvoir en faire grossir une. Les deux messages ont
//! une forme connue — un nom de compte, deux nonces, un sel en base64, un
//! nombre — et [`BARE_MAX`] comme [`FIRST_MAX`] les couvrent largement. Ce qui
//! déborde est REFUSÉ, jamais tronqué : un `AuthMessage` amputé ne
//! correspondrait à rien, et le pair verrait « mot de passe faux » là où il
//! faudrait lire « votre nom de compte est trop long ».

/// Ce qu'un `client-first-bare` peut occuper.
///
/// `n=<compte>,r=<nonce>` : un nom de compte est borné à soixante-quatre octets
/// par `check_login`, un nonce de client tient en quelques dizaines. Le double
/// laisse la place aux extensions que §5 permet et qu'on ignore.
pub const BARE_MAX: usize = 256;

/// Ce qu'un `server-first` peut occuper.
///
/// `r=<les deux nonces>,s=<sel en base64>,i=<nombre>` : les deux nonces, vingt-
/// quatre octets de sel encodés, et cinq chiffres.
pub const FIRST_MAX: usize = 256;

/// Les deux messages qu'il faut avoir gardés pour conclure.
#[derive(Debug, Clone, Copy)]
pub struct EtatScram {
    bare: [u8; BARE_MAX],
    bare_len: usize,
    first: [u8; FIRST_MAX],
    first_len: usize,
}

impl EtatScram {
    /// Retient les deux messages, ou refuse s'ils ne tiennent pas.
    ///
    /// **REFUSER PLUTÔT QUE TRONQUER** : un `AuthMessage` amputé donnerait une
    /// preuve fausse, et le pair lirait « mot de passe invalide » pour un nom
    /// de compte trop long. Le refus, lui, se diagnostique.
    #[must_use]
    pub fn neuf(bare: &[u8], first: &[u8]) -> Option<Self> {
        if bare.len() > BARE_MAX || first.len() > FIRST_MAX {
            return None;
        }
        let mut etat = Self {
            bare: [0; BARE_MAX],
            bare_len: bare.len(),
            first: [0; FIRST_MAX],
            first_len: first.len(),
        };
        etat.bare
            .get_mut(..bare.len())
            .unwrap_or_default()
            .copy_from_slice(bare);
        etat.first
            .get_mut(..first.len())
            .unwrap_or_default()
            .copy_from_slice(first);
        Some(etat)
    }

    /// Le `client-first-bare` retenu.
    #[must_use]
    pub fn bare(&self) -> &[u8] {
        self.bare.get(..self.bare_len).unwrap_or_default()
    }

    /// Le `server-first` retenu.
    #[must_use]
    pub fn first(&self) -> &[u8] {
        self.first.get(..self.first_len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{BARE_MAX, EtatScram, FIRST_MAX};

    #[test]
    fn ce_qui_est_retenu_se_relit_tel_quel() {
        let etat = EtatScram::neuf(b"n=jean,r=abc", b"r=abcdef,s=c2Vs,i=32768").expect("tient");
        assert_eq!(etat.bare(), b"n=jean,r=abc");
        assert_eq!(etat.first(), b"r=abcdef,s=c2Vs,i=32768");
    }

    #[test]
    fn le_vide_se_retient_aussi() {
        // Une politique peut rendre un `server-first` vide si elle refuse : la
        // session doit savoir le porter sans broncher.
        let etat = EtatScram::neuf(b"", b"").expect("tient");
        assert_eq!(etat.bare(), b"");
        assert_eq!(etat.first(), b"");
    }

    #[test]
    fn ce_qui_deborde_est_refuse_et_non_tronque() {
        let trop_long = [b'a'; BARE_MAX + 1];
        assert!(EtatScram::neuf(&trop_long, b"r=x").is_none());
        let trop_long = [b'a'; FIRST_MAX + 1];
        assert!(EtatScram::neuf(b"n=jean,r=abc", &trop_long).is_none());
        // Et la limite EXACTE tient, elle : c'est une borne, pas un interdit.
        let juste = [b'a'; BARE_MAX];
        assert!(EtatScram::neuf(&juste, b"r=x").is_some());
        let juste = [b'a'; FIRST_MAX];
        assert!(EtatScram::neuf(b"n=jean,r=abc", &juste).is_some());
    }

    #[test]
    fn l_etat_se_copie_et_se_debogue() {
        let etat = EtatScram::neuf(b"n=jean,r=abc", b"r=abc,s=c2Vs,i=4096").expect("tient");
        let copie = etat;
        assert_eq!(copie.bare(), etat.bare());
        assert!(!std::format!("{etat:?}").is_empty());
    }
}
