//! Sous quel mécanisme SASL un pair s'est authentifié.
//!
//! # POURQUOI LA SESSION LE RETIENT
//!
//! « Authentifié » suffit à décider si l'on relaie ; cela ne suffit pas à
//! DIRE CE QUI S'EST PASSÉ. Un exploitant qui lit son journal veut distinguer
//! un client qui a livré son mot de passe en clair dans le tunnel d'un client
//! qui a prouvé le connaître sans l'envoyer — et, parmi ces derniers, celui
//! qui a lié sa preuve au canal de celui qui ne l'a pas fait.
//!
//! C'est la seule chose que la boucle ne peut PAS deviner de l'extérieur : le
//! choix du mécanisme se joue dans la commande `AUTH`, que la session est
//! seule à décoder (C1).

/// Le mécanisme sous lequel un pair s'est authentifié.
///
/// **Il n'existe qu'APRÈS un succès.** Une tentative refusée n'en laisse
/// aucun : nommer le mécanisme d'un échec reviendrait à consigner ce qu'un
/// inconnu a essayé, et non ce qu'un compte a fait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mecanisme {
    /// `PLAIN` (RFC 4616) : le mot de passe traverse le tunnel tel quel.
    Plain,
    /// Le couple `USER`/`PASS` de POP3 (RFC 1939 §7).
    ///
    /// **POP3 n'annonce ici aucun mécanisme SASL**, et c'est la seule voie
    /// qu'il ouvre. Le nommer permet à une ligne de journal POP3 de se lire
    /// comme les autres, sans laisser croire à une session anonyme.
    UserPass,
    /// La commande `LOGIN` d'IMAP (RFC 9051 §6.2.3).
    ///
    /// **Ce n'est PAS un mécanisme SASL**, et c'est pourquoi il a son nom à
    /// lui : le secret voyage en argument de commande, hors de tout profil,
    /// là où `PLAIN` passe au moins par `AUTHENTICATE`. Les confondre au
    /// journal masquerait quel client emprunte la voie la plus ancienne.
    Login,
    /// `SCRAM-SHA-256` (RFC 7677) : une preuve, et le mot de passe reste chez
    /// le client.
    ScramSha256,
    /// `SCRAM-SHA-256-PLUS` (RFC 5802 §6, RFC 9266) : la même preuve, LIÉE au
    /// canal TLS qui la porte.
    ScramSha256Plus,
}

impl Mecanisme {
    /// Son nom tel que la RFC l'écrit — c'est celui qui part au journal.
    #[must_use]
    pub const fn nom(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::UserPass => "USER/PASS",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
        }
    }

    /// Le mécanisme SCRAM qui correspond à une preuve liée, ou non, au canal.
    #[must_use]
    pub const fn scram(liee: bool) -> Self {
        if liee {
            Self::ScramSha256Plus
        } else {
            Self::ScramSha256
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Mecanisme;

    #[test]
    fn chaque_mecanisme_porte_le_nom_de_sa_rfc() {
        assert_eq!(Mecanisme::Plain.nom(), "PLAIN");
        assert_eq!(Mecanisme::Login.nom(), "LOGIN");
        assert_eq!(Mecanisme::UserPass.nom(), "USER/PASS");
        assert_eq!(Mecanisme::ScramSha256.nom(), "SCRAM-SHA-256");
        assert_eq!(Mecanisme::ScramSha256Plus.nom(), "SCRAM-SHA-256-PLUS");
    }

    #[test]
    fn la_liaison_au_canal_distingue_les_deux_scram() {
        assert_eq!(Mecanisme::scram(true), Mecanisme::ScramSha256Plus);
        assert_eq!(Mecanisme::scram(false), Mecanisme::ScramSha256);
    }
}
