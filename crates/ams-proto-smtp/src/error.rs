//! Ce qui rend une commande irrecevable.

use core::fmt;

/// Ce qui rend une commande irrecevable.
///
/// # Deux refus qui ne se confondent pas
///
/// [`Error::UnknownVerb`] et [`Error::ObsoleteVerb`] désignent des situations
/// différentes, et la session leur doit des réponses différentes : la première est
/// une erreur de syntaxe (`500`), la seconde une commande comprise mais non
/// servie (`502`). Les mélanger ferait croire à un client qu'il a mal écrit ce
/// qu'on refuse délibérément.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// La ligne dépasse [`Limits::max_command_octets`](crate::Limits::max_command_octets).
    LineTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// La ligne ne se termine pas par CRLF, ou porte un CR ou un LF isolé.
    ///
    /// Même refus que dans `ams-mime`, et pour la même raison : c'est le
    /// désaccord entre serveurs sur ce qui termine une ligne qui a rendu la
    /// contrebande SMTP possible en 2023.
    MalformedLineEnding,

    /// Le verbe n'appartient pas au vocabulaire SMTP.
    UnknownVerb,

    /// Le verbe est compris, mais ne sera pas servi.
    ///
    /// `SEND`, `SOML`, `SAML` et `TURN` sont des reliquats de la RFC 821,
    /// retirés par la RFC 5321 §7.3 et §C. `TURN` inverse les rôles client et
    /// serveur sur une connexion déjà ouverte : c'est un vol de courrier
    /// documenté, et c'est pour cela qu'il a disparu.
    ObsoleteVerb,

    /// La commande attend un argument et n'en a pas.
    MissingArgument,

    /// La commande n'attend aucun argument et en porte un.
    UnexpectedArgument,

    /// `MAIL` sans `FROM:`, ou `RCPT` sans `TO:`.
    MissingPathKeyword,

    /// Un chemin sans ses chevrons, ou une boîte sans son `@`.
    ///
    /// L'espace entre `FROM:` et `<` tombe ici : l'ABNF de la RFC 5321 §4.1.1.2
    /// n'en prévoit pas, et le tolérer serait une divergence d'interprétation de
    /// plus entre implémentations.
    MalformedPath,

    /// Un chemin porte une route source (`@relais:boite@domaine`).
    ///
    /// Syntaxe obsolète de la RFC 821, et vecteur historique de relais ouvert.
    SourceRouteRefused,

    /// `MAIL FROM:<>` est licite ; `RCPT TO:<>` ne l'est pas.
    NullPathRefused,

    /// La partie locale est vide, ou mal formée.
    MalformedLocalPart,

    /// Le domaine est vide, ou mal formé.
    MalformedDomain,

    /// Un littéral d'adresse (`[…]`) est mal formé.
    MalformedAddressLiteral,

    /// La partie locale dépasse sa borne.
    LocalPartTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Le domaine dépasse sa borne.
    DomainTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Le chemin dépasse sa borne.
    PathTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Un paramètre ESMTP est mal formé.
    MalformedParameter,

    /// Plus de paramètres que [`Limits::max_parameters`](crate::Limits::max_parameters).
    TooManyParameters {
        /// La borne franchie.
        limit: usize,
    },

    /// Le nom de mécanisme d'`AUTH` est mal formé (RFC 4422 §3.1).
    MalformedMechanism,

    /// La réponse initiale d'`AUTH` n'est pas du base64 (RFC 4954 §4).
    MalformedInitialResponse,

    // ── Encodage des réponses ───────────────────────────────────────────────
    /// Une réponse sans aucune ligne.
    ///
    /// Il n'existe pas de réponse vide : la dernière ligne est ce qui dit au pair
    /// que la réponse est finie. Sans elle, il attend.
    EmptyReply,

    /// Le texte d'une ligne de réponse sort de `textstring` (RFC 5321 §4.1.2) :
    /// HTAB, ou l'imprimable US-ASCII.
    ///
    /// **C'est le refus le plus important de l'encodeur.** Une réponse contient
    /// souvent ce que le client vient d'envoyer — « 550 5.1.1 `<x@y.z>`:
    /// destinataire inconnu ». Un CR ou un LF qui y passerait laisserait le
    /// client écrire une ligne de réponse ENTIÈRE de son choix, et donc mentir à
    /// ce qui lit la connexion derrière lui.
    ReplyTextNotPrintable,

    /// Une ligne de réponse dépasse
    /// [`Limits::max_reply_octets`](crate::Limits::max_reply_octets).
    ReplyLineTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Le tampon fourni ne peut pas contenir la réponse.
    ///
    /// Ce n'est pas une erreur de protocole : c'est l'appelant qui n'a pas donné
    /// assez de place. `needed` dit combien il en fallait.
    BufferTooSmall {
        /// Le nombre d'octets qu'il aurait fallu.
        needed: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LineTooLong { limit } => {
                write!(f, "ligne de commande de plus de {limit} octets")
            }
            Error::MalformedLineEnding => {
                f.write_str("la ligne ne se termine pas proprement par CRLF")
            }
            Error::UnknownVerb => f.write_str("verbe inconnu"),
            Error::ObsoleteVerb => f.write_str("verbe obsolète, retiré par la RFC 5321"),
            Error::MissingArgument => f.write_str("argument manquant"),
            Error::UnexpectedArgument => f.write_str("argument inattendu"),
            Error::MissingPathKeyword => f.write_str("`FROM:` ou `TO:` manquant"),
            Error::MalformedPath => f.write_str("chemin mal formé (chevrons ou `@` manquant)"),
            Error::SourceRouteRefused => f.write_str("route source refusée (RFC 821, obsolète)"),
            Error::NullPathRefused => f.write_str("chemin nul refusé pour un destinataire"),
            Error::MalformedLocalPart => f.write_str("partie locale mal formée"),
            Error::MalformedDomain => f.write_str("domaine mal formé"),
            Error::MalformedAddressLiteral => f.write_str("littéral d'adresse mal formé"),
            Error::LocalPartTooLong { limit } => {
                write!(f, "partie locale de plus de {limit} octets")
            }
            Error::DomainTooLong { limit } => write!(f, "domaine de plus de {limit} octets"),
            Error::PathTooLong { limit } => write!(f, "chemin de plus de {limit} octets"),
            Error::MalformedParameter => f.write_str("paramètre ESMTP mal formé"),
            Error::TooManyParameters { limit } => write!(f, "plus de {limit} paramètres ESMTP"),
            Error::MalformedMechanism => f.write_str("nom de mécanisme SASL mal formé"),
            Error::MalformedInitialResponse => {
                f.write_str("réponse initiale AUTH hors de l'alphabet base64")
            }
            Error::EmptyReply => f.write_str("réponse sans aucune ligne"),
            Error::ReplyTextNotPrintable => {
                f.write_str("texte de réponse hors de `textstring` (HTAB ou imprimable)")
            }
            Error::ReplyLineTooLong { limit } => {
                write!(f, "ligne de réponse de plus de {limit} octets")
            }
            Error::BufferTooSmall { needed } => {
                write!(f, "tampon trop petit : {needed} octets nécessaires")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    /// Toutes les variantes, pour que rien ne s'ajoute sans être affiché.
    const TOUTES: &[Error] = &[
        Error::LineTooLong { limit: 512 },
        Error::MalformedLineEnding,
        Error::UnknownVerb,
        Error::ObsoleteVerb,
        Error::MissingArgument,
        Error::UnexpectedArgument,
        Error::MissingPathKeyword,
        Error::MalformedPath,
        Error::SourceRouteRefused,
        Error::NullPathRefused,
        Error::MalformedLocalPart,
        Error::MalformedDomain,
        Error::MalformedAddressLiteral,
        Error::LocalPartTooLong { limit: 64 },
        Error::DomainTooLong { limit: 255 },
        Error::PathTooLong { limit: 256 },
        Error::MalformedParameter,
        Error::TooManyParameters { limit: 16 },
        Error::MalformedMechanism,
        Error::MalformedInitialResponse,
        Error::EmptyReply,
        Error::ReplyTextNotPrintable,
        Error::ReplyLineTooLong { limit: 512 },
        Error::BufferTooSmall { needed: 40 },
    ];

    #[test]
    fn chaque_variante_s_affiche_et_dit_quelque_chose() {
        for erreur in TOUTES {
            let texte = std::format!("{erreur}");
            assert!(
                texte.len() > 10,
                "{erreur:?} : « {texte} » est trop laconique"
            );
        }
    }

    #[test]
    fn les_variantes_sont_deux_a_deux_distinctes() {
        for (rang, erreur) in TOUTES.iter().enumerate() {
            for (autre_rang, autre) in TOUTES.iter().enumerate() {
                if rang == autre_rang {
                    assert_eq!(erreur, autre);
                } else {
                    assert_ne!(erreur, autre, "deux variantes se confondent");
                }
            }
        }
    }

    #[test]
    fn le_verbe_inconnu_et_le_verbe_obsolete_ne_se_confondent_pas() {
        // La session leur doit des réponses différentes : 500 pour une erreur de
        // syntaxe, 502 pour une commande comprise mais non servie.
        assert_ne!(Error::UnknownVerb, Error::ObsoleteVerb);
        let copie = Error::ObsoleteVerb;
        assert_eq!(copie, Error::ObsoleteVerb);
        assert!(!std::format!("{copie:?}").is_empty());
    }
}
