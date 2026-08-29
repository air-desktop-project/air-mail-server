//! Les bornes qu'une commande IMAP ne doit pas franchir.

/// Ce qu'une commande IMAP n'a pas le droit de dépasser.
///
/// # AUCUNE NE VIENT DE LA RFC, ET C'EST LE SUJET
///
/// La RFC 9051 ne borne rien. Elle dit seulement (§4) qu'un serveur « devrait »
/// se protéger contre les littéraux démesurés, et laisse chacun choisir
/// comment. C'est cohérent avec un protocole qui doit pouvoir transporter un
/// message de cent mébioctets — et c'est ce qui fait qu'un serveur IMAP sans
/// bornes explicites est un serveur qu'on met à genoux avec une ligne.
///
/// Ces bornes sont donc DÉCIDÉES ici, et aucun nom de champ ne prétend le
/// contraire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longueur maximale d'une ligne de commande, `CRLF` non compris et
    /// **littéraux exclus**.
    ///
    /// Une ligne porte un tag, un verbe et des arguments ; ce qu'un littéral
    /// annonce se compte à part, parce que c'est de la donnée et non de la
    /// syntaxe.
    pub max_line_octets: usize,

    /// Longueur maximale d'un tag.
    ///
    /// **Le tag est RECOPIÉ dans la réponse.** Un tag de deux kibioctets ferait
    /// donc une réponse de deux kibioctets, pour un client qui n'a rien demandé
    /// de tel. Trente-deux octets couvrent tout ce qu'un client sérieux écrit —
    /// les plus bavards s'arrêtent à une dizaine.
    pub max_tag_octets: usize,

    /// Longueur maximale d'un littéral, en octets.
    ///
    /// C'est la borne qui compte : `{4294967295}` est une ligne de treize
    /// octets qui demande quatre gibioctets. La refuser AVANT de lire quoi que
    /// ce soit est toute la raison d'être de ce module.
    pub max_literal_octets: u64,

    /// Nombre maximal de littéraux dans une même commande.
    ///
    /// Sans cette borne, mille littéraux d'un octet passeraient chacun sous la
    /// précédente, et la commande entière n'aurait pas de fin.
    pub max_literals: usize,

    /// Longueur maximale d'une ligne de réponse, `CRLF` non compris.
    pub max_response_octets: usize,
}

impl Limits {
    /// Les bornes par défaut.
    ///
    /// Huit kibioctets pour une ligne : c'est ce que la RFC 9051 §4 suggère aux
    /// clients de ne pas dépasser, et le seul nombre que le texte avance.
    /// Le reste vient d'ici.
    pub const DEFAULT: Self = Self {
        max_line_octets: 8192,
        max_tag_octets: 32,
        // Soixante-quatre kibioctets : de quoi porter un nom de boîte, une
        // recherche, un mot de passe. **Pas de quoi porter un message** —
        // `APPEND` demandera un chemin qui écoule au fil de l'eau, comme le
        // `DATA` de SMTP, et ce chemin n'existe pas encore.
        //
        // Cette valeur est aussi ce qu'une connexion peut RETENIR : le pilote
        // accumule une commande entière avant de la traiter, et huit littéraux
        // d'un mébioctet feraient huit mébioctets par connexion, pour un serveur
        // qui n'a rien à en faire.
        max_literal_octets: 65_536,
        max_literals: 8,
        max_response_octets: 8192,
    };

    /// La borne d'un littéral NON SYNCHRONISANT (RFC 9051 §6.3.11, `LITERAL-`).
    ///
    /// Un littéral `{n+}` part sans que le serveur ait rien dit : il n'a donc
    /// aucun moyen de le refuser avant de le recevoir. La RFC 9051 l'accepte à
    /// une condition — **quatre kibioctets au plus** — et cette borne-là n'est
    /// pas négociable, puisque c'est elle qui rend la forme sûre.
    pub const NON_SYNCHRONIZING_MAX: u64 = 4096;
}

#[cfg(test)]
mod tests;
