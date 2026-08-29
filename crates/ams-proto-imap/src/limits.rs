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

    /// Longueur maximale du littéral d'un `APPEND`.
    ///
    /// # POURQUOI CELLE-CI N'EST PAS L'AUTRE
    ///
    /// [`max_literal_octets`](Limits::max_literal_octets) borne ce qu'une
    /// connexion RETIENT : le pilote accumule une commande entière avant de la
    /// traiter. Le littéral d'un `APPEND` ne se retient pas — il s'écoule vers
    /// le magasin au fil de l'eau, comme le `DATA` de SMTP — et sa borne est
    /// donc celle d'un MESSAGE, pas celle d'un tampon. Les confondre ferait ou
    /// bien refuser tout message d'un peu de tenue, ou bien retenir en mémoire
    /// ce qu'un client choisit.
    pub max_append_octets: u64,

    /// Nombre maximal de littéraux dans une même commande.
    ///
    /// Sans cette borne, mille littéraux d'un octet passeraient chacun sous la
    /// précédente, et la commande entière n'aurait pas de fin.
    pub max_literals: usize,

    /// Longueur maximale d'une ligne de réponse, `CRLF` non compris.
    pub max_response_octets: usize,

    /// Nombre maximal d'éléments dans un ensemble de numéros.
    ///
    /// `1,1,1,…` cent mille fois est un `sequence-set` parfaitement valide, et
    /// le parcourir pour chaque message d'une boîte ferait un travail
    /// quadratique offert à qui écrit une ligne.
    pub max_sequence_items: usize,

    /// Nombre maximal d'éléments dans une liste `FETCH`.
    ///
    /// Chaque élément demande un travail par message ; mille de plus par
    /// commande est déjà bien au-delà de ce qu'un client écrit.
    pub max_fetch_items: usize,
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
        // `APPEND` écoule le sien au fil de l'eau, comme le `DATA` de SMTP.
        //
        // Cette valeur est aussi ce qu'une connexion peut RETENIR : le pilote
        // accumule une commande entière avant de la traiter, et huit littéraux
        // d'un mébioctet feraient huit mébioctets par connexion, pour un serveur
        // qui n'a rien à en faire. Le littéral d'un `APPEND`, lui, ne se retient
        // pas : voir `max_append_octets`.
        max_literal_octets: 65_536,
        // Dix mébioctets, la même valeur que la borne SMTP par défaut : un
        // message qu'on refuserait de recevoir par un chemin n'a pas de raison
        // de passer par l'autre.
        max_append_octets: 10_485_760,
        max_literals: 8,
        max_response_octets: 8192,
        max_sequence_items: 1024,
        max_fetch_items: 64,
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
