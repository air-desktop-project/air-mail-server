//! Le mécanisme `PLAIN` (RFC 4616).
//!
//! La réponse est `authzid \0 authcid \0 passwd` : trois champs séparés par
//! deux octets nuls, **et exactement deux**. Aucun des trois n'est échappé, ce
//! qui rend le format trivial à lire — et c'est justement pourquoi les erreurs
//! qu'on peut y faire sont toutes des erreurs de longueur.

/// Les trois champs d'une réponse `PLAIN`, tels quels.
///
/// Ce sont des **octets**, pas des chaînes : la crate ne valide pas l'UTF-8 et
/// n'applique pas SASLprep (voir la documentation du module racine). Ce qu'un
/// pair a envoyé est rendu tel qu'il l'a envoyé, et c'est la politique qui
/// décide de ce qu'elle en accepte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credentials<'a> {
    /// L'identité d'autorisation — **vide dans le cas courant**, ce qui veut
    /// dire « la même que celle qui s'authentifie ».
    pub authorization_identity: &'a [u8],
    /// L'identité qui s'authentifie : le nom de compte.
    pub authentication_identity: &'a [u8],
    /// Le mot de passe, en clair. Il n'a traversé le réseau que sous TLS —
    /// `ams_session` le refuse autrement, sans réglage possible.
    pub password: &'a [u8],
}

/// Ce qui rend une réponse `PLAIN` irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Il n'y a pas exactement deux octets nuls.
    Shape,
    /// L'identité qui s'authentifie est vide.
    ///
    /// Refusé ici plutôt que laissé à la politique : une politique qui
    /// comparerait un nom vide à ses comptes pourrait, selon la façon dont elle
    /// est écrite, en trouver un. Le format, lui, sait que ça n'a pas de sens.
    EmptyIdentity,
}

/// Lit une réponse `PLAIN`.
///
/// # Errors
///
/// [`Error`] si la réponse n'a pas exactement deux séparateurs, ou si le nom de
/// compte est vide.
pub fn parse(reponse: &[u8]) -> Result<Credentials<'_>, Error> {
    // `split` rend TOUJOURS un morceau de plus qu'il n'y a de séparateurs :
    // exiger trois morceaux, c'est exiger deux nuls, ni plus ni moins. Un mot de
    // passe contenant un nul donne quatre morceaux, et il est refusé — la RFC
    // 4616 l'interdit, et l'accepter rendrait la lecture ambiguë.
    let mut morceaux = reponse.split(|&octet| octet == 0);
    let (Some(autorisation), Some(compte), Some(secret), None) = (
        morceaux.next(),
        morceaux.next(),
        morceaux.next(),
        morceaux.next(),
    ) else {
        return Err(Error::Shape);
    };
    if compte.is_empty() {
        return Err(Error::EmptyIdentity);
    }
    Ok(Credentials {
        authorization_identity: autorisation,
        authentication_identity: compte,
        password: secret,
    })
}

#[cfg(test)]
mod tests {
    use super::{Error, parse};

    #[test]
    fn le_cas_courant_a_une_identite_d_autorisation_vide() {
        // C'est la forme qu'envoient tous les clients : « je suis jean, et je
        // n'agis pour le compte de personne d'autre ».
        let lu = parse(b"\0jean\0secret").expect("recevable");
        assert_eq!(lu.authorization_identity, b"");
        assert_eq!(lu.authentication_identity, b"jean");
        assert_eq!(lu.password, b"secret");
    }

    #[test]
    fn une_identite_d_autorisation_est_rendue_telle_quelle() {
        let lu = parse(b"postmaster\0jean\0secret").expect("recevable");
        assert_eq!(lu.authorization_identity, b"postmaster");
        assert_eq!(lu.authentication_identity, b"jean");
    }

    #[test]
    fn un_mot_de_passe_vide_est_une_affaire_de_politique_pas_de_format() {
        // Le format n'a rien à y redire ; c'est la politique qui refusera. Un
        // refus ici dirait au pair QUEL champ a manqué, et ce genre de précision
        // se collectionne.
        let lu = parse(b"\0jean\0").expect("recevable");
        assert_eq!(lu.password, b"");
    }

    #[test]
    fn le_nombre_de_separateurs_est_exact() {
        for reponse in [
            &b""[..],            // aucun
            b"jean",             // aucun
            b"\0jean",           // un seul
            b"\0jean\0secret\0", // trois
            b"\0jean\0sec\0ret", // un nul dans le mot de passe
        ] {
            assert_eq!(parse(reponse), Err(Error::Shape), "{reponse:?}");
        }
    }

    #[test]
    fn un_nom_de_compte_vide_est_refuse() {
        assert_eq!(parse(b"\0\0secret"), Err(Error::EmptyIdentity));
        assert_eq!(parse(b"postmaster\0\0secret"), Err(Error::EmptyIdentity));
    }

    #[test]
    fn les_octets_ne_sont_ni_interpretes_ni_normalises() {
        // Pas d'UTF-8 exigé, pas de SASLprep : ce que le pair a envoyé est rendu
        // tel quel, et la politique décide.
        let lu = parse(b"\0je\xffan\0mot\x80passe").expect("recevable");
        assert_eq!(lu.authentication_identity, b"je\xffan");
        assert_eq!(lu.password, b"mot\x80passe");
    }

    #[test]
    fn les_types_se_comparent_et_se_deboguent() {
        let lu = parse(b"\0jean\0secret").expect("recevable");
        assert_eq!(lu, parse(b"\0jean\0secret").expect("recevable"));
        assert_ne!(lu, parse(b"\0jeanne\0secret").expect("recevable"));
        assert_ne!(Error::Shape, Error::EmptyIdentity);
    }
}
