//! Ce qui rend une signature ou une clé DKIM irrecevable.

use core::fmt;

/// Ce qui rend une signature ou une clé DKIM irrecevable.
///
/// # Toutes valent `permfail`, et la nuance sert à l'humain
///
/// RFC 6376 §3.9 : une signature qu'on ne sait pas lire ne se vérifie pas « au
/// mieux », elle échoue. La distinction faite ici sert à l'administrateur qui
/// relira ses journaux — un `a=rsa-sha1` refusé et un `b=` illisible ne se
/// corrigent pas de la même façon — jamais à la décision, qui n'a qu'une issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Une liste `tag=valeur` est mal formée (RFC 6376 §3.2).
    MalformedTagList,
    /// Un nom d'étiquette n'en est pas un : il doit commencer par une lettre.
    MalformedTagName,
    /// Une valeur porte un octet que la grammaire n'admet pas.
    MalformedTagValue,
    /// La même étiquette figure deux fois.
    ///
    /// RFC 6376 §3.2 l'interdit, et pour une raison qui n'est pas de forme :
    /// deux `d=` désigneraient deux domaines, et rien ne dirait lequel signe.
    DuplicateTag,
    /// Une étiquette obligatoire manque (§3.5).
    MissingTag(&'static str),
    /// `v=` ne vaut pas `1`.
    UnsupportedVersion,
    /// L'algorithme n'est pas reconnu, ou n'est plus admis.
    ///
    /// **`rsa-sha1` en fait partie** : RFC 8301 §3.1 l'interdit aux signataires
    /// comme aux vérificateurs. L'accepter reviendrait à valider des signatures
    /// qu'on sait falsifiables.
    UnsupportedAlgorithm,
    /// La canonicalisation demandée n'est ni `simple` ni `relaxed`.
    UnsupportedCanonicalization,
    /// Une valeur en base64 ne se décode pas.
    MalformedBase64,
    /// La liste `h=` ne nomme pas `from`.
    ///
    /// RFC 6376 §5.4 l'exige, et c'est le cœur du sujet : une signature qui ne
    /// couvre pas l'auteur ne dit rien de l'auteur, et c'est pourtant lui que
    /// l'humain lira.
    FromNotSigned,
    /// L'identité `i=` n'est ni le domaine `d=` ni l'un de ses sous-domaines.
    ///
    /// RFC 6376 §3.5 : sans cette règle, un signataire pourrait s'attribuer
    /// l'identité d'un domaine qu'il ne détient pas.
    IdentityOutsideDomain,
    /// La signature expire avant d'avoir été posée (`x=` sous `t=`).
    ExpiryBeforeSignature,
    /// Un nombre n'en est pas un, ou déborde.
    MalformedNumber,
    /// Un domaine ou un sélecteur n'en est pas un.
    MalformedDomain,
    /// L'enregistrement de clé n'est pas du DKIM (`v=` présent et différent de
    /// `DKIM1`).
    NotDkimKey,
    /// La clé publique est **révoquée** : `p=` est vide.
    ///
    /// Ce n'est pas une faute de forme, c'est une déclaration — le détenteur du
    /// domaine dit que cette clé ne doit plus rien signer (§3.6.1).
    RevokedKey,
    /// Le type de clé n'est pas géré.
    UnsupportedKeyType,
    /// L'enregistrement de clé ne sert pas le courrier (`s=` sans `email` ni
    /// `*`).
    NotForEmail,
    /// La sortie ne tient pas dans le tampon offert.
    BufferTooSmall,
    /// Le condensat du corps ne correspond pas au `bh=`.
    ///
    /// Le corps a changé depuis la signature — ou n'a jamais été celui qui a été
    /// signé. **C'est le contrôle qu'on fait EN PREMIER** : il coûte une
    /// comparaison de trente-deux octets, là où la signature coûte une
    /// exponentiation modulaire.
    BodyHashMismatch,
    /// La signature ne correspond pas.
    SignatureMismatch,
    /// La clé publique ne se décode pas.
    MalformedKey,
    /// La clé RSA fait moins de 1024 bits.
    ///
    /// RFC 8301 §3.2 l'interdit aux signataires, et l'accepter en vérification
    /// reviendrait à valider ce qu'on sait falsifiable : une clé de 512 bits se
    /// factorise pour le prix de quelques heures de calcul.
    KeyTooSmall,
    /// La clé RSA fait plus de 4096 bits.
    ///
    /// Elle ne protège personne de plus, et coûte à NOUS : c'est une zone
    /// hostile qui la publierait, pour faire brûler du calcul à qui lui écrit.
    KeyTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedTagList => f.write_str("liste `tag=valeur` mal formée (§3.2)"),
            Self::MalformedTagName => f.write_str("nom d'étiquette irrecevable"),
            Self::MalformedTagValue => f.write_str("valeur d'étiquette irrecevable"),
            Self::DuplicateTag => f.write_str("la même étiquette figure deux fois"),
            Self::MissingTag(nom) => write!(f, "l'étiquette obligatoire `{nom}` manque"),
            Self::UnsupportedVersion => f.write_str("`v=` ne vaut pas 1"),
            Self::UnsupportedAlgorithm => {
                f.write_str("algorithme inconnu ou retiré (`rsa-sha1` : RFC 8301)")
            }
            Self::UnsupportedCanonicalization => {
                f.write_str("canonicalisation inconnue : ni `simple` ni `relaxed`")
            }
            Self::MalformedBase64 => f.write_str("une valeur en base64 ne se décode pas"),
            Self::FromNotSigned => f.write_str("`h=` ne couvre pas `from` (§5.4)"),
            Self::IdentityOutsideDomain => {
                f.write_str("`i=` n'est pas sous le domaine de `d=` (§3.5)")
            }
            Self::ExpiryBeforeSignature => f.write_str("`x=` précède `t=`"),
            Self::MalformedNumber => f.write_str("nombre irrecevable"),
            Self::MalformedDomain => f.write_str("domaine ou sélecteur irrecevable"),
            Self::NotDkimKey => f.write_str("cet enregistrement n'est pas une clé DKIM1"),
            Self::RevokedKey => f.write_str("clé RÉVOQUÉE : `p=` est vide (§3.6.1)"),
            Self::UnsupportedKeyType => f.write_str("type de clé non géré"),
            Self::NotForEmail => f.write_str("cette clé ne sert pas le courrier (`s=`)"),
            Self::BufferTooSmall => f.write_str("le tampon offert ne suffit pas"),
            Self::BodyHashMismatch => f.write_str("le corps ne correspond pas au `bh=`"),
            Self::SignatureMismatch => f.write_str("la signature ne correspond pas"),
            Self::MalformedKey => f.write_str("la clé publique ne se décode pas"),
            Self::KeyTooSmall => f.write_str("clé RSA de moins de 1024 bits (RFC 8301 §3.2)"),
            Self::KeyTooLarge => f.write_str("clé RSA de plus de 4096 bits"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    /// Un `Write` qui compte : la crate est `no_std` SANS `alloc`.
    struct Compteur(usize);

    impl core::fmt::Write for Compteur {
        fn write_str(&mut self, morceau: &str) -> core::fmt::Result {
            self.0 = self.0.saturating_add(morceau.len());
            Ok(())
        }
    }

    #[test]
    fn chaque_variante_dit_quelque_chose() {
        for erreur in [
            Error::MalformedTagList,
            Error::MalformedTagName,
            Error::MalformedTagValue,
            Error::DuplicateTag,
            Error::MissingTag("d"),
            Error::UnsupportedVersion,
            Error::UnsupportedAlgorithm,
            Error::UnsupportedCanonicalization,
            Error::MalformedBase64,
            Error::FromNotSigned,
            Error::IdentityOutsideDomain,
            Error::ExpiryBeforeSignature,
            Error::MalformedNumber,
            Error::MalformedDomain,
            Error::NotDkimKey,
            Error::RevokedKey,
            Error::UnsupportedKeyType,
            Error::NotForEmail,
            Error::BufferTooSmall,
            Error::BodyHashMismatch,
            Error::SignatureMismatch,
            Error::MalformedKey,
            Error::KeyTooSmall,
            Error::KeyTooLarge,
        ] {
            let mut compteur = Compteur(0);
            core::fmt::write(&mut compteur, format_args!("{erreur}")).expect("formatable");
            assert!(compteur.0 > 10, "{erreur:?} est trop laconique");
            assert!(!std::format!("{erreur:?}").is_empty());
        }
        assert_eq!(Error::RevokedKey, Error::RevokedKey);
        assert_ne!(Error::RevokedKey, Error::NotDkimKey);
        assert_ne!(Error::MissingTag("d"), Error::MissingTag("s"));
    }
}
