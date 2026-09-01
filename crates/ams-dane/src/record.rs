//! Un enregistrement `TLSA`, et ce qu'il autorise.

use sha2::{Digest as _, Sha256, Sha512};

/// La plus longue empreinte qu'un `TLSA` porte : celle de SHA-512.
const EMPREINTE_MAX: usize = 64;

/// Ce que l'enregistrement désigne (§2.1.1 de RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// `DANE-TA(2)` — l'AUTORITÉ qui a signé le certificat du serveur.
    ///
    /// Le pair doit présenter cette autorité dans sa chaîne, et son certificat
    /// doit s'y rattacher. **Le nom se vérifie** dans ce cas (§3.1.1 de
    /// RFC 7672) : l'autorité peut avoir signé pour d'autres.
    TrustAnchor,
    /// `DANE-EE(3)` — le certificat du serveur LUI-MÊME.
    ///
    /// Il n'y a plus rien à valider que l'égalité : ni chaîne, ni autorité, ni
    /// nom. §3.1.1 : les vérifications de nom NE DOIVENT PAS être faites — le
    /// domaine a nommé ce certificat exactement, et c'est plus fort qu'un nom.
    EndEntity,
    /// Tout le reste, `PKIX-TA(0)` et `PKIX-EE(1)` compris.
    ///
    /// **INUTILISABLE POUR SMTP** (§3.1.3 de RFC 7672), et non « refusé » : un
    /// jeu qui n'en porterait que de ceux-là se comporte comme un jeu vide.
    Unusable(u8),
}

impl Usage {
    /// Le code de cet usage, tel que l'enregistrement le porte.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::TrustAnchor => 2,
            Self::EndEntity => 3,
            Self::Unusable(code) => code,
        }
    }

    fn depuis(code: u8) -> Self {
        match code {
            2 => Self::TrustAnchor,
            3 => Self::EndEntity,
            autre => Self::Unusable(autre),
        }
    }
}

/// Ce sur quoi l'empreinte porte (§2.1.2 de RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// Le certificat entier, tel qu'il est encodé en DER.
    Certificate,
    /// La seule clé publique, avec son algorithme (`SubjectPublicKeyInfo`).
    ///
    /// **C'est le choix qui survit à un renouvellement** : un certificat
    /// réémis avec la même clé garde la même empreinte, et le domaine n'a pas à
    /// republier son DNS le jour où il renouvelle.
    PublicKey,
    /// Un sélecteur qu'on ne sait pas traiter. L'enregistrement est inutilisable.
    Unusable(u8),
}

impl Selector {
    /// Le code de ce sélecteur.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Certificate => 0,
            Self::PublicKey => 1,
            Self::Unusable(code) => code,
        }
    }

    fn depuis(code: u8) -> Self {
        match code {
            0 => Self::Certificate,
            1 => Self::PublicKey,
            autre => Self::Unusable(autre),
        }
    }
}

/// Comment l'empreinte est calculée (§2.1.3 de RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matching {
    /// Aucune empreinte : la donnée EST le certificat, ou la clé.
    Exact,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
    /// Un algorithme qu'on ne sait pas calculer. L'enregistrement est
    /// inutilisable.
    ///
    /// **On ne le refuse pas**, et la nuance est celle de §2.2 de RFC 7672 : un
    /// algorithme de demain ne doit pas arrêter le courrier d'aujourd'hui.
    Unusable(u8),
}

impl Matching {
    /// Le code de cet appariement.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::Sha256 => 1,
            Self::Sha512 => 2,
            Self::Unusable(code) => code,
        }
    }

    fn depuis(code: u8) -> Self {
        match code {
            0 => Self::Exact,
            1 => Self::Sha256,
            2 => Self::Sha512,
            autre => Self::Unusable(autre),
        }
    }
}

/// Ce qu'il faut vérifier pour qu'un enregistrement soit satisfait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// Le certificat du pair EST celui-ci. Rien d'autre à vérifier — ni chaîne,
    /// ni nom, ni date (§5.1 de RFC 7671).
    LeafOnly,
    /// Ce certificat est l'AUTORITÉ. Le certificat du pair doit s'y rattacher,
    /// et son nom doit être vérifié.
    Anchor,
}

/// Un enregistrement `TLSA`, décodé.
///
/// # IL N'EST PAS COPIÉ EN ENTIER
///
/// L'empreinte tient dans un tableau de taille fixe — 64 octets au plus, celle
/// de SHA-512 — et l'appariement EXACT, qui porte un certificat entier, garde
/// une tranche de l'appelant. C3 : rien ici ne croît avec ce qu'un DNS répond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlsa<'a> {
    usage: Usage,
    selector: Selector,
    matching: Matching,
    /// L'empreinte, ou le certificat entier pour [`Matching::Exact`].
    donnee: &'a [u8],
}

impl<'a> Tlsa<'a> {
    /// Décode le `RDATA` d'un `TLSA`.
    ///
    /// Rend `None` pour ce qui n'est pas un enregistrement : moins de quatre
    /// octets, ou une donnée vide. **Un usage, un sélecteur ou un appariement
    /// inconnus ne sont PAS des erreurs** : ils rendent l'enregistrement
    /// inutilisable, ce que [`Tlsa::usable`] dit, et c'est le comportement que
    /// §2.2 de RFC 7672 demande — un algorithme de demain ne doit pas arrêter le
    /// courrier d'aujourd'hui.
    #[must_use]
    pub fn parse(rdata: &'a [u8]) -> Option<Self> {
        let usage = Usage::depuis(*rdata.first()?);
        let selector = Selector::depuis(*rdata.get(1)?);
        let matching = Matching::depuis(*rdata.get(2)?);
        // `get(2)` a réussi : la tranche à partir de trois existe forcément, et
        // `unwrap_or_default` porte cette certitude dans la bibliothèque
        // standard plutôt que dans une garde que rien n'atteindrait. C'est le
        // `is_empty` qui suit qui refuse un enregistrement sans donnée.
        let donnee = rdata.get(3..).unwrap_or_default();
        if donnee.is_empty() {
            return None;
        }
        Some(Self {
            usage,
            selector,
            matching,
            donnee,
        })
    }

    /// L'usage de cet enregistrement.
    #[must_use]
    pub fn usage(self) -> Usage {
        self.usage
    }

    /// Ce sur quoi son empreinte porte.
    #[must_use]
    pub fn selector(self) -> Selector {
        self.selector
    }

    /// Comment son empreinte est calculée.
    #[must_use]
    pub fn matching(self) -> Matching {
        self.matching
    }

    /// L'empreinte, ou le certificat entier.
    #[must_use]
    pub fn data(self) -> &'a [u8] {
        self.donnee
    }

    /// Cet enregistrement peut-il servir à une remise SMTP ?
    ///
    /// Il faut les trois : un usage que §3.1.3 de RFC 7672 autorise, un
    /// sélecteur qu'on sait extraire, et un appariement qu'on sait calculer —
    /// **avec la longueur d'empreinte qui va avec**. Une empreinte SHA-256 de
    /// trente et un octets n'est pas une empreinte, et la comparer à moitié
    /// serait pire que de l'ignorer.
    #[must_use]
    pub fn usable(self) -> bool {
        self.eprouve().is_some()
    }

    /// Ce qu'il faudra vérifier si cet enregistrement est satisfait.
    ///
    /// `None` quand il n'est pas utilisable : il n'y a alors rien à vérifier.
    #[must_use]
    pub fn requirement(self) -> Option<Match> {
        self.eprouve().map(|eprouve| eprouve.exigence)
    }

    /// Ce certificat satisfait-il cet enregistrement ?
    ///
    /// `certificate` est le certificat en DER. Le `SubjectPublicKeyInfo` que le
    /// sélecteur `1` désigne est retrouvé ici — voir [`crate::subject_public_key_info`]
    /// —, et un certificat dont on ne sait pas le retrouver ne satisfait rien.
    ///
    /// **Un enregistrement inutilisable ne correspond à RIEN**, et surtout pas à
    /// tout : rendre `true` par défaut ferait d'un usage inconnu un
    /// laissez-passer.
    #[must_use]
    pub fn matches(self, certificate: &[u8]) -> bool {
        let Some(eprouve) = self.eprouve() else {
            return false;
        };
        let sujet = match eprouve.porte {
            Porte::Certificat => certificate,
            // **UN CERTIFICAT DONT ON NE SAIT PAS TIRER LA CLEF NE SATISFAIT
            // RIEN**, et surtout pas tout : se rabattre sur le certificat entier
            // ferait comparer une empreinte de clef à autre chose qu'une clef.
            Porte::Clef => match crate::spki::subject_public_key_info(certificate) {
                Some(clef) => clef,
                None => return false,
            },
        };
        match eprouve.calcul {
            // **UNE COMPARAISON EN TEMPS CONSTANT N'A RIEN À FAIRE ICI**, et
            // c'est délibéré : ce qu'on compare est PUBLIC des deux côtés — un
            // certificat que le pair vient d'envoyer, et une empreinte publiée
            // dans le DNS. Il n'y a pas de secret dont la durée trahirait quoi
            // que ce soit.
            Calcul::Tel => sujet == self.donnee,
            Calcul::Sha256 => Sha256::digest(sujet).as_slice() == self.donnee,
            Calcul::Sha512 => empreinte_512(sujet) == self.donnee,
        }
    }

    /// Ce que cet enregistrement est, UNE FOIS ÉPROUVÉ.
    ///
    /// # POURQUOI UN TYPE, ET NON TROIS VÉRIFICATIONS RÉPÉTÉES
    ///
    /// `usable`, `requirement` et `matches` posaient la même question, chacune
    /// avec son bras « et sinon » que rien ne pouvait atteindre — trois gardes
    /// inatteignables, c'est-à-dire trois gardes qui n'en sont pas. Ici la
    /// validation se fait UNE fois et produit un type qui la porte : les cas
    /// écartés n'existent plus dans les `match` qui suivent.
    fn eprouve(self) -> Option<Eprouve> {
        let exigence = match self.usage {
            Usage::EndEntity => Match::LeafOnly,
            Usage::TrustAnchor => Match::Anchor,
            Usage::Unusable(_) => return None,
        };
        let porte = match self.selector {
            Selector::Certificate => Porte::Certificat,
            Selector::PublicKey => Porte::Clef,
            Selector::Unusable(_) => return None,
        };
        let calcul = match self.matching {
            // `parse` a déjà refusé une donnée vide : un certificat entier n'a
            // pas d'autre longueur à respecter.
            Matching::Exact => Calcul::Tel,
            Matching::Sha256 if self.donnee.len() == 32 => Calcul::Sha256,
            Matching::Sha512 if self.donnee.len() == 64 => Calcul::Sha512,
            // **UNE EMPREINTE DE LA MAUVAISE LONGUEUR N'EST PAS UNE EMPREINTE.**
            // La comparer à moitié serait pire que de l'ignorer.
            Matching::Sha256 | Matching::Sha512 | Matching::Unusable(_) => return None,
        };
        Some(Eprouve {
            exigence,
            porte,
            calcul,
        })
    }
}

/// Un `TLSA` dont les trois champs ont été éprouvés.
#[derive(Debug, Clone, Copy)]
struct Eprouve {
    exigence: Match,
    porte: Porte,
    calcul: Calcul,
}

/// Ce sur quoi l'empreinte porte, une fois le sélecteur reconnu.
#[derive(Debug, Clone, Copy)]
enum Porte {
    Certificat,
    Clef,
}

/// Comment l'empreinte se calcule, une fois l'appariement reconnu.
#[derive(Debug, Clone, Copy)]
enum Calcul {
    Tel,
    Sha256,
    Sha512,
}

/// L'empreinte SHA-512 de `octets`, dans un tableau de taille fixe.
fn empreinte_512(octets: &[u8]) -> [u8; EMPREINTE_MAX] {
    let mut place = [0_u8; EMPREINTE_MAX];
    let calcul = Sha512::digest(octets);
    // `Sha512` rend exactement soixante-quatre octets : la recopie ne peut pas
    // manquer, et `unwrap_or_default` porte cette certitude dans la
    // bibliothèque standard plutôt que dans une garde que rien n'atteindrait.
    let source = calcul.get(..EMPREINTE_MAX).unwrap_or_default();
    place
        .get_mut(..source.len())
        .unwrap_or_default()
        .copy_from_slice(source);
    place
}

#[cfg(test)]
pub(crate) mod tests;
