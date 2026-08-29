//! Les termes d'un enregistrement : mécanismes, modificateurs, qualificateurs.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Error;

/// Ce qu'un mécanisme dit quand il correspond (RFC 7208 §4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    /// `+` — l'adresse est autorisée. **C'est le défaut.**
    Pass,
    /// `-` — l'adresse ne l'est pas, et l'expéditeur le dit fermement.
    Fail,
    /// `~` — l'adresse ne l'est pas, mais l'expéditeur n'ose pas encore le dire.
    SoftFail,
    /// `?` — l'expéditeur ne se prononce pas.
    Neutral,
}

impl Qualifier {
    /// Lit un qualificateur en tête de terme, s'il y en a un.
    ///
    /// Rend aussi le reste du terme. **Absent, c'est `+`** : la RFC 7208 §4.6.2
    /// le dit, et l'oublier ferait passer pour neutre ce qu'un expéditeur a
    /// autorisé.
    #[must_use]
    pub fn split(terme: &[u8]) -> (Self, &[u8]) {
        match terme.split_first() {
            Some((b'+', reste)) => (Self::Pass, reste),
            Some((b'-', reste)) => (Self::Fail, reste),
            Some((b'~', reste)) => (Self::SoftFail, reste),
            Some((b'?', reste)) => (Self::Neutral, reste),
            _ => (Self::Pass, terme),
        }
    }
}

/// Un mécanisme, avec ce qu'il porte.
///
/// Pas `#[non_exhaustive]`, pour la même raison qu'ailleurs dans ce dépôt : un
/// mécanisme nouveau doit casser la compilation de l'évaluateur, pas tomber dans
/// un bras `_` qui l'ignorerait en silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism<'a> {
    /// `all` — correspond toujours. C'est le dernier mot d'un enregistrement.
    All,
    /// `ip4:<adresse>[/<préfixe>]` — **aucune résolution**.
    Ip4 {
        /// L'adresse du réseau.
        address: Ipv4Addr,
        /// La longueur du préfixe, de 0 à 32. Absente, elle vaut 32.
        prefix: u8,
    },
    /// `ip6:<adresse>[/<préfixe>]` — **aucune résolution**.
    Ip6 {
        /// L'adresse du réseau.
        address: Ipv6Addr,
        /// La longueur du préfixe, de 0 à 128. Absente, elle vaut 128.
        prefix: u8,
    },
    /// `a[:<domaine>][/<préfixe4>][//<préfixe6>]` — **résout**.
    A(DomainSpec<'a>),
    /// `mx[:<domaine>][/<préfixe4>][//<préfixe6>]` — **résout**.
    Mx(DomainSpec<'a>),
    /// `include:<domaine>` — **résout**, et évalue une politique entière.
    Include(DomainSpec<'a>),
    /// `exists:<domaine>` — **résout**.
    Exists(DomainSpec<'a>),
    /// `ptr[:<domaine>]` — **résout**, et la RFC 7208 §5.5 le déconseille.
    ///
    /// Il est lu, parce qu'un enregistrement qui en porte un doit être compris
    /// plutôt que refusé. Ce qu'il coûtera à l'évaluation — une résolution
    /// inverse, puis autant de résolutions directes qu'elle rend de noms — est
    /// une raison de plus pour que la limite des dix soit tenue par une machine
    /// à états.
    Ptr(DomainSpec<'a>),
}

/// Le domaine d'un mécanisme, **tel qu'il est écrit**.
///
/// # Il n'est ni validé ni développé ici
///
/// Un domaine SPF peut porter des macros (`%{i}`, `%{d}`, RFC 7208 §7) qui ne
/// prennent leur sens qu'au moment de l'évaluation, quand on connaît l'adresse
/// du pair et l'expéditeur. Les valider maintenant reviendrait à écrire deux
/// fois la même grammaire — et deux grammaires finissent par diverger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainSpec<'a> {
    /// Le domaine, ou une tranche vide quand le mécanisme n'en porte pas.
    ///
    /// Vide veut dire « le domaine courant » (RFC 7208 §5.3), pas « aucun ».
    pub spec: &'a [u8],
    /// Le préfixe IPv4, de 0 à 32. Absent, il vaut 32.
    pub prefix4: u8,
    /// Le préfixe IPv6, de 0 à 128. Absent, il vaut 128.
    pub prefix6: u8,
}

/// Un modificateur (RFC 7208 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier<'a> {
    /// `redirect=<domaine>` — l'évaluation se poursuit ailleurs.
    Redirect(&'a [u8]),
    /// `exp=<domaine>` — où trouver l'explication d'un `Fail`.
    Explanation(&'a [u8]),
    /// Un modificateur inconnu, que la RFC 7208 §6 demande d'**ignorer**.
    ///
    /// Ignorer plutôt que refuser : c'est ainsi qu'un protocole s'étend sans
    /// casser ce qui existe, et le refuser ferait échouer sur un enregistrement
    /// que tout le monde accepte.
    Unknown {
        /// Son nom.
        name: &'a [u8],
        /// Sa valeur.
        value: &'a [u8],
    },
}

/// Un terme : un mécanisme qualifié, ou un modificateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Term<'a> {
    /// Un mécanisme, avec son qualificateur.
    Mechanism {
        /// Ce qu'il dit quand il correspond.
        qualifier: Qualifier,
        /// Le mécanisme lui-même.
        mechanism: Mechanism<'a>,
    },
    /// Un modificateur.
    Modifier(Modifier<'a>),
}

/// Ce qu'il faut demander au DNS pour trancher un mécanisme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// La politique SPF du nom — c'est ce que fait un `include`.
    Policy,
    /// Les adresses (A **et** AAAA) du nom.
    Addresses,
    /// Les adresses des serveurs de courrier du nom.
    MxAddresses,
    /// Le nom existe-t-il ?
    Exists,
    /// Les noms que la résolution inverse de l'adresse du pair confirme.
    PtrNames,
}

/// Ce qu'un mécanisme répond, ou ce qu'il lui faut pour répondre.
///
/// # Un seul aiguillage, et il est total
///
/// La première version rendait `Option<bool>` : `None` voulait dire « il me faut
/// le DNS », et l'appelant devait alors REFAIRE le tri des mécanismes pour
/// savoir quoi demander. Deux aiguillages sur la même énumération, dont le
/// second portait des bras qu'aucun test ne pouvait atteindre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// Le mécanisme a répondu sans personne.
    Answered(bool),
    /// Il lui faut une résolution.
    Needs {
        /// Le domaine à interroger — vide pour « celui de la politique ».
        domain: DomainSpec<'a>,
        /// Ce qu'on veut en savoir.
        lookup: Lookup,
    },
}

impl<'a> Mechanism<'a> {
    /// Ce mécanisme répond-il seul, et sinon que lui faut-il ?
    #[must_use]
    pub fn resolve(&self, client: IpAddr) -> Resolution<'a> {
        match (self, client) {
            (Self::All, _) => Resolution::Answered(true),
            (Self::Ip4 { address, prefix }, IpAddr::V4(vue)) => {
                Resolution::Answered(meme_prefixe(&address.octets(), &vue.octets(), *prefix))
            }
            (Self::Ip6 { address, prefix }, IpAddr::V6(vue)) => {
                Resolution::Answered(meme_prefixe(&address.octets(), &vue.octets(), *prefix))
            }
            // UN `ip4:` NE CORRESPOND PAS À UNE ADRESSE IPv6, et inversement.
            // La RFC 7208 §5.6 est explicite ; les confondre ferait autoriser
            // un pair d'une autre famille que celle qu'on a écrite.
            (Self::Ip4 { .. } | Self::Ip6 { .. }, _) => Resolution::Answered(false),
            (Self::A(domain), _) => Resolution::Needs {
                domain: *domain,
                lookup: Lookup::Addresses,
            },
            (Self::Mx(domain), _) => Resolution::Needs {
                domain: *domain,
                lookup: Lookup::MxAddresses,
            },
            (Self::Include(domain), _) => Resolution::Needs {
                domain: *domain,
                lookup: Lookup::Policy,
            },
            (Self::Exists(domain), _) => Resolution::Needs {
                domain: *domain,
                lookup: Lookup::Exists,
            },
            (Self::Ptr(domain), _) => Resolution::Needs {
                domain: *domain,
                lookup: Lookup::PtrNames,
            },
        }
    }
}

/// Deux adresses de la même famille partagent-elles leurs `prefix` premiers
/// bits ?
///
/// Rend `false` pour deux familles différentes : la RFC 7208 §5.6 l'exige, et
/// les confondre autoriserait un pair d'une autre famille que celle qu'on a
/// écrite.
/// `prefixes` porte les deux longueurs du mécanisme — `a/24//64` en écrit une
/// par famille — et c'est ICI qu'on choisit laquelle s'applique. L'appelant qui
/// trierait les familles avant d'appeler ferait le même tri deux fois, dont un
/// qu'aucun test ne pourrait atteindre.
pub(crate) fn meme_adresse(reseau: IpAddr, vue: IpAddr, prefixes: (u8, u8)) -> bool {
    match (reseau, vue) {
        (IpAddr::V4(reseau), IpAddr::V4(vue)) => {
            meme_prefixe(&reseau.octets(), &vue.octets(), prefixes.0)
        }
        (IpAddr::V6(reseau), IpAddr::V6(vue)) => {
            meme_prefixe(&reseau.octets(), &vue.octets(), prefixes.1)
        }
        _ => false,
    }
}

/// Les deux adresses partagent-elles leurs `prefix` premiers bits ?
fn meme_prefixe(reseau: &[u8], vue: &[u8], prefix: u8) -> bool {
    let bits = usize::from(prefix);
    let octets_pleins = bits / 8;
    let bits_restants = bits % 8;

    let (tete_reseau, reste_reseau) = reseau.split_at(octets_pleins.min(reseau.len()));
    let (tete_vue, reste_vue) = vue.split_at(octets_pleins.min(vue.len()));
    if tete_reseau != tete_vue {
        return false;
    }
    if bits_restants == 0 {
        return true;
    }
    // Le masque des bits de poids fort qui restent : `/12` compare les quatre
    // bits hauts du deuxième octet.
    let masque =
        0xFF_u8 << (8_u32.saturating_sub(u32::from(u8::try_from(bits_restants).unwrap_or(0))));
    match (reste_reseau.first(), reste_vue.first()) {
        (Some(a), Some(b)) => (a & masque) == (b & masque),
        // Un préfixe plus long que l'adresse : impossible, `prefix` est borné à
        // la construction. `and_then` le dit sans ouvrir de branche à nous.
        _ => true,
    }
}

/// Lit un préfixe CIDR décimal, borné à `maximum`.
pub(crate) fn prefixe(brut: &[u8], maximum: u8) -> Result<u8, Error> {
    if brut.is_empty() || brut.len() > 3 {
        return Err(Error::MalformedPrefix);
    }
    // PAS DE ZÉRO EN TÊTE : `/08` et `/8` désigneraient le même réseau, et deux
    // écritures pour une valeur sont une de trop — la même règle que partout
    // ailleurs dans ce dépôt.
    if brut.len() > 1 && brut.first() == Some(&b'0') {
        return Err(Error::MalformedPrefix);
    }
    let mut valeur = 0_u16;
    for &octet in brut {
        let chiffre = octet
            .checked_sub(b'0')
            .filter(|&chiffre| chiffre <= 9)
            .ok_or(Error::MalformedPrefix)?;
        valeur = valeur.saturating_mul(10).saturating_add(u16::from(chiffre));
    }
    let valeur = u8::try_from(valeur).map_err(|_| Error::MalformedPrefix)?;
    if valeur > maximum {
        return Err(Error::MalformedPrefix);
    }
    Ok(valeur)
}

#[cfg(test)]
mod tests {
    use super::{Lookup, Mechanism, Qualifier, Resolution, meme_prefixe, prefixe};
    use crate::Error;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn un_qualificateur_absent_vaut_plus() {
        // RFC 7208 §4.6.2. L'oublier ferait passer pour neutre ce qu'un
        // expéditeur a autorisé.
        assert_eq!(Qualifier::split(b"all"), (Qualifier::Pass, &b"all"[..]));
        assert_eq!(Qualifier::split(b"+all"), (Qualifier::Pass, &b"all"[..]));
        assert_eq!(Qualifier::split(b"-all"), (Qualifier::Fail, &b"all"[..]));
        assert_eq!(
            Qualifier::split(b"~all"),
            (Qualifier::SoftFail, &b"all"[..])
        );
        assert_eq!(Qualifier::split(b"?all"), (Qualifier::Neutral, &b"all"[..]));
        // Un terme vide n'a pas de qualificateur, et reste vide.
        assert_eq!(Qualifier::split(b""), (Qualifier::Pass, &b""[..]));
    }

    #[test]
    fn all_correspond_toujours() {
        let quelconque = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(
            Mechanism::All.resolve(quelconque),
            Resolution::Answered(true)
        );
        assert_eq!(
            Mechanism::All.resolve(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Resolution::Answered(true)
        );
    }

    #[test]
    fn ip4_compare_le_prefixe_demande() {
        let mecanisme = Mechanism::Ip4 {
            address: Ipv4Addr::new(192, 0, 2, 0),
            prefix: 24,
        };
        for (adresse, attendu) in [
            (Ipv4Addr::new(192, 0, 2, 1), true),
            (Ipv4Addr::new(192, 0, 2, 255), true),
            (Ipv4Addr::new(192, 0, 3, 1), false),
            (Ipv4Addr::new(198, 51, 100, 1), false),
        ] {
            assert_eq!(
                mecanisme.resolve(IpAddr::V4(adresse)),
                Resolution::Answered(attendu),
                "{adresse}"
            );
        }
    }

    #[test]
    fn un_prefixe_qui_ne_tombe_pas_sur_un_octet_se_compare_bit_a_bit() {
        // `/12` compare les quatre bits hauts du deuxième octet : `10.16.x.x`
        // est dedans, `10.32.x.x` non.
        let mecanisme = Mechanism::Ip4 {
            address: Ipv4Addr::new(10, 16, 0, 0),
            prefix: 12,
        };
        assert_eq!(
            mecanisme.resolve(IpAddr::V4(Ipv4Addr::new(10, 31, 255, 255))),
            Resolution::Answered(true)
        );
        assert_eq!(
            mecanisme.resolve(IpAddr::V4(Ipv4Addr::new(10, 32, 0, 0))),
            Resolution::Answered(false)
        );
    }

    #[test]
    fn un_prefixe_nul_prend_tout_et_un_prefixe_plein_ne_prend_qu_une_adresse() {
        let tout = Mechanism::Ip4 {
            address: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 0,
        };
        assert_eq!(
            tout.resolve(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            Resolution::Answered(true)
        );
        let seule = Mechanism::Ip4 {
            address: Ipv4Addr::new(203, 0, 113, 7),
            prefix: 32,
        };
        assert_eq!(
            seule.resolve(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            Resolution::Answered(true)
        );
        assert_eq!(
            seule.resolve(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))),
            Resolution::Answered(false)
        );
    }

    #[test]
    fn ip6_se_compare_comme_ip4() {
        let mecanisme = Mechanism::Ip6 {
            address: "2001:db8::".parse().expect("adresse"),
            prefix: 32,
        };
        assert_eq!(
            mecanisme.resolve(IpAddr::V6("2001:db8:1234::1".parse().expect("adresse"))),
            Resolution::Answered(true)
        );
        assert_eq!(
            mecanisme.resolve(IpAddr::V6("2001:db9::1".parse().expect("adresse"))),
            Resolution::Answered(false)
        );
    }

    #[test]
    fn une_famille_ne_correspond_jamais_a_l_autre() {
        // RFC 7208 §5.6. Les confondre ferait autoriser un pair d'une autre
        // famille que celle qu'on a écrite.
        let ip4 = Mechanism::Ip4 {
            address: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 0,
        };
        assert_eq!(
            ip4.resolve(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Resolution::Answered(false)
        );
        let ip6 = Mechanism::Ip6 {
            address: Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        };
        assert_eq!(
            ip6.resolve(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Resolution::Answered(false)
        );
    }

    #[test]
    fn les_mecanismes_qui_resolvent_disent_ce_qu_il_leur_faut() {
        // Répondre `false` à leur place les ferait passer pour « ne correspond
        // pas », ce qui est une réponse — et ils n'en ont pas encore. Dire ce
        // qu'il leur faut évite en outre à l'appelant de refaire le tri.
        let vide = super::DomainSpec {
            spec: b"",
            prefix4: 32,
            prefix6: 128,
        };
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for (mecanisme, attendu) in [
            (Mechanism::A(vide), Lookup::Addresses),
            (Mechanism::Mx(vide), Lookup::MxAddresses),
            (Mechanism::Include(vide), Lookup::Policy),
            (Mechanism::Exists(vide), Lookup::Exists),
            (Mechanism::Ptr(vide), Lookup::PtrNames),
        ] {
            assert_eq!(
                mecanisme.resolve(client),
                Resolution::Needs {
                    domain: vide,
                    lookup: attendu
                },
                "{mecanisme:?}"
            );
        }
    }

    #[test]
    fn un_prefixe_se_lit_et_se_borne() {
        assert_eq!(prefixe(b"0", 32), Ok(0));
        assert_eq!(prefixe(b"24", 32), Ok(24));
        assert_eq!(prefixe(b"32", 32), Ok(32));
        assert_eq!(prefixe(b"128", 128), Ok(128));
        assert_eq!(prefixe(b"33", 32), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"129", 128), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"256", 128), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"1000", 128), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"", 32), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"x", 32), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"2x", 32), Err(Error::MalformedPrefix));
        // UNE ÉCRITURE PAR VALEUR : `/08` et `/8` désigneraient le même réseau.
        assert_eq!(prefixe(b"08", 32), Err(Error::MalformedPrefix));
        assert_eq!(prefixe(b"00", 32), Err(Error::MalformedPrefix));
    }

    #[test]
    fn un_prefixe_plus_long_que_l_adresse_ne_deborde_pas() {
        // Impossible par construction — `prefixe` le borne — mais la fonction
        // ne doit pas déborder pour autant.
        // 68 bits : huit octets pleins, puis quatre bits. Avec 64, le contrôle
        // « aucun bit restant » répondrait avant, et ce chemin-ci ne serait pas
        // touché.
        assert!(meme_prefixe(&[1, 2], &[1, 2], 68));
    }
}
