//! Ce que la lecture d'un enregistrement SPF doit tenir.

use super::Record;
use crate::term::DomainSpec;
use crate::{Error, Limits, Mechanism, Modifier, Qualifier, Term};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn lire(txt: &[u8]) -> Result<Record<'_>, Error> {
    Record::parse(txt, &Limits::DEFAULT)
}

/// Les termes d'un enregistrement recevable.
fn termes(txt: &[u8]) -> std::vec::Vec<Term<'_>> {
    lire(txt).expect("recevable").terms().collect()
}

fn domaine(spec: &[u8]) -> DomainSpec<'_> {
    DomainSpec {
        spec,
        prefix4: 32,
        prefix6: 128,
    }
}

// ── La version ──────────────────────────────────────────────────────────────

#[test]
fn un_txt_qui_ne_parle_pas_de_spf_n_est_pas_une_faute() {
    // Un domaine publie des TXT pour bien des raisons. Les refuser ferait
    // rendre `permerror` là où il n'y a qu'un enregistrement pour autre chose.
    for txt in [
        &b"google-site-verification=abc"[..],
        b"",
        b"v=spf2.0/pra",
        b"spf1 -all",
    ] {
        assert_eq!(lire(txt), Err(Error::NotSpf), "{txt:?}");
    }
}

#[test]
fn la_version_est_insensible_a_la_casse_mais_pas_approximative() {
    // RFC 7208 §4.5.
    assert!(lire(b"V=SPF1 -all").is_ok());
    assert!(
        lire(b"v=spf1").is_ok(),
        "un enregistrement sans terme est licite"
    );
    // `v=spf10` n'est PAS du SPF : sans le contrôle du séparateur, il passerait
    // pour un `v=spf1` suivi d'un terme `0`.
    assert_eq!(lire(b"v=spf10 -all"), Err(Error::NotSpf));
}

// ── Les mécanismes sans résolution ──────────────────────────────────────────

#[test]
fn les_qualificateurs_se_lisent_et_le_defaut_est_plus() {
    assert_eq!(
        termes(b"v=spf1 +all"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::All
        }]
    );
    assert_eq!(
        termes(b"v=spf1 -all"),
        [Term::Mechanism {
            qualifier: Qualifier::Fail,
            mechanism: Mechanism::All
        }]
    );
    assert_eq!(
        termes(b"v=spf1 all"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::All
        }]
    );
}

#[test]
fn ip4_et_ip6_portent_leur_adresse_et_leur_prefixe() {
    assert_eq!(
        termes(b"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"),
        [
            Term::Mechanism {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::Ip4 {
                    address: Ipv4Addr::new(192, 0, 2, 0),
                    prefix: 24
                }
            },
            Term::Mechanism {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::Ip6 {
                    address: "2001:db8::".parse().expect("adresse"),
                    prefix: 32
                }
            },
            Term::Mechanism {
                qualifier: Qualifier::Fail,
                mechanism: Mechanism::All
            },
        ]
    );
}

#[test]
fn un_prefixe_absent_vaut_l_adresse_entiere() {
    assert_eq!(
        termes(b"v=spf1 ip4:203.0.113.7"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Ip4 {
                address: Ipv4Addr::new(203, 0, 113, 7),
                prefix: 32
            }
        }]
    );
    assert_eq!(
        termes(b"v=spf1 ip6:::1"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Ip6 {
                address: Ipv6Addr::LOCALHOST,
                prefix: 128
            }
        }]
    );
}

#[test]
fn une_adresse_qui_n_en_est_pas_une_est_refusee() {
    for txt in [
        &b"v=spf1 ip4:999.0.2.1"[..],
        b"v=spf1 ip4:192.0.2",
        b"v=spf1 ip4:pas-une-adresse",
        b"v=spf1 ip6:2001:zz::",
        // Une adresse IPv4 dans un `ip6:` : la famille compte.
        b"v=spf1 ip6:192.0.2.1",
        // Et ce qui n'est même pas du texte n'est pas une adresse.
        b"v=spf1 ip4:\xff\xfe",
    ] {
        assert_eq!(lire(txt), Err(Error::MalformedAddress), "{txt:?}");
    }
}

#[test]
fn ip4_et_ip6_exigent_leur_argument() {
    assert_eq!(lire(b"v=spf1 ip4"), Err(Error::MalformedArgument));
    assert_eq!(lire(b"v=spf1 ip6"), Err(Error::MalformedArgument));
    assert_eq!(lire(b"v=spf1 ip4/24"), Err(Error::MalformedArgument));
    // Un préfixe collé au NOM plutôt qu'à l'adresse : `ip4/24:…` n'existe pas.
    assert_eq!(
        lire(b"v=spf1 ip4/24:192.0.2.0"),
        Err(Error::MalformedArgument)
    );
}

#[test]
fn all_n_admet_ni_argument_ni_prefixe() {
    // En accepter ferait passer pour conforme un enregistrement que d'autres
    // serveurs refuseront — et l'auteur ne le saurait qu'en le déployant.
    assert_eq!(
        lire(b"v=spf1 all:example.com"),
        Err(Error::MalformedArgument)
    );
    assert_eq!(lire(b"v=spf1 all/24"), Err(Error::MalformedArgument));
}

// ── Les mécanismes qui résolvent ────────────────────────────────────────────

#[test]
fn a_et_mx_se_passent_de_domaine() {
    // Sans domaine, c'est le domaine courant (RFC 7208 §5.3) — et une tranche
    // vide le dit, là où `None` obligerait chaque appelant à s'en méfier.
    assert_eq!(
        termes(b"v=spf1 a mx"),
        [
            Term::Mechanism {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::A(domaine(b""))
            },
            Term::Mechanism {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::Mx(domaine(b""))
            },
        ]
    );
}

#[test]
fn a_et_mx_portent_leurs_deux_prefixes() {
    // RFC 7208 §5.3 : `/n` pour IPv4, `//n` pour IPv6, et les deux ensemble.
    let attendu = |prefix4, prefix6| {
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::A(DomainSpec {
                spec: b"",
                prefix4,
                prefix6,
            }),
        }]
    };
    assert_eq!(termes(b"v=spf1 a/24"), attendu(24, 128));
    assert_eq!(termes(b"v=spf1 a//64"), attendu(32, 64));
    assert_eq!(termes(b"v=spf1 a/24//64"), attendu(24, 64));

    // Et avec un domaine, le préfixe se lit APRÈS lui.
    assert_eq!(
        termes(b"v=spf1 mx:example.com/24//64"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Mx(DomainSpec {
                spec: b"example.com",
                prefix4: 24,
                prefix6: 64,
            })
        }]
    );
}

#[test]
fn include_et_exists_exigent_un_domaine_et_refusent_un_prefixe() {
    assert_eq!(
        termes(b"v=spf1 include:_spf.example.com"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Include(domaine(b"_spf.example.com"))
        }]
    );
    assert_eq!(lire(b"v=spf1 include"), Err(Error::MalformedArgument));
    assert_eq!(lire(b"v=spf1 include:"), Err(Error::MalformedArgument));
    assert_eq!(
        lire(b"v=spf1 include:example.com/24"),
        Err(Error::MalformedArgument)
    );
    assert_eq!(lire(b"v=spf1 exists"), Err(Error::MalformedArgument));
    assert_eq!(
        lire(b"v=spf1 exists:example.com/24"),
        Err(Error::MalformedArgument)
    );
}

#[test]
fn les_macros_traversent_telles_quelles() {
    // Un `exists:%{i}._spf.…` ne prend son sens qu'au moment de l'évaluation.
    // Les valider ici reviendrait à écrire deux fois la même grammaire.
    assert_eq!(
        termes(b"v=spf1 exists:%{i}._spf.example.com"),
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Exists(domaine(b"%{i}._spf.example.com"))
        }]
    );
}

#[test]
fn ptr_est_lu_bien_qu_il_soit_deconseille() {
    // RFC 7208 §5.5 le déconseille à la PUBLICATION. Un enregistrement qui en
    // porte un doit tout de même être compris, sans quoi on rendrait
    // `permerror` là où d'autres serveurs concluent.
    assert_eq!(
        termes(b"v=spf1 ptr ptr:example.com"),
        [
            Term::Mechanism {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::Ptr(domaine(b""))
            },
            Term::Mechanism {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::Ptr(domaine(b"example.com"))
            },
        ]
    );
    assert_eq!(lire(b"v=spf1 ptr/24"), Err(Error::MalformedArgument));
}

// ── Les modificateurs ───────────────────────────────────────────────────────

#[test]
fn redirect_et_exp_se_lisent() {
    assert_eq!(
        termes(b"v=spf1 redirect=_spf.example.com"),
        [Term::Modifier(Modifier::Redirect(b"_spf.example.com"))]
    );
    assert_eq!(
        termes(b"v=spf1 -all exp=explain.example.com"),
        [
            Term::Mechanism {
                qualifier: Qualifier::Fail,
                mechanism: Mechanism::All
            },
            Term::Modifier(Modifier::Explanation(b"explain.example.com")),
        ]
    );
}

#[test]
fn un_modificateur_inconnu_est_lu_et_non_refuse() {
    // RFC 7208 §6 : il s'ignore. C'est ainsi qu'un protocole s'étend sans
    // casser ce qui existe, et le refuser ferait échouer sur un enregistrement
    // que tout le monde accepte.
    assert_eq!(
        termes(b"v=spf1 quelquechose=x -all"),
        [
            Term::Modifier(Modifier::Unknown {
                name: b"quelquechose",
                value: b"x"
            }),
            Term::Mechanism {
                qualifier: Qualifier::Fail,
                mechanism: Mechanism::All
            },
        ]
    );
}

#[test]
fn un_redirect_ou_un_exp_en_double_est_refuse() {
    // Ils désigneraient deux politiques, et rien ne dirait laquelle s'applique
    // (RFC 7208 §6).
    assert_eq!(
        lire(b"v=spf1 redirect=a.example redirect=b.example"),
        Err(Error::DuplicateModifier)
    );
    assert_eq!(
        lire(b"v=spf1 exp=a.example exp=b.example"),
        Err(Error::DuplicateModifier)
    );
    // La casse ne sauve personne.
    assert_eq!(
        lire(b"v=spf1 redirect=a.example REDIRECT=b.example"),
        Err(Error::DuplicateModifier)
    );
    // Un seul de chaque, en revanche, est licite.
    assert!(lire(b"v=spf1 redirect=a.example exp=b.example").is_ok());
}

#[test]
fn un_egal_dans_un_argument_ne_fait_pas_un_modificateur() {
    // `exists:%{i}=x` porte un `=` APRÈS son `:` : c'est un mécanisme.
    let lus = termes(b"v=spf1 exists:x=y");
    assert_eq!(
        lus,
        [Term::Mechanism {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Exists(domaine(b"x=y"))
        }]
    );
    // Et un `=` en tête ne nomme rien : ce n'est pas un modificateur non plus.
    assert_eq!(lire(b"v=spf1 =x"), Err(Error::UnknownTerm));
}

// ── Les refus ───────────────────────────────────────────────────────────────

#[test]
fn un_terme_inconnu_est_refuse() {
    // RFC 7208 §4.6.1 : un mécanisme inconnu vaut `permerror`. C'est la
    // différence avec un modificateur, qui s'ignore — et la RFC la fait exprès :
    // un mécanisme inconnu pourrait CHANGER le résultat, un modificateur non.
    for txt in [&b"v=spf1 xyzzy"[..], b"v=spf1 -all extra", b"v=spf1 a4"] {
        assert_eq!(lire(txt), Err(Error::UnknownTerm), "{txt:?}");
    }
}

#[test]
fn un_prefixe_irrecevable_est_refuse() {
    for txt in [
        &b"v=spf1 ip4:192.0.2.0/33"[..],
        b"v=spf1 ip4:192.0.2.0/",
        b"v=spf1 ip6:2001:db8::/129",
        b"v=spf1 a/24//129",
        b"v=spf1 a//129",
        b"v=spf1 a/33//64",
        // Une seule barre là où il en faut deux : `a/24/64` ne dit rien.
        b"v=spf1 a/24/64",
        b"v=spf1 a/x",
    ] {
        assert_eq!(lire(txt), Err(Error::MalformedPrefix), "{txt:?}");
    }
}

#[test]
fn les_bornes_de_taille_et_de_nombre_sont_tenues() {
    let etroites = Limits {
        max_record_octets: 20,
        max_terms: 2,
    };
    assert_eq!(
        Record::parse(b"v=spf1 ip4:192.0.2.0/24 -all", &etroites),
        Err(Error::TooLong)
    );
    assert_eq!(
        Record::parse(
            b"v=spf1 a mx ptr -all",
            &Limits {
                max_terms: 2,
                ..Limits::DEFAULT
            }
        ),
        Err(Error::TooManyTerms)
    );
}

#[test]
fn les_espaces_multiples_ne_font_pas_de_termes_vides() {
    // RFC 7208 §4.5 : une ou PLUSIEURS espaces séparent les termes.
    assert_eq!(termes(b"v=spf1   -all  "), termes(b"v=spf1 -all"));
    assert_eq!(termes(b"v=spf1 ").len(), 0);
}

// ── La validation d'un seul tenant ──────────────────────────────────────────

#[test]
fn un_terme_fautif_en_queue_fait_echouer_tout_l_enregistrement() {
    // C'EST LE POINT. Un parcours qui s'arrêterait au premier terme utile
    // appliquerait la moitié d'une politique — et deux pairs verraient deux
    // politiques différentes pour le même domaine, selon celui qui correspond
    // en premier.
    assert_eq!(lire(b"v=spf1 +all xyzzy"), Err(Error::UnknownTerm));
    assert_eq!(
        lire(b"v=spf1 ip4:192.0.2.0/24 ip4:999.0.0.1"),
        Err(Error::MalformedAddress)
    );
}

#[test]
fn le_parcours_d_un_enregistrement_valide_ne_peut_plus_echouer() {
    // La validation a eu lieu une fois : `terms()` ne rend pas de `Result`.
    let enregistrement =
        lire(b"v=spf1 a mx ip4:192.0.2.0/24 include:x.example -all").expect("recevable");
    assert_eq!(enregistrement.terms().count(), 5);
    assert_eq!(
        enregistrement.body(),
        b" a mx ip4:192.0.2.0/24 include:x.example -all"
    );
    // Et il se reparcourt à l'identique.
    let premier: std::vec::Vec<Term<'_>> = enregistrement.terms().collect();
    let second: std::vec::Vec<Term<'_>> = enregistrement.terms().collect();
    assert_eq!(premier, second);
}

#[test]
fn les_mecanismes_sans_dns_repondent_sur_un_enregistrement_reel() {
    // Le bout à bout de cette tranche : un enregistrement lu, puis interrogé
    // pour les seuls mécanismes qui n'ont besoin de personne.
    // L'enregistrement porte AUSSI un modificateur : c'est ce qui éprouve qu'on
    // ne l'interroge pas comme un mécanisme.
    let enregistrement =
        lire(b"v=spf1 ip4:192.0.2.0/24 include:x.example exp=e.example -all").expect("recevable");
    let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
    let reponses: std::vec::Vec<Option<bool>> = enregistrement
        .terms()
        .filter_map(|terme| match terme {
            Term::Mechanism { mechanism, .. } => Some(mechanism.matches_without_dns(client)),
            Term::Modifier(_) => None,
        })
        .collect();
    assert_eq!(reponses, [Some(true), None, Some(true)]);
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let enregistrement = lire(b"v=spf1 -all").expect("recevable");
    assert_eq!(enregistrement, lire(b"v=spf1 -all").expect("recevable"));
    assert_ne!(enregistrement, lire(b"v=spf1 ~all").expect("recevable"));
    assert!(!std::format!("{enregistrement:?}").is_empty());
    assert!(!std::format!("{:?}", enregistrement.terms()).is_empty());
}
