// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le banc de cette crate.
//!
//! # CE QU'IL ÉPROUVE EN PREMIER : L'ACCORD AVEC `asl`
//!
//! La fiche d'identité est écrite par un autre programme et lue par celui-ci,
//! ou l'inverse. Les essais partent donc d'une fiche **telle qu'`asl enroll`
//! l'écrit**, octet pour octet, et non d'une fiche que nous aurions composée à
//! notre convenance — un banc qui n'éprouverait que notre propre écriture
//! dirait que les deux programmes s'accordent sans l'avoir vérifié.

extern crate alloc;

use alloc::string::ToString as _;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asl_id::{Genre, Identifiant};
use asl_proto::Protocole;

use crate::annonce::{
    Declaration, composer_une_annonce, verifier_les_declarations, verifier_un_nom,
};
use crate::bail::lire_la_reponse;
use crate::fiche::{GRAINE_OCTETS, ecrire_une_fiche, lire_une_fiche};
use crate::{Faute, SERVICES_MAX};

/// Une machine d'essai.
fn machine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x71; 16])
}

/// Un compte d'essai.
fn compte() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Utilisateur, [0x5e; 16])
}

// ── La fiche ────────────────────────────────────────────────────────────────

/// **UNE FICHE ÉCRITE PAR `asl enroll` SE LIT ICI**, commentaires compris.
///
/// Les cinq lignes de commentaire, l'ordre des champs, l'espace autour du
/// `=` : c'est le fichier que l'utilitaire pose, recopié tel quel.
#[test]
fn une_fiche_ecrite_par_asl_se_lit_ici() {
    let brute = alloc::format!(
        "# asl — l'identité de cette machine.\n\
         #\n\
         # LA MOITIÉ PRIVÉE D'UNE PAIRE DE CLÉS. Elle n'a jamais quitté ce disque,\n\
         # et elle ne le doit pas : l'annuaire ne connaît que la moitié publique.\n\
         # Ne la copiez pas sur une autre machine — enrôlez-la, c'est gratuit.\n\
         machine = {}\n\
         compte = {}\n\
         graine = {}\n",
        machine().texte().as_str(),
        compte().texte().as_str(),
        "ab".repeat(GRAINE_OCTETS)
    );

    let fiche = lire_une_fiche(&brute).expect("elle se lit");
    assert_eq!(fiche.identite.machine(), machine());
    assert_eq!(fiche.compte, Some(compte()));
}

/// **CE QUE NOUS ÉCRIVONS, NOUS LE RELISONS — ET `asl` AUSSI.**
///
/// L'aller-retour ne prouve que la moitié : il prouve que notre écriture et
/// notre lecture s'accordent. Ce qui prouve l'autre moitié est que le texte
/// produit porte les mêmes trois clés, au même format, que l'essai ci-dessus.
#[test]
fn ce_que_nous_ecrivons_se_relit_et_porte_les_memes_clefs() {
    let graine = [0x3c_u8; GRAINE_OCTETS];
    let mut place = [0_u8; crate::FICHE_OCTETS_MAX];

    let combien =
        ecrire_une_fiche(machine(), Some(compte()), &graine, &mut place).expect("elle s'écrit");
    let texte = core::str::from_utf8(&place[..combien]).expect("de l'UTF-8");

    assert!(texte.contains("machine = "), "{texte}");
    assert!(texte.contains("compte = "), "{texte}");
    assert!(texte.contains("graine = 3c3c3c"), "{texte}");
    assert!(
        texte.contains("Ne la copiez pas sur une autre machine"),
        "LES COMMENTAIRES SONT DU CONTENU : c'est ce qu'un administrateur lit"
    );

    let fiche = lire_une_fiche(texte).expect("elle se relit");
    assert_eq!(fiche.identite.machine(), machine());
    assert_eq!(fiche.compte, Some(compte()));
}

/// **SANS COMPTE, LA FICHE N'EN PORTE PAS LA LIGNE** — et se lit quand même.
#[test]
fn une_fiche_sans_compte_se_lit_et_n_en_porte_pas_la_ligne() {
    let graine = [0x01_u8; GRAINE_OCTETS];
    let mut place = [0_u8; crate::FICHE_OCTETS_MAX];
    let combien = ecrire_une_fiche(machine(), None, &graine, &mut place).expect("elle s'écrit");
    let texte = core::str::from_utf8(&place[..combien]).expect("de l'UTF-8");

    assert!(!texte.contains("compte ="), "{texte}");
    assert_eq!(lire_une_fiche(texte).expect("elle se lit").compte, None);
}

/// **UN TAMPON TROP COURT FAIT ÉCHOUER L'ÉCRITURE ENTIÈRE.**
///
/// Et non une fiche tronquée : celle-là se relirait comme une fiche sans
/// graine, et l'appelant croirait avoir enrôlé la machine.
#[test]
fn un_tampon_trop_court_refuse_au_lieu_de_tronquer() {
    let graine = [0x02_u8; GRAINE_OCTETS];
    for taille in [0_usize, 16, 64, 200] {
        let mut place = alloc::vec![0_u8; taille];
        assert_eq!(
            ecrire_une_fiche(machine(), Some(compte()), &graine, &mut place),
            Err(Faute::TamponTropCourt),
            "un tampon de {taille} octets ne doit pas suffire"
        );
    }
}

/// **CE QU'UNE ÉCRITURE REFUSÉE LAISSE DERRIÈRE ELLE EST UN PRÉFIXE, TOUJOURS.**
///
/// # LA PROPRIÉTÉ QUE LE FUZZ A CORRIGÉE, ET DANS LES DEUX SENS
///
/// La première écriture de la cible affirmait qu'un refus ne laisse RIEN de
/// lisible. C'est faux, et pour une raison bénigne : à une taille précise, tout
/// tient **sauf le saut de ligne final**, et une fiche sans son dernier saut de
/// ligne se lit parfaitement — `lines()` n'en exige pas.
///
/// Mais la cible a aussi montré un vrai défaut : l'écrivain continuait après
/// avoir débordé, si bien qu'une écriture plus courte se posait là où la
/// refusée aurait dû commencer. Le tampon portait alors un MÉLANGE, et non un
/// préfixe.
///
/// La bonne propriété est donc celle-ci, et elle vaut pour toutes les tailles :
/// **ce qui reste se lit comme la même identité, ou ne se lit pas.**
#[test]
fn une_ecriture_refusee_ne_laisse_jamais_une_autre_identite() {
    let graine = [0x3c_u8; GRAINE_OCTETS];
    let mut entiere = [0_u8; crate::FICHE_OCTETS_MAX];
    let complete = ecrire_une_fiche(machine(), Some(compte()), &graine, &mut entiere)
        .expect("elle s'écrit en entier");
    let attendue = lire_une_fiche(core::str::from_utf8(&entiere[..complete]).expect("de l'UTF-8"))
        .expect("elle se relit");

    let mut lisibles = 0_u32;
    for taille in 0..complete {
        let mut place = alloc::vec![0_u8; taille];
        assert_eq!(
            ecrire_une_fiche(machine(), Some(compte()), &graine, &mut place),
            Err(Faute::TamponTropCourt),
            "un tampon de {taille} octets ne suffit pas"
        );
        let Ok(texte) = core::str::from_utf8(&place) else {
            continue;
        };
        if let Ok(lue) = lire_une_fiche(texte) {
            lisibles = lisibles.saturating_add(1);
            assert_eq!(
                lue.identite.machine(),
                attendue.identite.machine(),
                "un tampon de {taille} octets a rendu une AUTRE machine"
            );
            assert_eq!(
                lue.identite.publique().octets(),
                attendue.identite.publique().octets(),
                "un tampon de {taille} octets a rendu une AUTRE clé"
            );
        }
    }
    // **UNE SEULE TAILLE EST LISIBLE**, celle qui perd le saut de ligne final.
    // Si ce compte changeait, c'est que l'écrivain ne pose plus un préfixe.
    assert_eq!(
        lisibles, 1,
        "une seule taille doit laisser une fiche lisible : celle à qui il ne \
         manque que le saut de ligne"
    );
}

/// **UN `compte =` ILLISIBLE EST IGNORÉ, PAS REFUSÉ.**
///
/// Il ne sert qu'à l'affichage, et la machine s'authentifie avec sa clé. Le
/// refuser empêcherait de démarrer pour une ligne décorative.
#[test]
fn un_compte_illisible_est_ignore_et_n_empeche_pas_de_lire() {
    let brute = alloc::format!(
        "machine = {}\ncompte = ceci-n-est-pas-un-identifiant\ngraine = {}\n",
        machine().texte().as_str(),
        "00".repeat(GRAINE_OCTETS)
    );
    let fiche = lire_une_fiche(&brute).expect("elle se lit malgré le compte");
    assert_eq!(fiche.compte, None);
    assert_eq!(fiche.identite.machine(), machine());
}

/// **UN COMPTE QUI N'EST PAS UN COMPTE EST IGNORÉ DE MÊME.**
///
/// Une machine à la place d'un utilisateur se lit très bien comme
/// identifiant — c'est le GENRE qui ne va pas, et `analyser_genre` le dit.
#[test]
fn un_compte_du_mauvais_genre_est_ignore() {
    let brute = alloc::format!(
        "machine = {}\ncompte = {}\ngraine = {}\n",
        machine().texte().as_str(),
        machine().texte().as_str(),
        "00".repeat(GRAINE_OCTETS)
    );
    assert_eq!(lire_une_fiche(&brute).expect("elle se lit").compte, None);
}

/// **LES LIGNES QUI NE DISENT RIEN SONT SAUTÉES, PAS REFUSÉES.**
///
/// Une ligne vide, un commentaire, une ligne sans `=`, une clé inconnue : les
/// quatre cas, parce que les quatre existent dans un fichier qu'un humain a
/// ouvert.
#[test]
fn les_lignes_qui_ne_disent_rien_sont_sautees() {
    let brute = alloc::format!(
        "\n   \n# un commentaire\nune ligne sans égal\nclef-inconnue = valeur\n\
         machine = {}\ngraine = {}\n",
        machine().texte().as_str(),
        "ff".repeat(GRAINE_OCTETS)
    );
    assert_eq!(
        lire_une_fiche(&brute)
            .expect("elle se lit")
            .identite
            .machine(),
        machine()
    );
}

/// **LA DERNIÈRE OCCURRENCE GAGNE**, comme chez `asl`.
///
/// C'est ce que fait une boucle qui écrase, et c'est pourquoi une fiche se
/// réécrit ENTIÈRE : une ligne ajoutée au-dessus serait silencieusement
/// ignorée, ce qui est la pire des deux façons de se tromper.
#[test]
fn la_derniere_occurrence_gagne() {
    let autre = Identifiant::depuis_entropie(Genre::Machine, [0x0a; 16]);
    let brute = alloc::format!(
        "machine = {}\nmachine = {}\ngraine = {}\n",
        autre.texte().as_str(),
        machine().texte().as_str(),
        "11".repeat(GRAINE_OCTETS)
    );
    assert_eq!(
        lire_une_fiche(&brute)
            .expect("elle se lit")
            .identite
            .machine(),
        machine(),
        "la seconde ligne doit l'emporter"
    );
}

/// **CE QUI CONDAMNE UNE FICHE, ET CE QUI NE LA CONDAMNE PAS.**
#[test]
fn les_quatre_facons_de_refuser_une_fiche() {
    let bonne_graine = "22".repeat(GRAINE_OCTETS);

    let cas: [(&str, alloc::string::String, Faute); 7] = [
        (
            "pas de ligne machine",
            alloc::format!("graine = {bonne_graine}\n"),
            Faute::SansMachine,
        ),
        (
            "un compte à la place d'une machine",
            alloc::format!(
                "machine = {}\ngraine = {bonne_graine}\n",
                compte().texte().as_str()
            ),
            Faute::PasUneMachine,
        ),
        (
            "pas de ligne graine",
            alloc::format!("machine = {}\n", machine().texte().as_str()),
            Faute::SansGraine,
        ),
        (
            "une graine trop courte",
            alloc::format!("machine = {}\ngraine = 2222\n", machine().texte().as_str()),
            Faute::GraineIllisible,
        ),
        (
            "une graine trop longue",
            alloc::format!(
                "machine = {}\ngraine = {bonne_graine}00\n",
                machine().texte().as_str()
            ),
            Faute::GraineIllisible,
        ),
        (
            "un caractère qui n'est pas hexadécimal, en position PAIRE",
            alloc::format!(
                "machine = {}\ngraine = {}zz\n",
                machine().texte().as_str(),
                "22".repeat(GRAINE_OCTETS.saturating_sub(1))
            ),
            Faute::GraineIllisible,
        ),
        (
            // **LES DEUX POSITIONS, ET NON UNE.** Chaque octet se lit en deux
            // moitiés, et un essai qui n'éprouverait que la première laisserait
            // la seconde sans jamais être prise.
            "un caractère qui n'est pas hexadécimal, en position IMPAIRE",
            alloc::format!(
                "machine = {}\ngraine = {}2z\n",
                machine().texte().as_str(),
                "22".repeat(GRAINE_OCTETS.saturating_sub(1))
            ),
            Faute::GraineIllisible,
        ),
    ];

    for (quoi, brute, attendue) in cas {
        // `Fiche` n'est pas `PartialEq` — `Identite` ne l'est pas, et une clé
        // privée qui se compare se compare en temps variable.
        assert_eq!(lire_une_fiche(&brute).err(), Some(attendue), "cas : {quoi}");
    }
}

/// **LES MAJUSCULES HEXADÉCIMALES PASSENT**, et rendent les mêmes octets.
///
/// Un fichier écrit à la main peut porter les unes ou les autres, et refuser
/// les majuscules ferait échouer la lecture pour une raison qu'aucun message ne
/// rendrait évidente.
#[test]
fn les_majuscules_hexadecimales_rendent_les_memes_octets() {
    let en_bas = alloc::format!(
        "machine = {}\ngraine = {}\n",
        machine().texte().as_str(),
        "abcdef01".repeat(8)
    );
    let en_haut = alloc::format!(
        "machine = {}\ngraine = {}\n",
        machine().texte().as_str(),
        "ABCDEF01".repeat(8)
    );
    let une = lire_une_fiche(&en_bas).expect("elle se lit");
    let autre = lire_une_fiche(&en_haut).expect("elle se lit aussi");
    assert_eq!(
        une.identite.publique().octets(),
        autre.identite.publique().octets(),
        "la même graine doit dériver la même clé"
    );
}

// ── Les annonces ────────────────────────────────────────────────────────────

/// **LES HUIT NOMS D'USAGE S'ANNONCENT, UN POINT CHACUN.**
#[test]
fn les_huit_noms_d_usage_s_annoncent() {
    let declarations = [
        ("air-mail-smtp", 25_u16),
        ("air-mail-submission", 587),
        ("air-mail-smtps", 465),
        ("air-mail-imap", 143),
        ("air-mail-imaps", 993),
        ("air-mail-pop3", 110),
        ("air-mail-pop3s", 995),
        ("air-mail-api", 8443),
    ]
    .map(|(nom, port)| Declaration {
        nom,
        protocole: Protocole::Tcp,
        port,
    });

    verifier_les_declarations(&declarations).expect("les huit tiennent ensemble");

    let locales = [IpAddr::V6(Ipv6Addr::LOCALHOST)];
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    for declaration in &declarations {
        let combien = composer_une_annonce(machine(), declaration, &locales, &mut place)
            .expect("elle s'encode");
        let texte = core::str::from_utf8(&place[..combien]).expect("de l'UTF-8");
        assert!(texte.contains(declaration.nom), "{texte}");
        assert!(
            texte.contains(&alloc::format!("\"port\":{}", declaration.port)),
            "{texte}"
        );
    }
}

/// **UDP S'ANNONCE AUSSI**, et son verdict sera `non_sonde` : ce n'est pas une
/// panne, c'est qu'une sonde UDP ne distingue pas « écoute et ignore » de
/// « rien n'écoute ».
#[test]
fn un_point_udp_s_annonce() {
    let declaration = Declaration {
        nom: "air-mail-api-h3",
        protocole: Protocole::Udp,
        port: 8443,
    };
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien =
        composer_une_annonce(machine(), &declaration, &[], &mut place).expect("elle s'encode");
    let texte = core::str::from_utf8(&place[..combien]).expect("de l'UTF-8");
    assert!(texte.contains("\"udp\""), "{texte}");
}

/// **SANS ADRESSE LOCALE, L'ANNONCE N'EN PORTE PAS** — et l'annuaire répondra
/// `indetermine` au lieu d'affirmer « non » (C6).
#[test]
fn sans_adresse_locale_l_annonce_n_en_porte_aucune() {
    let declaration = Declaration {
        nom: "air-mail-smtp",
        protocole: Protocole::Tcp,
        port: 25,
    };
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien =
        composer_une_annonce(machine(), &declaration, &[], &mut place).expect("elle s'encode");
    let texte = core::str::from_utf8(&place[..combien]).expect("de l'UTF-8");
    assert!(texte.contains("\"adresses_locales\":[]"), "{texte}");
}

/// **DEUX NOMS RÉSERVÉS, ET DEUX RAISONS.**
///
/// `asl-directory` serait refusé par l'annuaire ; `asl-echo` serait ACCEPTÉ, et
/// ferait conclure « injoignable » à tout qui sonde cette machine.
#[test]
fn les_deux_noms_reserves_sont_refuses() {
    for nom in ["asl-directory", "asl-echo"] {
        assert_eq!(verifier_un_nom(nom), Err(Faute::NomReserve), "nom : {nom}");
    }
}

/// **UN NOM QUE LE PROTOCOLE N'ADMET PAS EST REFUSÉ ICI**, et non découvert
/// à la première annonce.
#[test]
fn un_nom_hors_de_l_alphabet_est_refuse() {
    for nom in ["", "Air-Mail", "-smtp", "smtp-", ".cache", "a/b", "é"] {
        assert_eq!(verifier_un_nom(nom), Err(Faute::NomRefuse), "nom : {nom:?}");
    }
}

/// **UN MAUVAIS NOM EST REFUSÉ PAR LES DEUX PORTES.**
///
/// `verifier_les_declarations` le refuse à l'écriture de la configuration, et
/// `composer_une_annonce` le refuse encore avant d'encoder : la seconde ne se
/// fie pas à la première, parce qu'un appelant peut n'en appeler qu'une.
#[test]
fn un_mauvais_nom_est_refuse_par_les_deux_portes() {
    let declaration = Declaration {
        nom: "Air-Mail-SMTP",
        protocole: Protocole::Tcp,
        port: 25,
    };
    assert_eq!(
        verifier_les_declarations(&[declaration]),
        Err(Faute::NomRefuse)
    );
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    assert_eq!(
        composer_une_annonce(machine(), &declaration, &[], &mut place),
        Err(Faute::NomRefuse)
    );

    // Et un nom réservé, par les deux portes aussi.
    let reserve = Declaration {
        nom: "asl-echo",
        ..declaration
    };
    assert_eq!(
        verifier_les_declarations(&[reserve]),
        Err(Faute::NomReserve)
    );
    assert_eq!(
        composer_une_annonce(machine(), &reserve, &[], &mut place),
        Err(Faute::NomReserve)
    );
}

/// **DEUX DÉCLARATIONS HOMONYMES SONT REFUSÉES**, parce qu'une réannonce du
/// même nom REMPLACE la précédente : l'exploitant croirait avoir annoncé deux
/// services, et l'annuaire n'en publierait qu'un.
#[test]
fn deux_declarations_du_meme_nom_sont_refusees() {
    let declarations = [
        Declaration {
            nom: "air-mail-imaps",
            protocole: Protocole::Tcp,
            port: 993,
        },
        Declaration {
            nom: "air-mail-imaps",
            protocole: Protocole::Tcp,
            port: 9993,
        },
    ];
    assert_eq!(
        verifier_les_declarations(&declarations),
        Err(Faute::NomEnDouble)
    );
}

/// **UN PORT NUL EST REFUSÉ DES DEUX CÔTÉS** : à la vérification du jeu, et à
/// l'encodage d'une annonce seule.
#[test]
fn un_port_nul_est_refuse() {
    let declaration = Declaration {
        nom: "air-mail-smtp",
        protocole: Protocole::Tcp,
        port: 0,
    };
    assert_eq!(
        verifier_les_declarations(&[declaration]),
        Err(Faute::PortNul)
    );
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    assert_eq!(
        composer_une_annonce(machine(), &declaration, &[], &mut place),
        Err(Faute::PortNul)
    );
}

/// **AU-DELÀ DE LA BORNE, LE JEU EST REFUSÉ** — à l'écriture de la
/// configuration, et non en ouvrant dix-sept connexions.
#[test]
fn plus_de_services_que_la_borne_est_refuse() {
    let noms: Vec<alloc::string::String> = (0..=SERVICES_MAX)
        .map(|rang| alloc::format!("service-{rang}"))
        .collect();
    let declarations: Vec<Declaration<'_>> = noms
        .iter()
        .map(|nom| Declaration {
            nom,
            protocole: Protocole::Tcp,
            port: 1_000,
        })
        .collect();
    assert_eq!(
        verifier_les_declarations(&declarations),
        Err(Faute::TropDeServices)
    );
    // Et la borne elle-même passe : c'est un plafond, pas un refus d'y toucher.
    verifier_les_declarations(&declarations[..SERVICES_MAX]).expect("seize tiennent");
}

/// **UN IDENTIFIANT QUI N'EST PAS CELUI D'UNE MACHINE EST REFUSÉ.**
///
/// Un `u-…` à la place d'un `m-…` s'annoncerait sous un identifiant qui désigne
/// autre chose, et l'annuaire ne saurait pas de qui l'annonce parle.
#[test]
fn seule_une_machine_annonce() {
    let declaration = Declaration {
        nom: "air-mail-smtp",
        protocole: Protocole::Tcp,
        port: 25,
    };
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    assert_eq!(
        composer_une_annonce(compte(), &declaration, &[], &mut place),
        Err(Faute::PasUneMachine)
    );
}

/// **TROP D'ADRESSES LOCALES, ET LE PROTOCOLE REFUSE.**
///
/// Ce compte-là est borné là-bas (C3 du dépôt ASL), et le refus remonte tel
/// quel plutôt que d'être tronqué ici : une annonce amputée de ses adresses
/// ferait rendre `indetermine` sans qu'on sache pourquoi.
#[test]
fn trop_d_adresses_locales_fait_refuser_le_protocole() {
    let locales: Vec<IpAddr> = (0..=u8::try_from(asl_proto::ADRESSES_MAX).unwrap_or(u8::MAX))
        .map(|rang| IpAddr::V4(Ipv4Addr::new(192, 0, 2, rang)))
        .collect();
    let declaration = Declaration {
        nom: "air-mail-smtp",
        protocole: Protocole::Tcp,
        port: 25,
    };
    let mut place = [0_u8; asl_proto::cadrage::MESSAGE_MAX];
    assert_eq!(
        composer_une_annonce(machine(), &declaration, &locales, &mut place),
        Err(Faute::ProtocoleRefuse)
    );
}

/// **UN TAMPON TROP COURT POUR UNE ANNONCE REFUSE AUSSI.**
#[test]
fn un_tampon_trop_court_pour_une_annonce_refuse() {
    let declaration = Declaration {
        nom: "air-mail-smtp",
        protocole: Protocole::Tcp,
        port: 25,
    };
    let mut place = [0_u8; 8];
    assert_eq!(
        composer_une_annonce(machine(), &declaration, &[], &mut place),
        Err(Faute::TamponTropCourt)
    );
}

// ── La réponse de l'annuaire ────────────────────────────────────────────────

/// **CE QU'ON RETIENT D'UNE RÉPONSE, ET CE QU'ON N'EN DÉDUIT PAS.**
///
/// Les joignables et les injoignables se comptent à part, et leur somme ne fait
/// pas le total : un point peut être `en_cours` — l'annuaire n'a pas encore
/// sondé — ou `non_sonde`, ce qu'est toujours un point UDP.
#[test]
fn ce_qu_on_retient_d_une_reponse() {
    let corps = alloc::format!(
        "{{\"service\":\"{}\",\"keepalive_secondes\":10,\"inactivite_secondes\":30,\
         \"vu_depuis\":{{\"adresse\":\"2001:db8::1\",\"port\":51840}},\
         \"derriere_nat\":\"non\",\"joignabilite\":[\
         {{\"protocole\":\"tcp\",\"port\":993,\"verdict\":\"joignable\",\
         \"candidat\":\"[2001:db8::1]:993\",\"origine\":\"reflexif\",\"a\":1789217731000}},\
         {{\"protocole\":\"tcp\",\"port\":143,\"verdict\":\"injoignable\",\"a\":1789217752000}},\
         {{\"protocole\":\"tcp\",\"port\":25,\"verdict\":\"en_cours\"}},\
         {{\"protocole\":\"udp\",\"port\":8443,\"verdict\":\"non_sonde\",\
         \"raison\":\"protocole_non_sondable\"}}]}}",
        Identifiant::depuis_entropie(Genre::Service, [0x4a; 16])
            .texte()
            .as_str()
    );

    let cadence = lire_la_reponse(corps.as_bytes()).expect("elle se lit");
    assert_eq!(cadence.keepalive_secondes, 10);
    assert_eq!(cadence.inactivite_secondes, 30);
    assert_eq!(cadence.derriere_nat, asl_proto::VerdictNat::Non);
    assert_eq!(cadence.joignables, 1);
    assert_eq!(cadence.injoignables, 1);
    assert_eq!(
        cadence.joignables.saturating_add(cadence.injoignables),
        2,
        "DEUX SUR QUATRE : les deux autres n'ont pas été mesurés, et on ne \
         l'affirme pas"
    );
}

/// **UN CORPS QUI NE SE DÉCODE PAS EST REFUSÉ, ET RIEN N'EST SUPPOSÉ.**
#[test]
fn un_corps_illisible_est_refuse() {
    for corps in [
        &b""[..],
        b"pas du JSON",
        b"{}",
        br#"{"service":"s-","keepalive_secondes":10}"#,
    ] {
        assert_eq!(lire_la_reponse(corps), Err(Faute::ProtocoleRefuse));
    }
}

// ── Les fautes se disent ────────────────────────────────────────────────────

/// **CHAQUE FAUTE A SA PHRASE, ET AUCUNE NE DIT « erreur ».**
///
/// Une variante sans texte propre rendrait un message que le lecteur ne peut
/// pas relier à ce qu'il a écrit dans sa configuration.
#[test]
fn chaque_faute_se_dit() {
    let toutes = [
        Faute::SansMachine,
        Faute::PasUneMachine,
        Faute::SansGraine,
        Faute::GraineIllisible,
        Faute::NomRefuse,
        Faute::NomReserve,
        Faute::NomEnDouble,
        Faute::PortNul,
        Faute::TropDeServices,
        Faute::ProtocoleRefuse,
        Faute::TamponTropCourt,
    ];
    for faute in toutes {
        let dit = faute.to_string();
        assert!(!dit.is_empty(), "{faute:?} ne dit rien");
        assert!(
            !dit.contains("erreur"),
            "{faute:?} dit « erreur » au lieu de dire quoi : {dit}"
        );
    }
}
