// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un paquet écrit doit être — et ce que la lecture doit en retrouver.
//!
//! # L'ALLER-RETOUR NE SUFFIT PAS, ET LES VECTEURS NON PLUS
//!
//! Un aller-retour entre notre écriture et notre lecture passerait même si
//! l'ordre des champs était faux DES DEUX CÔTÉS. Les vecteurs de l'annexe A de
//! RFC 9001, eux, tranchent : ils viennent du document, pas de nous.
//!
//! On fait donc les deux. L'aller-retour éprouve tout ce qui varie — les
//! numéros, les longueurs, les identifiants — et le vecteur ancre le résultat à
//! quelque chose que nous n'avons pas choisi.

use ams_proto_quic::{ConnectionId, Long, LongKind, VERSION_1, is_long, parse_long};
use ams_quic_crypto::{Keys, Role, Secret};

use super::{Plan, payload_capacity, seal_packet};
use crate::error::Reason;
use crate::receive::{PacketKind, open_packet};

/// L'identifiant de destination de l'annexe A.1 de RFC 9001.
const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// Les clés `Initial` du serveur, telles que l'annexe A.1 les dérive.
fn clefs(role: Role) -> Keys {
    Secret::initial(&DCID, role)
        .expect("dérivable")
        .keys()
        .expect("dérivables")
}

/// Un identifiant de connexion à partir de ces octets.
fn identifiant(octets: &[u8]) -> ConnectionId {
    ConnectionId::new(octets).expect("vingt octets au plus")
}

/// Les trois plans, avec des identifiants distincts pour qu'une confusion se
/// voie.
fn plans() -> [(&'static str, Plan<'static>); 3] {
    [
        (
            "Initial",
            Plan::Initial {
                destination: identifiant(&DCID),
                source: identifiant(&[1, 2, 3, 4]),
                token: &[],
            },
        ),
        (
            "Handshake",
            Plan::Handshake {
                destination: identifiant(&DCID),
                source: identifiant(&[1, 2, 3, 4]),
            },
        ),
        (
            "1-RTT",
            Plan::OneRtt {
                destination: identifiant(&DCID),
                key_phase: false,
            },
        ),
    ]
}

/// **CE QU'ON ÉCRIT, ON LE RELIT** — et l'on y retrouve tout.
#[test]
fn ce_qu_on_ecrit_se_relit() {
    let clefs = clefs(Role::Server);
    let charge = b"des trames quelconques, assez longues pour l'echantillon";

    for (quoi, plan) in plans() {
        let mut tampon = std::vec![0_u8; 1500];
        let ecrit = seal_packet(&mut tampon, &clefs, &plan, 7, None, charge).expect("écrivable");
        assert!(ecrit <= tampon.len());

        // Le datagramme fait exactement ce que l'écriture a rendu : un paquet
        // à en-tête court va jusqu'au bout, et ne saurait pas où s'arrêter s'il
        // restait du bourrage derrière.
        let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
        let ouvert = open_packet(&mut datagramme, &clefs, None, DCID.len()).expect("lisible");

        assert_eq!(ouvert.number, 7, "{quoi}");
        assert_eq!(ouvert.total, ecrit, "{quoi}");
        assert_eq!(
            datagramme.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
            Some(&charge[..]),
            "{quoi}"
        );
        let attendu = match quoi {
            "Initial" => PacketKind::Long(LongKind::Initial),
            "Handshake" => PacketKind::Long(LongKind::Handshake),
            _ => PacketKind::Short,
        };
        assert_eq!(ouvert.kind, attendu, "{quoi}");
    }
}

/// **L'EN-TÊTE EST CELUI DE §17.2**, et c'est la grammaire — écrite pour lire —
/// qui le dit, sans que la protection d'en-tête soit ôtée.
///
/// Les champs en clair d'un en-tête long ne sont pas masqués : seuls le premier
/// octet et le numéro le sont. Un lecteur peut donc vérifier la version et les
/// identifiants sans aucune clé — et c'est ce que fait tout démultiplexeur.
#[test]
fn l_entete_long_est_lisible_sans_clef() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Initial {
        destination: identifiant(&DCID),
        source: identifiant(&[0xaa, 0xbb, 0xcc]),
        token: &[],
    };
    let mut tampon = std::vec![0_u8; 1500];
    let ecrit = seal_packet(&mut tampon, &clefs, &plan, 1, None, b"une charge").expect("écrivable");
    let paquet = tampon.get(..ecrit).expect("écrit");

    assert!(is_long(paquet), "le bit de forme doit être posé");
    let Ok(Long::Numbered(entete)) = parse_long(paquet) else {
        panic!("un en-tête long numéroté");
    };
    assert_eq!(entete.version(), VERSION_1);
    assert_eq!(entete.destination().as_bytes(), DCID);
    assert_eq!(entete.source().as_bytes(), [0xaa, 0xbb, 0xcc]);
    assert_eq!(entete.token(), b"");
    // §17.2 : la longueur couvre le numéro, la charge et le tag.
    assert_eq!(
        entete.length(),
        u64::try_from(ecrit - entete.number_offset()).expect("tient")
    );
}

/// **LA PHASE DE CLÉ SE RETROUVE**, et elle n'est lisible qu'après démasquage.
///
/// §17.3.1 : le bit est protégé, comme le numéro. Un observateur ne peut donc
/// pas compter les mises à jour de clé — et c'est ce qui empêche de suivre une
/// connexion à travers un changement d'adresse.
#[test]
fn la_phase_de_clef_se_retrouve() {
    let clefs = clefs(Role::Server);
    for phase in [false, true] {
        let plan = Plan::OneRtt {
            destination: identifiant(&DCID),
            key_phase: phase,
        };
        let mut tampon = std::vec![0_u8; 1500];
        let ecrit =
            seal_packet(&mut tampon, &clefs, &plan, 3, None, b"une charge").expect("écrivable");
        let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
        let ouvert = open_packet(&mut datagramme, &clefs, None, DCID.len()).expect("lisible");
        assert_eq!(ouvert.key_phase, phase);
    }
}

/// **LE NUMÉRO SE TRONQUE SELON CE QUI EST ACQUITTÉ** (§17.1), et se
/// reconstruit.
#[test]
fn le_numero_se_tronque_et_se_reconstruit() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Handshake {
        destination: identifiant(&DCID),
        source: identifiant(&[9]),
    };
    // Des numéros de plus en plus grands, avec et sans acquittement.
    for (numero, acquitte) in [
        (0_u64, None),
        (1, None),
        (255, None),
        (256, None),
        (65_535, None),
        (1_000_000, Some(999_990_u64)),
        (1_000_000, Some(1)),
        (4_611_686_018_427_387_903, Some(4_611_686_018_427_387_900)),
    ] {
        let mut tampon = std::vec![0_u8; 1500];
        let ecrit = seal_packet(&mut tampon, &clefs, &plan, numero, acquitte, b"une charge")
            .expect("écrivable");
        let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
        // Le lecteur reconstruit à partir du plus grand qu'il a DÉJÀ traité,
        // c'est-à-dire celui d'avant.
        let plus_grand = numero.checked_sub(1);
        let ouvert = open_packet(&mut datagramme, &clefs, plus_grand, DCID.len()).expect("lisible");
        assert_eq!(ouvert.number, numero, "{numero} / {acquitte:?}");
    }
}

/// **UNE CHARGE TROP COURTE SE REFUSE** (§5.4.2).
///
/// L'échantillon se prend quatre octets après le début du numéro, sur seize
/// octets — comme si le numéro faisait toujours quatre. Sans cette garde, on
/// émettrait un paquet que le pair **MUST** jeter, et la connexion se figerait
/// sans que rien ne l'explique.
#[test]
fn une_charge_trop_courte_se_refuse() {
    let clefs = clefs(Role::Server);
    let plan = Plan::OneRtt {
        destination: identifiant(&DCID),
        key_phase: false,
    };
    let mut tampon = std::vec![0_u8; 1500];

    // Numéro zéro sans acquittement : un octet. Il faut donc trois octets de
    // trames, et deux ne suffisent pas.
    for trop_court in [&b""[..], b"a", b"ab"] {
        let issue = seal_packet(&mut tampon, &clefs, &plan, 0, None, trop_court)
            .expect_err("§5.4.2 l'interdit");
        assert_eq!(issue.reason(), Reason::SendOverflow, "{trop_court:?}");
    }
    // Trois octets suffisent, et c'est exactement ce que la RFC annonce.
    let ecrit = seal_packet(&mut tampon, &clefs, &plan, 0, None, b"abc").expect("trois suffisent");
    let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
    let ouvert = open_packet(&mut datagramme, &clefs, None, DCID.len()).expect("lisible");
    assert_eq!(ouvert.payload_len, 3);
}

/// **UN TAMPON TROP PETIT SE REFUSE, ET N'ÉCRIT RIEN DE PARTIEL.**
#[test]
fn un_tampon_trop_petit_se_refuse() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Initial {
        destination: identifiant(&DCID),
        source: identifiant(&[1, 2, 3, 4]),
        token: &[],
    };
    let charge = b"des trames";
    let mut assez = std::vec![0_u8; 1500];
    let taille = seal_packet(&mut assez, &clefs, &plan, 0, None, charge).expect("écrivable");

    for place in 0..taille {
        let mut juste = std::vec![0_u8; place];
        let issue = seal_packet(&mut juste, &clefs, &plan, 0, None, charge)
            .expect_err("il manque de la place");
        assert_eq!(issue.reason(), Reason::WindowTooSmall, "{place} octets");
        assert!(
            juste.iter().all(|octet| *octet == 0),
            "{place} octets : rien de partiel ne doit être écrit"
        );
    }
    // La taille exacte suffit.
    let mut pile = std::vec![0_u8; taille];
    assert_eq!(
        seal_packet(&mut pile, &clefs, &plan, 0, None, charge).expect("pile"),
        taille
    );
}

/// **CE QUE `payload_capacity` PROMET, `seal_packet` LE TIENT.**
///
/// C'est la seule propriété qui compte pour la garde d'amplification : un
/// appelant qui compose exactement ce qu'on lui a promis ne doit jamais se voir
/// refuser l'écriture après coup.
#[test]
fn ce_qui_est_promis_est_tenu() {
    let clefs = clefs(Role::Server);
    for (quoi, plan) in plans() {
        for place in [64_usize, 200, 1200, 1452] {
            for (numero, acquitte) in [(0_u64, None), (300, None), (1_000_000, Some(999_000_u64))] {
                let promis = payload_capacity(&plan, numero, acquitte, place);
                if promis < 3 {
                    continue;
                }
                let charge = std::vec![0x41_u8; promis];
                let mut tampon = std::vec![0_u8; place];
                let ecrit = seal_packet(&mut tampon, &clefs, &plan, numero, acquitte, &charge)
                    .unwrap_or_else(|issue| {
                        panic!("{quoi} / {place} / {numero} : {promis} promis, refusé : {issue:?}")
                    });
                assert!(
                    ecrit <= place,
                    "{quoi} / {place} : {ecrit} écrits pour {place} de place"
                );
            }
        }
    }
}

/// `payload_capacity` rend zéro quand rien ne rentre, plutôt que de déborder.
#[test]
fn ce_qui_ne_rentre_pas_vaut_zero() {
    let plan = Plan::OneRtt {
        destination: identifiant(&DCID),
        key_phase: false,
    };
    for place in [0_usize, 1, 8, 24] {
        assert_eq!(payload_capacity(&plan, 0, None, place), 0, "{place}");
    }
    // Un numéro hors de l'espace de §12.3 ne promet rien non plus.
    assert_eq!(
        payload_capacity(&plan, u64::MAX, None, 1500),
        0,
        "un numéro impossible ne promet rien"
    );
}

/// **UN NUMÉRO HORS DE L'ESPACE SE REFUSE** (§12.3).
#[test]
fn un_numero_hors_de_l_espace_se_refuse() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Handshake {
        destination: identifiant(&DCID),
        source: identifiant(&[7]),
    };
    let mut tampon = std::vec![0_u8; 1500];
    let issue = seal_packet(&mut tampon, &clefs, &plan, u64::MAX, None, b"une charge")
        .expect_err("§12.3 borne l'espace des numéros");
    assert_eq!(issue.reason(), Reason::SendOverflow);
}

/// **UN JETON SE PORTE, ET SE RELIT** (§17.2.2).
#[test]
fn un_jeton_se_porte_et_se_relit() {
    let clefs = clefs(Role::Server);
    for jeton in [&b""[..], b"court", &[0x5a; 200][..]] {
        let plan = Plan::Initial {
            destination: identifiant(&DCID),
            source: identifiant(&[1, 2]),
            token: jeton,
        };
        let mut tampon = std::vec![0_u8; 1500];
        let ecrit =
            seal_packet(&mut tampon, &clefs, &plan, 0, None, b"une charge").expect("écrivable");
        let paquet = tampon.get(..ecrit).expect("écrit");
        let Ok(Long::Numbered(entete)) = parse_long(paquet) else {
            panic!("un en-tête long numéroté");
        };
        assert_eq!(entete.token(), jeton, "{} octets", jeton.len());
        // Et le paquet reste lisible de bout en bout.
        let mut datagramme = paquet.to_vec();
        let ouvert = open_packet(&mut datagramme, &clefs, None, DCID.len()).expect("lisible");
        assert_eq!(ouvert.total, ecrit);
    }
}

/// **UN IDENTIFIANT VIDE EST LICITE** (§5.1), et se relit.
///
/// Un pair peut demander qu'on ne lui en envoie pas — il se repère alors à
/// l'adresse. C'est fragile (§5.1 le dit), mais c'est permis.
#[test]
fn un_identifiant_vide_est_licite() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Handshake {
        destination: identifiant(&[]),
        source: identifiant(&[]),
    };
    let mut tampon = std::vec![0_u8; 1500];
    let ecrit = seal_packet(&mut tampon, &clefs, &plan, 0, None, b"une charge").expect("écrivable");
    let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
    let ouvert = open_packet(&mut datagramme, &clefs, None, 0).expect("lisible");
    assert_eq!(ouvert.total, ecrit);
}

/// **DEUX PAQUETS TIENNENT DANS UN DATAGRAMME** (§12.2), et le second se lit
/// après le premier.
///
/// C'est ce que la longueur annoncée permet : sans elle, le lecteur ne saurait
/// pas où le premier s'arrête. Et l'en-tête court ferme le datagramme, parce
/// qu'il n'en porte pas.
#[test]
fn deux_paquets_tiennent_dans_un_datagramme() {
    let clefs = clefs(Role::Server);
    let long = Plan::Handshake {
        destination: identifiant(&DCID),
        source: identifiant(&[1]),
    };
    let court = Plan::OneRtt {
        destination: identifiant(&DCID),
        key_phase: true,
    };
    assert!(long.can_be_followed());
    assert!(!court.can_be_followed(), "§12.2 : il ferme le datagramme");

    let mut datagramme = std::vec![0_u8; 1500];
    let premier =
        seal_packet(&mut datagramme, &clefs, &long, 0, None, b"le premier").expect("écrivable");
    let second = seal_packet(
        datagramme.get_mut(premier..).expect("de la place"),
        &clefs,
        &court,
        1,
        None,
        b"le second",
    )
    .expect("écrivable");
    datagramme.truncate(premier + second);

    let ouvert = open_packet(&mut datagramme, &clefs, None, DCID.len()).expect("premier lisible");
    assert_eq!(ouvert.total, premier);
    assert_eq!(ouvert.kind, PacketKind::Long(LongKind::Handshake));
    assert_eq!(
        datagramme.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
        Some(&b"le premier"[..])
    );

    let suite = datagramme.get_mut(premier..).expect("le second");
    let ouvert = open_packet(suite, &clefs, Some(0), DCID.len()).expect("second lisible");
    assert_eq!(ouvert.kind, PacketKind::Short);
    assert_eq!(ouvert.number, 1);
    assert!(ouvert.key_phase);
    assert_eq!(
        suite.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
        Some(&b"le second"[..])
    );
}

/// **UN OCTET CHANGÉ DANS L'EN-TÊTE FAIT ÉCHOUER L'AUTHENTIFICATION.**
///
/// §5.3 de RFC 9001 : l'en-tête entier sert de données associées. C'est ce qui
/// protège la longueur annoncée et les identifiants autant que la charge — sans
/// quoi un intermédiaire pourrait redécouper un datagramme.
#[test]
fn un_entete_modifie_ne_s_authentifie_pas() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Initial {
        destination: identifiant(&DCID),
        source: identifiant(&[1, 2, 3, 4]),
        token: &[],
    };
    let mut tampon = std::vec![0_u8; 1500];
    let ecrit = seal_packet(&mut tampon, &clefs, &plan, 0, None, b"une charge").expect("écrivable");
    let paquet = tampon.get(..ecrit).expect("écrit").to_vec();

    // Chaque octet de l'en-tête en clair, l'un après l'autre. Le premier octet
    // et le numéro sont masqués : les toucher change autre chose, et c'est
    // éprouvé ailleurs.
    let Ok(Long::Numbered(entete)) = parse_long(&paquet) else {
        panic!("un en-tête long numéroté");
    };
    for rang in 1..entete.number_offset() {
        let mut abime = paquet.clone();
        abime[rang] ^= 0x01;
        assert!(
            open_packet(&mut abime, &clefs, None, DCID.len()).is_err(),
            "l'octet {rang} de l'en-tête n'est pas authentifié"
        );
    }
}

/// **LE MASQUE SE POSE APRÈS LE CHIFFREMENT**, et non avant.
///
/// §5.4.2 : l'échantillon se prend dans le CHIFFRÉ. Si l'on masquait d'abord, le
/// pair — qui démasque ce qu'il a reçu — prendrait bien le même échantillon, mais
/// nous l'aurions pris dans du clair. **Rien ne le dirait chez nous** : le
/// paquet serait simplement illisible chez lui.
///
/// On le constate en deux temps : les bits de forme restent lisibles (c'est ce
/// qui permet de reconnaître un paquet QUIC sans clé), et le démasquage retrouve
/// exactement le premier octet qu'on avait voulu écrire.
#[test]
fn le_masque_se_pose_apres_le_chiffrement() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Handshake {
        destination: identifiant(&DCID),
        source: identifiant(&[1]),
    };
    let mut tampon = std::vec![0_u8; 1500];
    let ecrit = seal_packet(&mut tampon, &clefs, &plan, 0, None, b"une charge").expect("écrivable");
    let mut paquet = tampon.get(..ecrit).expect("écrit").to_vec();

    // §17.2 : les bits de forme et le bit fixe ne sont PAS masqués — c'est ce
    // qui permet à un démultiplexeur de trier sans aucune clé.
    let premier = *paquet.first().expect("un premier octet");
    assert_eq!(premier & 0x80, 0x80, "le bit de forme reste lisible");
    assert_eq!(premier & 0x40, 0x40, "le bit fixe reste lisible");

    // Et le démasquage retrouve ce qu'on voulait : `Handshake`, un numéro d'un
    // octet, et les deux bits réservés à zéro (§17.2).
    let numero_a = match parse_long(&paquet) {
        Ok(Long::Numbered(entete)) => entete.number_offset(),
        _ => panic!("un en-tête long numéroté"),
    };
    let longueur = ams_quic_crypto::unprotect(&clefs, &mut paquet, numero_a).expect("démasquable");
    assert_eq!(longueur, 1, "un numéro d'un octet");
    assert_eq!(
        paquet.first().copied(),
        Some(0x80 | 0x40 | 0x20),
        "le premier octet démasqué est celui du plan, bits réservés à zéro"
    );
}

/// **UNE CHARGE PLUS GRANDE QU'UN DATAGRAMME SE REFUSE.**
///
/// `ams-quic-crypto` borne ce qu'il chiffre à ce qu'un datagramme UDP peut
/// porter. Le vérifier au moment de la disposition, et non au chiffrement, rend
/// ce dernier infaillible — et une étape infaillible n'a pas de branche que nul
/// essai n'atteint.
#[test]
fn une_charge_plus_grande_qu_un_datagramme_se_refuse() {
    let clefs = clefs(Role::Server);
    let plan = Plan::Handshake {
        destination: identifiant(&DCID),
        source: identifiant(&[1]),
    };
    let borne = ams_quic_crypto::PACKET_OCTETS_MAX;
    let mut tampon = std::vec![0_u8; borne + 128];

    let trop = std::vec![0x41_u8; borne + 1];
    let issue = seal_packet(&mut tampon, &clefs, &plan, 0, None, &trop)
        .expect_err("plus qu'un datagramme ne porte");
    assert_eq!(issue.reason(), Reason::SendOverflow);

    // La borne elle-même passe, et se relit.
    let pile = std::vec![0x41_u8; borne];
    let ecrit = seal_packet(&mut tampon, &clefs, &plan, 0, None, &pile).expect("la borne tient");
    let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
    let ouvert = open_packet(&mut datagramme, &clefs, None, DCID.len()).expect("lisible");
    assert_eq!(ouvert.payload_len, borne);
}
