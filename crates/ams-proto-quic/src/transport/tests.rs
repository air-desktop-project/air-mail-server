// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un paramètre de transport a le droit d'être.

use super::{
    DEFAULT_ACK_DELAY_EXPONENT, DEFAULT_ACTIVE_CONNECTION_ID_LIMIT, DEFAULT_MAX_ACK_DELAY_MS,
    DEFAULT_MAX_UDP_PAYLOAD_SIZE, MAX_ACK_DELAY_LIMIT_MS, MIN_ACTIVE_CONNECTION_ID_LIMIT,
    MIN_UDP_PAYLOAD_SIZE, Sender, TransportParameters,
};
use crate::error::{Reason, TransportError};
use crate::frame::{MAX_STREAMS_LIMIT, STATELESS_RESET_TOKEN_OCTETS};
use crate::varint;

/// Un identifiant de connexion à partir de ces octets.
fn identifiant(octets: &[u8]) -> crate::ConnectionId {
    crate::ConnectionId::new(octets).expect("vingt octets au plus")
}

/// Écrit un entier de §16 dans un tampon.
fn entier(valeur: u64) -> std::vec::Vec<u8> {
    let mut place = [0_u8; 8];
    let ecrits = varint::encode(valeur, &mut place).expect("écrivable");
    place.get(..ecrits).unwrap_or_default().to_vec()
}

/// Assemble une liste de paramètres.
fn liste(paires: &[(u64, std::vec::Vec<u8>)]) -> std::vec::Vec<u8> {
    let mut sortie = std::vec::Vec::new();
    for (identifiant, valeur) in paires {
        sortie.extend_from_slice(&entier(*identifiant));
        sortie.extend_from_slice(&entier(u64::try_from(valeur.len()).expect("court")));
        sortie.extend_from_slice(valeur);
    }
    sortie
}

/// **LES DÉFAUTS SONT DES VALEURS, PAS DES ABSENCES** (§18.2) : ils valent dès
/// le premier paquet, avant même que les paramètres du pair n'arrivent.
#[test]
fn les_defauts_sont_ceux_de_la_rfc() {
    let vides = TransportParameters::read(&[], Sender::Client).expect("une liste vide est licite");
    assert_eq!(vides, TransportParameters::DEFAULT);
    assert_eq!(vides, TransportParameters::default());
    assert_eq!(vides.max_udp_payload_size, DEFAULT_MAX_UDP_PAYLOAD_SIZE);
    assert_eq!(vides.ack_delay_exponent, DEFAULT_ACK_DELAY_EXPONENT);
    assert_eq!(vides.max_ack_delay_ms, DEFAULT_MAX_ACK_DELAY_MS);
    assert_eq!(
        vides.active_connection_id_limit,
        DEFAULT_ACTIVE_CONNECTION_ID_LIMIT
    );
    assert_eq!(vides.max_idle_timeout_ms, 0, "zéro veut dire : jamais");
    assert_eq!(
        vides.initial_max_data, 0,
        "aucun crédit tant qu'on n'en donne pas"
    );
    assert!(!vides.disable_active_migration);
    assert!(vides.initial_source_connection_id.is_none());
}

/// Les paramètres qu'un client envoie se lisent tous.
#[test]
fn les_parametres_d_un_client_se_lisent() {
    let brut = liste(&[
        (0x01, entier(30_000)),
        (0x03, entier(1_452)),
        (0x04, entier(1_048_576)),
        (0x05, entier(65_536)),
        (0x06, entier(65_537)),
        (0x07, entier(65_538)),
        (0x08, entier(100)),
        (0x09, entier(3)),
        (0x0a, entier(5)),
        (0x0b, entier(20)),
        (0x0c, std::vec::Vec::new()),
        (0x0e, entier(8)),
        (0x0f, std::vec::Vec::from([1_u8, 2, 3, 4])),
    ]);
    let lus = TransportParameters::read(&brut, Sender::Client).expect("lisible");
    assert_eq!(lus.max_idle_timeout_ms, 30_000);
    assert_eq!(lus.max_udp_payload_size, 1_452);
    assert_eq!(lus.initial_max_data, 1_048_576);
    assert_eq!(lus.initial_max_stream_data_bidi_local, 65_536);
    assert_eq!(lus.initial_max_stream_data_bidi_remote, 65_537);
    assert_eq!(lus.initial_max_stream_data_uni, 65_538);
    assert_eq!(lus.initial_max_streams_bidi, 100);
    assert_eq!(lus.initial_max_streams_uni, 3);
    assert_eq!(lus.ack_delay_exponent, 5);
    assert_eq!(lus.max_ack_delay_ms, 20);
    assert!(lus.disable_active_migration);
    assert_eq!(lus.active_connection_id_limit, 8);
    assert_eq!(lus.initial_source_connection_id.map(|id| id.len()), Some(4));
}

/// **CE QU'ON NE CONNAÎT PAS S'IGNORE** (§18.1) — et c'est l'exact inverse des
/// trames, où §12.4 en fait une faute. On ignore là où l'on NÉGOCIE, on refuse
/// là où l'on EXÉCUTE.
#[test]
fn un_parametre_inconnu_s_ignore() {
    let brut = liste(&[
        (0xff_ff, std::vec::Vec::from([1_u8, 2, 3])),
        (0x04, entier(4_096)),
        // Un paramètre de graissage de §18.1 : 31*N + 27.
        (27, std::vec::Vec::from([0_u8; 7])),
        (0x01, entier(1_000)),
    ]);
    let lus = TransportParameters::read(&brut, Sender::Client).expect("lisible");
    assert_eq!(lus.initial_max_data, 4_096, "l'inconnu n'a rien décalé");
    assert_eq!(lus.max_idle_timeout_ms, 1_000);
}

/// **UN PARAMÈTRE DEUX FOIS EST UNE FAUTE** (§7.4) : deux valeurs pour une même
/// limite laisseraient chaque mise en œuvre choisir la sienne.
#[test]
fn un_parametre_repete_se_refuse() {
    let brut = liste(&[(0x04, entier(1_000)), (0x04, entier(2_000))]);
    let issue = TransportParameters::read(&brut, Sender::Client).expect_err("répété");
    assert_eq!(issue.reason(), Reason::BadTransportParameter);
    assert_eq!(issue.code(), TransportError::TransportParameterError);

    // Même une répétition à l'identique.
    let brut = liste(&[(0x01, entier(5)), (0x01, entier(5))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_err());

    // Mais deux paramètres différents, non.
    let brut = liste(&[(0x04, entier(1_000)), (0x05, entier(2_000))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_ok());
}

/// **CERTAINS PARAMÈTRES N'APPARTIENNENT QU'AU SERVEUR** (§18.2) : un client qui
/// les enverrait prétendrait avoir émis un `Retry` ou choisi l'identifiant
/// d'origine — c'est-à-dire réécrire ce qui prouve que la poignée de main n'a
/// pas été détournée.
#[test]
fn un_client_n_annonce_pas_ce_qui_est_au_serveur() {
    let jeton = std::vec::Vec::from([0_u8; STATELESS_RESET_TOKEN_OCTETS]);
    for (identifiant, valeur) in [
        (0x00_u64, std::vec::Vec::from([1_u8, 2])),
        (0x02, jeton.clone()),
        (0x0d, std::vec::Vec::from([0_u8; 4])),
        (0x10, std::vec::Vec::from([3_u8, 4])),
    ] {
        let brut = liste(&[(identifiant, valeur.clone())]);
        let issue =
            TransportParameters::read(&brut, Sender::Client).expect_err("ce n'est pas au client");
        assert_eq!(
            issue.reason(),
            Reason::BadTransportParameter,
            "{identifiant:#x}"
        );
        // Du serveur, en revanche, ils passent.
        assert!(
            TransportParameters::read(&brut, Sender::Server).is_ok(),
            "{identifiant:#x}"
        );
    }
}

/// Les identifiants qu'un serveur annonce se retiennent.
#[test]
fn les_identifiants_d_un_serveur_se_retiennent() {
    let brut = liste(&[
        (0x00, std::vec::Vec::from([1_u8, 2, 3])),
        (0x10, std::vec::Vec::from([9_u8])),
        (0x0f, std::vec::Vec::from([7_u8, 8])),
    ]);
    let lus = TransportParameters::read(&brut, Sender::Server).expect("lisible");
    assert_eq!(
        lus.original_destination_connection_id.map(|id| id.len()),
        Some(3)
    );
    assert_eq!(lus.retry_source_connection_id.map(|id| id.len()), Some(1));
    assert_eq!(lus.initial_source_connection_id.map(|id| id.len()), Some(2));
}

/// **CHAQUE BORNE DE §18.2, ET CE QU'ELLE FERME.**
#[test]
fn chaque_borne_de_la_rfc_se_verifie() {
    // La charge UDP : au moins 1200, sans quoi le pair ne pourrait pas recevoir
    // la poignée de main elle-même.
    let brut = liste(&[(0x03, entier(MIN_UDP_PAYLOAD_SIZE))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_ok());
    let brut = liste(&[(0x03, entier(MIN_UDP_PAYLOAD_SIZE.saturating_sub(1)))]);
    assert_eq!(
        TransportParameters::read(&brut, Sender::Client)
            .expect_err("trop court")
            .reason(),
        Reason::BadTransportParameter
    );

    // Le compte de flux : 2^60, la même borne que §19.11.
    for identifiant in [0x08_u64, 0x09] {
        let brut = liste(&[(identifiant, entier(MAX_STREAMS_LIMIT))]);
        assert!(TransportParameters::read(&brut, Sender::Client).is_ok());
        let brut = liste(&[(identifiant, entier(MAX_STREAMS_LIMIT.saturating_add(1)))]);
        assert!(TransportParameters::read(&brut, Sender::Client).is_err());
    }

    // L'exposant de délai : vingt au plus.
    let brut = liste(&[(0x0a, entier(20))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_ok());
    let brut = liste(&[(0x0a, entier(21))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_err());

    // Le délai maximal : strictement sous 2^14.
    let brut = liste(&[(0x0b, entier(MAX_ACK_DELAY_LIMIT_MS.saturating_sub(1)))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_ok());
    let brut = liste(&[(0x0b, entier(MAX_ACK_DELAY_LIMIT_MS))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_err());

    // Le nombre d'identifiants actifs : au moins deux, sans quoi changer de
    // chemin sans se faire suivre deviendrait impossible.
    let brut = liste(&[(0x0e, entier(MIN_ACTIVE_CONNECTION_ID_LIMIT))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_ok());
    let brut = liste(&[(0x0e, entier(1))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_err());
}

/// **UNE VALEUR OCCUPE TOUT CE QU'ELLE ANNONCE, ET RIEN DE PLUS.** Des octets en
/// trop derrière un entier voudraient dire qu'on n'a pas lu ce que le pair a
/// écrit — et l'on prendrait sa limite pour une autre.
#[test]
fn une_valeur_qui_ne_remplit_pas_sa_longueur_se_refuse() {
    // Un entier d'un octet annoncé sur trois.
    let mut valeur = entier(5);
    valeur.extend_from_slice(&[0, 0]);
    let brut = liste(&[(0x04, valeur)]);
    let issue = TransportParameters::read(&brut, Sender::Client).expect_err("des octets en trop");
    assert_eq!(issue.reason(), Reason::BadTransportParameter);

    // Et `disable_active_migration` ne porte rien du tout.
    let brut = liste(&[(0x0c, std::vec::Vec::from([0_u8]))]);
    assert!(TransportParameters::read(&brut, Sender::Client).is_err());

    // Le jeton de réinitialisation fait seize octets, ni plus ni moins.
    let brut = liste(&[(0x02, std::vec::Vec::from([0_u8; 15]))]);
    assert!(TransportParameters::read(&brut, Sender::Server).is_err());
    let brut = liste(&[(
        0x02,
        std::vec::Vec::from([0_u8; STATELESS_RESET_TOKEN_OCTETS]),
    )]);
    assert!(TransportParameters::read(&brut, Sender::Server).is_ok());
}

/// Une liste tronquée, et un identifiant de connexion hors borne.
#[test]
fn une_liste_mal_formee_se_refuse() {
    // **UNE COUPURE SUR UNE FRONTIÈRE DONNE UNE LISTE PLUS COURTE, ET VALIDE.**
    // Une liste de paramètres n'annonce pas combien elle en porte : elle
    // s'arrête où le tampon s'arrête. Seules les coupures qui tombent DANS un
    // paramètre sont des fautes — et les distinguer est justement ce que le
    // test doit dire.
    let premier = liste(&[(0x04, entier(1_000))]);
    let entiere = liste(&[(0x04, entier(1_000)), (0x01, entier(30_000))]);
    // La seule frontière INTÉRIEURE est la fin du premier paramètre : on la
    // calcule plutôt que de l'écrire, pour que le test ne dépende pas de la
    // longueur qu'un entier de §16 se trouve prendre.
    let frontieres = [premier.len()];
    for coupure in 1..entiere.len() {
        let court = entiere.get(..coupure).expect("préfixe");
        let issue = TransportParameters::read(court, Sender::Client);
        match frontieres.contains(&coupure) {
            true => assert!(issue.is_ok(), "la frontière {coupure} est une liste"),
            false => assert!(issue.is_err(), "coupure {coupure}"),
        }
    }

    // Une longueur qui annonce plus que la liste ne porte.
    let mut ment = entier(0x04);
    ment.extend_from_slice(&entier(crate::varint::VARINT_MAX));
    assert_eq!(
        TransportParameters::read(&ment, Sender::Client)
            .expect_err("il ment")
            .reason(),
        Reason::Truncated
    );

    // Un identifiant de connexion au-delà de vingt octets.
    let brut = liste(&[(0x0f, std::vec::Vec::from([0_u8; 21]))]);
    assert_eq!(
        TransportParameters::read(&brut, Sender::Client)
            .expect_err("hors borne")
            .reason(),
        Reason::ConnectionIdTooLong
    );
}

/// L'adresse préférée se lit sans qu'on en fasse rien : la lire est ce qui
/// empêche de décaler ce qui suit.
#[test]
fn l_adresse_preferee_se_saute_sans_decaler() {
    let brut = liste(&[
        (0x0d, std::vec::Vec::from([0_u8; 41])),
        (0x04, entier(4_096)),
    ]);
    let lus = TransportParameters::read(&brut, Sender::Server).expect("lisible");
    assert_eq!(lus.initial_max_data, 4_096);
}

/// **CHAQUE PARAMÈTRE ENTIER SE REFUSE VIDE OU REMBOURRÉ**, et pas seulement
/// ceux qu'on a pensé à éprouver. Un seul oublié laisserait un pair annoncer une
/// limite qu'on lirait de travers.
#[test]
fn chaque_parametre_entier_veut_une_valeur_exacte() {
    // Des valeurs licites pour chacun, qu'on abîmera ensuite.
    let cas: [(u64, u64); 11] = [
        (0x01, 30_000),
        (0x03, 1_452),
        (0x04, 1_000),
        (0x05, 1_000),
        (0x06, 1_000),
        (0x07, 1_000),
        (0x08, 10),
        (0x09, 10),
        (0x0a, 5),
        (0x0b, 20),
        (0x0e, 4),
    ];
    for (identifiant, valeur) in cas {
        // Telle quelle, elle passe.
        let brut = liste(&[(identifiant, entier(valeur))]);
        assert!(
            TransportParameters::read(&brut, Sender::Client).is_ok(),
            "{identifiant:#x} devrait passer"
        );

        // Vide : il n'y a pas d'entier à lire.
        let brut = liste(&[(identifiant, std::vec::Vec::new())]);
        assert!(
            TransportParameters::read(&brut, Sender::Client).is_err(),
            "{identifiant:#x} vide devrait être refusé"
        );

        // Rembourré : on n'a pas lu ce que le pair a écrit.
        let mut rembourre = entier(valeur);
        rembourre.push(0);
        let brut = liste(&[(identifiant, rembourre)]);
        let issue =
            TransportParameters::read(&brut, Sender::Client).expect_err("des octets en trop");
        assert_eq!(
            issue.reason(),
            Reason::BadTransportParameter,
            "{identifiant:#x} rembourré"
        );
    }
}

/// Un identifiant de paramètre lui-même tronqué : le premier octet annonce huit,
/// et il n'y en a qu'un.
#[test]
fn un_identifiant_de_parametre_tronque_se_refuse() {
    let issue = TransportParameters::read(&[0xc0], Sender::Client).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
}

/// Les identifiants de connexion des paramètres du serveur ont la même borne
/// que partout ailleurs.
#[test]
fn les_identifiants_du_serveur_ont_leur_borne() {
    for identifiant in [0x00_u64, 0x10] {
        let brut = liste(&[(identifiant, std::vec::Vec::from([0_u8; 21]))]);
        let issue = TransportParameters::read(&brut, Sender::Server).expect_err("hors borne");
        assert_eq!(
            issue.reason(),
            Reason::ConnectionIdTooLong,
            "{identifiant:#x}"
        );
    }
}

/// **CE QU'ON ÉCRIT SE RELIT, ET REND CE QU'ON AVAIT** (§18).
///
/// C'est la seule propriété qui compte : les paramètres voyagent dans une
/// extension TLS, et un pair qui les relit autrement qu'on ne les a écrits
/// prendrait nos limites pour d'autres — sans que rien ne le dise, jusqu'à ce
/// qu'un flux se fige.
#[test]
fn ce_qu_on_ecrit_se_relit() {
    let mut poses = TransportParameters::DEFAULT;
    poses.max_idle_timeout_ms = 30_000;
    poses.max_udp_payload_size = 1_452;
    poses.initial_max_data = 1_048_576;
    poses.initial_max_stream_data_bidi_local = 262_144;
    poses.initial_max_stream_data_bidi_remote = 262_144;
    poses.initial_max_stream_data_uni = 262_144;
    poses.initial_max_streams_bidi = 100;
    poses.initial_max_streams_uni = 3;
    poses.ack_delay_exponent = 3;
    poses.max_ack_delay_ms = 25;
    poses.disable_active_migration = true;
    poses.active_connection_id_limit = 4;
    poses.initial_source_connection_id = Some(identifiant(&[1, 2, 3, 4, 5, 6, 7, 8]));
    poses.original_destination_connection_id = Some(identifiant(&[9, 8, 7, 6]));

    let mut octets = [0_u8; 256];
    let ecrits = poses
        .write(Sender::Server, &mut octets)
        .expect("écrivables");
    let relus = TransportParameters::read(octets.get(..ecrits).expect("écrits"), Sender::Server)
        .expect("relisibles");
    assert_eq!(relus, poses);
}

/// **LES DÉFAUTS AUSSI FONT L'ALLER-RETOUR.**
///
/// §18 permet d'omettre un paramètre dont la valeur est celle par défaut. On les
/// écrit quand même — les omettre demanderait de comparer chaque champ à
/// `DEFAULT`, et une comparaison de ce genre se tait le jour où le défaut
/// change.
#[test]
fn les_defauts_aussi_font_l_aller_retour() {
    let mut octets = [0_u8; 256];
    let ecrits = TransportParameters::DEFAULT
        .write(Sender::Client, &mut octets)
        .expect("écrivables");
    let relus = TransportParameters::read(octets.get(..ecrits).expect("écrits"), Sender::Client)
        .expect("relisibles");
    assert_eq!(relus, TransportParameters::DEFAULT);
}

/// **UN PARAMÈTRE SANS VALEUR SE DÉCLARE PAR SA PRÉSENCE** (§18.2).
///
/// `disable_active_migration` n'a pas de valeur : l'écrire vaut « vrai ». Un
/// écrivain qui le poserait toujours annoncerait donc une migration désactivée
/// alors qu'on ne l'a pas demandée.
#[test]
fn un_parametre_sans_valeur_se_declare_par_sa_presence() {
    let mut octets = [0_u8; 256];
    let ecrits = TransportParameters::DEFAULT
        .write(Sender::Client, &mut octets)
        .expect("écrivables");
    let ecrit = octets.get(..ecrits).expect("écrits");
    // §18.2 : l'identifiant 0x0c, suivi d'une longueur nulle.
    assert!(
        !ecrit.windows(2).any(|paire| paire == [0x0c, 0x00]),
        "il ne doit pas être écrit quand il est faux"
    );

    let mut avec = TransportParameters::DEFAULT;
    avec.disable_active_migration = true;
    let ecrits = avec.write(Sender::Client, &mut octets).expect("écrivables");
    let ecrit = octets.get(..ecrits).expect("écrits");
    assert!(
        ecrit.windows(2).any(|paire| paire == [0x0c, 0x00]),
        "il doit être écrit quand il est vrai"
    );
}

/// **CE QUI N'APPARTIENT PAS À CELUI QUI ENVOIE SE REFUSE** (§18.2).
///
/// La taire ferait rejeter la poignée de main par le pair, très loin d'ici — et
/// pour une raison qu'aucun journal de ce côté-ci n'expliquerait.
#[test]
fn ce_qui_n_appartient_pas_a_l_envoyeur_se_refuse() {
    let mut octets = [0_u8; 256];
    for (quoi, poses) in [
        ("original_destination_connection_id", {
            let mut poses = TransportParameters::DEFAULT;
            poses.original_destination_connection_id = Some(identifiant(&[1, 2]));
            poses
        }),
        ("retry_source_connection_id", {
            let mut poses = TransportParameters::DEFAULT;
            poses.retry_source_connection_id = Some(identifiant(&[3, 4]));
            poses
        }),
    ] {
        let issue = poses
            .write(Sender::Client, &mut octets)
            .expect_err("§18.2 réserve celui-ci au serveur");
        assert_eq!(issue.reason(), Reason::BadTransportParameter, "{quoi}");
        // Et le serveur, lui, l'écrit.
        assert!(poses.write(Sender::Server, &mut octets).is_ok(), "{quoi}");
    }
}

/// **UN TAMPON TROP PETIT SE REFUSE, ET N'ÉCRIT RIEN QUI SE LISE.**
#[test]
fn un_tampon_trop_petit_se_refuse() {
    // **DES PARAMÈTRES COMPLETS**, et non les défauts : les identifiants et le
    // drapeau de migration ne s'écrivent que s'ils sont là, et ce sont
    // justement leurs écritures qu'un tampon trop court doit refuser.
    let mut poses = TransportParameters::DEFAULT;
    poses.disable_active_migration = true;
    poses.initial_source_connection_id = Some(identifiant(&[1, 2, 3, 4, 5, 6, 7, 8]));
    poses.original_destination_connection_id = Some(identifiant(&[9, 8, 7, 6]));
    poses.retry_source_connection_id = Some(identifiant(&[5, 5]));

    let mut assez = [0_u8; 256];
    let taille = poses.write(Sender::Server, &mut assez).expect("écrivables");

    for place in 0..taille {
        let mut juste = std::vec![0_u8; place];
        let issue = poses
            .write(Sender::Server, &mut juste)
            .expect_err("il manque de la place");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{place} octets");
    }
    // La taille exacte suffit, et l'aller-retour tient.
    let mut pile = std::vec![0_u8; taille];
    assert_eq!(
        poses.write(Sender::Server, &mut pile).expect("pile"),
        taille
    );
    assert_eq!(
        TransportParameters::read(&pile, Sender::Server).expect("relisibles"),
        poses
    );
}

/// **UNE VALEUR QUE §16 NE SAIT PAS ÉCRIRE SE REFUSE.**
///
/// Les paramètres de transport sont des entiers de longueur variable, bornés à
/// 2^62 - 1. Une valeur au-delà ne s'écrit pas — et la tronquer annoncerait une
/// limite qui n'est pas celle qu'on a voulue.
#[test]
fn une_valeur_hors_borne_se_refuse() {
    let mut poses = TransportParameters::DEFAULT;
    poses.initial_max_data = crate::VARINT_MAX + 1;
    let mut octets = [0_u8; 256];
    let issue = poses
        .write(Sender::Server, &mut octets)
        .expect_err("§16 ne l'écrit pas");
    assert_eq!(issue.reason(), Reason::VarintTooLarge);

    // La borne elle-même s'écrit.
    poses.initial_max_data = crate::VARINT_MAX;
    assert!(poses.write(Sender::Server, &mut octets).is_ok());
}
