//! Une requête, une réponse : ce que le client écrit, et ce qu'il comprend.

use std::vec::Vec;

use super::{Client, Progress, REQUEST_HEAD_MAX, Request, START_OCTETS_MAX};
use crate::error::Cause;
use crate::frame::{FRAME_HEADER_OCTETS, FrameHeader, FrameKind};
use crate::hpack::{Decoder, encode_field, encode_status};
use crate::preface::PREFACE;
use crate::settings::Settings;

/// Un cadre entier.
fn cadre(genre: FrameKind, drapeaux: u8, flux: u32, charge: &[u8]) -> Vec<u8> {
    let longueur = u32::try_from(charge.len()).expect("petit");
    let mut octets = FrameHeader::new(genre, drapeaux, flux, longueur)
        .write()
        .to_vec();
    octets.extend_from_slice(charge);
    octets
}

/// Les `SETTINGS` d'un serveur ordinaire.
fn reglages() -> Vec<u8> {
    let mut place = [0_u8; Settings::OCTETS_MAX];
    let n = Settings::DEFAULT.write(&mut place).expect("écrivable");
    cadre(FrameKind::Settings, 0, 0, &place[..n])
}

/// Un bloc de réponse : `:status`, et d'autres champs.
fn tete(statut: Option<u16>, autres: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut place = [0_u8; 1024];
    let mut n = 0_usize;
    if let Some(code) = statut {
        n = n.saturating_add(encode_status(code, &mut place[n..]).expect("codable"));
    }
    for (nom, valeur) in autres {
        n = n.saturating_add(encode_field(nom, valeur, &mut place[n..]).expect("codable"));
    }
    place[..n].to_vec()
}

const REQUETE: Request<'static> = Request {
    method: b"POST",
    authority: b"push.example.com",
    path: b"/push/abc",
    fields: &[(b"ttl", b"60"), (b"content-encoding", b"aes128gcm")],
    body: b"le corps",
};

fn demarrer(requete: &Request<'_>) -> (Client, Vec<u8>) {
    let mut client = Client::new();
    let mut out = std::vec![0_u8; START_OCTETS_MAX];
    let n = client.start(requete, &mut out).expect("démarrable");
    out.truncate(n);
    (client, out)
}

/// Joue ces octets serveur, et rend (progrès, ce que le client écrit, réponse).
fn jouer(
    client: &mut Client,
    octets: &[u8],
    corps: &[u8],
) -> Result<(Progress, Vec<u8>, Vec<u8>), crate::Error> {
    let mut out = std::vec![0_u8; 128 * 1024];
    let mut reponse = std::vec![0_u8; 64];
    let progres = client.receive(octets, corps, &mut out, &mut reponse)?;
    out.truncate(progres.written);
    reponse.truncate(client.body_len());
    Ok((progres, out, reponse))
}

fn cause(resultat: Result<(Progress, Vec<u8>, Vec<u8>), crate::Error>) -> Cause {
    resultat.expect_err("une faute").cause()
}

/// Préambule, `SETTINGS` sans push, et une tête de requête lisible.
#[test]
fn le_debut_d_une_requete_s_ecrit() {
    let (_, out) = demarrer(&REQUETE);
    assert!(out.starts_with(PREFACE));
    let reste = &out[PREFACE.len()..];
    let reglages = FrameHeader::parse(reste[..9].try_into().expect("neuf"));
    assert_eq!(reglages.kind(), FrameKind::Settings);
    let mut lus = Settings::DEFAULT;
    crate::settings::SettingsReader::apply_all(&reste[9..reglages.total()], &mut lus)
        .expect("lisibles");
    assert!(!lus.enable_push);
    let reste = &reste[reglages.total()..];
    let tete = FrameHeader::parse(reste[..9].try_into().expect("neuf"));
    assert_eq!((tete.kind(), tete.stream()), (FrameKind::Headers, 1));
    assert!(tete.flags().end_headers() && !tete.flags().end_stream());
    let mut decodeur = Decoder::new();
    let bloc = &reste[9..tete.total()];
    let mut vus = Vec::new();
    let mut lu = 0_usize;
    let mut place = [0_u8; 256];
    while let Some(champ) = decodeur.next(&bloc[lu..], &mut place).expect("décodable") {
        vus.push((champ.field.name.to_vec(), champ.field.value.to_vec()));
        lu = lu.saturating_add(champ.read);
    }
    let attendus: [(&[u8], &[u8]); 6] = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"push.example.com"),
        (b":path", b"/push/abc"),
        (b"ttl", b"60"),
        (b"content-encoding", b"aes128gcm"),
    ];
    assert_eq!(vus.len(), attendus.len());
    for ((nom, valeur), (a, b)) in vus.iter().zip(attendus) {
        assert_eq!((nom.as_slice(), valeur.as_slice()), (a, b));
    }
    // Sans corps, la requête finit avec sa tête.
    let (_, out) = demarrer(&Request {
        body: b"",
        ..REQUETE
    });
    let reste = &out[PREFACE.len()..];
    let reglages = FrameHeader::parse(reste[..9].try_into().expect("neuf"));
    let tete = FrameHeader::parse(reste[reglages.total()..][..9].try_into().expect("neuf"));
    assert!(tete.flags().end_stream());
}

/// **UN ÉCHANGE ENTIER** : les réglages du serveur font partir l'acquittement
/// et le corps ; la réponse arrive, avec son statut et son corps.
#[test]
fn un_echange_se_deroule() {
    let (mut client, _) = demarrer(&REQUETE);
    assert_eq!(client.status(), None);
    let (progres, out, _) = jouer(&mut client, &reglages(), REQUETE.body).expect("recevable");
    assert!(!progres.done);
    let mut attendu = cadre(FrameKind::Settings, 1, 0, &[]);
    attendu.extend(cadre(FrameKind::Data, 1, 1, REQUETE.body));
    assert_eq!(out, attendu);
    let mut serveur = cadre(FrameKind::Settings, 1, 0, &[]);
    serveur.extend(cadre(FrameKind::WindowUpdate, 0, 0, &[0, 0, 1, 0]));
    serveur.extend(cadre(
        FrameKind::Headers,
        4,
        1,
        &tete(Some(201), &[(b"location", b"/m/1")]),
    ));
    serveur.extend(cadre(FrameKind::Data, 0, 1, b"o"));
    serveur.extend(cadre(FrameKind::Data, 1, 1, b"k"));
    // Un cadre de trop, derrière la fin : il ne se consomme pas.
    serveur.extend(cadre(FrameKind::Ping, 0, 0, &[0; 8]));
    let (progres, out, reponse) = jouer(&mut client, &serveur, REQUETE.body).expect("recevable");
    assert!(progres.done);
    assert_eq!(
        progres.consumed,
        serveur
            .len()
            .saturating_sub(FRAME_HEADER_OCTETS)
            .saturating_sub(8)
    );
    assert!(out.is_empty());
    assert_eq!(
        (client.status(), reponse.as_slice()),
        (Some(201), &b"ok"[..])
    );
    // D'autres réglages après le corps s'acquittent, sans rien renvoyer.
    let mut encore = Client::default();
    let _ = encore.start(
        &Request {
            body: b"",
            ..REQUETE
        },
        &mut [0; START_OCTETS_MAX],
    );
    let (_, out, _) = jouer(&mut encore, &reglages(), b"").expect("recevable");
    assert_eq!(out, cadre(FrameKind::Settings, 1, 0, &[]));
}

/// Un corps plus grand qu'un cadre part en plusieurs, le dernier seul fermant
/// le flux ; plus grand que la fenêtre, il ne part pas.
#[test]
fn un_corps_se_decoupe_et_respecte_la_fenetre() {
    let corps = std::vec![7_u8; 40_000];
    let (mut client, _) = demarrer(&Request {
        body: &corps,
        ..REQUETE
    });
    let (_, out, _) = jouer(&mut client, &reglages(), &corps).expect("recevable");
    let mut rang = FRAME_HEADER_OCTETS;
    let mut vus = Vec::new();
    while rang < out.len() {
        let entete =
            FrameHeader::parse(out[rang..rang.saturating_add(9)].try_into().expect("neuf"));
        vus.push((entete.length(), entete.flags().end_stream()));
        rang = rang.saturating_add(entete.total());
    }
    assert_eq!(vus, [(16_384, false), (16_384, false), (7_232, true)]);
    // Une fenêtre de cent octets.
    let (mut client, _) = demarrer(&REQUETE);
    let petite = cadre(FrameKind::Settings, 0, 0, &[0, 4, 0, 0, 0, 4]);
    assert_eq!(
        cause(jouer(&mut client, &petite, &[1; 101])),
        Cause::RequestBodyTooLarge
    );
}

/// Ce qui ne ressemble pas à un serveur HTTP/2 est une faute.
#[test]
fn ce_que_le_serveur_ne_doit_pas_faire() {
    let entame = |octets: Vec<u8>| {
        let (mut client, _) = demarrer(&REQUETE);
        let mut tout = reglages();
        tout.extend(octets);
        cause(jouer(&mut client, &tout, REQUETE.body))
    };
    // Le premier cadre n'est pas `SETTINGS`.
    let (mut client, _) = demarrer(&REQUETE);
    assert_eq!(
        cause(jouer(
            &mut client,
            &cadre(FrameKind::Ping, 0, 0, &[0; 8]),
            b""
        )),
        Cause::FirstFrameNotSettings
    );
    assert_eq!(
        entame(cadre(FrameKind::Data, 0, 3, b"x")),
        Cause::BadStreamId
    );
    assert_eq!(
        entame(cadre(FrameKind::RstStream, 0, 1, &[0, 0, 0, 8])),
        Cause::StreamReset
    );
    assert_eq!(
        entame(cadre(FrameKind::PushPromise, 4, 1, &[0, 0, 0, 2])),
        Cause::PushFromClient
    );
    assert_eq!(
        entame(cadre(FrameKind::GoAway, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0])),
        Cause::Refused
    );
    assert_eq!(
        entame(cadre(FrameKind::Continuation, 4, 1, &[])),
        Cause::BlockInterrupted
    );
    // Une réponse sans statut, ou un statut illisible.
    assert_eq!(
        entame(cadre(FrameKind::Headers, 5, 1, &tete(None, &[]))),
        Cause::NoStatus
    );
    assert_eq!(
        entame(cadre(
            FrameKind::Headers,
            5,
            1,
            &tete(None, &[(b":status", b"abc")])
        )),
        Cause::NoStatus
    );
    // Un statut hors de la plage HTTP n'est pas une réponse finale.
    for code in [b"0" as &[u8], b"42", b"600", b"999"] {
        assert_eq!(
            entame(cadre(
                FrameKind::Headers,
                5,
                1,
                &tete(None, &[(b":status", code)])
            )),
            Cause::NoStatus,
            "{code:?}"
        );
    }
    // Un flux qui finit avant toute tête.
    assert_eq!(entame(cadre(FrameKind::Data, 1, 1, b"x")), Cause::NoStatus);
    // Deux réponses finales.
    let mut deux = cadre(FrameKind::Headers, 4, 1, &tete(Some(200), &[]));
    deux.extend(cadre(FrameKind::Headers, 4, 1, &tete(Some(200), &[])));
    assert_eq!(entame(deux), Cause::NoStatus);
    // Une priorité qui ne tient pas dans la charge.
    assert_eq!(
        entame(cadre(FrameKind::Headers, 0x24, 1, &[0, 0])),
        Cause::PaddingTooLong
    );
    // Un corps de réponse plus long que son tampon.
    let mut long = cadre(FrameKind::Headers, 4, 1, &tete(Some(200), &[]));
    long.extend(cadre(FrameKind::Data, 0, 1, &[0; 65]));
    assert_eq!(entame(long), Cause::ResponseBodyTooLong);
}

/// Ce qu'un serveur a le droit de faire, et que le client suit.
#[test]
fn ce_que_le_serveur_peut_faire() {
    let (mut client, _) = demarrer(&REQUETE);
    let mut serveur = reglages();
    // Un `PING` s'acquitte en écho ; son acquittement ne s'acquitte pas.
    serveur.extend(cadre(FrameKind::Ping, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]));
    serveur.extend(cadre(FrameKind::Ping, 1, 0, &[0; 8]));
    // Un `GOAWAY` qui laisse passer notre flux.
    serveur.extend(cadre(FrameKind::GoAway, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]));
    // Une réponse informative, puis la finale — avec remplissage et
    // priorité, coupée par une `CONTINUATION`.
    serveur.extend(cadre(FrameKind::Headers, 4, 1, &tete(Some(100), &[])));
    let bloc = tete(Some(204), &[(b"apns-id", b"x")]);
    let mut charge = std::vec![2_u8];
    charge.extend([0, 0, 0, 0, 16]);
    charge.extend(&bloc[..3]);
    charge.extend([0, 0]);
    serveur.extend(cadre(FrameKind::Headers, 0x28, 1, &charge));
    serveur.extend(cadre(FrameKind::Continuation, 4, 1, &bloc[3..]));
    serveur.extend(cadre(FrameKind::Data, 0x8, 1, &[1, b'z', 0]));
    // Des en-têtes de fin, qui ferment le flux.
    serveur.extend(cadre(
        FrameKind::Headers,
        5,
        1,
        &tete(None, &[(b"x-fin", b"1")]),
    ));
    let (progres, out, reponse) = jouer(&mut client, &serveur, REQUETE.body).expect("recevable");
    assert!(progres.done);
    let mut attendu = cadre(FrameKind::Settings, 1, 0, &[]);
    attendu.extend(cadre(FrameKind::Data, 1, 1, REQUETE.body));
    attendu.extend(cadre(FrameKind::Ping, 1, 0, &[1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(out, attendu);
    assert_eq!(
        (client.status(), reponse.as_slice()),
        (Some(204), &b"z"[..])
    );
    // Une tête finale qui ferme le flux d'un coup.
    let (mut client, _) = demarrer(&REQUETE);
    let mut serveur = reglages();
    serveur.extend(cadre(FrameKind::Headers, 5, 1, &tete(Some(410), &[])));
    let (progres, _, _) = jouer(&mut client, &serveur, REQUETE.body).expect("recevable");
    assert!(progres.done);
    assert_eq!(client.status(), Some(410));
}

/// Un cadre incomplet attend la suite, sans rien consommer.
#[test]
fn un_cadre_incomplet_attend() {
    let (mut client, _) = demarrer(&REQUETE);
    let entier = reglages();
    let (progres, out, _) = jouer(
        &mut client,
        &entier[..entier.len().saturating_sub(1)],
        REQUETE.body,
    )
    .expect("recevable");
    assert_eq!(
        (progres.consumed, progres.written, progres.done),
        (0, 0, false)
    );
    assert!(out.is_empty());
    // Et une annonce démesurée se refuse dès l'en-tête.
    let (mut client, _) = demarrer(&REQUETE);
    let demesure = FrameHeader::new(FrameKind::Settings, 0, 0, 1 << 20).write();
    assert_eq!(
        cause(jouer(&mut client, &demesure, b"")),
        Cause::FrameTooLong
    );
}

/// Un tampon trop court, une tête trop longue : dit, et non tronqué.
#[test]
fn ce_qui_ne_tient_pas_se_dit() {
    let mut client = Client::new();
    for taille in [0, PREFACE.len(), PREFACE.len() + 12, PREFACE.len() + 30] {
        let mut petit = std::vec![0_u8; taille];
        assert_eq!(
            client
                .start(&REQUETE, &mut petit)
                .expect_err("trop court")
                .cause(),
            Cause::BufferTooSmall,
            "{taille}"
        );
    }
    // `~` s'allonge sous Huffman : la tête dépasse le cadre.
    let enorme = std::vec![b'~'; REQUEST_HEAD_MAX];
    let champs: [(&[u8], &[u8]); 1] = [(b"x-long", &enorme)];
    let mut out = std::vec![0_u8; START_OCTETS_MAX];
    assert_eq!(
        client
            .start(
                &Request {
                    fields: &champs,
                    ..REQUETE
                },
                &mut out
            )
            .expect_err("trop long")
            .cause(),
        Cause::ResponseHeadTooLong
    );
    // Les acquittements et le corps doivent tenir dans `out`.
    let (mut client, _) = demarrer(&REQUETE);
    let mut petit = [0_u8; 4];
    let mut reponse = [0_u8; 4];
    assert_eq!(
        client
            .receive(&reglages(), REQUETE.body, &mut petit, &mut reponse)
            .expect_err("trop court")
            .cause(),
        Cause::BufferTooSmall
    );
}

/// Le remplissage, les réglages et les blocs démesurés sont des fautes ; un
/// tampon de sortie qui n'a de place que pour l'acquittement aussi.
#[test]
fn les_demesures_du_serveur_se_refusent() {
    let entame = |octets: Vec<u8>| {
        let (mut client, _) = demarrer(&REQUETE);
        let mut tout = reglages();
        tout.extend(octets);
        cause(jouer(&mut client, &tout, REQUETE.body))
    };
    // Un remplissage plus long que la charge.
    assert_eq!(
        entame(cadre(FrameKind::Data, 0x8, 1, &[9, 0])),
        Cause::PaddingTooLong
    );
    assert_eq!(
        entame(cadre(FrameKind::Headers, 0xC, 1, &[9, 0])),
        Cause::PaddingTooLong
    );
    // Un bloc HPACK illisible : l'index zéro n'existe pas.
    assert_eq!(
        entame(cadre(FrameKind::Headers, 4, 1, &[0x80])),
        Cause::BadIndex
    );
    // Une réponse informative ne ferme pas le flux : il n'y a pas eu de
    // réponse.
    assert_eq!(
        entame(cadre(FrameKind::Headers, 5, 1, &tete(Some(100), &[]))),
        Cause::NoStatus
    );
    // Un réglage hors de ses bornes.
    let (mut client, _) = demarrer(&REQUETE);
    assert_eq!(
        cause(jouer(
            &mut client,
            &cadre(FrameKind::Settings, 0, 0, &[0, 2, 0, 0, 0, 2]),
            b""
        )),
        Cause::SettingValueOutOfRange
    );
    // Un bloc d'en-tête qui n'en finit pas.
    let mut sans_fin = cadre(FrameKind::Headers, 0, 1, &tete(Some(200), &[]));
    for _ in 0..=crate::block::CONTINUATIONS_MAX {
        sans_fin.extend(cadre(FrameKind::Continuation, 0, 1, &[0x88]));
    }
    assert_eq!(entame(sans_fin), Cause::BlockTooLong);
    // De la place pour l'acquittement, pas pour le corps.
    let (mut client, _) = demarrer(&REQUETE);
    let mut juste = [0_u8; FRAME_HEADER_OCTETS];
    let mut reponse = [0_u8; 4];
    assert_eq!(
        client
            .receive(&reglages(), REQUETE.body, &mut juste, &mut reponse)
            .expect_err("trop court")
            .cause(),
        Cause::BufferTooSmall
    );
}

/// Les fautes nouvelles du client se disent, comme les autres.
#[test]
fn les_fautes_du_client_se_lisent() {
    use std::string::ToString as _;
    for (cause, mot) in [
        (Cause::RequestBodyTooLarge, "fenêtre"),
        (Cause::ResponseBodyTooLong, "réponse"),
        (Cause::StreamReset, "réinitialisé"),
        (Cause::Refused, "GOAWAY"),
        (Cause::NoStatus, ":status"),
    ] {
        let dit = crate::Error::connection(crate::ErrorCode::ProtocolError, cause).to_string();
        assert!(dit.contains(mot), "{dit}");
    }
}
