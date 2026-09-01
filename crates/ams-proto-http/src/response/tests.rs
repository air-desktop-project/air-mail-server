//! Ce qu'une réponse doit dire, et ce qu'on refuse d'y lire.

use super::{Body, parse_response};
use crate::{Error, StatusCode};

/// La borne de tête que l'appelant impose.
const TETE_MAX: usize = 4096;

fn lire(octets: &[u8]) -> Result<Option<super::ResponseHead>, Error> {
    parse_response(octets, TETE_MAX)
}

#[test]
fn une_reponse_ordinaire_se_lit() {
    let brut = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 42\r\n\r\n";
    let tete = lire(brut).expect("lisible").expect("entière");
    assert_eq!(tete.status(), StatusCode::OK);
    assert_eq!(tete.body(), Body::Length(42));
    assert_eq!(tete.length(), brut.len());
}

/// **UNE TÊTE INCOMPLÈTE N'EST PAS UNE ERREUR.**
///
/// Distinguer « pas encore » d'un refus est ce qui permet de lire un flux
/// morceau par morceau sans deviner combien il en reste.
#[test]
fn une_tete_incomplete_demande_a_lire_davantage() {
    let brut = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
    for combien in 0..brut.len() {
        let morceau = brut.get(..combien).expect("tranche");
        assert_eq!(lire(morceau), Ok(None), "à {combien} octets");
    }
    assert!(lire(brut).expect("lisible").is_some());
}

/// **UNE TÊTE QUI NE FINIT PAS SE REFUSE**, et non un tampon qu'on agrandit.
#[test]
fn une_tete_demesuree_est_refusee() {
    let mut brut = std::vec::Vec::from(&b"HTTP/1.1 200 OK\r\n"[..]);
    while brut.len() < TETE_MAX {
        brut.extend_from_slice(b"X-Remplissage: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    assert_eq!(lire(&brut), Err(Error::FieldTooLong));
}

#[test]
fn les_trois_delimitations_du_corps_se_distinguent() {
    // §6 de RFC 9112.
    let longueur = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n";
    assert_eq!(
        lire(longueur).expect("lisible").expect("entière").body(),
        Body::Length(7)
    );

    let decoupe = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        lire(decoupe).expect("lisible").expect("entière").body(),
        Body::Chunked
    );

    let jusqu_a_la_fin = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
    assert_eq!(
        lire(jusqu_a_la_fin)
            .expect("lisible")
            .expect("entière")
            .body(),
        Body::UntilClose
    );
}

/// **LES DEUX À LA FOIS, C'EST LA CONTREBANDE** (§11.2 de RFC 9112).
///
/// Un message qui porte `Content-Length` ET `Transfer-Encoding` se découpe
/// différemment selon qui le lit — et c'est ainsi qu'on fait passer un second
/// message à travers un intermédiaire.
#[test]
fn content_length_et_transfer_encoding_ensemble_sont_refuses() {
    for brut in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 7\r\n\r\n",
    ] {
        assert_eq!(lire(brut), Err(Error::MalformedContentLength));
    }
}

/// **DEUX `Content-Length` QUI DIFFÈRENT SE LISENT DE DEUX FAÇONS.**
#[test]
fn deux_longueurs_contradictoires_sont_refusees() {
    let brut = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Length: 9\r\n\r\n";
    assert_eq!(lire(brut), Err(Error::MalformedContentLength));
    // Deux fois la MÊME, en revanche, ne dit rien de contradictoire.
    let brut = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Length: 7\r\n\r\n";
    assert_eq!(
        lire(brut).expect("lisible").expect("entière").body(),
        Body::Length(7)
    );
}

#[test]
fn une_longueur_illisible_est_refusee() {
    for valeur in [
        "",
        " ",
        "-1",
        "sept",
        "7a",
        "0x7",
        // Une multiplication qui déborde…
        "99999999999999999999999999",
        // …et une ADDITION qui déborde : `u64::MAX` plus un, tout juste.
        "18446744073709551616",
    ] {
        let brut = std::format!("HTTP/1.1 200 OK\r\nContent-Length: {valeur}\r\n\r\n");
        assert_eq!(
            lire(brut.as_bytes()),
            Err(Error::MalformedContentLength),
            "« {valeur} »"
        );
    }
}

/// **ON NE CONNAÎT QUE `chunked`.** Un codage qu'on ne sait pas défaire rendrait
/// un corps qu'on lirait de travers.
#[test]
fn un_codage_de_transfert_inconnu_est_refuse() {
    for valeur in ["gzip", "chunked, gzip", "gzip, chunked", "identity", ""] {
        let brut = std::format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {valeur}\r\n\r\n");
        assert_eq!(
            lire(brut.as_bytes()),
            Err(Error::MalformedContentLength),
            "« {valeur} »"
        );
    }
    // La casse, elle, ne compte pas (§5.1 de RFC 9110).
    let brut = b"HTTP/1.1 200 OK\r\nTRANSFER-ENCODING: Chunked\r\n\r\n";
    assert_eq!(
        lire(brut).expect("lisible").expect("entière").body(),
        Body::Chunked
    );
}

/// **UNE CONTINUATION N'EST PLUS DU HTTP** (§5.2 de RFC 9112).
///
/// Un message qui en porte se lit différemment selon l'implémentation, et c'est
/// ainsi qu'on fait passer un second message.
#[test]
fn une_ligne_de_continuation_est_refusee() {
    for brut in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n suite\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\tsuite\r\n\r\n",
    ] {
        assert_eq!(lire(brut), Err(Error::MalformedFieldName));
    }
}

/// **PAS D'ESPACE AVANT LE DEUX-POINTS** (§5.1 de RFC 9112).
#[test]
fn un_nom_de_champ_mal_forme_est_refuse() {
    for brut in [
        &b"HTTP/1.1 200 OK\r\nFoo : bar\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\nFoo\t: bar\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n: bar\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nsans-deux-points\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nFo\x00o: bar\r\n\r\n",
    ] {
        assert_eq!(lire(brut), Err(Error::MalformedFieldName), "{brut:?}");
    }
}

#[test]
fn une_valeur_de_champ_illisible_est_refusee() {
    let brut = b"HTTP/1.1 200 OK\r\nFoo: ba\x00r\r\n\r\n";
    assert_eq!(lire(brut), Err(Error::MalformedFieldValue));
}

/// La valeur se rogne de ses blancs, des deux côtés (§5.1 de RFC 9112).
#[test]
fn la_valeur_se_rogne_de_ses_blancs() {
    let brut = b"HTTP/1.1 200 OK\r\nContent-Length: \t 42 \t \r\n\r\n";
    assert_eq!(
        lire(brut).expect("lisible").expect("entière").body(),
        Body::Length(42)
    );
    // Et une valeur entièrement blanche est vide, donc illisible en longueur.
    let brut = b"HTTP/1.1 200 OK\r\nContent-Length:   \r\n\r\n";
    assert_eq!(lire(brut), Err(Error::MalformedContentLength));
}

/// **HTTP/1.0 ET HTTP/1.1 SEULEMENT.**
#[test]
fn une_ligne_d_etat_qui_n_en_est_pas_une_est_refusee() {
    for brut in [
        &b"HTTP/2 200 OK\r\n\r\n"[..],
        b"HTTP/1.1200 OK\r\n\r\n",
        b"HTTP/1.1 20 OK\r\n\r\n",
        // Un code tronqué : il n'y a même pas trois chiffres à lire.
        b"HTTP/1.1 20\r\n\r\n",
        b"HTTP/1.1 \r\n\r\n",
        b"HTTP/1.1 2000 OK\r\n\r\n",
        b"HTTP/1.1 abc OK\r\n\r\n",
        b"HTTP/1.1 099 OK\r\n\r\n",
        b"HTTP/1.1 600 OK\r\n\r\n",
        b"200 OK\r\n\r\n",
        b"\r\n\r\n",
    ] {
        assert!(lire(brut).is_err(), "{brut:?} aurait dû être refusé");
    }
    // Sans raison, en revanche, c'est licite.
    let brut = b"HTTP/1.1 204\r\n\r\n";
    assert_eq!(
        lire(brut).expect("lisible").expect("entière").status(),
        StatusCode::NO_CONTENT
    );
    // Et HTTP/1.0 aussi.
    let brut = b"HTTP/1.0 200 OK\r\n\r\n";
    assert_eq!(
        lire(brut).expect("lisible").expect("entière").status(),
        StatusCode::OK
    );
}

#[test]
fn une_ligne_d_etat_demesuree_est_refusee() {
    let mut brut = std::vec::Vec::from(&b"HTTP/1.1 200 "[..]);
    brut.extend(std::iter::repeat_n(b'a', 200));
    brut.extend_from_slice(b"\r\n\r\n");
    assert_eq!(lire(&brut), Err(Error::FieldTooLong));
}

/// **UN `LF` ISOLÉ NE TERMINE PAS UNE LIGNE ICI.**
///
/// Le laisser passer ferait lire deux messages là où il y en a un — c'est la
/// même faille que la contrebande SMTP, dans un autre protocole.
#[test]
fn un_lf_isole_ne_termine_pas_une_ligne() {
    // La tête ne finit que sur `\r\n\r\n` : un `\n\n` ne la clôt pas.
    let brut = b"HTTP/1.1 200 OK\nContent-Length: 7\n\n";
    assert_eq!(lire(brut), Ok(None), "un LF isolé a clos la tête");
    // Et une ligne qui n'est terminée que par un `LF` est REFUSÉE : la laisser
    // passer ferait lire deux champs là où un autre lecteur en verrait un.
    let brut = b"HTTP/1.1 200 OK\r\nFoo: bar\nBaz: qux\r\n\r\n";
    assert_eq!(lire(brut), Err(Error::MalformedFieldName));
    // Y compris dans la ligne d'état.
    let brut = b"HTTP/1.1 200 OK\nFoo: bar\r\n\r\n";
    assert_eq!(lire(brut), Err(Error::MalformedFieldName));
    // Et un `CR` isolé au milieu d'une valeur non plus.
    let brut = b"HTTP/1.1 200 OK\r\nFoo: ba\rr\r\n\r\n";
    assert_eq!(lire(brut), Err(Error::MalformedFieldName));
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let brut = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n";
    let tete = lire(brut).expect("lisible").expect("entière");
    let copie = tete;
    assert_eq!(copie, tete);
    assert!(!std::format!("{tete:?}").is_empty());
    assert!(!std::format!("{:?}", Body::Chunked).is_empty());
    assert_ne!(Body::Chunked, Body::UntilClose);
    assert_ne!(Body::Length(1), Body::Length(2));
}
