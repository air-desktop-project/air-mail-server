//! Ce qu'une réponse a le droit de dire.

use super::{REPLY_LINES_MAX, Reply, reply_len};
use crate::{Error, Limits};

/// Les bornes ordinaires.
const BORNES: Limits = Limits::DEFAULT;

#[test]
fn une_reponse_d_une_ligne_se_lit() {
    let octets = b"220 mail.example.com ESMTP\r\n";
    assert_eq!(reply_len(octets, &BORNES), Ok(Some(octets.len())));
    let reponse = Reply::parse(octets, &BORNES).expect("lisible");
    assert_eq!(reponse.code().value(), 220);
    let lignes: std::vec::Vec<&[u8]> = reponse.lines().collect();
    assert_eq!(lignes, std::vec![&b"mail.example.com ESMTP"[..]]);
}

/// La RFC 5321 §4.2 admet trois chiffres et rien d'autre, et bien des serveurs
/// l'écrivent.
#[test]
fn un_code_sans_texte_se_lit() {
    let octets = b"250\r\n";
    let reponse = Reply::parse(octets, &BORNES).expect("lisible");
    assert_eq!(reponse.code().value(), 250);
    assert_eq!(
        reponse.lines().collect::<std::vec::Vec<_>>(),
        std::vec![&b""[..]]
    );
}

#[test]
fn le_tiret_annonce_une_ligne_de_plus() {
    let octets = b"250-mail.example.com\r\n250-STARTTLS\r\n250 SIZE 10485760\r\n";
    assert_eq!(reply_len(octets, &BORNES), Ok(Some(octets.len())));
    let reponse = Reply::parse(octets, &BORNES).expect("lisible");
    assert_eq!(reponse.code().value(), 250);
    assert_eq!(reponse.lines().count(), 3);
    assert!(reponse.offers(b"STARTTLS"));
    // §4.1.1.1 : le mot-clé ignore la casse.
    assert!(reponse.offers(b"starttls"));
    assert!(!reponse.offers(b"AUTH"));
    assert_eq!(reponse.parameter(b"SIZE"), Some(&b"10485760"[..]));
    assert_eq!(reponse.parameter(b"AUTH"), None);
    // Un mot-clé sans paramètre rend le vide, et non l'absence.
    assert_eq!(reponse.parameter(b"STARTTLS"), Some(&b""[..]));
}

#[test]
fn tant_qu_il_en_manque_on_le_dit() {
    for partiel in [
        &b""[..],
        b"2",
        b"220",
        b"220 mail.example.com",
        b"220 mail.example.com\r",
        b"250-un\r\n",
        b"250-un\r\n250-deux\r\n",
    ] {
        assert_eq!(reply_len(partiel, &BORNES), Ok(None), "{partiel:?}");
    }
}

/// La longueur rendue est celle du bloc, **pas celle du tampon** : ce qui suit
/// appartient à la réponse d'après.
#[test]
fn ce_qui_suit_le_bloc_n_en_fait_pas_partie() {
    let octets = b"220 pret\r\n250 ok\r\n";
    assert_eq!(reply_len(octets, &BORNES), Ok(Some(10)));
    assert_eq!(
        Reply::parse(octets, &BORNES),
        Err(Error::MalformedReply),
        "un bloc suivi d'un autre n'est pas un bloc"
    );
    let bloc = Reply::parse(&octets[..10], &BORNES).expect("lisible");
    assert_eq!(bloc.code().value(), 220);
}

// ── CES OCTETS VIENNENT D'UN SERVEUR QU'ON A CHOISI DE CROIRE ───────────────

/// **§4.2.1 : toutes les lignes portent le même code.** Un bloc qui en change
/// en route se lit différemment selon l'implémentation — la première ligne pour
/// les uns, la dernière pour les autres — et c'est la matière d'une contrebande.
#[test]
fn un_code_qui_change_en_route_fait_ecarter_le_bloc() {
    let octets = b"250-mail.example.com\r\n550 non\r\n";
    // Le bloc n'est même pas DÉLIMITÉ : refuser à la lecture plutôt qu'à
    // l'interprétation évite qu'un appelant en consomme la première moitié.
    assert_eq!(reply_len(octets, &BORNES), Err(Error::MalformedReply));
    assert_eq!(Reply::parse(octets, &BORNES), Err(Error::MalformedReply));
}

#[test]
fn ce_qui_n_est_pas_une_reponse_est_ecarte() {
    for mechant in [
        &b"2x0 non\r\n"[..],
        b"abc\r\n",
        b"25\r\n",
        b"250x non\r\n",
        b"250\tnon\r\n",
        // `1yz` : la RFC le définit et dit que SMTP n'en émet aucun. En
        // accepter un laisserait attendre une seconde réponse qui ne viendrait
        // jamais.
        b"120 patientez\r\n",
        b"600 au-dela\r\n",
        b"000 en-deca\r\n",
    ] {
        assert_eq!(
            reply_len(mechant, &BORNES),
            Err(Error::MalformedReply),
            "{mechant:?}"
        );
        assert_eq!(
            Reply::parse(mechant, &BORNES),
            Err(Error::MalformedReply),
            "{mechant:?}"
        );
    }
}

/// **Rien ne dit que la suite viendra.** Un pair muet ferait croître le tampon
/// de son correspondant jusqu'à ce que celui-ci cède.
#[test]
fn une_ligne_qui_ne_finit_pas_est_bornee() {
    let mut trop = std::vec::Vec::from(&b"250 "[..]);
    trop.resize(BORNES.max_reply_octets + 2, b'x');
    assert_eq!(
        reply_len(&trop, &BORNES),
        Err(Error::LineTooLong {
            limit: BORNES.max_reply_octets
        })
    );
    // La même ligne terminée est refusée pour la même raison.
    trop.extend_from_slice(b"\r\n");
    assert_eq!(
        reply_len(&trop, &BORNES),
        Err(Error::LineTooLong {
            limit: BORNES.max_reply_octets
        })
    );
}

/// Une réponse de trois cent mille lignes serait bien formée, et coûterait
/// tout autant.
#[test]
fn le_nombre_de_lignes_est_borne() {
    let mut bavard = std::vec::Vec::new();
    for _ in 0..=REPLY_LINES_MAX {
        bavard.extend_from_slice(b"250-encore\r\n");
    }
    bavard.extend_from_slice(b"250 fini\r\n");
    assert_eq!(
        reply_len(&bavard, &BORNES),
        Err(Error::TooManyReplyLines {
            limit: REPLY_LINES_MAX
        })
    );
    assert_eq!(
        Reply::parse(&bavard, &BORNES),
        Err(Error::TooManyReplyLines {
            limit: REPLY_LINES_MAX
        })
    );

    // La borne elle-même passe.
    let mut juste = std::vec::Vec::new();
    for _ in 0..REPLY_LINES_MAX - 1 {
        juste.extend_from_slice(b"250-encore\r\n");
    }
    juste.extend_from_slice(b"250 fini\r\n");
    assert_eq!(reply_len(&juste, &BORNES), Ok(Some(juste.len())));
    assert_eq!(
        Reply::parse(&juste, &BORNES)
            .expect("lisible")
            .lines()
            .count(),
        REPLY_LINES_MAX
    );
}

/// **Trouvé par le fuzzer.** `250 a\nb\r\n` passait : ce qui suivait le saut de
/// ligne était du texte pour nous, et une ligne pour tout ce qui lirait ce texte
/// ensuite — un journal, un rapport, un message de non-remise. C'est la
/// contrebande SMTP prise par l'autre bout.
#[test]
fn c_est_ici_que_la_contrebande_par_la_reponse_s_arrete() {
    for mechante in [
        &b"250 a\nb\r\n"[..],
        b"250 a\rb\r\n",
        b"250-a\nb\r\n250 fini\r\n",
        b"250 a\0b\r\n",
        b"250 a\x7fb\r\n",
    ] {
        assert_eq!(
            reply_len(mechante, &BORNES),
            Err(Error::ReplyTextNotPrintable),
            "{mechante:?}"
        );
        assert_eq!(
            Reply::parse(mechante, &BORNES),
            Err(Error::ReplyTextNotPrintable),
            "{mechante:?}"
        );
    }
}

/// Les octets HAUTS passent : des serveurs en émettent dans leur bannière, et
/// refuser une remise pour un accent coûterait du courrier sans rien protéger.
/// La tabulation aussi — la RFC 5321 §4.2 la prévoit.
#[test]
fn un_accent_dans_une_banniere_ne_fait_pas_echouer_une_remise() {
    let octets = b"220 mail.example.com pr\xc3\xaat\ta servir\r\n";
    let reponse = Reply::parse(octets, &BORNES).expect("lisible");
    assert_eq!(reponse.code().value(), 220);
}

#[test]
fn ce_qui_se_lit_se_montre() {
    let octets = b"250 ok\r\n";
    let reponse = Reply::parse(octets, &BORNES).expect("lisible");
    assert!(!std::format!("{reponse:?}").is_empty());
    assert!(!std::format!("{:?}", reponse.lines()).is_empty());
    assert!(!std::format!("{:?}", reponse.lines().clone()).is_empty());
    let copie = reponse;
    assert_eq!(copie.code(), reponse.code());
    for erreur in [
        Error::MalformedReply,
        Error::TooManyReplyLines { limit: 64 },
    ] {
        assert!(!std::format!("{erreur}").is_empty());
    }
}
