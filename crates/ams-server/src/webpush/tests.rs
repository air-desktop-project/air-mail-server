//! Ce que l'envoyeur Web Push prépare, et ce qu'il comprend des réponses.

use super::{Envoi, chiffrer_et_signer, preparer, verdict};

/// Un abonnement dont on tient la moitié privée du navigateur : c'est ce qui
/// permet de relire le message, comme le navigateur le ferait.
fn abonnement(ua_prive: &[u8; 32]) -> ams_config::Push {
    let ua_public = ams_push::vapid_public_key(ua_prive).expect("une clef");
    ams_config::Push::new(
        ams_config::PushChannel::WebPush,
        String::from("https://push.example.com:443/wpush/v2/abc"),
        ua_public.to_vec(),
        std::vec![5; 16],
        1,
    )
    .expect("recevable")
}

/// **LE NAVIGATEUR RELIT CE QUI PART** : le message se déchiffre avec sa
/// clef, et ne dit que la boîte.
#[test]
fn le_navigateur_relit_le_reveil() {
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;
    let ua_prive = [3_u8; 32];
    let push = abonnement(&ua_prive);
    let requete = chiffrer_et_signer(
        &push,
        "support",
        &[9; 32],
        "mailto:postmaster@narro.ch",
        1_790_000_000,
        &[7; 32],
        &[1; 16],
    )
    .expect("préparé");
    // Côté navigateur (RFC 8291 §3.4), à l'envers.
    let corps = &requete.corps;
    let (entete, chiffre) = corps.split_at(ams_push::HEADER_OCTETS);
    let sel = &entete[..16];
    let as_public = &entete[21..];
    let secret = p256::SecretKey::from_slice(&ua_prive).expect("clef");
    let serveur = p256::PublicKey::from_sec1_bytes(as_public).expect("point");
    let partage = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), serveur.as_affine());
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(push.key());
    info.extend_from_slice(as_public);
    let mut ikm = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(push.auth()), partage.raw_secret_bytes())
        .expand(&info, &mut ikm)
        .expect("expansible");
    let prk = Hkdf::<Sha256>::new(Some(sel), &ikm);
    let (mut cek, mut nonce) = ([0_u8; 16], [0_u8; 12]);
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .expect("clef");
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .expect("nonce");
    let (texte, etiquette) = chiffre.split_at(chiffre.len() - 16);
    let mut clair = texte.to_vec();
    Aes128Gcm::new(&cek.into())
        .decrypt_inout_detached(
            &nonce.into(),
            &[],
            clair.as_mut_slice().into(),
            etiquette.try_into().expect("seize octets"),
        )
        .expect("authentique");
    assert_eq!(
        clair,
        br#"{"account":"support"}"#.iter().copied().chain([2]).collect::<Vec<_>>()
    );
    // L'audience est l'ORIGINE, port par défaut ôté.
    let vapid = String::from_utf8(requete.vapid).expect("ASCII");
    let jeton = vapid
        .strip_prefix("vapid t=")
        .expect("§3")
        .split(", k=")
        .next()
        .expect("t");
    let revendications = jeton.split('.').nth(1).expect("trois morceaux");
    let mut decode = vec![0_u8; 256];
    let lu = ams_api::decode_base64url(revendications.as_bytes(), &mut decode).expect("base64url");
    let texte = String::from_utf8(lu.to_vec()).expect("UTF-8");
    assert!(
        texte.contains(r#""aud":"https://push.example.com""#),
        "{texte}"
    );
    assert!(texte.contains(r#""exp":1790043200"#), "{texte}");
}

/// Deux envois ne partagent ni clef éphémère ni sel.
#[test]
fn deux_envois_ne_se_ressemblent_pas() {
    let push = abonnement(&[3; 32]);
    let un = preparer(&push, "marie", &[9; 32], "mailto:x@y", 1).expect("préparé");
    let deux = preparer(&push, "marie", &[9; 32], "mailto:x@y", 1).expect("préparé");
    assert_ne!(
        un.corps[..ams_push::HEADER_OCTETS],
        deux.corps[..ams_push::HEADER_OCTETS]
    );
}

/// Ce qui ne se prépare pas se dit par `None`.
#[test]
fn ce_qui_ne_se_prepare_pas() {
    let apns = ams_config::Push::new(
        ams_config::PushChannel::Apns,
        "ab".repeat(32),
        Vec::new(),
        Vec::new(),
        1,
    )
    .expect("recevable");
    assert!(
        chiffrer_et_signer(&apns, "m", &[9; 32], "mailto:x@y", 1, &[7; 32], &[1; 16]).is_none()
    );
    let push = abonnement(&[3; 32]);
    // Une clef VAPID nulle, un contact hors forme, un aléa qui n'est pas un
    // scalaire.
    assert!(
        chiffrer_et_signer(&push, "m", &[0; 32], "mailto:x@y", 1, &[7; 32], &[1; 16]).is_none()
    );
    assert!(chiffrer_et_signer(&push, "m", &[9; 32], "tel:1", 1, &[7; 32], &[1; 16]).is_none());
    assert!(
        chiffrer_et_signer(&push, "m", &[9; 32], "mailto:x@y", 1, &[0; 32], &[1; 16]).is_none()
    );
}

/// §5 de RFC 8030 : un succès, un abonnement parti, un refus.
#[test]
fn le_statut_dit_ce_qu_est_devenu_l_envoi() {
    for (statut, envoi) in [
        (201, Envoi::Transmis),
        (202, Envoi::Transmis),
        (404, Envoi::Perime),
        (410, Envoi::Perime),
        (400, Envoi::Echec),
        (413, Envoi::Echec),
        (429, Envoi::Echec),
        (503, Envoi::Echec),
    ] {
        assert_eq!(verdict(statut), envoi, "{statut}");
    }
}
