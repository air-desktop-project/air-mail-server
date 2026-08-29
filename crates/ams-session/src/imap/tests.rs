//! Ce qu'une session IMAP dit, et ce qu'elle refuse.

use ams_proto_imap::Limits;
use ams_sasl::Credentials;

use super::{Action, Session, State, TAG_MAX_OCTETS};
use crate::Authenticator;

const BORNES: Limits = Limits::DEFAULT;

/// Le seul compte que la politique de test connaisse.
#[derive(Debug, Clone)]
struct UnCompte;

impl Authenticator for UnCompte {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        credentials.authentication_identity == b"jean" && credentials.password == b"ouvre-toi"
    }
}

/// Une session, chiffrée ou non.
fn nouvelle(chiffree: bool) -> Session<UnCompte> {
    let mut session = Session::new(BORNES, true, UnCompte);
    if chiffree {
        session.on_tls_established();
    }
    session
}

/// Traite une commande et rend la réponse en clair.
fn dire(session: &mut Session<UnCompte>, commande: &[u8]) -> (std::string::String, Action) {
    let mut sortie = [0_u8; 1024];
    let tour = session.handle(commande, &mut sortie).expect("traitable");
    (
        std::string::String::from_utf8_lossy(tour.reply()).into_owned(),
        tour.action(),
    )
}

// ── LA BANNIÈRE ET LES CAPACITÉS ────────────────────────────────────────────

#[test]
fn la_banniere_annonce_ce_qu_on_sait_faire() {
    let mut sortie = [0_u8; 256];
    let banniere = nouvelle(false).greeting(&mut sortie).expect("composable");
    let texte = std::string::String::from_utf8_lossy(banniere).into_owned();
    assert!(texte.starts_with("* OK [CAPABILITY IMAP4rev2 LITERAL- STARTTLS LOGINDISABLED]"));
    assert!(texte.ends_with("service ready\r\n"), "{texte}");
}

/// **§6.2.3 : tant que la connexion n'est pas protégée, on l'annonce.** Et une
/// fois protégée, c'est `AUTH=PLAIN` qui apparaît.
#[test]
fn les_capacites_suivent_le_chiffrement() {
    let (clair, _) = dire(&mut nouvelle(false), b"a001 CAPABILITY\r\n");
    assert!(clair.contains("LOGINDISABLED"), "{clair}");
    assert!(clair.contains("STARTTLS"), "{clair}");
    assert!(!clair.contains("AUTH=PLAIN"), "{clair}");

    let (chiffre, _) = dire(&mut nouvelle(true), b"a001 CAPABILITY\r\n");
    assert!(chiffre.contains("AUTH=PLAIN"), "{chiffre}");
    assert!(!chiffre.contains("LOGINDISABLED"), "{chiffre}");
    assert!(!chiffre.contains("STARTTLS"), "{chiffre}");
    // Une réponse non sollicitée, puis la conclusion.
    assert!(chiffre.starts_with("* CAPABILITY "), "{chiffre}");
    assert!(
        chiffre.ends_with("a001 OK CAPABILITY completed\r\n"),
        "{chiffre}"
    );
}

/// **Annoncer `STARTTLS` sans savoir le faire ferait mentir la bannière.**
#[test]
fn sans_materiel_starttls_n_est_pas_annonce() {
    let mut session = Session::new(BORNES, false, UnCompte);
    let (texte, _) = dire(&mut session, b"a001 CAPABILITY\r\n");
    assert!(!texte.contains("STARTTLS"), "{texte}");
    let (refus, action) = dire(&mut session, b"a002 STARTTLS\r\n");
    assert!(
        refus.starts_with("a002 NO STARTTLS is not available"),
        "{refus}"
    );
    assert_eq!(action, Action::Continue);
}

// ── LE CHIFFREMENT ──────────────────────────────────────────────────────────

/// **Ce qui a été dit en clair a pu être dit par quelqu'un d'autre** : après la
/// poignée de main, tout ce qui précède est oublié (§6.2.1).
#[test]
fn starttls_efface_tout_ce_qui_precede() {
    let mut session = nouvelle(false);
    let (reponse, action) = dire(&mut session, b"a001 STARTTLS\r\n");
    assert!(
        reponse.starts_with("a001 OK Begin TLS negotiation now"),
        "{reponse}"
    );
    assert_eq!(action, Action::StartTls);

    session.on_tls_established();
    assert!(session.is_encrypted());
    assert_eq!(session.state(), State::NotAuthenticated);
    assert!(session.user().is_empty());

    // Et on ne monte pas deux fois.
    let (refus, _) = dire(&mut session, b"a002 STARTTLS\r\n");
    assert!(
        refus.starts_with("a002 BAD TLS is already active"),
        "{refus}"
    );
}

// ── UN MOT DE PASSE NE TRAVERSE PAS UNE CONNEXION EN CLAIR ──────────────────

/// **Annoncer sans refuser laisserait un client mal écrit envoyer le mot de
/// passe quand même**, et l'annonce n'aurait servi qu'à se donner bonne
/// conscience.
#[test]
fn c_est_ici_que_le_mot_de_passe_en_clair_est_refuse() {
    let mut session = nouvelle(false);
    let (refus, _) = dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    assert!(
        refus.starts_with("a001 NO [PRIVACYREQUIRED] Encryption required before LOGIN"),
        "{refus}"
    );
    assert_eq!(session.state(), State::NotAuthenticated);

    // `AUTHENTICATE PLAIN` fait la même chose en base64, qui n'est pas un
    // chiffrement : même refus.
    let (refus, _) = dire(&mut session, b"a002 AUTHENTICATE PLAIN\r\n");
    assert!(
        refus.starts_with("a002 NO [PRIVACYREQUIRED] Encryption required before AUTHENTICATE"),
        "{refus}"
    );
}

#[test]
fn un_login_juste_authentifie() {
    let mut session = nouvelle(true);
    let (reponse, action) = dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    assert!(reponse.starts_with("a001 OK Authenticated"), "{reponse}");
    assert_eq!(action, Action::Continue);
    assert_eq!(session.state(), State::Authenticated);
    assert_eq!(session.user(), b"jean");
}

/// Les trois écritures d'un argument valent la même chose.
#[test]
fn un_login_se_lit_sous_ses_trois_ecritures() {
    for commande in [
        &b"a001 LOGIN jean ouvre-toi\r\n"[..],
        b"a001 LOGIN \"jean\" \"ouvre-toi\"\r\n",
        b"a001 LOGIN {4+}\r\njean {9+}\r\nouvre-toi\r\n",
    ] {
        let mut session = nouvelle(true);
        let (reponse, _) = dire(&mut session, commande);
        assert!(
            reponse.contains("OK Authenticated"),
            "{commande:?} : {reponse}"
        );
    }
}

/// **Le refus ne dit pas ce qui a manqué** : « utilisateur inconnu » et « mot de
/// passe faux » sont deux réponses différentes, et cette différence est un
/// annuaire pour qui la mesure.
#[test]
fn un_login_faux_est_refuse_sans_rien_dire() {
    let mut sortie = [0_u8; 512];
    for commande in [
        &b"a001 LOGIN jean mauvais\r\n"[..],
        b"a001 LOGIN inconnu ouvre-toi\r\n",
    ] {
        let mut session = nouvelle(true);
        let tour = session.handle(commande, &mut sortie).expect("traitable");
        let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
        assert!(
            texte.starts_with("a001 NO [AUTHENTICATIONFAILED] Authentication credentials invalid"),
            "{texte}"
        );
        // Compté comme une faute : mille essais par minute, c'est ce qu'un
        // garde doit voir passer.
        assert!(tour.peer_fault(), "{commande:?}");
        assert_eq!(session.state(), State::NotAuthenticated);
    }
}

#[test]
fn un_login_mal_forme_est_une_faute_de_syntaxe() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a001 LOGIN jean\r\n"[..],
        b"a001 LOGIN\r\n",
        b"a001 LOGIN jean ouvre-toi de trop\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD LOGIN expects"),
            "{commande:?} : {texte}"
        );
    }
}

// ── SASL ────────────────────────────────────────────────────────────────────

#[test]
fn authenticate_plain_en_deux_temps() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    let tour = session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(tour.reply(), b"+ \r\n");
    assert_eq!(tour.action(), Action::ReadAuthResponse);

    // base64 de "\0jean\0ouvre-toi"
    let tour = session
        .on_auth_response(b"AGplYW4Ab3V2cmUtdG9p", &mut sortie)
        .expect("traitable");
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(texte.starts_with("a001 OK Authenticated"), "{texte}");
    assert_eq!(session.state(), State::Authenticated);
    assert_eq!(session.user(), b"jean");
}

/// RFC 4959 : la réponse initiale évite un aller-retour.
#[test]
fn authenticate_plain_avec_reponse_initiale() {
    let mut session = nouvelle(true);
    let (texte, action) = dire(
        &mut session,
        b"a001 AUTHENTICATE PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
    );
    assert!(texte.starts_with("a001 OK Authenticated"), "{texte}");
    assert_eq!(action, Action::Continue);
    assert_eq!(session.user(), b"jean");
}

/// **Un client qui se ravise n'est pas un client fautif** : le lui reprocher
/// gonflerait un compteur qui doit rester celui des vraies fautes.
#[test]
fn un_echange_annule_n_est_pas_une_faute_d_authentification() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    let tour = session
        .on_auth_response(b"*", &mut sortie)
        .expect("traitable");
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(
        texte.starts_with("a001 BAD Authentication cancelled"),
        "{texte}"
    );
    assert_eq!(session.state(), State::NotAuthenticated);
}

#[test]
fn une_reponse_sasl_hors_echange_est_refusee() {
    let mut sortie = [0_u8; 512];
    assert_eq!(
        nouvelle(true).on_auth_response(b"AGplYW4=", &mut sortie),
        Err(super::Error::NotInAuthExchange)
    );
}

#[test]
fn une_commande_pendant_un_echange_sasl_est_refusee() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(
        session.handle(b"a002 NOOP\r\n", &mut sortie),
        Err(super::Error::NotInCommandPhase)
    );
}

#[test]
fn un_mecanisme_inconnu_est_refuse_sans_etre_une_faute() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 AUTHENTICATE GSSAPI\r\n");
    assert!(
        texte.starts_with("a001 NO Unsupported authentication mechanism"),
        "{texte}"
    );
}

#[test]
fn un_authenticate_mal_forme_est_une_faute() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a001 AUTHENTICATE\r\n"[..],
        b"a001 AUTHENTICATE PLAIN aaa bbb\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains("BAD AUTHENTICATE"), "{commande:?} : {texte}");
    }
}

#[test]
fn une_reponse_sasl_illisible_est_refusee() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    let tour = session
        .on_auth_response(b"pas du base64 !", &mut sortie)
        .expect("traitable");
    assert!(tour.peer_fault());
    // Et une base64 correcte qui ne porte pas du `PLAIN`.
    let mut autre = nouvelle(true);
    autre
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    let tour = autre
        .on_auth_response(b"YWJj", &mut sortie)
        .expect("traitable");
    assert!(tour.peer_fault());
}

// ── LES ÉTATS ───────────────────────────────────────────────────────────────

/// **`SELECT` avant authentification est une commande parfaitement formée** :
/// c'est l'état qui la refuse, pas la grammaire.
#[test]
fn c_est_l_etat_qui_refuse_pas_la_grammaire() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 SELECT INBOX\r\n");
    assert!(
        texte.starts_with("a001 BAD Command is not allowed before authentication"),
        "{texte}"
    );

    let (texte, _) = dire(&mut session, b"a002 FETCH 1 BODY[]\r\n");
    assert!(
        texte.starts_with("a002 BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

/// Une fois authentifié, on ne se présente plus : ces deux-là ne valent que
/// dans l'état non authentifié (§6.2).
///
/// `STARTTLS` n'y figure pas, et c'est une conséquence : **on ne peut pas être
/// authentifié sans être chiffré**, donc une session authentifiée reçoit « TLS
/// is already active » avant qu'aucune question d'état ne se pose.
#[test]
fn les_commandes_de_presentation_ne_valent_plus_apres_authentification() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    assert_eq!(session.state(), State::Authenticated);
    for (commande, attendu) in [
        (
            &b"a003 LOGIN jean ouvre-toi\r\n"[..],
            "LOGIN is not allowed in this state",
        ),
        (
            b"a004 AUTHENTICATE PLAIN\r\n",
            "AUTHENTICATE is not allowed in this state",
        ),
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains(attendu), "{commande:?} : {texte}");
    }
}

/// Un identifiant plus long que ce qu'un compte peut porter ne correspond à
/// aucun compte : le refus est le même que pour un mot de passe faux, et il ne
/// dit pas davantage.
#[test]
fn des_identifiants_demesures_sont_refuses_comme_les_autres() {
    let mut session = nouvelle(true);
    let mut commande = std::vec::Vec::from(&b"a001 LOGIN "[..]);
    commande.resize(commande.len() + 200, b'x');
    commande.extend_from_slice(b" ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(texte.contains("NO [AUTHENTICATIONFAILED]"), "{texte}");

    // Et une réponse initiale SASL plus longue que ce qu'on décode.
    let mut commande = std::vec::Vec::from(&b"a002 AUTHENTICATE PLAIN "[..]);
    commande.resize(commande.len() + 2000, b'A');
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(texte.contains("NO [AUTHENTICATIONFAILED]"), "{texte}");
}

/// **`NO`, et non `BAD`** : la commande est correcte et permise ; c'est ce
/// serveur qui ne la sert pas encore.
#[test]
fn ce_qu_on_ne_sert_pas_encore_le_dit_sans_accuser_le_client() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [
        &b"a002 SELECT INBOX\r\n"[..],
        b"a003 LIST \"\" *\r\n",
        b"a004 NAMESPACE\r\n",
        b"a005 STATUS INBOX (MESSAGES)\r\n",
        b"a006 APPEND INBOX {3+}\r\nabc\r\n",
        b"a007 CREATE test\r\n",
        b"a008 DELETE test\r\n",
        b"a009 RENAME a b\r\n",
        b"a010 SUBSCRIBE a\r\n",
        b"a011 UNSUBSCRIBE a\r\n",
        b"a012 EXAMINE INBOX\r\n",
        b"a013 IDLE\r\n",
        b"a014 ENABLE UTF8=ACCEPT\r\n",
    ] {
        let mut sortie = [0_u8; 512];
        let tour = session.handle(commande, &mut sortie).expect("traitable");
        let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
        assert!(
            texte.contains("NO [UNAVAILABLE] Mailbox commands are not served yet"),
            "{commande:?} : {texte}"
        );
        assert!(
            !tour.peer_fault(),
            "{commande:?} n'est pas une faute du pair"
        );
    }
}

/// Les commandes valables partout le sont vraiment partout.
#[test]
fn les_commandes_de_tous_les_etats_passent_partout() {
    for chiffree in [false, true] {
        let mut session = nouvelle(chiffree);
        let (texte, action) = dire(&mut session, b"a001 NOOP\r\n");
        assert!(texte.starts_with("a001 OK NOOP completed"), "{texte}");
        assert_eq!(action, Action::Continue);
        let (texte, _) = dire(&mut session, b"a002 CAPABILITY\r\n");
        assert!(texte.contains("* CAPABILITY IMAP4rev2"), "{texte}");
    }
}

#[test]
fn logout_dit_adieu_puis_conclut() {
    let mut session = nouvelle(true);
    let (texte, action) = dire(&mut session, b"a001 LOGOUT\r\n");
    assert_eq!(
        texte,
        "* BYE IMAP4rev2 server logging out\r\na001 OK LOGOUT completed\r\n"
    );
    assert_eq!(action, Action::Close);
    assert_eq!(session.state(), State::Logout);

    let mut sortie = [0_u8; 512];
    assert_eq!(
        session.handle(b"a002 NOOP\r\n", &mut sortie),
        Err(super::Error::SessionClosed)
    );
}

/// Reconnus, mais pas servis : la différence entre un client qui se rabat et un
/// client qui abandonne.
#[test]
fn les_verbes_retires_par_rev2_sont_refuses_en_le_disant() {
    let mut session = nouvelle(true);
    for commande in [&b"a001 LSUB \"\" *\r\n"[..], b"a002 CHECK\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command removed in IMAP4rev2"),
            "{commande:?} : {texte}"
        );
    }
}

// ── CE QU'ON N'A PAS SU LIRE ────────────────────────────────────────────────

/// **Si le tag est irrecevable, il n'y a rien à désigner** — et le recopier pour
/// le dire serait précisément l'injection que sa validation ferme.
#[test]
fn un_tag_illisible_fait_repondre_sans_tag() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a*1 NOOP\r\n"[..],
        b"+ NOOP\r\n",
        b" NOOP\r\n",
        b"a001\r\nb\r\n NOOP\r\n",
    ] {
        let mut sortie = [0_u8; 512];
        let tour = session.handle(commande, &mut sortie).expect("traitable");
        let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
        assert!(
            texte.starts_with("* BAD Malformed tag"),
            "{commande:?} : {texte}"
        );
        assert!(tour.peer_fault());
    }
}

#[test]
fn un_verbe_inconnu_se_dit_avec_le_tag() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 XYZZY\r\n");
    assert!(texte.starts_with("a001 BAD Unknown command"), "{texte}");
    let (texte, _) = dire(&mut session, b"a002\r\n");
    assert!(texte.starts_with("a002 BAD Missing command"), "{texte}");
    // Un tag trop long est une faute de lecture comme une autre.
    let mut long = std::vec::Vec::from(&b"a"[..]);
    long.resize(TAG_MAX_OCTETS + 1, b'a');
    long.extend_from_slice(b" NOOP\r\n");
    let (texte, _) = dire(&mut session, &long);
    assert!(texte.starts_with("* BAD Malformed tag"), "{texte}");
}

// ── LE RESTE ────────────────────────────────────────────────────────────────

/// **`BYE` est la seule réponse qu'un serveur puisse émettre sans qu'une
/// commande l'ait demandée** (§7.1.5), et c'est exactement le cas quand le garde
/// écarte un pair.
#[test]
fn l_indisponibilite_se_dit_sans_tag() {
    let mut sortie = [0_u8; 128];
    assert_eq!(
        nouvelle(false)
            .unavailable(&mut sortie)
            .expect("composable"),
        b"* BYE [UNAVAILABLE] Service temporarily unavailable\r\n"
    );
}

/// **On ne sait plus où la commande se termine** : reprendre la lecture
/// laisserait le client choisir ce qu'on lira comme une commande.
#[test]
fn une_commande_indecodable_se_dit_avant_de_raccrocher() {
    let mut sortie = [0_u8; 128];
    assert_eq!(
        nouvelle(false)
            .cannot_parse(&mut sortie)
            .expect("composable"),
        b"* BAD Command could not be parsed; closing connection\r\n"
    );
    // Les deux ont aussi besoin de place.
    let mut court = [0_u8; 4];
    let session = nouvelle(false);
    assert!(session.unavailable(&mut court).is_err());
    assert!(session.cannot_parse(&mut court).is_err());
}

#[test]
fn la_demande_de_continuation_s_ecrit() {
    let mut sortie = [0_u8; 64];
    assert_eq!(
        nouvelle(false)
            .literal_continuation(&mut sortie)
            .expect("composable"),
        b"+ ready for literal\r\n"
    );
}

/// Le genre d'une issue, en TOTAL : chaque variante a son bras, et chacun est
/// emprunté par un test. Un `matches!` dans une assertion laisserait au
/// contraire un bras que rien n'atteint jamais, puisque l'assertion réussit — un
/// trou de couverture né du test lui-même.
fn genre(issue: &Result<super::Turn<'_>, super::Error>) -> &'static str {
    match issue {
        Ok(_) => "réponse",
        Err(super::Error::Reply(_)) => "tampon",
        Err(super::Error::NotInCommandPhase) => "hors phase",
        Err(super::Error::SessionClosed) => "close",
        Err(super::Error::NotInAuthExchange) => "hors échange",
    }
}

/// **Le tampon peut céder n'importe où**, et une réponse à moitié écrite ne
/// vaut rien : on essaie donc TOUTES les tailles, pour chaque forme de réponse.
/// Certaines en écrivent deux lignes, d'autres composent une liste, d'autres
/// encore répondent sans tag — et chacune a ses propres endroits où manquer.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    /// Conduit la session jusqu'à la commande, puis la rejoue en tampon borné.
    fn court(avant: &[&[u8]], commande: &'static [u8], chiffree: bool) {
        let mut assez = [0_u8; 1024];
        let mut reference = nouvelle(chiffree);
        for prealable in avant {
            reference.handle(prealable, &mut assez).expect("traitable");
        }
        let entier = reference
            .handle(commande, &mut assez)
            .expect("traitable")
            .reply()
            .len();
        for taille in 0..entier {
            let mut session = nouvelle(chiffree);
            let mut grand = [0_u8; 1024];
            for prealable in avant {
                session.handle(prealable, &mut grand).expect("traitable");
            }
            let mut petit = std::vec![0_u8; taille];
            let issue = session.handle(commande, &mut petit);
            assert_eq!(genre(&issue), "tampon", "{commande:?} taille {taille}");
        }
    }

    court(&[], b"a001 NOOP\r\n", true);
    court(&[], b"a001 CAPABILITY\r\n", true);
    court(&[], b"a001 CAPABILITY\r\n", false);
    court(&[], b"a001 LOGOUT\r\n", true);
    court(&[], b"a001 STARTTLS\r\n", false);
    court(&[], b"a001 STARTTLS\r\n", true);
    court(&[], b"a001 LOGIN jean ouvre-toi\r\n", true);
    court(&[], b"a001 LOGIN jean ouvre-toi\r\n", false);
    court(&[], b"a001 LOGIN jean mauvais\r\n", true);
    court(&[], b"a001 LOGIN jean\r\n", true);
    court(&[], b"a001 AUTHENTICATE PLAIN\r\n", true);
    court(
        &[],
        b"a001 AUTHENTICATE PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
        true,
    );
    court(&[], b"a001 AUTHENTICATE GSSAPI\r\n", true);
    court(&[], b"a001 AUTHENTICATE\r\n", true);
    court(&[], b"a001 SELECT INBOX\r\n", true);
    court(&[], b"a001 FETCH 1 BODY[]\r\n", true);
    court(&[], b"a001 LSUB \"\" *\r\n", true);
    court(&[], b"a001 XYZZY\r\n", true);
    court(&[], b"a*1 NOOP\r\n", true);
    court(
        &[b"a000 LOGIN jean ouvre-toi\r\n"],
        b"a001 SELECT INBOX\r\n",
        true,
    );

    // Les deux écritures qui ne passent pas par `handle`.
    let session = nouvelle(false);
    let mut assez = [0_u8; 256];
    let banniere = session.greeting(&mut assez).expect("composable").len();
    for taille in 0..banniere {
        let mut petit = std::vec![0_u8; taille];
        assert!(session.greeting(&mut petit).is_err(), "taille {taille}");
    }
    let continuation = session
        .literal_continuation(&mut assez)
        .expect("composable")
        .len();
    for taille in 0..continuation {
        let mut petit = std::vec![0_u8; taille];
        assert!(
            session.literal_continuation(&mut petit).is_err(),
            "taille {taille}"
        );
    }

    // Et la réponse à un défi SASL.
    let mut session = nouvelle(true);
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut assez)
        .expect("traitable");
    let mut petit = [0_u8; 4];
    assert_eq!(
        genre(&session.on_auth_response(b"AGplYW4Ab3V2cmUtdG9p", &mut petit)),
        "tampon"
    );
    let mut session = nouvelle(true);
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut assez)
        .expect("traitable");
    assert_eq!(genre(&session.on_auth_response(b"*", &mut petit)), "tampon");
}

/// Les trois autres genres d'issue, pour que chaque bras du classement soit
/// emprunté.
#[test]
fn chaque_genre_d_issue_se_produit() {
    let mut assez = [0_u8; 512];
    let mut session = nouvelle(true);
    assert_eq!(
        genre(&session.handle(b"a001 NOOP\r\n", &mut assez)),
        "réponse"
    );
    session
        .handle(b"a002 AUTHENTICATE PLAIN\r\n", &mut assez)
        .expect("traitable");
    assert_eq!(
        genre(&session.handle(b"a003 NOOP\r\n", &mut assez)),
        "hors phase"
    );
    let mut session = nouvelle(true);
    session
        .handle(b"a001 LOGOUT\r\n", &mut assez)
        .expect("traitable");
    assert_eq!(
        genre(&session.handle(b"a002 NOOP\r\n", &mut assez)),
        "close"
    );
    assert_eq!(
        genre(&nouvelle(true).on_auth_response(b"x", &mut assez)),
        "hors échange"
    );
}

#[test]
fn ce_qui_se_deroule_se_montre() {
    let session = nouvelle(false);
    assert!(!std::format!("{session:?}").is_empty());
    assert!(!std::format!("{:?}", session.clone()).is_empty());
    assert!(!std::format!("{:?}", State::Selected).is_empty());
    assert_eq!(State::Selected, State::Selected);
    assert_ne!(Action::Continue, Action::Close);
    for erreur in [
        super::Error::Reply(ams_proto_imap::Error::MissingTag),
        super::Error::NotInCommandPhase,
        super::Error::SessionClosed,
        super::Error::NotInAuthExchange,
    ] {
        assert!(std::format!("{erreur}").len() > 10, "{erreur:?}");
    }
}
