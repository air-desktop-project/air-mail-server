//! Ce qu'une session IMAP dit, et ce qu'elle refuse.

use ams_proto_imap::{Flags, Limits};
use ams_sasl::Credentials;

use super::{Action, Mailbox, Mailboxes, MessageInfo, Session, State, TAG_MAX_OCTETS};
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

/// Une boîte d'épreuve.
///
/// **Un seul type pour tous les cas**, y compris celui d'un message disparu : une
/// méthode générique est recopiée pour chaque type qui l'instancie, et le
/// compteur de couverture compte chaque copie. Deux types de boîte doubleraient
/// donc la surface à couvrir, pour éprouver la même chose.
#[derive(Debug, Clone)]
pub struct Boite {
    /// `None` : un message que le magasin annonce et ne rend pas.
    messages: std::vec::Vec<Option<MessageInfo>>,
    /// Se laisse-t-elle modifier ? `Archives` ne le fait pas.
    modifiable: bool,
}

impl Mailbox for Boite {
    fn exists(&self) -> u32 {
        u32::try_from(self.messages.len()).unwrap_or(u32::MAX)
    }
    fn uid_validity(&self) -> u32 {
        42
    }
    fn uid_next(&self) -> u32 {
        self.messages
            .iter()
            .flatten()
            .last()
            .map_or(1, |dernier| dernier.uid.saturating_add(1))
    }
    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let rang = usize::try_from(sequence.checked_sub(1)?).unwrap_or(usize::MAX);
        self.messages.get(rang).copied().flatten()
    }
    fn header_octets(&self, sequence: u32) -> u64 {
        // Deux cinquièmes de la taille : de quoi distinguer les trois sections.
        self.info(sequence)
            .map_or(0, |info| info.size.saturating_mul(2) / 5)
    }
    fn writable(&self) -> bool {
        self.modifiable
    }
    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        // Le message d'épreuve est fait de son rang, répété.
        let Some(info) = self.info(sequence) else {
            return 0;
        };
        let reste = info.size.saturating_sub(offset);
        let voulu = usize::try_from(reste).unwrap_or(usize::MAX).min(out.len());
        let place = out.get_mut(..voulu).unwrap_or_default();
        place.fill(b'0'.saturating_add(u8::try_from(sequence % 10).unwrap_or(0)));
        place.len()
    }
    fn mark_seen(&mut self, sequence: u32) {
        let rang = usize::try_from(sequence.saturating_sub(1)).unwrap_or(usize::MAX);
        for message in self.messages.iter_mut().skip(rang).take(1).flatten() {
            message.flags = message.flags.with(Flags::SEEN);
        }
    }
}

/// Un message d'épreuve.
fn message(uid: u32, size: u64, flags: Flags, internal_date: u64) -> Option<MessageInfo> {
    Some(MessageInfo {
        uid,
        size,
        flags,
        internal_date,
    })
}

/// Quatre boîtes, dont une trouée.
#[derive(Debug, Clone)]
pub struct Boites;

impl Mailboxes for Boites {
    type Open = Boite;

    fn name(&self, _user: &[u8], index: usize) -> Option<&[u8]> {
        [&b"INBOX"[..], b"Archives", b"Archives/2026"]
            .get(index)
            .copied()
    }

    fn open(&self, _user: &[u8], name: &[u8]) -> Option<Boite> {
        let messages = match name {
            b"INBOX" => std::vec![
                message(10, 100, Flags::NONE, 1_787_987_311),
                message(20, 200, Flags::SEEN, 1_787_987_400),
                message(30, 300, Flags::ANSWERED, 1_787_987_500),
            ],
            // Celle-ci en annonce trois, et n'en rend que deux : le deuxième a
            // disparu sous nos pieds.
            b"Trouee" => std::vec![
                message(1, 10, Flags::NONE, 0),
                None,
                message(3, 10, Flags::NONE, 0),
            ],
            b"Archives" | b"Archives/2026" => std::vec::Vec::new(),
            _ => return None,
        };
        // `Archives` ne se modifie pas : de quoi éprouver un `SELECT` qui
        // répond `[READ-ONLY]` sans qu'on ait dit `EXAMINE`.
        Some(Boite {
            messages,
            modifiable: !name.starts_with(b"Archives"),
        })
    }
}

/// Une session, chiffrée ou non.
fn nouvelle(chiffree: bool) -> Session<UnCompte, Boites> {
    let mut session = Session::new(BORNES, true, UnCompte, Boites);
    if chiffree {
        session.on_tls_established();
    }
    session
}

/// Traite une commande et rend la réponse en clair.
fn dire(session: &mut Session<UnCompte, Boites>, commande: &[u8]) -> (std::string::String, Action) {
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
    let mut session = Session::new(BORNES, false, UnCompte, Boites);
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
        &b"a002 CREATE test\r\n"[..],
        b"a003 DELETE test\r\n",
        b"a004 RENAME a b\r\n",
        b"a005 SUBSCRIBE a\r\n",
        b"a006 UNSUBSCRIBE a\r\n",
        b"a007 NAMESPACE\r\n",
        b"a008 APPEND INBOX {3+}\r\nabc\r\n",
        b"a009 IDLE\r\n",
        b"a010 ENABLE UTF8=ACCEPT\r\n",
    ] {
        let mut sortie = [0_u8; 2048];
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
    // Celles qui exigent une boîte ouverte le disent autrement : elles sont
    // hors d'état, et non hors de service.
    dire(&mut session, b"a011 SELECT INBOX\r\n");
    for commande in [
        &b"a012 EXPUNGE\r\n"[..],
        b"a013 SEARCH ALL\r\n",
        b"a014 STORE 1 +FLAGS (\\Seen)\r\n",
        b"a015 COPY 1 Archives\r\n",
        b"a016 MOVE 1 Archives\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("NO [UNAVAILABLE] Mailbox commands are not served yet"),
            "{commande:?} : {texte}"
        );
    }
}

// ── LES BOÎTES ──────────────────────────────────────────────────────────────

/// Ouvre une session authentifiée avec `INBOX` sélectionnée.
fn selectionnee() -> Session<UnCompte, Boites> {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT INBOX\r\n");
    session
}

/// **Un client qui ne reçoit pas `UIDVALIDITY` ne peut pas savoir si les UID
/// qu'il a retenus valent encore**, et resynchronise tout.
#[test]
fn select_dit_tout_ce_que_le_client_ne_sait_pas() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, action) = dire(&mut session, b"a002 SELECT INBOX\r\n");
    for ligne in [
        "* 3 EXISTS\r\n",
        "* OK [UIDVALIDITY 42] UIDVALIDITY\r\n",
        "* OK [UIDNEXT 31] UIDNEXT\r\n",
        "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n",
        "* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted\r\n",
        "* LIST () \"/\" INBOX\r\n",
        "a002 OK [READ-WRITE] SELECT completed\r\n",
    ] {
        assert!(texte.contains(ligne), "{ligne:?} manque dans :\n{texte}");
    }
    assert_eq!(action, Action::Continue);
    assert_eq!(session.state(), State::Selected);
    assert_eq!(session.selected(), b"INBOX");
}

/// **`PERMANENTFLAGS` dit ce qui SURVIT à la session.** En lecture seule, rien
/// ne survit — et le dire évite qu'un client croie avoir marqué un message.
#[test]
fn examine_ouvre_en_lecture_seule_et_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 EXAMINE INBOX\r\n");
    assert!(
        texte.contains("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n"),
        "{texte}"
    );
    assert!(
        texte.contains("a002 OK [READ-ONLY] EXAMINE completed\r\n"),
        "{texte}"
    );
    assert_eq!(session.state(), State::Selected);
}

/// **`[READ-WRITE]` est une promesse, et c'est la boîte qui la tient.** Un
/// magasin qui ne sait rien écrire ferait mentir `SELECT` : le client
/// n'apprendrait qu'en essayant que rien ne se modifie.
#[test]
fn une_boite_qui_ne_se_modifie_pas_est_annoncee_en_lecture_seule() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SELECT Archives\r\n");
    assert!(
        texte.contains("a002 OK [READ-ONLY] SELECT completed\r\n"),
        "{texte}"
    );
    assert!(
        texte.contains("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n"),
        "{texte}"
    );
    assert_eq!(session.state(), State::Selected);
}

/// **§6.3.2 : un `SELECT` qui échoue FERME la boîte précédente.** Le client se
/// retrouve authentifié sans sélection, et il doit le savoir.
#[test]
fn un_select_qui_echoue_ferme_la_boite_precedente() {
    let mut session = selectionnee();
    assert_eq!(session.state(), State::Selected);
    let (texte, _) = dire(&mut session, b"a003 SELECT Inconnue\r\n");
    assert!(texte.starts_with("a003 NO [NONEXISTENT]"), "{texte}");
    assert_eq!(session.state(), State::Authenticated);
    assert!(session.selected().is_empty());
}

#[test]
fn close_et_unselect_referment_la_boite() {
    for commande in [&b"a003 CLOSE\r\n"[..], b"a003 UNSELECT\r\n"] {
        let mut session = selectionnee();
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.starts_with("a003 OK Mailbox closed"), "{texte}");
        assert_eq!(session.state(), State::Authenticated);
        assert!(session.selected().is_empty());
    }
}

/// **`*` traverse la hiérarchie ; `%` s'arrête au séparateur** (§6.3.9). Les
/// confondre ferait rendre à `%` les boîtes d'un sous-dossier.
#[test]
fn les_deux_jokers_de_list_ne_disent_pas_la_meme_chose() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (tout, _) = dire(&mut session, b"a002 LIST \"\" *\r\n");
    assert!(tout.contains("* LIST () \"/\" INBOX\r\n"), "{tout}");
    assert!(tout.contains("* LIST () \"/\" Archives\r\n"), "{tout}");
    assert!(tout.contains("* LIST () \"/\" Archives/2026\r\n"), "{tout}");

    let (plat, _) = dire(&mut session, b"a003 LIST \"\" %\r\n");
    assert!(plat.contains("\"/\" INBOX\r\n"), "{plat}");
    assert!(plat.contains("\"/\" Archives\r\n"), "{plat}");
    assert!(
        !plat.contains("Archives/2026"),
        "`%` ne traverse pas le séparateur :\n{plat}"
    );

    // Un motif littéral ne rend que ce qu'il nomme.
    let (une, _) = dire(&mut session, b"a004 LIST \"\" INBOX\r\n");
    assert_eq!(une.matches("* LIST").count(), 1, "{une}");
    // Et un motif qui ne correspond à rien ne rend rien.
    let (aucune, _) = dire(&mut session, b"a005 LIST \"\" Rien*\r\n");
    assert!(!aucune.contains("* LIST"), "{aucune}");
    assert!(aucune.contains("a005 OK LIST completed"), "{aucune}");
}

/// Les sous-dossiers s'ouvrent aussi, et un message de rang zéro n'existe pas.
#[test]
fn les_bords_de_la_boite_d_epreuve_se_visitent() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SELECT Archives/2026\r\n");
    assert!(texte.contains("* 0 EXISTS"), "{texte}");
    // Le rang zéro n'est pas un message : l'ensemble le refuse avant d'y
    // toucher, et la boîte le refuserait aussi.
    let (texte, _) = dire(&mut session, b"a003 FETCH 0 UID\r\n");
    assert!(texte.contains("BAD FETCH"), "{texte}");
}

#[test]
fn status_dit_ce_qu_une_boite_contient_sans_l_ouvrir() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 STATUS INBOX (MESSAGES)\r\n");
    assert!(
        texte.contains("* STATUS INBOX (MESSAGES 3 UIDNEXT 31 UIDVALIDITY 42)\r\n"),
        "{texte}"
    );
    assert!(texte.contains("a002 OK STATUS completed"), "{texte}");
    // La session n'a pas été sélectionnée pour autant.
    assert_eq!(session.state(), State::Authenticated);

    let (absente, _) = dire(&mut session, b"a003 STATUS Inconnue (MESSAGES)\r\n");
    assert!(absente.starts_with("a003 NO [NONEXISTENT]"), "{absente}");
}

/// **`STATUS` sur la boîte SÉLECTIONNÉE répond, et sans la rouvrir.** §6.3.11 le
/// déconseille au client, mais le client le fait — et un magasin qui verrouille
/// se heurterait à son propre verrou, pour nier une boîte qu'il tient ouverte.
#[test]
fn status_repond_aussi_de_la_boite_ouverte() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT INBOX\r\n");
    let (texte, _) = dire(&mut session, b"a003 STATUS INBOX (MESSAGES)\r\n");
    assert!(
        texte.contains("* STATUS INBOX (MESSAGES 3 UIDNEXT 31 UIDVALIDITY 42)\r\n"),
        "{texte}"
    );
    // Et la sélection n'a pas bougé.
    assert_eq!(session.state(), State::Selected);
    assert_eq!(session.selected(), b"INBOX");

    // Une AUTRE boîte, elle, s'ouvre pour la question.
    let (autre, _) = dire(&mut session, b"a004 STATUS Archives (MESSAGES)\r\n");
    assert!(
        autre.contains("* STATUS Archives (MESSAGES 0 UIDNEXT 1 UIDVALIDITY 42)\r\n"),
        "{autre}"
    );
    assert_eq!(session.selected(), b"INBOX");
}

/// **Les octets d'un message traversent la session sans y séjourner.** C'est la
/// boucle qui les écrit sur le fil ; la session ne fait que les emprunter à la
/// boîte ouverte, et n'en garde rien.
#[test]
fn la_session_lit_par_la_boite_ouverte() {
    let mut session = nouvelle(true);
    let mut tampon = [0_u8; 8];

    // Sans boîte ouverte, il n'y a rien à lire.
    assert_eq!(session.read_selected(1, 0, &mut tampon), 0);

    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT INBOX\r\n");
    assert_eq!(session.read_selected(1, 0, &mut tampon), 8);
    // La boîte d'épreuve rend le rang du message, répété.
    assert_eq!(&tampon, b"11111111");
    // Un rang qui n'existe pas ne rend rien.
    assert_eq!(session.read_selected(99, 0, &mut tampon), 0);
}

#[test]
fn les_commandes_de_boite_mal_formees_sont_des_fautes() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for (commande, attendu) in [
        (&b"a002 SELECT\r\n"[..], "SELECT expects"),
        (b"a003 STATUS\r\n", "STATUS expects"),
        (b"a004 LIST \"\"\r\n", "LIST expects"),
        (b"a005 LIST a b c\r\n", "LIST expects"),
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains(attendu), "{commande:?} : {texte}");
    }
    // Un nom de boîte qu'on refuse d'écrire dans une réponse.
    let (texte, _) = dire(&mut session, b"a006 SELECT \"a b\"\r\n");
    assert!(texte.contains("SELECT expects"), "{texte}");
    // Un argument que la grammaire n'a pas su lire.
    let (texte, _) = dire(&mut session, b"a007 SELECT \"sans fin\r\n");
    assert!(texte.contains("SELECT expects"), "{texte}");
    // Un nom plus long que ce que la session retient.
    let mut trop = std::vec::Vec::from(&b"a008 SELECT "[..]);
    trop.resize(trop.len() + 300, b'x');
    trop.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &trop);
    assert!(texte.contains("SELECT expects"), "{texte}");
}

/// Les commandes de boîte demandent d'être authentifié.
#[test]
fn les_commandes_de_boite_demandent_l_authentification() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a001 SELECT INBOX\r\n"[..],
        b"a002 LIST \"\" *\r\n",
        b"a003 STATUS INBOX (MESSAGES)\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed before authentication"),
            "{commande:?} : {texte}"
        );
    }
    // Et celles qui demandent une boîte ouverte le disent.
    dire(&mut session, b"a004 LOGIN jean ouvre-toi\r\n");
    for commande in [
        &b"a005 CLOSE\r\n"[..],
        b"a006 FETCH 1 UID\r\n",
        b"a007 UID FETCH 1 UID\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed unless a mailbox is selected"),
            "{commande:?} : {texte}"
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
    // Les commandes de boîte écrivent plusieurs lignes, et chacune peut manquer
    // de place à un endroit différent.
    const APRES_LOGIN: &[&[u8]] = &[b"a000 LOGIN jean ouvre-toi\r\n"];
    const APRES_SELECT: &[&[u8]] = &[b"a000 LOGIN jean ouvre-toi\r\n", b"a000 SELECT INBOX\r\n"];
    court(APRES_LOGIN, b"a001 EXAMINE INBOX\r\n", true);
    court(APRES_LOGIN, b"a001 SELECT Inconnue\r\n", true);
    court(APRES_LOGIN, b"a001 SELECT\r\n", true);
    court(APRES_LOGIN, b"a001 LIST \"\" *\r\n", true);
    court(APRES_LOGIN, b"a001 LIST \"\"\r\n", true);
    court(APRES_LOGIN, b"a001 STATUS INBOX (MESSAGES)\r\n", true);
    court(APRES_LOGIN, b"a001 STATUS Inconnue (MESSAGES)\r\n", true);
    court(APRES_LOGIN, b"a001 CREATE test\r\n", true);
    court(APRES_SELECT, b"a001 CLOSE\r\n", true);
    court(APRES_SELECT, b"a001 FETCH 1 UID\r\n", true);
    court(APRES_SELECT, b"a001 UID FETCH 1 UID\r\n", true);
    court(APRES_SELECT, b"a001 UID STORE 1 (\\Seen)\r\n", true);
    court(APRES_SELECT, b"a001 FETCH 1 ENVELOPE\r\n", true);
    court(
        APRES_SELECT,
        b"a001 FETCH 1 (BODY[] BODY[HEADER])\r\n",
        true,
    );
    court(APRES_SELECT, b"a001 EXPUNGE\r\n", true);

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

/// Le genre d'une issue d'émission, en TOTAL — chaque bras est emprunté.
fn genre_d_emission(issue: &Result<Option<super::FetchChunk<'_>>, super::Error>) -> &'static str {
    match issue {
        Ok(None) => "fini",
        Ok(Some(super::FetchChunk::Bytes(_))) => "octets",
        Ok(Some(super::FetchChunk::Message { .. })) => "message",
        Err(super::Error::Reply(_)) => "tampon",
        Err(_) => "autre",
    }
}

/// **Le tampon peut céder pendant l'émission aussi**, et une réponse `FETCH` à
/// moitié écrite désynchroniserait le client tout autant.
///
/// On conduit l'émission jusqu'au morceau `k` avec un grand tampon, puis on
/// offre au morceau `k` toutes les tailles jusqu'à la sienne : sans cela, la
/// première faute masquerait tous les morceaux suivants.
#[test]
fn un_tampon_trop_court_pendant_l_emission_le_dit() {
    for commande in [
        // Le deuxième message porte un drapeau : sans lui, `FLAGS ()` n'écrit
        // rien, et la place ne peut pas manquer là où il faut l'éprouver.
        &b"a003 FETCH 2 (UID FLAGS INTERNALDATE RFC822.SIZE)\r\n"[..],
        b"a003 FETCH 1 BODY[]\r\n",
        b"a003 FETCH 1 BODY[HEADER]<2.3>\r\n",
        b"a003 FETCH 1:2 (UID BODY.PEEK[TEXT])\r\n",
    ] {
        // Combien de morceaux, et de quelle taille chacun.
        let mut assez = [0_u8; 2048];
        let mut reference = selectionnee();
        reference.handle(commande, &mut assez).expect("traitable");
        let mut tailles = std::vec::Vec::new();
        while let Some(morceau) = reference.next_fetch(&mut assez).expect("émettable") {
            tailles.push(match morceau {
                super::FetchChunk::Bytes(octets) => octets.len(),
                super::FetchChunk::Message { .. } => 0,
            });
        }

        for (rang, longueur) in tailles.iter().enumerate() {
            for taille in 0..*longueur {
                let mut session = selectionnee();
                session.handle(commande, &mut assez).expect("traitable");
                for _ in 0..rang {
                    session.next_fetch(&mut assez).expect("émettable");
                }
                let mut petit = std::vec![0_u8; taille];
                assert_eq!(
                    genre_d_emission(&session.next_fetch(&mut petit)),
                    "tampon",
                    "{commande:?} morceau {rang} taille {taille}"
                );
            }
        }
    }
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

// ── FETCH ───────────────────────────────────────────────────────────────────

/// Écoule un `FETCH` et rend ce que l'appelant écrirait sur le fil.
fn ecouler(session: &mut Session<UnCompte, Boites>, commande: &[u8]) -> std::string::String {
    let mut sortie = [0_u8; 2048];
    let tour = session.handle(commande, &mut sortie).expect("traitable");
    let conclusion = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert_eq!(tour.action(), Action::SendFetch, "{conclusion}");
    let mut fil = std::string::String::new();
    let mut morceaux = [0_u8; 2048];
    while let Some(morceau) = session.next_fetch(&mut morceaux).expect("émettable") {
        match morceau {
            super::FetchChunk::Bytes(octets) => {
                fil.push_str(&std::string::String::from_utf8_lossy(octets));
            }
            super::FetchChunk::Message {
                sequence,
                offset,
                length,
            } => {
                fil.push_str(&std::format!("<{sequence}:{offset}+{length}>"));
            }
        }
    }
    fil.push_str(&conclusion);
    fil
}

/// Chaque bras du classement d'émission est emprunté par un cas réel.
#[test]
fn chaque_genre_d_emission_se_produit() {
    let mut session = selectionnee();
    let mut sortie = [0_u8; 2048];
    assert_eq!(genre_d_emission(&session.next_fetch(&mut sortie)), "fini");
    session
        .handle(b"a003 FETCH 1 BODY[]\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(genre_d_emission(&session.next_fetch(&mut sortie)), "octets");
    assert_eq!(
        genre_d_emission(&session.next_fetch(&mut sortie)),
        "message"
    );
    let mut court = [0_u8; 1];
    assert_eq!(genre_d_emission(&session.next_fetch(&mut court)), "tampon");
    // Un `next_fetch` hors émission ne rend rien, et ce n'est pas une faute.
    let mut vierge = nouvelle(true);
    assert_eq!(genre_d_emission(&vierge.next_fetch(&mut sortie)), "fini");
}

#[test]
fn un_fetch_sans_corps_tient_sur_une_ligne_par_message() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1:2 (UID FLAGS RFC822.SIZE)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (UID 10 FLAGS () RFC822.SIZE 100)\r\n\
         * 2 FETCH (UID 20 FLAGS (\\Seen) RFC822.SIZE 200)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

#[test]
fn la_date_d_arrivee_s_ecrit_a_la_facon_d_imap() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 INTERNALDATE\r\n");
    assert!(
        fil.contains("* 1 FETCH (INTERNALDATE \"29-Aug-2026 07:08:31 +0000\")\r\n"),
        "{fil}"
    );
}

/// **La session ne lit jamais un message** : elle rend un intervalle, et c'est
/// l'appelant qui l'écoule.
#[test]
fn un_corps_se_rend_en_intervalle_precede_de_sa_longueur() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BODY[]\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[] {100}\r\n<1:0+100>)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

/// Les trois sections désignent trois intervalles, et le découpage vient du
/// magasin.
#[test]
fn les_trois_sections_designent_trois_intervalles() {
    let mut session = selectionnee();
    // `header_octets` vaut deux cinquièmes de la taille : 40 pour le premier.
    assert!(
        ecouler(&mut session, b"a003 FETCH 1 BODY[HEADER]\r\n")
            .contains("BODY[HEADER] {40}\r\n<1:0+40>")
    );
    assert!(
        ecouler(&mut session, b"a004 FETCH 1 BODY[TEXT]\r\n")
            .contains("BODY[TEXT] {60}\r\n<1:40+60>")
    );
    assert!(
        ecouler(&mut session, b"a005 FETCH 1 BODY[]\r\n").contains("BODY[] {100}\r\n<1:0+100>")
    );
}

/// **C'est ici que le débordement s'arrête** : le décalage vient du réseau, la
/// taille du magasin, et les additionner sans précaution donnerait un intervalle
/// qui déborde du fichier.
#[test]
fn c_est_ici_que_la_demande_partielle_est_ramenee_dans_le_message() {
    let mut session = selectionnee();
    // Une tranche ordinaire.
    assert!(
        ecouler(&mut session, b"a003 FETCH 1 BODY[]<10.20>\r\n")
            .contains("BODY[]<10> {20}\r\n<1:10+20>"),
        "une tranche ordinaire"
    );
    // Une longueur qui dépasse la fin est ramenée à ce qui reste.
    assert!(
        ecouler(&mut session, b"a004 FETCH 1 BODY[]<90.1000>\r\n")
            .contains("BODY[]<90> {10}\r\n<1:90+10>"),
        "une longueur qui dépasse"
    );
    // Un décalage AU-DELÀ de la fin ne rend rien, et ne lit rien.
    let fil = ecouler(&mut session, b"a005 FETCH 1 BODY[]<4294967295.1>\r\n");
    assert!(fil.contains("BODY[]<4294967295> {0}\r\n<1:100+0>"), "{fil}");
    // Et dans une section, le décalage part du début de la SECTION.
    assert!(
        ecouler(&mut session, b"a006 FETCH 1 BODY[TEXT]<5.10>\r\n")
            .contains("BODY[TEXT]<5> {10}\r\n<1:45+10>"),
        "un décalage dans une section"
    );
}

/// **`PEEK` n'est pas une variante cosmétique** : sans lui, le message est
/// marqué comme lu, et les `FLAGS` de la même réponse doivent le dire.
#[test]
fn un_corps_sans_peek_marque_le_message_comme_lu() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (FLAGS BODY[])\r\n");
    assert!(fil.contains("FLAGS (\\Seen)"), "{fil}");

    // Avec `PEEK`, rien ne change.
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (FLAGS BODY.PEEK[])\r\n");
    assert!(fil.contains("FLAGS ()"), "{fil}");
}

/// **L'étoile ne veut pas dire la même chose dans les deux modes** : le plus
/// grand numéro de séquence, ou le plus grand UID.
#[test]
fn uid_fetch_designe_par_uid_et_rend_le_rang() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID FETCH 20:30 UID\r\n");
    assert_eq!(
        fil,
        "* 2 FETCH (UID 20)\r\n* 3 FETCH (UID 30)\r\n\
         a003 OK UID FETCH completed\r\n"
    );
    // `*` vaut le plus grand UID, pas le nombre de messages.
    let fil = ecouler(&mut session, b"a004 UID FETCH 25:* UID\r\n");
    assert_eq!(fil, "* 3 FETCH (UID 30)\r\na004 OK UID FETCH completed\r\n");
    // EN NUMÉROS DE SÉQUENCE, `25:*` DÉSIGNE LE DERNIER MESSAGE, et c'est la
    // RFC qui le veut : l'intervalle n'est pas ordonné (§9), donc `25:*` vaut
    // ici `3:25`, qui contient le troisième. Un serveur qui rendrait le vide
    // ferait perdre au client le message qu'il cherchait justement.
    let fil = ecouler(&mut session, b"a005 FETCH 25:* UID\r\n");
    assert_eq!(fil, "* 3 FETCH (UID 30)\r\na005 OK FETCH completed\r\n");
}

#[test]
fn un_uid_autre_que_fetch_se_refuse_en_le_disant() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID STORE 1 +FLAGS (\\Seen)\r\n");
    assert!(
        texte.contains("NO [CANNOT] Only UID FETCH is served yet"),
        "{texte}"
    );
}

/// **Un seul corps par commande** : en rendre deux demanderait d'entrelacer
/// deux intervalles de fichier dans une même réponse.
#[test]
fn deux_corps_dans_un_fetch_se_refusent_en_le_disant() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 FETCH 1 (BODY[] BODY[HEADER])\r\n");
    assert!(
        texte.contains("NO [CANNOT] Only one body item per FETCH is served"),
        "{texte}"
    );
}

#[test]
fn un_element_reconnu_mais_non_servi_se_dit_sans_accuser_le_client() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 FETCH 1 ENVELOPE\r\n");
    assert!(
        texte.contains("NO [CANNOT] This FETCH item is not served yet"),
        "{texte}"
    );
}

#[test]
fn un_fetch_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 FETCH 0 UID\r\n"[..],
        b"a004 FETCH 1\r\n",
        b"a005 FETCH\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD FETCH arguments are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

/// Un ensemble plus long que ce que la session retient n'est pas la demande d'un
/// client qui lit son courrier.
#[test]
fn un_ensemble_trop_long_a_retenir_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 FETCH 1"[..]);
    for _ in 0..600 {
        commande.extend_from_slice(b",1");
    }
    commande.extend_from_slice(b" UID\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Sequence set is too long"),
        "{texte}"
    );
}

/// Sur une boîte vide, un `FETCH` ne rend rien et ne se plaint pas.
#[test]
fn un_fetch_sur_une_boite_vide_ne_rend_rien() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Archives\r\n");
    let fil = ecouler(&mut session, b"a003 FETCH 1:* (UID BODY[])\r\n");
    assert_eq!(fil, "a003 OK FETCH completed\r\n");
}

/// Sans émission en cours, il n'y a rien à écouler.
#[test]
fn sans_fetch_en_cours_il_n_y_a_rien_a_ecouler() {
    let mut session = selectionnee();
    let mut sortie = [0_u8; 256];
    assert!(
        session
            .next_fetch(&mut sortie)
            .expect("émettable")
            .is_none()
    );
    // Et une boîte refermée pendant l'émission arrête celle-ci.
    let mut sortie = [0_u8; 2048];
    session
        .handle(b"a003 FETCH 1:* UID\r\n", &mut sortie)
        .expect("traitable");
    dire(&mut session, b"a004 CLOSE\r\n");
    let mut morceaux = [0_u8; 256];
    assert!(
        session
            .next_fetch(&mut morceaux)
            .expect("émettable")
            .is_none()
    );
}

/// **Un message qui n'est plus là est sauté**, et le reste est rendu. Un serveur
/// qui s'arrêterait là ferait perdre au client tout ce qui suit.
#[test]
fn un_message_disparu_est_saute_sans_arreter_le_fetch() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let fil = ecouler(&mut session, b"a003 FETCH 1:* UID\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (UID 1)\r\n* 3 FETCH (UID 3)\r\na003 OK FETCH completed\r\n"
    );
}

/// **Un magasin partagé en est un aussi** : la boucle n'en a qu'un pour mille
/// connexions, et la session le prend par valeur.
///
/// On l'éprouve SANS session : une session de plus serait une instanciation de
/// plus, donc une copie de tout son code à couvrir, pour vérifier deux
/// délégations.
#[test]
fn un_magasin_partage_se_passe_par_reference() {
    let boites = Boites;
    let partage = &boites;
    assert_eq!(Mailboxes::name(&partage, b"jean", 0), Some(&b"INBOX"[..]));
    assert!(Mailboxes::open(&partage, b"jean", b"INBOX").is_some());
    assert!(Mailboxes::open(&partage, b"jean", b"Inconnue").is_none());
}

/// Les commandes qui exigent un état le disent dans les deux sens.
#[test]
fn les_commandes_hors_etat_le_disent() {
    let mut session = nouvelle(true);
    // Avant authentification, celles qui demandent d'être authentifié.
    for commande in [&b"a001 CREATE test\r\n"[..], b"a002 NAMESPACE\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed before authentication"),
            "{commande:?} : {texte}"
        );
    }
    dire(&mut session, b"a003 LOGIN jean ouvre-toi\r\n");
    // Authentifié mais sans boîte, celles qui en demandent une.
    for commande in [&b"a004 EXPUNGE\r\n"[..], b"a005 SEARCH ALL\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed unless a mailbox is selected"),
            "{commande:?} : {texte}"
        );
    }
}

/// Un nom plus long que ce que la session retient n'est pas un nom de boîte.
#[test]
fn un_argument_de_list_demesure_est_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let mut commande = std::vec::Vec::from(&b"a002 LIST \"\" "[..]);
    commande.resize(commande.len() + 300, b'x');
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(texte.contains("BAD LIST arguments are too long"), "{texte}");
}
