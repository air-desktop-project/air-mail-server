//! Ce qu'une session IMAP dit, et ce qu'elle refuse.

use ams_proto_imap::{Flags, Limits, StoreMode};
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
    /// Le rang d'un message qui S'EFFACE ENTRE L'INSTANTANÉ ET L'ÉCRITURE.
    ///
    /// Ce n'est pas la même disparition qu'un `None` dans `messages` : celui-là
    /// n'est jamais choisi, puisqu'il n'a pas d'`info`. Celui-ci est choisi, et
    /// s'évanouit quand on écrit — ce qu'une boîte lue sans verrou ne peut pas
    /// exclure, et ce dont §6.4.6 dit qu'il ne faut pas faire une erreur.
    /// `0` : aucun.
    evanescent: u32,
    /// Combien de messages cette boîte a effacés, vu du dehors.
    efface: std::rc::Rc<std::cell::Cell<u32>>,
    /// L'UID d'un message qui REFUSE de s'effacer.
    ///
    /// C'est le cas qu'un magasin réel rencontre : entre l'instantané et
    /// l'ordre, une autre session a retiré la marque `\Deleted`, et le magasin
    /// refuse alors d'effacer plutôt que de perdre du courrier. `0` : aucun.
    tetu: u32,
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
    fn permanent_flags(&self) -> Flags {
        if self.modifiable {
            Flags::SEEN
                .with(Flags::ANSWERED)
                .with(Flags::FLAGGED)
                .with(Flags::DELETED)
                .with(Flags::DRAFT)
        } else {
            Flags::NONE
        }
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
    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32> {
        // La boîte d'épreuve ne copie que vers elle-même, comme le magasin
        // réel : c'est la seule boîte qui existe.
        if !mailbox.eq_ignore_ascii_case(b"INBOX") {
            return None;
        }
        let info = self.info(sequence)?;
        // Le têtu ne se copie pas non plus : de quoi éprouver qu'une copie
        // manquée n'emporte pas les autres.
        if info.uid == self.tetu {
            return None;
        }
        let neuf = self.uid_next();
        self.messages
            .push(message(neuf, info.size, info.flags, info.internal_date));
        self.efface.set(self.efface.get());
        Some(neuf)
    }

    fn undo_copies(&mut self, mailbox: &[u8], premier: u32, dernier: u32) {
        if !mailbox.eq_ignore_ascii_case(b"INBOX") {
            return;
        }
        self.messages
            .retain(|message| message.is_none_or(|info| info.uid < premier || info.uid > dernier));
    }

    fn remove(&mut self, sequence: u32) -> bool {
        // Retirer, c'est effacer sans regarder la marque — et la boîte
        // d'épreuve n'en regarde pas non plus.
        let Ok(rang) = usize::try_from(sequence.saturating_sub(1)) else {
            return false;
        };
        if rang >= self.messages.len() || !self.modifiable {
            return false;
        }
        self.messages.remove(rang);
        true
    }

    fn expunge(&mut self, sequence: u32) -> bool {
        if !self.modifiable {
            return false;
        }
        let Some(rang) = usize::try_from(sequence.saturating_sub(1)).ok() else {
            return false;
        };
        if rang >= self.messages.len() {
            return false;
        }
        // Le têtu ne s'efface pas : sa marque a été retirée entre-temps.
        if self
            .info(sequence)
            .is_some_and(|info| info.uid == self.tetu)
        {
            return false;
        }
        // Le message évanescent s'efface tout seul avant qu'on l'atteigne : il
        // n'est plus là, ce qui est bien ce que `true` veut dire.
        self.messages.remove(rang);
        self.efface.set(self.efface.get().saturating_add(1));
        true
    }

    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags> {
        if !self.modifiable || sequence == self.evanescent {
            return None;
        }
        let rang = usize::try_from(sequence.checked_sub(1)?).unwrap_or(usize::MAX);
        let message = self.messages.get_mut(rang)?.as_mut()?;
        message.flags = match mode {
            StoreMode::Replace => flags,
            StoreMode::Add => message.flags.with(flags),
            StoreMode::Remove => message.flags.without(flags),
        };
        Some(message.flags)
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

/// Ce qu'une validation produit, vu du test : l'UID, les drapeaux, la date.
type Valide = std::rc::Rc<std::cell::Cell<Option<(u32, Flags, Option<u64>)>>>;

/// Ce qu'un dépôt a reçu, vu du test.
type Ecrit = std::rc::Rc<std::cell::RefCell<std::vec::Vec<u8>>>;

/// Un dépôt d'épreuve : il retient ce qu'on lui écrit, et le partage.
#[derive(Debug, Default)]
pub struct Depot {
    /// Ce qui a été écrit, pour que le test le relise.
    ecrit: Ecrit,
    /// Ce dépôt refuse-t-il d'écrire ? De quoi éprouver un magasin qui lâche.
    refuse: bool,
    /// Ce dépôt refuse-t-il de se valider ?
    invalide: bool,
    /// Le prochain UID de la boîte.
    uid: u32,
    /// Ce que la validation a produit, pour que le test le relise.
    valide: Valide,
}

impl super::Deposit for Depot {
    fn write(&mut self, chunk: &[u8]) -> bool {
        if self.refuse {
            return false;
        }
        self.ecrit.borrow_mut().extend_from_slice(chunk);
        true
    }

    fn commit(self, flags: Flags, date: Option<u64>) -> Option<u32> {
        if self.invalide {
            return None;
        }
        self.valide.set(Some((self.uid, flags, date)));
        Some(self.uid)
    }

    fn abort(self) {
        self.ecrit.borrow_mut().clear();
    }
}

/// Quatre boîtes, dont une trouée.
///
/// Le compteur d'effacements est PARTAGÉ avec l'appelant : une boîte d'épreuve
/// meurt avec la session qui la tient, et `CLOSE` efface au moment précis où
/// elle meurt. Sans ce compteur, ce que `CLOSE` a fait ne serait observable
/// nulle part.
#[derive(Debug, Clone, Default)]
pub struct Boites {
    efface: std::rc::Rc<std::cell::Cell<u32>>,
    /// Ce qu'un dépôt a reçu, partagé avec le test.
    ecrit: Ecrit,
    /// Ce qu'une validation a produit, partagé avec le test.
    valide: Valide,
    /// Les boîtes créées pendant la session.
    creees: std::rc::Rc<std::cell::RefCell<std::vec::Vec<std::vec::Vec<u8>>>>,
}

impl Mailboxes for Boites {
    type Open = Boite;

    fn name<'n>(&self, _user: &[u8], index: usize, out: &'n mut [u8]) -> Option<&'n [u8]> {
        // Les boîtes créées s'ajoutent à celles qui sont là de tout temps.
        let creees = self.creees.borrow();
        let nom = [&b"INBOX"[..], b"Archives", b"Archives/2026"]
            .get(index)
            .copied()
            .or_else(|| {
                creees
                    .get(index.saturating_sub(3))
                    .map(std::vec::Vec::as_slice)
            })?;
        let longueur = nom.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        out.get(..longueur)
    }

    fn create(&self, _user: &[u8], name: &[u8]) -> super::Creation {
        // La boîte d'épreuve refuse ce qui la fâche, comme un magasin réel.
        if name.starts_with(b"Impossible") {
            return super::Creation::Refusee;
        }
        let deja = matches!(name, b"Archives" | b"Archives/2026" | b"Trouee" | b"Tetue")
            || self.creees.borrow().iter().any(|connu| connu == name);
        if deja {
            return super::Creation::DejaLa;
        }
        self.creees.borrow_mut().push(name.to_vec());
        super::Creation::Faite
    }

    type Deposit = Depot;

    fn append(&self, _user: &[u8], name: &[u8]) -> Option<Depot> {
        // `Refusante` accepte le dépôt et le perd en route ; `Ingrate` l'accepte
        // et refuse de le valider. Les deux existent parce que ce sont deux
        // façons différentes d'échouer.
        let connue = matches!(name, b"INBOX" | b"Archives" | b"Refusante" | b"Ingrate");
        connue.then(|| Depot {
            ecrit: std::rc::Rc::clone(&self.ecrit),
            refuse: name == b"Refusante",
            invalide: name == b"Ingrate",
            uid: 31,
            valide: std::rc::Rc::clone(&self.valide),
        })
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
            // Assez de messages aux UID espacés pour que leur ensemble ne
            // tienne pas dans ce qu'on accepte d'écrire pour un `COPYUID`.
            b"Eparse" => (0..60)
                .map(|rang: u32| {
                    message(rang.saturating_mul(2).saturating_add(1), 10, Flags::NONE, 0)
                })
                .collect(),
            // Trois messages aux UID QUI SE SUIVENT : de quoi éprouver qu'un
            // ensemble se comprime en plage plutôt qu'en liste.
            b"Suite" => std::vec![
                message(5, 100, Flags::NONE, 0),
                message(6, 100, Flags::NONE, 0),
                message(7, 100, Flags::NONE, 0),
            ],
            // Trois messages ordinaires, dont le deuxième refusera de s'effacer.
            b"Tetue" => std::vec![
                message(10, 100, Flags::NONE, 0),
                message(20, 200, Flags::NONE, 0),
                message(30, 300, Flags::NONE, 0),
            ],
            // Deux messages aux UID les plus grands qui soient : de quoi
            // composer une plage de vingt-six octets, plus longue qu'un tampon
            // qui a pourtant suffi à l'en-tête.
            b"Grande" => std::vec![
                message(u32::MAX.saturating_sub(1), 10, Flags::NONE, 0),
                message(u32::MAX, 10, Flags::NONE, 0),
            ],
            b"Archives" | b"Archives/2026" => std::vec::Vec::new(),
            _ => return None,
        };
        // `Archives` ne se modifie pas : de quoi éprouver un `SELECT` qui
        // répond `[READ-ONLY]` sans qu'on ait dit `EXAMINE`.
        Some(Boite {
            messages,
            modifiable: !name.starts_with(b"Archives"),
            // Dans la boîte trouée, le troisième s'efface quand on écrit.
            evanescent: if name == b"Trouee" { 3 } else { 0 },
            efface: std::rc::Rc::clone(&self.efface),
            // Dans la boîte têtue, le message d'UID 20 refuse de s'effacer.
            tetu: if name == b"Tetue" { 20 } else { 0 },
        })
    }
}

/// Une session, chiffrée ou non.
fn nouvelle(chiffree: bool) -> Session<UnCompte, Boites> {
    let mut session = Session::new(BORNES, true, UnCompte, Boites::default());
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
    let mut session = Session::new(BORNES, false, UnCompte, Boites::default());
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
        &b"a003 DELETE test\r\n"[..],
        b"a004 RENAME a b\r\n",
        b"a005 SUBSCRIBE a\r\n",
        b"a006 UNSUBSCRIBE a\r\n",
        b"a007 NAMESPACE\r\n",
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
        "* LIST () \"/\" \"INBOX\"\r\n",
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
    for (commande, conclusion) in [
        (&b"a003 CLOSE\r\n"[..], "a003 OK CLOSE completed"),
        (b"a003 UNSELECT\r\n", "a003 OK UNSELECT completed"),
    ] {
        let mut session = selectionnee();
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.starts_with(conclusion), "{texte}");
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
    assert!(tout.contains("* LIST () \"/\" \"INBOX\"\r\n"), "{tout}");
    assert!(tout.contains("* LIST () \"/\" \"Archives\"\r\n"), "{tout}");
    assert!(
        tout.contains("* LIST () \"/\" \"Archives/2026\"\r\n"),
        "{tout}"
    );

    let (plat, _) = dire(&mut session, b"a003 LIST \"\" %\r\n");
    assert!(plat.contains("\"/\" \"INBOX\"\r\n"), "{plat}");
    assert!(plat.contains("\"/\" \"Archives\"\r\n"), "{plat}");
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
        texte.contains("* STATUS \"INBOX\" (MESSAGES 3 UIDNEXT 31 UIDVALIDITY 42)\r\n"),
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
        texte.contains("* STATUS \"INBOX\" (MESSAGES 3 UIDNEXT 31 UIDVALIDITY 42)\r\n"),
        "{texte}"
    );
    // Et la sélection n'a pas bougé.
    assert_eq!(session.state(), State::Selected);
    assert_eq!(session.selected(), b"INBOX");

    // Une AUTRE boîte, elle, s'ouvre pour la question.
    let (autre, _) = dire(&mut session, b"a004 STATUS Archives (MESSAGES)\r\n");
    assert!(
        autre.contains("* STATUS \"Archives\" (MESSAGES 0 UIDNEXT 1 UIDVALIDITY 42)\r\n"),
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
    // UN ESPACE EST ADMIS — « Sent Messages » est un nom ordinaire —, et la
    // réponse cite le nom. Ce qui est refusé, c'est ce qui casserait la réponse.
    let (espace, _) = dire(&mut session, b"a006 SELECT \"a b\"\r\n");
    assert!(espace.contains("NO [NONEXISTENT]"), "{espace}");
    let (guillemet, _) = dire(&mut session, b"a006 SELECT \"a\\\"b\"\r\n");
    assert!(guillemet.contains("SELECT expects"), "{guillemet}");
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
    // Certaines émissions demandent qu'on ait d'abord marqué : un `EXPUNGE` sur
    // une boîte où rien n'est marqué n'écrit que sa conclusion.
    fn prete(preambule: &[u8]) -> Session<UnCompte, Boites> {
        let mut session = selectionnee();
        if !preambule.is_empty() {
            ecouler(&mut session, preambule);
        }
        session
    }

    for (preambule, commande) in [
        // Le deuxième message porte un drapeau : sans lui, `FLAGS ()` n'écrit
        // rien, et la place ne peut pas manquer là où il faut l'éprouver.
        (
            &b""[..],
            &b"a003 FETCH 2 (UID FLAGS INTERNALDATE RFC822.SIZE)\r\n"[..],
        ),
        (b"", b"a003 FETCH 1 BODY[]\r\n"),
        (b"", b"a003 FETCH 1 BODY[HEADER]<2.3>\r\n"),
        (b"", b"a003 FETCH 1:2 (UID BODY.PEEK[TEXT])\r\n"),
        (
            b"a003 STORE 1:2 +FLAGS.SILENT (\\Deleted)\r\n",
            b"a004 EXPUNGE\r\n",
        ),
    ] {
        // Combien de morceaux, et de quelle taille chacun.
        let mut assez = [0_u8; 2048];
        let mut reference = prete(preambule);
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
                let mut session = prete(preambule);
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
    // La session, elle, ne s'affiche pas et ne se recopie pas : elle peut tenir
    // un dépôt en cours, c'est-à-dire un fichier ouvert.
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
    // LA RÉPONSE DU TOUR VIENT D'ABORD, comme la boucle l'écrit : un `MOVE` y
    // loge son `* OK [COPYUID …]`, que §6.4.8 veut AVANT les `EXPUNGE`. La
    // mettre à la fin ferait passer un ordre faux pour un ordre bon.
    let debut = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert_eq!(tour.action(), Action::SendFetch, "{debut}");
    let mut fil = debut;
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

/// **`UID` porte un verbe, et pas n'importe lequel.** Un verbe inconnu se refuse
/// en le disant, plutôt que de laisser le client croire à une syntaxe fautive.
#[test]
fn un_uid_dont_le_verbe_est_inconnu_se_refuse_en_le_disant() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID CHERCHE 1\r\n");
    assert!(
        texte.contains("NO [CANNOT] This UID command is not served yet"),
        "{texte}"
    );
    // Et `UID` sans rien derrière ne trouve pas de verbe.
    let (nu, _) = dire(&mut session, b"a004 UID\r\n");
    assert!(nu.contains("NO [CANNOT]"), "{nu}");
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
    let boites = Boites::default();
    let partage = &boites;
    let mut place = [0_u8; 64];
    assert_eq!(
        Mailboxes::name(&partage, b"jean", 0, &mut place),
        Some(&b"INBOX"[..])
    );
    assert!(Mailboxes::open(&partage, b"jean", b"INBOX").is_some());
    assert!(Mailboxes::open(&partage, b"jean", b"Inconnue").is_none());
    assert!(Mailboxes::append(&partage, b"jean", b"INBOX").is_some());
    assert!(Mailboxes::append(&partage, b"jean", b"Inconnue").is_none());
    assert_eq!(
        Mailboxes::create(&partage, b"jean", b"Archives"),
        super::Creation::DejaLa
    );
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

// ── `STORE` ─────────────────────────────────────────────────────────────────

/// **Les trois verbes ne font pas la même chose**, et c'est tout l'intérêt.
#[test]
fn les_trois_verbes_de_store_ecrivent_ce_qu_ils_disent() {
    let mut session = selectionnee();
    // Le message 2 porte déjà `\Seen`.
    let ajout = ecouler(&mut session, b"a003 STORE 2 +FLAGS (\\Flagged)\r\n");
    assert_eq!(
        ajout,
        "* 2 FETCH (FLAGS (\\Seen \\Flagged))\r\na003 OK STORE completed\r\n"
    );
    let retrait = ecouler(&mut session, b"a004 STORE 2 -FLAGS (\\Seen)\r\n");
    assert_eq!(
        retrait,
        "* 2 FETCH (FLAGS (\\Flagged))\r\na004 OK STORE completed\r\n"
    );
    let remplacement = ecouler(&mut session, b"a005 STORE 2 FLAGS (\\Draft)\r\n");
    assert_eq!(
        remplacement,
        "* 2 FETCH (FLAGS (\\Draft))\r\na005 OK STORE completed\r\n"
    );
    // Et `FLAGS ()` efface tout.
    let efface = ecouler(&mut session, b"a006 STORE 2 FLAGS ()\r\n");
    assert_eq!(
        efface,
        "* 2 FETCH (FLAGS ())\r\na006 OK STORE completed\r\n"
    );
}

/// **`.SILENT` ne rend rien, et fait le travail quand même.**
#[test]
fn silent_ecrit_sans_rien_rendre() {
    let mut session = selectionnee();
    let silencieux = ecouler(&mut session, b"a003 STORE 1:3 +FLAGS.SILENT (\\Draft)\r\n");
    assert_eq!(silencieux, "a003 OK STORE completed\r\n");
    // Le travail est fait : un `FETCH` le montre.
    let apres = ecouler(&mut session, b"a004 FETCH 1 FLAGS\r\n");
    assert_eq!(
        apres,
        "* 1 FETCH (FLAGS (\\Draft))\r\na004 OK FETCH completed\r\n"
    );
}

/// **`UID STORE` désigne par UID, et rend le rang.**
#[test]
fn uid_store_designe_par_uid() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID STORE 30 +FLAGS (\\Flagged)\r\n");
    assert_eq!(
        fil,
        "* 3 FETCH (FLAGS (\\Answered \\Flagged))\r\na003 OK UID STORE completed\r\n"
    );
}

/// **Un message annoncé et disparu ne fait pas échouer la commande** (§6.4.6) :
/// le client l'apprend en ne recevant rien pour lui.
#[test]
fn un_message_disparu_ne_fait_pas_echouer_le_store() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    // Le deuxième n'a pas d'`info` : il n'est même pas choisi. Le troisième en
    // a une, et s'efface quand on écrit — deux disparitions différentes, et
    // aucune des deux ne fait échouer la commande.
    let fil = ecouler(&mut session, b"a003 STORE 1:3 +FLAGS (\\Seen)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (FLAGS (\\Seen))\r\na003 OK STORE completed\r\n"
    );
}

/// **On ne promet que ce qui survit.** Un drapeau hors de `PERMANENTFLAGS`
/// serait écrit puis perdu, et le client ne l'apprendrait jamais.
#[test]
fn store_dans_une_boite_en_lecture_seule_se_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Archives\r\n");
    let (texte, action) = dire(&mut session, b"a003 STORE 1 +FLAGS (\\Seen)\r\n");
    assert!(
        texte.contains("NO [CANNOT] This flag does not persist in this mailbox"),
        "{texte}"
    );
    assert_eq!(action, Action::Continue);
}

/// **Un drapeau inconnu est un REFUS, pas un silence.**
#[test]
fn un_drapeau_inconnu_se_refuse_en_le_disant() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 STORE 1 +FLAGS ($Important)\r\n");
    assert!(
        texte.contains("NO [CANNOT] This flag cannot be stored"),
        "{texte}"
    );
}

#[test]
fn un_store_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 STORE\r\n"[..],
        b"a004 STORE 1\r\n",
        b"a005 STORE 1 MARKS (\\Seen)\r\n",
        b"a006 STORE x +FLAGS (\\Seen)\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD STORE arguments are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un ensemble trop long est refusé plutôt que tronqué.**
#[test]
fn un_ensemble_de_store_trop_long_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 STORE "[..]);
    for _ in 0..(super::SEQUENCE_TEXT_MAX / 2) {
        commande.extend_from_slice(b"1,");
    }
    commande.extend_from_slice(b"1 +FLAGS (\\Seen)\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Sequence set is too long"),
        "{texte}"
    );
}

/// **Un `STORE` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_store_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 STORE 1 +FLAGS (\\Seen)\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

/// **§6.4.5 : un corps rendu SANS `PEEK` marque le message comme lu**, et les
/// `FLAGS` de la même réponse le disent.
#[test]
fn un_corps_sans_peek_marque_le_message_et_le_dit() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (FLAGS BODY[])\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (FLAGS (\\Seen) BODY[] {100}\r\n<1:0+100>)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

// ── `EXPUNGE` ───────────────────────────────────────────────────────────────

/// **Chaque `* n EXPUNGE` RENUMÉROTE ce qui suit** (§7.5.1). Effacer les
/// messages 1 et 3 d'une boîte de trois ne rend donc pas « 1 puis 3 », mais
/// « 1 puis 2 » : après le premier, l'ancien troisième est devenu le deuxième.
/// Un serveur qui annoncerait les rangs d'origine ferait effacer au client un
/// message qu'il voulait garder.
#[test]
fn expunge_renumerote_a_mesure_qu_il_efface() {
    let mut session = selectionnee();
    dire(&mut session, b"a003 STORE 1,3 +FLAGS (\\Deleted)\r\n");
    ecouler(&mut session, b"a003 STORE 1,3 +FLAGS (\\Deleted)\r\n");
    let fil = ecouler(&mut session, b"a004 EXPUNGE\r\n");
    assert_eq!(
        fil,
        "* 1 EXPUNGE\r\n* 2 EXPUNGE\r\na004 OK EXPUNGE completed\r\n"
    );
    // Il ne reste que l'ancien deuxième, devenu le premier.
    let reste = ecouler(&mut session, b"a005 FETCH 1:* UID\r\n");
    assert_eq!(reste, "* 1 FETCH (UID 20)\r\na005 OK FETCH completed\r\n");
}

/// **Rien de marqué, rien d'effacé** — et la commande réussit quand même.
#[test]
fn expunge_sans_rien_de_marque_n_efface_rien() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 EXPUNGE\r\n");
    assert_eq!(fil, "a003 OK EXPUNGE completed\r\n");
    let reste = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert!(reste.contains("* 3 FETCH (UID 30)"), "{reste}");
}

/// **`UID EXPUNGE` s'en tient à son ensemble** (§6.4.9) : ce qui est marqué mais
/// hors de l'ensemble RESTE. C'est la commande qu'un client utilise quand il
/// sait que d'autres sessions marquent la même boîte.
#[test]
fn uid_expunge_ne_touche_que_son_ensemble() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 STORE 1:3 +FLAGS (\\Deleted)\r\n");
    let fil = ecouler(&mut session, b"a004 UID EXPUNGE 20\r\n");
    assert_eq!(fil, "* 2 EXPUNGE\r\na004 OK UID EXPUNGE completed\r\n");
    let reste = ecouler(&mut session, b"a005 FETCH 1:* UID\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 10)\r\n* 2 FETCH (UID 30)\r\na005 OK FETCH completed\r\n"
    );
}

/// **`CLOSE` efface, `UNSELECT` non** (§6.4.2 et §6.4.4) : c'est la seule chose
/// qui les distingue, et les confondre ferait effacer du courrier à qui
/// demandait le contraire.
#[test]
fn close_efface_et_unselect_ne_touche_a_rien() {
    for (commande, efface) in [(&b"a004 CLOSE\r\n"[..], 1), (b"a004 UNSELECT\r\n", 0)] {
        let boites = Boites::default();
        let compteur = std::rc::Rc::clone(&boites.efface);
        let mut session = Session::new(BORNES, true, UnCompte, boites);
        session.on_tls_established();
        dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
        dire(&mut session, b"a002 SELECT INBOX\r\n");
        ecouler(&mut session, b"a003 STORE 2 +FLAGS (\\Deleted)\r\n");
        assert_eq!(compteur.get(), 0, "rien ne doit être effacé avant l'ordre");
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains("OK"), "{texte}");
        assert_eq!(compteur.get(), efface, "{commande:?} : {texte}");
    }
}

/// **Un magasin peut refuser d'effacer, et cela ne s'annonce pas.** Entre
/// l'instantané et l'ordre, une autre session a pu retirer la marque : effacer
/// alors, ce serait perdre du courrier. La session passe au suivant sans rien
/// dire — annoncer un effacement qui n'a pas eu lieu ferait perdre au client le
/// fil des numéros de séquence.
#[test]
fn un_message_qui_refuse_de_s_effacer_n_est_pas_annonce() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    ecouler(&mut session, b"a003 STORE 1:3 +FLAGS (\\Deleted)\r\n");
    // Le premier s'efface, le deuxième refuse, le troisième s'efface. Le
    // deuxième ayant pris la place du premier, le troisième est annoncé `2`.
    let fil = ecouler(&mut session, b"a004 EXPUNGE\r\n");
    assert_eq!(
        fil,
        "* 1 EXPUNGE\r\n* 2 EXPUNGE\r\na004 OK EXPUNGE completed\r\n"
    );
    // Et le têtu est bien celui qui reste.
    let reste = ecouler(&mut session, b"a005 FETCH 1:* UID\r\n");
    assert_eq!(reste, "* 1 FETCH (UID 20)\r\na005 OK FETCH completed\r\n");
}

/// **Un message que la boîte annonce sans le rendre n'est pas même choisi.**
/// C'est l'autre disparition, celle qui n'a pas d'`info` — et un parcours qui
/// s'arrêterait sur elle laisserait le reste de la boîte intact.
#[test]
fn un_trou_dans_la_boite_n_arrete_pas_l_effacement() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    ecouler(&mut session, b"a003 STORE 1 +FLAGS (\\Deleted)\r\n");
    let fil = ecouler(&mut session, b"a004 EXPUNGE\r\n");
    assert_eq!(fil, "* 1 EXPUNGE\r\na004 OK EXPUNGE completed\r\n");
}

/// **Une boîte en lecture seule n'efface rien**, et le dit.
#[test]
fn expunge_dans_une_boite_en_lecture_seule_se_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 EXAMINE INBOX\r\n");
    let (texte, action) = dire(&mut session, b"a003 EXPUNGE\r\n");
    assert!(
        texte.contains("NO [CANNOT] Mailbox is read-only"),
        "{texte}"
    );
    assert_eq!(action, Action::Continue);
}

/// **`CLOSE` sur une boîte ouverte en lecture seule n'efface rien** (§6.4.2).
#[test]
fn close_en_lecture_seule_n_efface_rien() {
    let boites = Boites::default();
    let compteur = std::rc::Rc::clone(&boites.efface);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 EXAMINE INBOX\r\n");
    dire(&mut session, b"a003 CLOSE\r\n");
    assert_eq!(compteur.get(), 0);
}

#[test]
fn un_expunge_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for (commande, attendu) in [
        (
            &b"a003 EXPUNGE 1:2\r\n"[..],
            "BAD EXPUNGE takes no arguments",
        ),
        (
            b"a004 UID EXPUNGE\r\n",
            "BAD UID EXPUNGE expects a sequence set",
        ),
        (
            b"a005 UID EXPUNGE x\r\n",
            "BAD EXPUNGE arguments are malformed",
        ),
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains(attendu), "{commande:?} : {texte}");
    }
}

/// **Un ensemble trop long est refusé plutôt que tronqué.**
#[test]
fn un_ensemble_d_expunge_trop_long_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 UID EXPUNGE "[..]);
    for _ in 0..(super::SEQUENCE_TEXT_MAX / 2) {
        commande.extend_from_slice(b"1,");
    }
    commande.extend_from_slice(b"1\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Sequence set is too long"),
        "{texte}"
    );
}

/// **Un `EXPUNGE` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_expunge_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 EXPUNGE\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

// ── `SEARCH` ────────────────────────────────────────────────────────────────

/// **IMAP4rev2 a remplacé `* SEARCH` par `* ESEARCH`** (§7.3.4), et les
/// résultats y sont un ENSEMBLE, pas une liste.
#[test]
fn search_rend_un_esearch_et_comprime_ses_resultats() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH ALL\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") ALL 1:3\r\na003 OK SEARCH completed\r\n"
    );
}

/// **Rien trouvé, rien annoncé** : `ESEARCH` omet `ALL` plutôt que de rendre un
/// ensemble vide, qui ne s'écrit pas.
#[test]
fn une_recherche_sans_resultat_omet_l_ensemble() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH ANSWERED DELETED\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\")\r\na003 OK SEARCH completed\r\n"
    );
}

/// Les plages non contiguës se séparent par une virgule.
#[test]
fn les_resultats_epars_se_separent() {
    let mut session = selectionnee();
    // Les messages 1 et 3 : deux plages d'un seul élément.
    let fil = ecouler(&mut session, b"a003 SEARCH OR 1 3\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") ALL 1,3\r\na003 OK SEARCH completed\r\n"
    );
}

/// **`UID SEARCH` rend des UID**, et le dit dans la réponse (§7.3.4).
#[test]
fn uid_search_rend_des_uid_et_l_annonce() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID SEARCH NOT SEEN\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") UID ALL 10,30\r\na003 OK UID SEARCH completed\r\n"
    );
}

#[test]
fn les_criteres_ordinaires_se_cherchent() {
    let mut session = selectionnee();
    for (commande, attendu) in [
        // Des trois messages d'épreuve, seul le deuxième est `\Seen` et seul le
        // troisième est `\Answered`.
        (&b"a003 SEARCH UNSEEN\r\n"[..], "ALL 1,3"),
        (b"a003 SEARCH SEEN\r\n", "ALL 2"),
        (b"a003 SEARCH LARGER 150\r\n", "ALL 2:3"),
        (b"a003 SEARCH SMALLER 250 SEEN\r\n", "ALL 2"),
        (b"a003 SEARCH NOT SEEN\r\n", "ALL 1,3"),
        (b"a003 SEARCH UID 20:*\r\n", "ALL 2:3"),
        (b"a003 SEARCH 2:*\r\n", "ALL 2:3"),
        (b"a003 SEARCH ANSWERED\r\n", "ALL 3"),
        (b"a003 SEARCH OR SEEN ANSWERED\r\n", "ALL 2:3"),
    ] {
        let fil = ecouler(&mut session, commande);
        assert!(fil.contains(attendu), "{commande:?} : {fil}");
    }
}

/// **Le jeu de caractères est optionnel, et rev2 impose UTF-8.** Chercher dans
/// un encodage qu'on ignore ferait rendre n'importe quoi.
#[test]
fn le_jeu_de_caracteres_se_lit_ou_se_refuse() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH CHARSET UTF-8 SEEN\r\n");
    assert!(fil.contains("ALL 2\r\n"), "{fil}");
    let aussi = ecouler(&mut session, b"a004 SEARCH CHARSET \"US-ASCII\" SEEN\r\n");
    assert!(aussi.contains("ALL 2\r\n"), "{aussi}");
    let (refus, _) = dire(&mut session, b"a005 SEARCH CHARSET ISO-8859-1 SEEN\r\n");
    assert!(
        refus.contains("NO [BADCHARSET (UTF-8 US-ASCII)]"),
        "{refus}"
    );
}

/// **Un critère qu'on ne sert pas est refusé, pas rendu faux.**
#[test]
fn un_critere_de_recherche_non_servi_se_refuse() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 SEARCH SUBJECT facture\r\n");
    assert!(
        texte.contains("NO [CANNOT] This search key is not served yet"),
        "{texte}"
    );
}

#[test]
fn un_search_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 SEARCH\r\n"[..],
        b"a004 SEARCH NOT\r\n",
        b"a005 SEARCH (SEEN\r\n",
        b"a006 SEARCH LARGER x\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD SEARCH arguments are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un critère plus long que ce qu'on retient est refusé plutôt que tronqué.**
#[test]
fn un_critere_trop_long_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 SEARCH "[..]);
    commande.resize(commande.len() + super::SEQUENCE_TEXT_MAX + 1, b'x');
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Search criteria are too long"),
        "{texte}"
    );
}

/// **Une expression trop touffue est une borne, pas une faute de syntaxe.**
#[test]
fn une_expression_trop_touffue_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 SEARCH "[..]);
    for _ in 0..100 {
        commande.extend_from_slice(b"SEEN ");
    }
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Search expression is too complex"),
        "{texte}"
    );

    let mut profonde = std::vec::Vec::from(&b"a004 SEARCH "[..]);
    for _ in 0..32 {
        profonde.extend_from_slice(b"NOT ");
    }
    profonde.extend_from_slice(b"SEEN\r\n");
    let (aussi, _) = dire(&mut session, &profonde);
    assert!(
        aussi.contains("NO [CANNOT] Search expression is too complex"),
        "{aussi}"
    );
}

/// **Un `SEARCH` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_search_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SEARCH ALL\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

/// **Un message que la boîte annonce sans le rendre ne correspond à rien**, et
/// n'arrête pas le parcours.
#[test]
fn un_trou_dans_la_boite_n_arrete_pas_la_recherche() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let fil = ecouler(&mut session, b"a003 SEARCH ALL\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") ALL 1,3\r\na003 OK SEARCH completed\r\n"
    );
}

/// **Une commande de boîte hors sélection est hors d'état, pas hors de
/// service** : `BAD` et non `NO [UNAVAILABLE]`, parce que c'est le client qui
/// l'a demandée au mauvais moment.
#[test]
fn une_commande_de_boite_sans_selection_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 COPY 1 INBOX\r\n"[..], b"a003 MOVE 1 Archives\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed unless a mailbox is selected"),
            "{commande:?} : {texte}"
        );
    }
}

/// **UNE LIGNE `ESEARCH` PEUT ÊTRE PLUS LONGUE QU'UN TAMPON.** C'est la seule
/// réponse du serveur qui ne tienne pas forcément dans un morceau : elle se
/// découpe, et **le découpage ne change pas ce que le client lit**. Un tampon
/// trop court pour avancer d'un seul octet le dit, plutôt que de rendre du vide
/// indéfiniment — ce qui serait une boucle sans fin chez l'appelant.
#[test]
fn une_recherche_se_decoupe_sans_changer_de_resultat() {
    let attendu = "* ESEARCH (TAG \"a003\") ALL 1,3\r\na003 OK SEARCH completed\r\n";
    let mut reference = selectionnee();
    assert_eq!(ecouler(&mut reference, b"a003 SEARCH OR 1 3\r\n"), attendu);

    for taille in 1..=64_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(b"a003 SEARCH OR 1 3\r\n", &mut grand)
            .expect("traitable");
        let mut fil = std::string::String::new();
        let mut petit = std::vec![0_u8; taille];
        let mut refuse = false;
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("une recherche ne rend pas de corps")
                }
                Err(erreur) => {
                    assert!(
                        matches!(erreur, super::Error::Reply(_)),
                        "taille {taille} : {erreur:?}"
                    );
                    refuse = true;
                    break;
                }
            }
        }
        if !refuse {
            assert_eq!(fil, attendu, "taille {taille}");
        }
    }
}

/// **Un tampon peut suffire à l'en-tête et pas à la première plage.** Il faut le
/// dire, plutôt que de rendre indéfiniment du vide à un appelant qui l'écrira
/// indéfiniment — une boucle sans fin chez lui, née d'un tampon chez nous.
///
/// Le cas demande un tag court et des UID longs : `* ESEARCH (TAG "a") UID`
/// tient en vingt-trois octets, ` ALL 4294967294:4294967295` en demande
/// vingt-six.
#[test]
fn un_tampon_qui_suffit_a_l_entete_et_pas_a_la_plage_le_dit() {
    for taille in 23..=25_usize {
        let mut session = nouvelle(true);
        dire(&mut session, b"a LOGIN jean ouvre-toi\r\n");
        dire(&mut session, b"b SELECT Grande\r\n");
        let mut grand = [0_u8; 512];
        session
            .handle(b"a UID SEARCH ALL\r\n", &mut grand)
            .expect("traitable");
        let mut petit = std::vec![0_u8; taille];
        // Le premier morceau passe : c'est l'en-tête.
        let premier = session.next_fetch(&mut petit).expect("émettable");
        assert!(premier.is_some(), "taille {taille}");
        // Le second ne peut rien écrire, et le dit.
        let second = session.next_fetch(&mut petit);
        assert!(
            matches!(second, Err(super::Error::Reply(_))),
            "taille {taille} : {second:?}"
        );
    }
    // Vingt-six octets suffisent à la plage ; la conclusion étiquetée, elle,
    // en demande vingt-sept, et c'est un morceau comme les autres.
    let mut session = nouvelle(true);
    dire(&mut session, b"a LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"b SELECT Grande\r\n");
    let mut grand = [0_u8; 512];
    session
        .handle(b"a UID SEARCH ALL\r\n", &mut grand)
        .expect("traitable");
    let mut fil = std::string::String::new();
    let mut petit = [0_u8; 27];
    while let Some(morceau) = session.next_fetch(&mut petit).expect("émettable") {
        if let super::FetchChunk::Bytes(octets) = morceau {
            fil.push_str(&std::string::String::from_utf8_lossy(octets));
        }
    }
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a\") UID ALL 4294967294:4294967295\r\na OK UID SEARCH completed\r\n"
    );
}

// ── `COPY` ──────────────────────────────────────────────────────────────────

/// **§6.4.7 : `COPYUID` dit au client OÙ ses messages ont atterri**, et les deux
/// ensembles se lisent dans le même ordre.
#[test]
fn copy_rend_un_copyuid_qui_apparie_source_et_destination() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 1:2 INBOX\r\n");
    // 10 et 20 ne se suivent pas : deux plages d'un élément, séparées.
    assert_eq!(texte, "a003 OK [COPYUID 42 10,20 31:32] COPY completed\r\n");
    // Les copies sont bien là, à la suite.
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert!(fil.contains("* 4 FETCH (UID 31)"), "{fil}");
    assert!(fil.contains("* 5 FETCH (UID 32)"), "{fil}");
}

/// L'ensemble source est celui que le client a désigné, TROUS COMPRIS.
#[test]
fn copyuid_nomme_les_uid_epars_de_la_source() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 1,3 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 10,30 31:32] COPY completed\r\n");
}

/// **`UID COPY` désigne par UID**, et le dit dans sa conclusion.
#[test]
fn uid_copy_designe_par_uid() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID COPY 30 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 30 31] UID COPY completed\r\n");
}

/// **§6.4.7 : une destination qui n'existe pas se dit `[TRYCREATE]`.** C'est le
/// code qui apprend au client qu'un `CREATE` suivi du même `COPY` marcherait.
#[test]
fn une_destination_inconnue_se_dit_trycreate() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 1 Inconnue\r\n");
    assert!(
        texte.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{texte}"
    );
}

/// **§6.4.7 : un `COPY` n'est pas partiellement réussi.** Ce qui a été copié
/// avant l'échec est défait, et le client peut recommencer sans faire de
/// doublons.
#[test]
fn un_copy_qui_echoue_defait_ce_qu_il_avait_fait() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    // Le deuxième message refuse d'être copié ; le premier ne doit pas rester.
    let (texte, _) = dire(&mut session, b"a003 COPY 1:3 INBOX\r\n");
    assert!(
        texte.contains("NO Copy failed; no messages were copied"),
        "{texte}"
    );
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(fil.matches("* ").count(), 3, "{fil}");
}

/// Rien à copier n'est pas un échec, et ne s'accompagne d'aucun `COPYUID`.
#[test]
fn un_copy_qui_ne_designe_rien_reussit_sans_rien_dire() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 9 INBOX\r\n");
    assert_eq!(texte, "a003 OK COPY completed\r\n");
}

#[test]
fn un_copy_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 COPY\r\n"[..],
        b"a004 COPY 1\r\n",
        b"a005 COPY x INBOX\r\n",
        b"a006 COPY 1 \r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD COPY expects a sequence set and a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un ensemble source trop long fait OMETTRE `COPYUID`**, jamais le tronquer :
/// un ensemble tronqué désignerait d'autres messages que ceux qu'on a copiés.
#[test]
fn un_copyuid_qui_deborde_est_omis_entierement() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Eparse\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 1:* INBOX\r\n");
    assert_eq!(texte, "a003 OK COPY completed\r\n");
}

/// **Des UID qui se suivent se comprime en plage**, et non en liste.
#[test]
fn copyuid_comprime_une_source_contigue() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Suite\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 1:3 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 5:7 8:10] COPY completed\r\n");
}

/// **Un message que la boîte annonce sans le rendre n'est pas copié**, et
/// n'arrête pas la copie des autres.
#[test]
fn un_trou_dans_la_boite_n_arrete_pas_la_copie() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 1:3 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 1,3 4:5] COPY completed\r\n");
}

/// Le premier message qui échoue n'a rien à défaire derrière lui.
#[test]
fn un_copy_qui_echoue_au_premier_ne_defait_rien() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 2 INBOX\r\n");
    assert!(
        texte.contains("NO Copy failed; no messages were copied"),
        "{texte}"
    );
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(fil.matches("* ").count(), 3, "{fil}");
}

/// Un `UID COPY` qui ne désigne rien réussit, et le nomme.
#[test]
fn un_uid_copy_qui_ne_designe_rien_le_nomme() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID COPY 999 INBOX\r\n");
    assert_eq!(texte, "a003 OK UID COPY completed\r\n");
}

/// Le débordement du `COPYUID` vaut aussi pour un `UID COPY`.
#[test]
fn un_uid_copy_qui_deborde_omet_aussi_son_copyuid() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Eparse\r\n");
    let (texte, _) = dire(&mut session, b"a003 UID COPY 1:* INBOX\r\n");
    assert_eq!(texte, "a003 OK UID COPY completed\r\n");
}

// ── `MOVE` ──────────────────────────────────────────────────────────────────

/// **§6.4.8 impose l'ordre des réponses** : d'abord `* OK [COPYUID …]`, qui dit
/// où les messages sont allés ; puis les `* n EXPUNGE`, qui disent qu'ils ne
/// sont plus là ; enfin la conclusion.
#[test]
fn move_dit_ou_avant_de_dire_que_ce_n_est_plus_la() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 MOVE 1:2 INBOX\r\n");
    assert_eq!(
        fil,
        "* OK [COPYUID 42 10,20 31:32] Moved\r\n\
         * 1 EXPUNGE\r\n* 1 EXPUNGE\r\n\
         a003 OK MOVE completed\r\n"
    );
    // Il reste l'ancien troisième et les deux copies.
    let reste = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 30)\r\n* 2 FETCH (UID 31)\r\n* 3 FETCH (UID 32)\r\n\
         a004 OK FETCH completed\r\n"
    );
}

/// **On retire par UID, même quand le client a désigné des rangs.** Retirer
/// renumérote : un ensemble de rangs cesserait de désigner ce qu'il désignait
/// dès le premier retrait, et l'on retirerait des messages que personne n'a
/// nommés.
#[test]
fn move_retire_ceux_qu_on_a_nommes_et_pas_leurs_voisins() {
    let mut session = selectionnee();
    // On déplace le PREMIER seulement : le deuxième ne doit pas suivre.
    let fil = ecouler(&mut session, b"a003 MOVE 1 INBOX\r\n");
    assert_eq!(
        fil,
        "* OK [COPYUID 42 10 31] Moved\r\n* 1 EXPUNGE\r\na003 OK MOVE completed\r\n"
    );
    let reste = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 20)\r\n* 2 FETCH (UID 30)\r\n* 3 FETCH (UID 31)\r\n\
         a004 OK FETCH completed\r\n"
    );
}

/// **`UID MOVE` désigne par UID**, et le dit dans sa conclusion.
#[test]
fn uid_move_designe_par_uid() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID MOVE 30 INBOX\r\n");
    assert_eq!(
        fil,
        "* OK [COPYUID 42 30 31] Moved\r\n* 3 EXPUNGE\r\na003 OK UID MOVE completed\r\n"
    );
}

/// **§6.4.8 : une destination qui n'existe pas se dit `[TRYCREATE]`.**
#[test]
fn une_destination_inconnue_se_dit_trycreate_aussi_pour_move() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 MOVE 1 Inconnue\r\n");
    assert!(
        texte.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{texte}"
    );
}

/// **Un `MOVE` qui ne peut pas tout copier ne déplace rien**, et défait ses
/// copies : rien n'est retiré de la source.
#[test]
fn un_move_qui_echoue_ne_retire_rien() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    let (texte, _) = dire(&mut session, b"a003 MOVE 1:3 INBOX\r\n");
    assert!(
        texte.contains("NO Move failed; no messages were moved"),
        "{texte}"
    );
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(fil.matches("* ").count(), 3, "{fil}");
}

/// Rien à déplacer n'est pas un échec.
#[test]
fn un_move_qui_ne_designe_rien_reussit() {
    let mut session = selectionnee();
    let (texte, action) = dire(&mut session, b"a003 MOVE 9 INBOX\r\n");
    assert_eq!(texte, "a003 OK MOVE completed\r\n");
    assert_eq!(action, Action::Continue);
    let (aussi, _) = dire(&mut session, b"a004 UID MOVE 999 INBOX\r\n");
    assert_eq!(aussi, "a004 OK UID MOVE completed\r\n");
}

/// **Un ensemble qu'on ne saurait plus nommer fait REFUSER le déplacement**, et
/// défaire les copies : retirer au hasard serait perdre du courrier.
#[test]
fn un_move_dont_l_ensemble_est_trop_morcele_se_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Eparse\r\n");
    let (texte, _) = dire(&mut session, b"a003 MOVE 1:* INBOX\r\n");
    assert!(
        texte.contains("NO [CANNOT] Move set is too fragmented"),
        "{texte}"
    );
    // La source est intacte : soixante messages, et pas un de plus.
    let fil = ecouler(&mut session, b"a004 SEARCH ALL\r\n");
    assert!(fil.contains("ALL 1:60"), "{fil}");
}

#[test]
fn un_move_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 MOVE\r\n"[..],
        b"a004 MOVE 1\r\n",
        b"a005 MOVE x INBOX\r\n",
        b"a006 MOVE 1 \r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD MOVE expects a sequence set and a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un `MOVE` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_move_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 MOVE 1 INBOX\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

// ── `APPEND` ────────────────────────────────────────────────────────────────

/// Conduit un `APPEND` de bout en bout, et rend la conclusion.
fn deposer(
    session: &mut Session<UnCompte, Boites>,
    ligne: &[u8],
    message: &[u8],
) -> std::string::String {
    let mut sortie = [0_u8; 1024];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("un APPEND qu'on sait écouler");
    let tour = session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    if tour.action() != Action::ReadAppend {
        // Refusé avant d'avoir rien lu : c'est l'intérêt du synchronisant.
        return std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    }
    // On écoule par petits morceaux : c'est ce que fait la boucle.
    let mut reste = message;
    while !reste.is_empty() && session.append_remaining() > 0 {
        let coupe = reste.len().min(7);
        let pris = session.append_chunk(reste.get(..coupe).unwrap_or_default());
        reste = reste.get(pris..).unwrap_or_default();
    }
    let fin = session.end_append(&mut sortie).expect("traitable");
    std::string::String::from_utf8_lossy(fin.reply()).into_owned()
}

/// **§6.3.12 : `APPENDUID` dit où le message est allé.**
#[test]
fn append_depose_le_message_et_dit_ou() {
    let boites = Boites::default();
    let ecrit = std::rc::Rc::clone(&boites.ecrit);
    let valide = std::rc::Rc::clone(&boites.valide);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(
        &mut session,
        b"a002 APPEND INBOX {13}\r\n",
        b"Bonjour !\r\n\r\n",
    );
    assert_eq!(conclusion, "a002 OK [APPENDUID 42 31] APPEND completed\r\n");
    assert_eq!(&*ecrit.borrow(), b"Bonjour !\r\n\r\n");
    assert_eq!(valide.get(), Some((31, Flags::NONE, None)));
}

/// **Les drapeaux et la date suivent le message** (§6.3.12).
#[test]
fn les_drapeaux_et_la_date_arrivent_avec_le_message() {
    let boites = Boites::default();
    let valide = std::rc::Rc::clone(&boites.valide);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(
        &mut session,
        b"a002 APPEND INBOX (\\Seen \\Draft) \"29-Aug-2026 07:08:31 +0000\" {5}\r\n",
        b"salut",
    );
    assert!(conclusion.contains("OK [APPENDUID 42 31]"), "{conclusion}");
    let (uid, flags, date) = valide.get().expect("validé");
    assert_eq!(uid, 31);
    assert!(flags.contains(Flags::SEEN));
    assert!(flags.contains(Flags::DRAFT));
    assert_eq!(date, Some(1_787_987_311));
}

/// **On lit même ce qu'on refuse.** Les octets d'un littéral non synchronisant
/// arrivent quoi qu'on réponde ; ne pas les lire ferait lire un message comme
/// des commandes. Un littéral SYNCHRONISANT, lui, se refuse avant d'inviter :
/// inviter puis refuser ferait attendre le serveur pour des octets que le client
/// n'enverra jamais.
#[test]
fn une_boite_inconnue_se_dit_trycreate_apres_avoir_tout_lu() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    // Non synchronisant : les octets arrivent quoi qu'on réponde.
    let conclusion = deposer(&mut session, b"a002 APPEND Inconnue {5+}\r\n", b"salut");
    assert!(
        conclusion.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{conclusion}"
    );
    assert_eq!(session.append_remaining(), 0);

    // Le même, synchronisant : refusé sans qu'un octet ait été lu.
    let mut sortie = [0_u8; 1024];
    let ligne = &b"a003 APPEND Inconnue {5}\r\n"[..];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("écoulable");
    let tour = session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    assert_eq!(tour.action(), Action::Continue);
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(texte.contains("NO [TRYCREATE]"), "{texte}");
    assert_eq!(session.append_remaining(), 0);
}

/// **Un magasin qui lâche en route ne fait pas cesser la lecture** : les octets
/// restants sont un message, pas des commandes.
#[test]
fn un_magasin_qui_lache_ne_fait_pas_cesser_la_lecture() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(
        &mut session,
        b"a002 APPEND Refusante {9}\r\n",
        b"un message",
    );
    assert!(
        conclusion.contains("NO Append failed; the message was not stored"),
        "{conclusion}"
    );
    assert_eq!(session.append_remaining(), 0);
}

/// Un dépôt qui refuse de se valider est un échec, pas un succès muet.
#[test]
fn un_depot_qui_refuse_de_se_valider_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(&mut session, b"a002 APPEND Ingrate {5}\r\n", b"salut");
    assert!(
        conclusion.contains("NO Append failed; the message was not stored"),
        "{conclusion}"
    );
}

/// **VALIDER UN MESSAGE TRONQUÉ serait déposer du courrier que personne n'a
/// envoyé.** Le pair a raccroché au milieu : rien ne se dépose.
#[test]
fn un_message_tronque_ne_se_depose_pas() {
    let boites = Boites::default();
    let ecrit = std::rc::Rc::clone(&boites.ecrit);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let mut sortie = [0_u8; 1024];
    let ligne = &b"a002 APPEND INBOX {20}\r\n"[..];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("écoulable");
    session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    session.append_chunk(b"court");
    assert_eq!(session.append_remaining(), 15);
    let fin = session.end_append(&mut sortie).expect("traitable");
    let conclusion = std::string::String::from_utf8_lossy(fin.reply()).into_owned();
    assert!(
        conclusion.contains("NO Append failed; the message was not stored"),
        "{conclusion}"
    );
    // Le dépôt a été abandonné : il n'en subsiste rien.
    assert!(ecrit.borrow().is_empty());
}

/// **Un `APPEND` avant authentification n'est pas un `APPEND`.**
#[test]
fn un_append_avant_authentification_est_refuse() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 1024];
    let ligne = &b"a001 APPEND INBOX {5}\r\n"[..];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("écoulable");
    let tour = session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
    assert_eq!(tour.action(), Action::Continue);

    // Non synchronisant : les octets arrivent, on les jette, et l'on répond à la
    // fin.
    let conclusion = deposer(&mut session, b"a002 APPEND INBOX {5+}\r\n", b"salut");
    assert!(
        conclusion.contains("BAD Command is not allowed before authentication"),
        "{conclusion}"
    );
}

/// Conclure un `APPEND` qu'on n'a pas commencé n'est pas un `APPEND`.
#[test]
fn conclure_un_append_qui_n_existe_pas_est_une_faute() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 1024];
    let fin = session.end_append(&mut sortie).expect("traitable");
    let texte = std::string::String::from_utf8_lossy(fin.reply()).into_owned();
    assert!(texte.contains("BAD No APPEND in progress"), "{texte}");
    // Et écouler sans dépôt ne consomme rien.
    assert_eq!(session.append_chunk(b"x"), 0);
}

/// **Un `APPEND` qui passe par le chemin ordinaire n'est pas celui qu'on sait
/// écouler** : c'est un nom de boîte donné comme littéral, ou pas de littéral
/// du tout.
#[test]
fn un_append_du_chemin_ordinaire_se_refuse_en_le_disant() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 APPEND INBOX\r\n");
    assert!(
        texte.contains("BAD APPEND expects a mailbox name and a message literal"),
        "{texte}"
    );
}

// ── `CREATE` ────────────────────────────────────────────────────────────────

/// **Une boîte créée se voit** : `LIST` la rend, et `SELECT` l'ouvre.
#[test]
fn une_boite_creee_apparait_dans_la_liste() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE Brouillons\r\n");
    assert!(texte.contains("a002 OK CREATE completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        liste.contains("* LIST () \"/\" \"Brouillons\"\r\n"),
        "{liste}"
    );
}

/// **§6.3.4 : `INBOX` existe toujours**, et ne se crée donc pas.
#[test]
fn inbox_ne_se_cree_pas() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 CREATE INBOX\r\n"[..], b"a003 CREATE inbox\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("NO [ALREADYEXISTS] INBOX always exists"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Une boîte qui existe déjà se dit `[ALREADYEXISTS]`** (§6.3.4).
#[test]
fn une_boite_deja_la_se_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE Archives\r\n");
    assert!(
        texte.contains("NO [ALREADYEXISTS] Mailbox already exists"),
        "{texte}"
    );
    // Et deux fois la même création, aussi.
    dire(&mut session, b"a003 CREATE Neuve\r\n");
    let (deux, _) = dire(&mut session, b"a004 CREATE Neuve\r\n");
    assert!(deux.contains("NO [ALREADYEXISTS]"), "{deux}");
}

/// **Un nom qu'on ne sait pas transcrire est REFUSÉ, pas transformé.** Rendre au
/// client un nom qui n'est pas celui qu'il a demandé lui ferait chercher
/// longtemps — et transcrire, c'est ouvrir la porte à ce qu'on ne voit pas.
#[test]
fn un_nom_dangereux_se_refuse_sans_le_transformer() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for nom in [
        &b"\"../etc\""[..],
        b"\"a/../b\"",
        b"\"Sent.2026\"",
        b"\"a//b\"",
        b"\"/absolu\"",
        b"\"a%b\"",
    ] {
        let mut commande = std::vec::Vec::from(&b"a002 CREATE "[..]);
        commande.extend_from_slice(nom);
        commande.extend_from_slice(b"\r\n");
        let (texte, _) = dire(&mut session, &commande);
        assert!(
            texte.contains("NO [CANNOT] This mailbox name is not served"),
            "{:?} : {texte}",
            core::str::from_utf8(nom)
        );
    }
}

/// **« Sent Messages » est un nom de dossier des plus ordinaires**, et la
/// réponse le cite entre guillemets plutôt que de le rendre nu — deux mots là où
/// il y en a un se liraient mal.
#[test]
fn un_nom_avec_un_espace_se_cree_et_se_cite() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE \"Sent Messages\"\r\n");
    assert!(texte.contains("a002 OK CREATE completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        liste.contains("* LIST () \"/\" \"Sent Messages\"\r\n"),
        "{liste}"
    );
}

/// Un `/` final ne change pas la boîte désignée (§6.3.4).
#[test]
fn un_slash_final_ne_change_pas_la_boite() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE \"Archives/\"\r\n");
    assert!(texte.contains("NO [ALREADYEXISTS]"), "{texte}");
}

/// Un magasin qui refuse le dit, et ce n'est pas une faute du client.
#[test]
fn un_magasin_qui_refuse_de_creer_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE Impossible\r\n");
    assert!(texte.contains("NO Cannot create mailbox"), "{texte}");
}

#[test]
fn un_create_mal_forme_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 CREATE\r\n"[..], b"a003 CREATE \r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD CREATE expects a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un `CREATE` avant authentification n'est pas un `CREATE`.**
#[test]
fn un_create_avant_authentification_est_refuse() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 CREATE Brouillons\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}
