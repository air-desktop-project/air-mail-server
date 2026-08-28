//! Ce que la session POP3 doit tenir.

use super::{Action, Error, Mailbox, Session};
use crate::Authenticator;
use ams_proto_pop3::{Limits, MessageNumber};
use ams_sasl::Credentials;

/// Le seul compte que la politique de test connaisse.
const COMPTE: &[u8] = b"jean";
/// Son mot de passe.
const SECRET: &[u8] = b"ouvre-toi";

/// Une politique qui connaît un compte.
struct UnCompte;

impl Authenticator for UnCompte {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        credentials.authentication_identity == COMPTE && credentials.password == SECRET
    }
}

/// Une boîte en mémoire, dont on peut effacer des messages.
#[derive(Debug, Clone)]
struct Boite {
    tailles: std::vec::Vec<u64>,
    effaces: std::vec::Vec<bool>,
}

impl Boite {
    fn nouvelle(tailles: &[u64]) -> Self {
        Self {
            tailles: tailles.to_vec(),
            effaces: std::vec![false; tailles.len()],
        }
    }

    /// Le rang dans le tableau, ou `None` si le message n'existe pas.
    ///
    /// TOTAL : un `MessageNumber` ne vaut jamais zéro, donc le retrait ne
    /// déborde pas, et `saturating_sub` le dit sans ouvrir une branche que rien
    /// ne pourrait emprunter.
    fn rang(&self, message: MessageNumber) -> Option<usize> {
        let rang = usize::try_from(message.value().saturating_sub(1)).unwrap_or(usize::MAX);
        (rang < self.tailles.len()).then_some(rang)
    }
}

impl Mailbox for Boite {
    fn highest(&self) -> u32 {
        u32::try_from(self.tailles.len()).unwrap_or(u32::MAX)
    }

    fn size(&self, message: MessageNumber) -> Option<u64> {
        let rang = self.rang(message)?;
        (!self.effaces[rang]).then(|| self.tailles[rang])
    }

    fn uid(&self, message: MessageNumber) -> Option<u32> {
        let rang = self.rang(message)?;
        // Cent fois le numéro, pour qu'aucun test ne confonde un UID et un rang.
        (!self.effaces[rang]).then(|| message.value().saturating_mul(100))
    }

    fn mark_deleted(&mut self, message: MessageNumber) -> bool {
        let Some(rang) = self.rang(message) else {
            return false;
        };
        if self.effaces[rang] {
            return false;
        }
        self.effaces[rang] = true;
        true
    }

    fn reset_deletions(&mut self) {
        self.effaces.fill(false);
    }
}

fn session() -> Session<UnCompte, Boite> {
    Session::new(Limits::DEFAULT, true, UnCompte)
}

/// Joue une ligne et rend la réponse.
fn jouer(session: &mut Session<UnCompte, Boite>, ligne: &[u8]) -> std::string::String {
    let mut tampon = [0_u8; 512];
    let tour = session.handle(ligne, &mut tampon).expect("réponse");
    std::string::String::from_utf8(tour.reply().to_vec()).expect("réponse ASCII")
}

/// Amène une session jusqu'à TRANSACTION, boîte ouverte.
fn ouvrir(tailles: &[u64]) -> Session<UnCompte, Boite> {
    let mut session = session();
    session.on_tls_established();
    jouer(&mut session, b"USER jean\r\n");
    let mut tampon = [0_u8; 512];
    let tour = session
        .handle(b"PASS ouvre-toi\r\n", &mut tampon)
        .expect("réponse");
    assert_eq!(tour.action(), Action::OpenMailbox);
    session
        .on_mailbox_opened(Some(Boite::nouvelle(tailles)), &mut tampon)
        .expect("ouverture");
    session
}

/// Toutes les lignes d'une réponse multiligne, terminateur compris.
fn multiligne(session: &mut Session<UnCompte, Boite>) -> std::vec::Vec<std::string::String> {
    let mut lignes = std::vec::Vec::new();
    let mut tampon = [0_u8; 512];
    // ON BOUCLE JUSQU'À `None`, et pas jusqu'au terminateur : c'est le contrat
    // que l'appelant tiendra, et s'arrêter plus tôt cachait que la session
    // refusait l'appel d'après. Le pilote, lui, prenait ce refus pour une panne.
    while let Some(ligne) = session.next_listing(&mut tampon).expect("ligne") {
        lignes.push(std::string::String::from_utf8_lossy(ligne).into_owned());
        assert!(lignes.len() < 100, "listing sans fin");
    }
    lignes
}

// ── AUTHORIZATION ───────────────────────────────────────────────────────────

#[test]
fn la_banniere_ne_porte_aucun_horodatage_apop() {
    // Un horodatage entre chevrons est l'INVITATION à faire `APOP`, que C6
    // exclut. L'y mettre ferait essayer un mécanisme qu'on refusera.
    let session = session();
    let mut tampon = [0_u8; 128];
    let banniere = session.greeting(&mut tampon).expect("bannière");
    assert_eq!(banniere, b"+OK POP3 server ready\r\n");
    assert!(!banniere.contains(&b'<'));
}

#[test]
fn user_et_pass_sont_refuses_hors_chiffrement() {
    // C6, ET CE N'EST PAS UN RÉGLAGE : le mot de passe traverse le fil tel quel.
    let mut session = session();
    assert_eq!(
        jouer(&mut session, b"USER jean\r\n"),
        "-ERR Encryption required\r\n"
    );
    assert_eq!(
        jouer(&mut session, b"PASS ouvre-toi\r\n"),
        "-ERR Encryption required\r\n"
    );
}

#[test]
fn stls_puis_user_et_pass_ouvrent_la_session() {
    let mut session = session();
    let mut tampon = [0_u8; 512];
    let tour = session.handle(b"STLS\r\n", &mut tampon).expect("réponse");
    assert_eq!(tour.action(), Action::StartTls);
    session.on_tls_established();
    assert!(session.is_encrypted());

    assert_eq!(jouer(&mut session, b"USER jean\r\n"), "+OK Send PASS\r\n");
    let tour = session
        .handle(b"PASS ouvre-toi\r\n", &mut tampon)
        .expect("réponse");
    assert_eq!(tour.action(), Action::OpenMailbox);
    assert_eq!(session.user(), COMPTE);

    let tour = session
        .on_mailbox_opened(Some(Boite::nouvelle(&[10])), &mut tampon)
        .expect("ouverture");
    assert_eq!(tour.reply(), b"+OK Mailbox open\r\n");
    assert!(session.is_open());
}

#[test]
fn la_poignee_de_main_efface_ce_qui_a_ete_dit_en_clair() {
    // RFC 2595 §4 : un `USER` d'avant le chiffrement a pu être dit par
    // quelqu'un d'autre.
    let mut session = session();
    session.on_tls_established();
    jouer(&mut session, b"USER jean\r\n");
    session.on_tls_established();
    assert_eq!(
        jouer(&mut session, b"PASS ouvre-toi\r\n"),
        "-ERR Send USER first\r\n"
    );
}

#[test]
fn un_mot_de_passe_faux_oublie_le_nom_et_ne_dit_pas_pourquoi() {
    // « Compte inconnu » et « mot de passe faux » sont deux réponses
    // différentes, et cette différence est un annuaire pour qui la mesure.
    let mut session = session();
    session.on_tls_established();
    jouer(&mut session, b"USER jean\r\n");
    let mut tampon = [0_u8; 512];
    let tour = session
        .handle(b"PASS autre\r\n", &mut tampon)
        .expect("réponse");
    assert_eq!(tour.reply(), b"-ERR Authentication failed\r\n");
    // ET C'EST UNE FAUTE (C8) : mille mots de passe par minute doivent finir par
    // fermer la porte.
    assert!(tour.peer_fault());
    // Le nom est oublié : le pair recommence par `USER`.
    assert_eq!(
        jouer(&mut session, b"PASS ouvre-toi\r\n"),
        "-ERR Send USER first\r\n"
    );

    // Un compte INCONNU obtient exactement la même réponse.
    jouer(&mut session, b"USER paul\r\n");
    assert_eq!(
        jouer(&mut session, b"PASS ouvre-toi\r\n"),
        "-ERR Authentication failed\r\n"
    );
}

#[test]
fn un_nom_plus_long_que_tout_compte_possible_est_refuse() {
    let mut session = session();
    session.on_tls_established();
    let long = std::format!("USER {}\r\n", "a".repeat(65));
    // La grammaire le refuse d'abord : sa borne d'argument est la même que celle
    // du magasin de comptes, et un nom plus long ne peut correspondre à rien.
    assert_eq!(
        jouer(&mut session, long.as_bytes()),
        "-ERR Invalid command\r\n"
    );
}

#[test]
fn une_boite_indisponible_renvoie_a_l_autorisation() {
    // Verrouillée par une autre session, ou illisible. Le pair pourra
    // réessayer, et c'est ce que la RFC 1939 §4 prévoit.
    let mut session = session();
    session.on_tls_established();
    jouer(&mut session, b"USER jean\r\n");
    let mut tampon = [0_u8; 512];
    session
        .handle(b"PASS ouvre-toi\r\n", &mut tampon)
        .expect("réponse");
    let tour = session
        .on_mailbox_opened(None, &mut tampon)
        .expect("refus d'ouverture");
    assert_eq!(tour.reply(), b"-ERR Mailbox unavailable\r\n");
    assert!(!session.is_open());
    assert_eq!(
        jouer(&mut session, b"STAT\r\n"),
        "-ERR Command not valid in this state\r\n"
    );
}

#[test]
fn stls_ne_se_repete_pas_et_n_existe_pas_sans_de_quoi_chiffrer() {
    let mut session = session();
    session.on_tls_established();
    assert_eq!(
        jouer(&mut session, b"STLS\r\n"),
        "-ERR Already using TLS\r\n"
    );

    let mut sans = Session::new(Limits::DEFAULT, false, UnCompte);
    assert_eq!(
        jouer(&mut sans, b"STLS\r\n"),
        "-ERR Command not supported\r\n"
    );
}

#[test]
fn les_capacites_disent_ce_qui_est_reellement_servi() {
    // RFC 2449 §5. Annoncer `USER` en clair inviterait à envoyer un mot de passe
    // que l'on refusera.
    let mut session = session();
    let mut tampon = [0_u8; 512];
    let tour = session.handle(b"CAPA\r\n", &mut tampon).expect("réponse");
    assert_eq!(tour.action(), Action::SendListing);
    assert_eq!(
        multiligne(&mut session),
        ["TOP\r\n", "UIDL\r\n", "STLS\r\n", ".\r\n"]
    );

    // Une fois chiffré : `USER` apparaît, `STLS` disparaît.
    session.on_tls_established();
    session.handle(b"CAPA\r\n", &mut tampon).expect("réponse");
    assert_eq!(
        multiligne(&mut session),
        ["TOP\r\n", "UIDL\r\n", "USER\r\n", ".\r\n"]
    );
}

#[test]
fn un_quit_depuis_l_autorisation_n_efface_rien() {
    // L'état UPDATE n'est atteint que depuis TRANSACTION (RFC 1939 §6), et
    // l'inverse perdrait du courrier sur une coupure réseau.
    let mut session = session();
    let mut tampon = [0_u8; 512];
    let tour = session.handle(b"QUIT\r\n", &mut tampon).expect("réponse");
    assert_eq!(tour.action(), Action::Close);
    assert_eq!(
        session.handle(b"NOOP\r\n", &mut tampon),
        Err(Error::SessionClosed)
    );
}

// ── TRANSACTION ─────────────────────────────────────────────────────────────

#[test]
fn noop_repond_avant_meme_l_ouverture() {
    // RFC 1939 §5 : `NOOP` est licite dans les deux états. C'est ce qu'un client
    // envoie pour tenir la connexion ouverte, et refuser en AUTHORIZATION
    // n'aurait aucun sens.
    let mut session = session();
    assert_eq!(jouer(&mut session, b"NOOP\r\n"), "+OK\r\n");
}

#[test]
fn stat_compte_les_messages_et_leurs_octets() {
    let mut session = ouvrir(&[100, 200, 300]);
    assert_eq!(jouer(&mut session, b"STAT\r\n"), "+OK 3 600\r\n");
    // Un message effacé ne compte plus (RFC 1939 §5).
    jouer(&mut session, b"DELE 2\r\n");
    assert_eq!(jouer(&mut session, b"STAT\r\n"), "+OK 2 400\r\n");
}

#[test]
fn list_et_uidl_repondent_pour_un_message_ou_pour_tous() {
    let mut session = ouvrir(&[100, 200]);
    assert_eq!(jouer(&mut session, b"LIST 2\r\n"), "+OK 2 200\r\n");
    // L'UIDL n'est PAS la taille : cent fois le numéro, dans cette boîte de test.
    assert_eq!(jouer(&mut session, b"UIDL 2\r\n"), "+OK 2 200\r\n");

    let mut tampon = [0_u8; 512];
    session.handle(b"LIST\r\n", &mut tampon).expect("réponse");
    assert_eq!(
        multiligne(&mut session),
        ["1 100\r\n", "2 200\r\n", ".\r\n"]
    );

    session.handle(b"UIDL\r\n", &mut tampon).expect("réponse");
    assert_eq!(
        multiligne(&mut session),
        ["1 100\r\n", "2 200\r\n", ".\r\n"]
    );
}

#[test]
fn un_message_efface_disparait_des_listes_sans_renumeroter_les_autres() {
    // RFC 1939 §5 : les numéros sont STABLES pendant toute la session. Un
    // message effacé laisse son numéro inoccupé — renuméroter ferait désigner
    // au pair un message pour un autre.
    let mut session = ouvrir(&[100, 200, 300]);
    jouer(&mut session, b"DELE 2\r\n");
    let mut tampon = [0_u8; 512];
    session.handle(b"LIST\r\n", &mut tampon).expect("réponse");
    assert_eq!(
        multiligne(&mut session),
        ["1 100\r\n", "3 300\r\n", ".\r\n"]
    );
    assert_eq!(
        jouer(&mut session, b"LIST 2\r\n"),
        "-ERR No such message\r\n"
    );
}

#[test]
fn dele_ne_marque_qu_une_fois_et_rset_oublie_tout() {
    let mut session = ouvrir(&[100, 200]);
    assert_eq!(
        jouer(&mut session, b"DELE 1\r\n"),
        "+OK Message deleted\r\n"
    );
    assert_eq!(
        jouer(&mut session, b"DELE 1\r\n"),
        "-ERR No such message\r\n"
    );
    assert_eq!(
        jouer(&mut session, b"DELE 9\r\n"),
        "-ERR No such message\r\n"
    );
    assert_eq!(jouer(&mut session, b"RSET\r\n"), "+OK Deletions reset\r\n");
    assert_eq!(jouer(&mut session, b"STAT\r\n"), "+OK 2 300\r\n");
}

#[test]
fn noop_repond_sans_texte_en_trop() {
    let mut session = ouvrir(&[100]);
    assert_eq!(jouer(&mut session, b"NOOP\r\n"), "+OK\r\n");
}

#[test]
fn un_quit_depuis_la_transaction_demande_d_appliquer_les_effacements() {
    let mut session = ouvrir(&[100]);
    jouer(&mut session, b"DELE 1\r\n");
    let mut tampon = [0_u8; 512];
    let tour = session.handle(b"QUIT\r\n", &mut tampon).expect("réponse");
    assert_eq!(tour.action(), Action::CommitAndClose);

    // ET L'APPELANT REPREND LA BOÎTE pour effacer. Elle ne revient pas : la
    // session est close, il n'y a plus rien à servir, et la laisser en place
    // inviterait à s'en servir après coup.
    let reprise = session.take_mailbox().expect("la boîte devait être là");
    assert!(reprise.effaces[0], "la marque devait avoir suivi");
    assert!(!session.is_open());
    assert!(session.take_mailbox().is_none(), "elle ne revient pas");
}

#[test]
fn l_appelant_peut_lire_la_boite_pour_en_tirer_un_message() {
    // La session ne lit aucun fichier : c'est l'appelant qui le fait, et il lui
    // faut l'objet qu'il a lui-même remis.
    let neuve = session();
    assert!(neuve.mailbox().is_none(), "rien à lire avant l'ouverture");

    let mut session = ouvrir(&[100, 200]);
    let mut tampon = [0_u8; 512];
    session.handle(b"RETR 2\r\n", &mut tampon).expect("réponse");
    let boite = session.mailbox().expect("boîte ouverte");
    assert_eq!(boite.tailles, [100, 200]);
}

#[test]
fn une_commande_du_mauvais_etat_ne_dit_pas_lequel() {
    // Un pair apprendrait sinon, sans mot de passe, dans quel état il se trouve.
    let mut session = session();
    session.on_tls_established();
    for ligne in [&b"STAT\r\n"[..], b"RETR 1\r\n", b"DELE 1\r\n", b"RSET\r\n"] {
        assert_eq!(
            jouer(&mut session, ligne),
            "-ERR Command not valid in this state\r\n",
            "{ligne:?}"
        );
    }
    // Et dans l'autre sens.
    let mut ouverte = ouvrir(&[100]);
    for ligne in [&b"USER jean\r\n"[..], b"PASS x\r\n", b"STLS\r\n"] {
        assert_eq!(
            jouer(&mut ouverte, ligne),
            "-ERR Command not valid in this state\r\n",
            "{ligne:?}"
        );
    }
}

#[test]
fn une_ligne_irrecevable_est_une_faute_sans_explication() {
    let mut session = ouvrir(&[100]);
    let mut tampon = [0_u8; 512];
    for ligne in [&b"XYZZY\r\n"[..], b"RETR 0\r\n", b"QUIT\n", b"TOP 1\r\n"] {
        let tour = session.handle(ligne, &mut tampon).expect("réponse");
        assert_eq!(tour.reply(), b"-ERR Invalid command\r\n", "{ligne:?}");
        assert!(tour.peer_fault(), "{ligne:?}");
    }
}

// ── L'ÉMISSION D'UN MESSAGE ─────────────────────────────────────────────────

/// Passe `corps` à travers l'émetteur, morceau par morceau, et rend le tout.
fn emettre(
    session: &mut Session<UnCompte, Boite>,
    corps: &[u8],
    taille_des_morceaux: usize,
) -> std::vec::Vec<u8> {
    let mut sortie = std::vec::Vec::new();
    let mut reste = corps;
    // Un tampon de sortie DÉLIBÉRÉMENT petit : la transformation doit reprendre
    // là où elle s'est arrêtée, et c'est ce que le découpage éprouve.
    let mut tampon = [0_u8; 8];
    while !reste.is_empty() && !session.body_complete() {
        let morceau = &reste[..taille_des_morceaux.min(reste.len())];
        let (lus, emis) = session.feed_body(morceau, &mut tampon).expect("émission");
        sortie.extend_from_slice(emis);
        reste = &reste[lus..];
    }
    let mut fin = [0_u8; 8];
    sortie.extend_from_slice(session.finish_body(&mut fin).expect("terminateur"));
    sortie
}

#[test]
fn retr_double_les_points_et_termine_le_message() {
    let mut session = ouvrir(&[100]);
    let mut tampon = [0_u8; 512];
    let tour = session.handle(b"RETR 1\r\n", &mut tampon).expect("réponse");
    assert_eq!(
        tour.action(),
        Action::SendBody {
            message: MessageNumber::new(1).expect("non nul"),
            lines: None
        }
    );
    // UNE LIGNE QUI COMMENCE PAR UN POINT EN REÇOIT UN SECOND : sans cela, elle
    // serait prise pour le terminateur et le message finirait au milieu.
    let corps = b"Subject: essai\r\n\r\n.cache\r\nfin\r\n";
    assert_eq!(
        emettre(&mut session, corps, 4),
        b"Subject: essai\r\n\r\n..cache\r\nfin\r\n.\r\n"
    );
}

#[test]
fn un_message_sans_fin_de_ligne_en_recoit_une() {
    // Sans elle, le terminateur se collerait à la dernière ligne, et le client
    // lirait un message tronqué suivi d'un point qui n'en est pas un.
    let mut session = ouvrir(&[100]);
    let mut tampon = [0_u8; 512];
    session.handle(b"RETR 1\r\n", &mut tampon).expect("réponse");
    assert_eq!(emettre(&mut session, b"sans fin", 3), b"sans fin\r\n.\r\n");
}

#[test]
fn top_rend_l_entete_puis_le_compte_de_lignes_demande() {
    let corps = b"Subject: essai\r\nFrom: jean\r\n\r\nun\r\ndeux\r\ntrois\r\n";
    let mut tampon = [0_u8; 512];

    // Zéro ligne : l'en-tête seul, et c'est le cas le plus courant.
    let mut session = ouvrir(&[100]);
    session
        .handle(b"TOP 1 0\r\n", &mut tampon)
        .expect("réponse");
    assert_eq!(
        emettre(&mut session, corps, 5),
        b"Subject: essai\r\nFrom: jean\r\n\r\n.\r\n"
    );

    // Deux lignes de corps.
    let mut session = ouvrir(&[100]);
    session
        .handle(b"TOP 1 2\r\n", &mut tampon)
        .expect("réponse");
    assert_eq!(
        emettre(&mut session, corps, 5),
        b"Subject: essai\r\nFrom: jean\r\n\r\nun\r\ndeux\r\n.\r\n"
    );

    // Plus de lignes que le message n'en a : on rend tout, sans se plaindre.
    let mut session = ouvrir(&[100]);
    session
        .handle(b"TOP 1 99\r\n", &mut tampon)
        .expect("réponse");
    assert_eq!(
        emettre(&mut session, corps, 5),
        b"Subject: essai\r\nFrom: jean\r\n\r\nun\r\ndeux\r\ntrois\r\n.\r\n"
    );
}

#[test]
fn l_emission_est_independante_du_decoupage() {
    // C'est la même propriété qu'en phase de données SMTP, et pour la même
    // raison : ce qui sort ne doit pas dépendre de la façon dont le disque ou le
    // réseau a découpé l'entrée.
    let corps = b"a\r\n.b\r\n\r\n.\r\nfin\r\n";
    let mut attendu = std::vec::Vec::new();
    for taille in [1, 2, 3, 5, 17, 64] {
        let mut session = ouvrir(&[100]);
        let mut tampon = [0_u8; 512];
        session.handle(b"RETR 1\r\n", &mut tampon).expect("réponse");
        let vu = emettre(&mut session, corps, taille);
        if attendu.is_empty() {
            attendu = vu;
        } else {
            assert_eq!(vu, attendu, "découpage par {taille}");
        }
    }
    assert_eq!(attendu, b"a\r\n..b\r\n\r\n..\r\nfin\r\n.\r\n");
}

#[test]
fn un_message_absent_ne_s_emet_pas() {
    let mut session = ouvrir(&[100]);
    assert_eq!(
        jouer(&mut session, b"RETR 9\r\n"),
        "-ERR No such message\r\n"
    );
    assert_eq!(
        jouer(&mut session, b"TOP 9 0\r\n"),
        "-ERR No such message\r\n"
    );
    jouer(&mut session, b"DELE 1\r\n");
    assert_eq!(
        jouer(&mut session, b"RETR 1\r\n"),
        "-ERR No such message\r\n"
    );
}

// ── Les refus faits à l'APPELANT ────────────────────────────────────────────

#[test]
fn l_appelant_ne_peut_pas_sauter_les_etapes() {
    let mut session = session();
    let mut tampon = [0_u8; 512];
    // Aucune ouverture n'a été demandée.
    assert_eq!(
        session.on_mailbox_opened(None, &mut tampon),
        Err(Error::NotInCommandPhase)
    );
    // Aucune émission n'est en cours.
    assert_eq!(
        session.next_listing(&mut tampon),
        Err(Error::NotInCommandPhase)
    );
    assert_eq!(
        session.feed_body(b"x", &mut tampon).err(),
        Some(Error::NotInCommandPhase)
    );
    assert_eq!(
        session.finish_body(&mut tampon),
        Err(Error::NotInCommandPhase)
    );
    // Et pendant une émission, plus aucune commande.
    let mut session = ouvrir(&[100]);
    session.handle(b"CAPA\r\n", &mut tampon).expect("réponse");
    assert_eq!(
        session.handle(b"NOOP\r\n", &mut tampon),
        Err(Error::NotInCommandPhase)
    );
}

#[test]
fn un_tampon_trop_petit_est_dit_plutot_que_deborde() {
    let mut session = ouvrir(&[100]);
    let mut minuscule = [0_u8; 2];
    assert!(session.handle(b"NOOP\r\n", &mut minuscule).is_err());
    assert!(session.greeting(&mut minuscule).is_err());
    assert!(session.unavailable(&mut minuscule).is_err());

    // Jusque sur le terminateur d'une réponse multiligne.
    let mut tampon = [0_u8; 512];
    session.handle(b"CAPA\r\n", &mut tampon).expect("réponse");
    assert!(session.next_listing(&mut minuscule).is_err());
    // Et sur une ligne de liste.
    let mut session = ouvrir(&[100]);
    session.handle(b"LIST\r\n", &mut tampon).expect("réponse");
    assert!(session.next_listing(&mut minuscule).is_err());
    // Et sur le terminateur d'un corps.
    let mut session = ouvrir(&[100]);
    session.handle(b"RETR 1\r\n", &mut tampon).expect("réponse");
    assert!(session.finish_body(&mut minuscule).is_err());
}

#[test]
fn un_nom_trop_long_pour_la_session_est_refuse_meme_si_la_grammaire_l_accepte() {
    // Les bornes viennent de la configuration : un administrateur peut porter
    // `max_argument_octets` au-delà de ce que la session sait retenir. Le nom
    // est alors refusé ICI — le tronquer désignerait quelqu'un d'autre.
    let larges = Limits {
        max_argument_octets: 200,
        ..Limits::DEFAULT
    };
    let mut session = Session::new(larges, true, UnCompte);
    session.on_tls_established();
    let long = std::format!("USER {}\r\n", "a".repeat(100));
    assert_eq!(
        jouer(&mut session, long.as_bytes()),
        "-ERR Invalid user\r\n"
    );
}

#[test]
fn une_liste_vide_ne_rend_que_son_terminateur() {
    let mut session = ouvrir(&[]);
    let mut tampon = [0_u8; 512];
    session.handle(b"LIST\r\n", &mut tampon).expect("réponse");
    assert_eq!(multiligne(&mut session), [".\r\n"]);
    assert_eq!(jouer(&mut session, b"STAT\r\n"), "+OK 0 0\r\n");
}

#[test]
fn le_terminateur_aussi_refuse_un_tampon_trop_petit() {
    // La boîte est vide : la toute première ligne demandée EST le terminateur.
    let mut session = ouvrir(&[]);
    let mut tampon = [0_u8; 512];
    session.handle(b"LIST\r\n", &mut tampon).expect("réponse");
    let mut minuscule = [0_u8; 2];
    assert!(session.next_listing(&mut minuscule).is_err());
}

#[test]
fn les_reponses_a_un_seul_message_refusent_aussi_un_tampon_trop_petit() {
    let mut session = ouvrir(&[100]);
    let mut minuscule = [0_u8; 2];
    assert!(session.handle(b"STAT\r\n", &mut minuscule).is_err());
    assert!(session.handle(b"LIST 1\r\n", &mut minuscule).is_err());
}

#[test]
fn nourrir_apres_la_fin_consomme_sans_rien_emettre() {
    // `TOP` a rendu son compte, mais l'appelant lit un fichier par morceaux et
    // peut en avoir un d'avance. Il doit pouvoir le donner sans que rien n'en
    // sorte — plutôt que d'avoir à vérifier avant chaque morceau.
    let mut session = ouvrir(&[100]);
    let mut tampon = [0_u8; 512];
    session
        .handle(b"TOP 1 0\r\n", &mut tampon)
        .expect("réponse");
    let (lus, emis) = session
        .feed_body(b"Subject: x\r\n\r\n", &mut tampon)
        .expect("émission");
    assert_eq!(lus, 14);
    assert_eq!(emis, b"Subject: x\r\n\r\n");
    assert!(session.body_complete());

    let (lus, emis) = session
        .feed_body(b"corps que personne n'a demande\r\n", &mut tampon)
        .expect("émission");
    assert_eq!(lus, 32, "le morceau doit être consommé en entier");
    assert!(emis.is_empty(), "rien ne devait sortir");
}

#[test]
fn les_erreurs_disent_quelque_chose_et_se_distinguent() {
    let toutes = [
        Error::Reply(ams_proto_pop3::Error::BufferTooSmall { needed: 8 }),
        Error::NotInCommandPhase,
        Error::SessionClosed,
    ];
    for erreur in toutes {
        assert!(std::format!("{erreur}").len() > 10, "{erreur:?}");
    }
    assert_ne!(Error::NotInCommandPhase, Error::SessionClosed);
    assert_eq!(Error::SessionClosed, Error::SessionClosed);
}
