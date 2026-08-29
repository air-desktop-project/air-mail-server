//! Ce qu'un `APPEND` annonce avant son message.

use super::Append;
use crate::{Error, Flags};

/// Dix mébioctets, la borne par défaut.
const MAX: u64 = 10_485_760;

/// Lit une ligne d'`APPEND`, ou panique.
fn lu(ligne: &[u8]) -> Append<'_> {
    Append::parse(ligne, MAX)
        .expect("lisible")
        .expect("un APPEND qu'on sait écouler")
}

#[test]
fn la_forme_la_plus_simple_se_lit() {
    let append = lu(b"a001 APPEND INBOX {310}\r\n");
    assert_eq!(append.mailbox(), b"INBOX");
    assert_eq!(append.flags(), Flags::NONE);
    assert_eq!(append.date(), None);
    assert_eq!(append.octets(), 310);
    assert!(append.synchronizing());
}

#[test]
fn les_drapeaux_et_la_date_sont_facultatifs_et_se_lisent() {
    let append = lu(b"a001 APPEND INBOX (\\Seen \\Draft) {12}\r\n");
    assert!(append.flags().contains(Flags::SEEN));
    assert!(append.flags().contains(Flags::DRAFT));
    assert_eq!(append.date(), None);

    let date = lu(b"a001 APPEND INBOX \"29-Aug-2026 07:08:31 +0000\" {12}\r\n");
    assert_eq!(date.flags(), Flags::NONE);
    assert_eq!(date.date(), Some(1_787_987_311));

    let deux = lu(b"a001 APPEND INBOX (\\Seen) \"29-Aug-2026 07:08:31 +0000\" {12}\r\n");
    assert_eq!(deux.flags(), Flags::SEEN);
    assert_eq!(deux.date(), Some(1_787_987_311));
    // Une liste vide est une liste.
    assert_eq!(lu(b"a001 APPEND INBOX () {12}\r\n").flags(), Flags::NONE);
}

#[test]
fn le_nom_de_boite_se_lit_entre_guillemets_aussi() {
    assert_eq!(
        lu(b"a001 APPEND \"Mon dossier\" {12}\r\n").mailbox(),
        b"Mon dossier"
    );
}

/// Un littéral non synchronisant se lit, et se distingue.
#[test]
fn un_litteral_non_synchronisant_se_distingue() {
    let append = lu(b"a001 APPEND INBOX {12+}\r\n");
    assert_eq!(append.octets(), 12);
    assert!(!append.synchronizing());
}

/// **Ce n'est ni une faute ni un refus, mais « pas ce chemin-ci ».**
#[test]
fn ce_qui_n_est_pas_un_append_ecoulable_rend_rien() {
    for ligne in [
        // Pas de littéral : ce n'est pas la forme qu'on écoule.
        &b"a001 APPEND INBOX\r\n"[..],
        // Un autre verbe.
        b"a001 LOGIN toto {5}\r\n",
        b"a001 SELECT INBOX\r\n",
        // UN NOM DE BOÎTE DONNÉ COMME LITTÉRAL : le littéral qu'on voit n'est
        // pas le message, et l'écouler écrirait le nom dans le courrier.
        b"a001 APPEND {5}\r\n",
        b"a001 APPEND  {12}\r\n",
    ] {
        assert_eq!(
            Append::parse(ligne, MAX).expect("pas une faute"),
            None,
            "{:?}",
            core::str::from_utf8(ligne)
        );
    }
}

#[test]
fn les_formes_fautives_sont_des_fautes() {
    for ligne in [
        // Une parenthèse qui ne ferme pas.
        &b"a001 APPEND INBOX (\\Seen {12}\r\n"[..],
        // Une date illisible.
        b"a001 APPEND INBOX \"pas une date\" {12}\r\n",
        b"a001 APPEND INBOX truc {12}\r\n",
    ] {
        assert!(
            Append::parse(ligne, MAX).is_err(),
            "{:?} aurait dû être refusée",
            core::str::from_utf8(ligne)
        );
    }
    // Un drapeau qu'on ne sait pas écrire est un refus nommé.
    assert_eq!(
        Append::parse(b"a001 APPEND INBOX ($Important) {12}\r\n", MAX).err(),
        Some(Error::UnknownFlag)
    );
}

/// **Un message plus gros que ce qu'on accepte est refusé AVANT d'être lu.**
/// C'est tout l'intérêt du littéral synchronisant : le client attend.
#[test]
fn un_message_demesure_est_refuse_avant_d_etre_lu() {
    assert_eq!(
        Append::parse(b"a001 APPEND INBOX {20000000}\r\n", MAX).err(),
        Some(Error::LiteralTooLong { limit: MAX })
    );
}

/// Une ligne sans `CRLF` se lit pareil : l'appelant peut la donner telle qu'il
/// l'a découpée.
#[test]
fn le_crlf_final_est_facultatif() {
    assert_eq!(lu(b"a001 APPEND INBOX {310}").octets(), 310);
}

/// **Un guillemet qui ne ferme pas rend tout ce qui suit.** La commande, elle,
/// n'aura pas de littéral : l'accolade est dans la chaîne, et le découpage le
/// sait.
#[test]
fn un_guillemet_orphelin_rend_tout_ce_qui_suit() {
    assert_eq!(
        super::un_mot(b"\"jamais fermee"),
        (&b"jamais fermee"[..], &b""[..])
    );
    assert_eq!(
        Append::parse(b"a001 APPEND \"jamais fermee {12}\r\n", MAX).expect("pas une faute"),
        None
    );
}
