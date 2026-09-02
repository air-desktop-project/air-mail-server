use super::{ChunkEvent, ChunkReceiver};
use crate::{DataFault, Limits};

/// Un récepteur qui accepte un mébioctet.
fn receveur() -> ChunkReceiver {
    ChunkReceiver::new(&Limits::DEFAULT, 1_048_576)
}

/// Déroule un morceau entier, et rend ce qui a été rendu et le dernier
/// événement.
fn lire(
    receveur: &mut ChunkReceiver,
    flux: &[u8],
) -> Result<(std::vec::Vec<u8>, ChunkEvent<'static>), DataFault> {
    let mut rendu = std::vec::Vec::new();
    let mut reste = flux;
    loop {
        let (evenement, combien) = receveur.next(reste)?;
        reste = reste.get(combien..).unwrap_or_default();
        match evenement {
            ChunkEvent::Content(octets) => rendu.extend_from_slice(octets),
            ChunkEvent::ChunkComplete => return Ok((rendu, ChunkEvent::ChunkComplete)),
            ChunkEvent::Complete => return Ok((rendu, ChunkEvent::Complete)),
            ChunkEvent::NeedMore => return Ok((rendu, ChunkEvent::NeedMore)),
        }
    }
}

// ── CE QUI EST COMPTÉ ARRIVE ENTIER ─────────────────────────────────────────

#[test]
fn un_morceau_unique_rend_ses_octets_et_termine() {
    let mut receveur = receveur();
    receveur.begin(15, true).expect("annoncé");
    let (rendu, fin) = lire(&mut receveur, b"From: moi\r\n\r\n!!").expect("lu");
    assert_eq!(rendu, b"From: moi\r\n\r\n!!");
    assert_eq!(fin, ChunkEvent::Complete);
    assert!(receveur.is_complete());
    assert_eq!(receveur.content_octets(), 15);
}

/// **UN MORCEAU DE ZÉRO OCTET EST L'IDIOME DE `BDAT`** : `BDAT 0 LAST` termine
/// un message dont tout est déjà arrivé (RFC 3030 §2).
#[test]
fn un_dernier_morceau_vide_termine_le_message() {
    let mut receveur = receveur();
    receveur.begin(5, false).expect("annoncé");
    let (rendu, fin) = lire(&mut receveur, b"salut").expect("lu");
    assert_eq!(rendu, b"salut");
    assert_eq!(fin, ChunkEvent::ChunkComplete);
    assert!(!receveur.is_complete());

    receveur.begin(0, true).expect("annoncé");
    let (rendu, fin) = lire(&mut receveur, b"").expect("lu");
    assert!(rendu.is_empty());
    assert_eq!(fin, ChunkEvent::Complete);
    assert!(receveur.is_complete());
    assert_eq!(receveur.content_octets(), 5);
}

/// **ON NE LIT JAMAIS AU-DELÀ DU MORCEAU** : ce qui suit est une COMMANDE.
#[test]
fn ce_qui_depasse_le_morceau_n_est_pas_lu() {
    let mut receveur = receveur();
    receveur.begin(4, false).expect("annoncé");
    let flux = b"abcdBDAT 0 LAST\r\n";
    let (evenement, combien) = receveur.next(flux).expect("lu");
    assert_eq!(evenement, ChunkEvent::Content(b"abcd"));
    assert_eq!(combien, 4, "les octets de la commande suivante restent");
    let (evenement, combien) = receveur
        .next(flux.get(4..).unwrap_or_default())
        .expect("lu");
    assert_eq!(evenement, ChunkEvent::ChunkComplete);
    assert_eq!(combien, 0);
}

/// **LE DÉCOUPAGE DE L'ENTRÉE NE CHANGE RIEN** : c'est le pair qui choisit la
/// taille de ses paquets, jamais ce que le message contient.
#[test]
fn le_decoupage_des_lectures_ne_change_rien() {
    let message = b"Sujet: x\r\n\r\ncorps\r\n";
    for coupe in 0..=message.len() {
        let mut receveur = receveur();
        receveur.begin(message.len() as u64, true).expect("annoncé");
        let mut rendu = std::vec::Vec::new();
        for part in [
            message.get(..coupe).unwrap_or_default(),
            message.get(coupe..).unwrap_or_default(),
        ] {
            let mut reste = part;
            loop {
                let (evenement, combien) = receveur.next(reste).expect("lu");
                reste = reste.get(combien..).unwrap_or_default();
                match evenement {
                    ChunkEvent::Content(octets) => rendu.extend_from_slice(octets),
                    ChunkEvent::NeedMore | ChunkEvent::Complete => break,
                    ChunkEvent::ChunkComplete => panic!("ce morceau est le dernier"),
                }
            }
        }
        assert_eq!(rendu, message, "coupe à {coupe}");
        assert!(receveur.is_complete(), "coupe à {coupe}");
    }
}

/// **UN `CRLF` COUPÉ PAR UNE FRONTIÈRE DE MORCEAU RESTE UN `CRLF`.**
///
/// C'est pourquoi l'état de lecture vit dans le récepteur, et non dans le
/// morceau : l'inverse refuserait un message parfaitement légal.
#[test]
fn un_crlf_coupe_entre_deux_morceaux_est_accepte() {
    let mut receveur = receveur();
    receveur.begin(4, false).expect("annoncé");
    let (rendu, _) = lire(&mut receveur, b"abc\r").expect("lu");
    assert_eq!(rendu, b"abc\r");

    receveur.begin(4, true).expect("annoncé");
    let (rendu, fin) = lire(&mut receveur, b"\ndef").expect("lu");
    assert_eq!(rendu, b"\ndef");
    assert_eq!(fin, ChunkEvent::Complete);
    assert_eq!(receveur.content_octets(), 8);
}

// ── ET CE QUI EST REFUSÉ ────────────────────────────────────────────────────

/// **AUCUN `CR` NI `LF` ISOLÉ**, comme en phase `DATA` : ce qu'on dépose repart
/// un jour chez un voisin qui coupe sur `<CRLF>.<CRLF>`.
///
/// **CE QUI PRÉCÈDE L'OCTET FAUTIF EST RENDU**, puis le refus tombe. Refuser le
/// morceau entier ferait dépendre le compte des octets du DÉCOUPAGE des
/// lectures, c'est-à-dire du réseau — le fuzz l'a trouvé sur `T\nr`.
#[test]
fn un_lf_ou_un_cr_isole_est_refuse() {
    for (mauvais, bons, ou) in [
        (&b"a\nb"[..], 1, "un LF nu"),
        (b"a\rb", 2, "un CR suivi d'autre chose"),
        (b"\n", 0, "un LF seul"),
        (b"a\r\rb", 2, "deux CR"),
    ] {
        let mut receveur = receveur();
        receveur.begin(mauvais.len() as u64, true).expect("annoncé");
        if bons > 0 {
            assert_eq!(
                receveur.next(mauvais).map(|(_, n)| n),
                Ok(bons),
                "{ou} : le début n'a pas été rendu"
            );
        }
        assert_eq!(
            receveur
                .next(mauvais.get(bons..).unwrap_or_default())
                .map(|(_, n)| n),
            Err(DataFault::BareLineEnding),
            "{ou} est passé"
        );
    }
}

/// **UN MESSAGE NE SE TERMINE PAS SUR UN `CR` PENDANT** : plus rien ne viendra
/// le suivre, donc il est isolé.
#[test]
fn un_message_qui_finit_sur_un_cr_est_refuse() {
    let mut receveur = receveur();
    receveur.begin(2, true).expect("annoncé");
    let (evenement, combien) = receveur.next(b"a\r").expect("lu");
    assert_eq!(evenement, ChunkEvent::Content(b"a\r"));
    assert_eq!(combien, 2);
    assert_eq!(receveur.next(b""), Err(DataFault::BareLineEnding));
}

/// **LA BORNE SE VÉRIFIE À L'ANNONCE**, avant d'avoir lu un octet : le morceau
/// dit sa taille, et lire un mébioctet qu'on jettera ne sert personne.
#[test]
fn un_morceau_trop_gros_est_refuse_avant_d_etre_lu() {
    let mut receveur = ChunkReceiver::new(&Limits::DEFAULT, 10);
    assert_eq!(
        receveur.begin(11, true),
        Err(DataFault::MessageTooLarge { limit: 10 })
    );
    // Et la borne porte sur le MESSAGE, pas sur un morceau : deux morceaux qui
    // tiennent chacun ne tiennent pas forcément ensemble.
    receveur.begin(6, false).expect("annoncé");
    lire(&mut receveur, b"abcdef").expect("lu");
    assert_eq!(
        receveur.begin(6, true),
        Err(DataFault::MessageTooLarge { limit: 10 })
    );
}

/// Une entrée vide au milieu d'un morceau demande la suite, sans rien consommer.
#[test]
fn une_entree_vide_demande_la_suite() {
    let mut receveur = receveur();
    receveur.begin(3, true).expect("annoncé");
    assert_eq!(receveur.next(b""), Ok((ChunkEvent::NeedMore, 0)));
    assert!(!receveur.is_complete());
    assert!(!std::format!("{receveur:?}").is_empty());
    assert!(!std::format!("{:?}", ChunkEvent::NeedMore).is_empty());
}
