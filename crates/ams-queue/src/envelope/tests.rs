//! Ce que l'enveloppe accepte de porter, et ce qu'elle refuse.

use super::{Envelope, RECIPIENTS_MAX, envelope_max, parse_envelope, write_envelope};
use crate::Error;

/// Écrit une enveloppe et rend le texte, possédé.
fn ecrire(enveloppe: &Envelope<'_, '_>) -> std::string::String {
    let mut place = std::vec![0_u8; envelope_max(enveloppe)];
    std::string::String::from(write_envelope(enveloppe, &mut place).expect("écrivable"))
}

#[test]
fn une_enveloppe_ecrite_se_relit_a_l_identique() {
    let destinataires = ["marie@ailleurs.test", "jean@autre.test"];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &destinataires,
    };
    let texte = ecrire(&enveloppe);
    assert_eq!(
        texte,
        "jean@example.com\nmarie@ailleurs.test\njean@autre.test\n"
    );

    let mut place = [""; 8];
    let relue = parse_envelope(&texte, &mut place).expect("relisible");
    assert_eq!(relue.return_path, "jean@example.com");
    assert_eq!(relue.recipients, &destinataires);
}

#[test]
fn un_saut_de_ligne_dans_une_adresse_n_ajoute_pas_un_destinataire() {
    // **C'EST L'INJECTION QUE CETTE CRATE DOIT FERMER.** Une adresse qui porte
    // un `LF` écrirait une ligne de plus dans un fichier que nous composons
    // nous-mêmes, et la reprise suivante la lirait comme un destinataire.
    let destinataires = ["marie@ailleurs.test\nvictime@banque.test"];
    let mut place = [0_u8; 512];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &destinataires,
            },
            &mut place
        ),
        Err(Error::BadAddress)
    );
    // Et par le chemin de retour non plus.
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com\nautre@x.test",
                recipients: &["marie@ailleurs.test"],
            },
            &mut place
        ),
        Err(Error::BadAddress)
    );
}

#[test]
fn une_adresse_vide_ou_avec_un_espace_est_refusee() {
    let mut place = [0_u8; 512];
    for mauvaise in ["", " ", "a b@x.test", "a\tb@x.test", "café@x.test"] {
        assert_eq!(
            write_envelope(
                &Envelope {
                    return_path: mauvaise,
                    recipients: &["marie@ailleurs.test"],
                },
                &mut place
            ),
            Err(Error::BadAddress),
            "« {mauvaise} » aurait dû être refusée"
        );
    }
}

#[test]
fn une_adresse_trop_longue_est_refusee() {
    // §4.5.3.1.3 de RFC 5321 borne un chemin à 256 octets.
    let longue = "a".repeat(257);
    let mut place = [0_u8; 1024];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: &longue,
                recipients: &["marie@ailleurs.test"],
            },
            &mut place
        ),
        Err(Error::BadAddress)
    );
    let juste = "a".repeat(256);
    assert!(
        write_envelope(
            &Envelope {
                return_path: &juste,
                recipients: &["marie@ailleurs.test"],
            },
            &mut place
        )
        .is_ok()
    );
}

#[test]
fn une_enveloppe_sans_destinataire_est_refusee() {
    let mut place = [0_u8; 512];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &[],
            },
            &mut place
        ),
        Err(Error::BadRecipients)
    );
    // Et à la relecture aussi : un fichier qui n'a qu'un chemin de retour ne
    // désigne personne, et le remettre ne veut rien dire.
    let mut cases = [""; 4];
    assert_eq!(
        parse_envelope("jean@example.com\n", &mut cases),
        Err(Error::BadRecipients)
    );
}

#[test]
fn une_enveloppe_vide_est_refusee() {
    let mut cases = [""; 4];
    assert_eq!(parse_envelope("", &mut cases), Err(Error::BadAddress));
    assert_eq!(parse_envelope("\n\n", &mut cases), Err(Error::BadAddress));
}

#[test]
fn plus_de_destinataires_que_la_borne_est_refuse() {
    let beaucoup: std::vec::Vec<&str> = std::vec!["a@x.test"; RECIPIENTS_MAX + 1];
    let mut place = std::vec![0_u8; 65_536];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &beaucoup,
            },
            &mut place
        ),
        Err(Error::BadRecipients)
    );
    // La borne elle-même passe.
    let juste: std::vec::Vec<&str> = std::vec!["a@x.test"; RECIPIENTS_MAX];
    assert!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &juste,
            },
            &mut place
        )
        .is_ok()
    );
}

#[test]
fn un_fichier_plus_garni_que_la_place_est_refuse_pas_tronque() {
    // **REMETTRE À UNE PARTIE DES DESTINATAIRES EN OUBLIANT LES AUTRES EST
    // EXACTEMENT CE QU'UNE FILE NE DOIT PAS FAIRE.**
    let texte = "jean@example.com\na@x.test\nb@x.test\nc@x.test\n";
    let mut trop_petite = [""; 2];
    assert_eq!(
        parse_envelope(texte, &mut trop_petite),
        Err(Error::BadRecipients)
    );
    let mut juste = [""; 3];
    assert_eq!(
        parse_envelope(texte, &mut juste)
            .expect("relisible")
            .recipients
            .len(),
        3
    );
}

#[test]
fn une_adresse_illisible_fait_refuser_le_fichier_entier() {
    let mut cases = [""; 8];
    for mauvais in [
        "jean@example.com\na b@x.test\n",
        " \na@x.test\n",
        "jean@example.com\n\u{e9}@x.test\n",
    ] {
        assert!(
            parse_envelope(mauvais, &mut cases).is_err(),
            "« {mauvais} » aurait dû être refusé"
        );
    }
}

#[test]
fn un_tampon_trop_court_est_une_erreur() {
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &["marie@ailleurs.test"],
    };
    let taille = envelope_max(&enveloppe);
    for court in 0..taille {
        let mut place = std::vec![0_u8; court];
        assert_eq!(
            write_envelope(&enveloppe, &mut place),
            Err(Error::BufferTooSmall)
        );
    }
    // Et la taille annoncée suffit, exactement.
    let mut place = std::vec![0_u8; taille];
    assert!(write_envelope(&enveloppe, &mut place).is_ok());
}

#[test]
fn les_lignes_vides_se_sautent() {
    // Un fichier recopié à la main peut en porter ; les refuser ferait perdre
    // du courrier pour une raison qui n'en est pas une.
    let mut cases = [""; 4];
    let relue = parse_envelope("jean@example.com\n\na@x.test\n\n", &mut cases).expect("relisible");
    assert_eq!(relue.recipients, &["a@x.test"]);
}

#[test]
fn une_enveloppe_se_copie_et_se_debogue() {
    let destinataires = ["a@x.test"];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &destinataires,
    };
    let copie = enveloppe;
    assert_eq!(copie, enveloppe);
    assert!(!std::format!("{enveloppe:?}").is_empty());
    assert_ne!(
        enveloppe,
        Envelope {
            return_path: "autre@example.com",
            recipients: &destinataires,
        }
    );
    assert!(!std::format!("{:?}", Error::BadAddress).is_empty());
    assert_ne!(Error::BadAddress, Error::BadRecipients);
    let copie_d_erreur = Error::BufferTooSmall;
    assert_eq!(copie_d_erreur, Error::BufferTooSmall);
}
