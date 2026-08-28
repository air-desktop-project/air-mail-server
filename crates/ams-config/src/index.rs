//! L'index d'une boîte Maildir : deux nombres, et rien de plus.
//!
//! # Pourquoi si peu
//!
//! Un index Maildir classique recopie la liste des messages pour éviter un
//! parcours de répertoire. Celui-ci ne le fait pas, et le refus est délibéré :
//! recopier ce que les noms de fichiers disent déjà créerait une **seconde
//! source de vérité**, capable de diverger de la première sans que rien ne le
//! signale. L'UID, les drapeaux et la taille sont dans les noms — ils y restent.
//!
//! Ce fichier ne porte donc que ce qu'aucun nom ne peut porter : l'`UIDVALIDITY`
//! de la boîte, et le filigrane des UID. Le perdre ne perd aucun message et
//! aucun UID ; cela oblige seulement à changer l'`UIDVALIDITY`.

use alloc::vec::Vec;

use ams_index::{MailboxState, Uid, UidValidity};
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_index_capnp::index;
use crate::codec::{Error, TRAVERSAL_LIMIT_WORDS};

/// Lit un index.
///
/// # Ce qui est refusé, et ce que le refus coûte
///
/// Une `UIDVALIDITY` nulle ou un filigrane nul rendent une erreur. **Le
/// stockage doit traiter cette erreur comme une absence d'index** — c'est-à-dire
/// reconstruire et changer l'`UIDVALIDITY` — plutôt que comme une panne : un
/// index illisible qui empêcherait la boîte de s'ouvrir transformerait un octet
/// retourné en indisponibilité.
///
/// # Errors
///
/// [`Error`] si les octets ne forment pas un message lisible, ou si l'un des
/// deux nombres est nul.
pub fn decode_index(octets: &[u8]) -> Result<MailboxState, Error> {
    let mut reste = octets;
    let message = serialize::read_message_from_flat_slice(
        &mut reste,
        ReaderOptions {
            traversal_limit_in_words: Some(
                usize::try_from(TRAVERSAL_LIMIT_WORDS).unwrap_or(usize::MAX),
            ),
            nesting_limit: 8,
        },
    )?;
    let lu: index::Reader<'_> = message.get_root()?;

    let uid_validity =
        UidValidity::new(lu.get_uid_validity()).ok_or(Error::Empty("uidValidity"))?;
    let uid_next = Uid::new(lu.get_uid_next()).ok_or(Error::Empty("uidNext"))?;
    Ok(MailboxState {
        uid_validity,
        uid_next,
    })
}

/// Écrit un index.
///
/// # Errors
///
/// [`Error::Malformed`] si l'encodage échoue — ce qui n'arrive que sur un défaut
/// de la bibliothèque.
pub fn encode_index(etat: &MailboxState) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut ecrit = message.init_root::<index::Builder<'_>>();
        ecrit.set_uid_validity(etat.uid_validity.value());
        ecrit.set_uid_next(etat.uid_next.value());
    }
    Ok(serialize::write_message_to_words(&message))
}

#[cfg(test)]
mod tests {
    use super::{decode_index, encode_index};
    use crate::codec::Error;
    use ams_index::{MailboxState, Uid, UidValidity};

    fn etat(validite: u32, filigrane: u32) -> MailboxState {
        MailboxState {
            uid_validity: UidValidity::new(validite).expect("non nulle"),
            uid_next: Uid::new(filigrane).expect("non nul"),
        }
    }

    #[test]
    fn un_index_ecrit_se_relit_a_l_identique() {
        let original = etat(1_724_800_000, 4096);
        let relu = decode_index(&encode_index(&original).expect("encodable")).expect("relisible");
        assert_eq!(relu, original);
    }

    #[test]
    fn les_valeurs_extremes_traversent() {
        for original in [etat(1, 1), etat(u32::MAX, u32::MAX)] {
            let relu =
                decode_index(&encode_index(&original).expect("encodable")).expect("relisible");
            assert_eq!(relu, original);
        }
    }

    #[test]
    fn un_zero_est_refuse_des_deux_cotes() {
        // Un champ absent d'un message Cap'n Proto vaut zéro. Accepter un zéro
        // ferait donc passer un index VIDE pour un index valide — et une
        // `UIDVALIDITY` nulle est interdite par la RFC 9051 §2.3.1.1.
        //
        // Le message est construit ICI plutôt qu'avec `encode_index`, qui
        // n'accepte pas de zéro. On initialise bien la racine : un constructeur
        // SANS racine fait paniquer `capnp` lui-même à la sérialisation —
        // constaté, et sans rapport avec nos chemins, qui initialisent toujours.
        let mut message = capnp::message::Builder::new_default();
        message.init_root::<crate::ams_index_capnp::index::Builder<'_>>();
        let tout_a_zero = capnp::serialize::write_message_to_words(&message);

        assert_eq!(decode_index(&tout_a_zero), Err(Error::Empty("uidValidity")));

        // Et le filigrane nul est refusé lui aussi. Zéro n'est pas un UID :
        // l'accepter ferait servir un numéro que la RFC 9051 §2.3.1.1 réserve,
        // et le premier message d'une boîte neuve porterait un UID invalide.
        let mut message = capnp::message::Builder::new_default();
        {
            let mut ecrit = message.init_root::<crate::ams_index_capnp::index::Builder<'_>>();
            ecrit.set_uid_validity(7);
        }
        let sans_filigrane = capnp::serialize::write_message_to_words(&message);
        assert_eq!(decode_index(&sans_filigrane), Err(Error::Empty("uidNext")));
    }

    #[test]
    fn un_index_corrompu_rend_une_erreur_jamais_une_panique() {
        // Le stockage traite cette erreur comme une ABSENCE d'index : il
        // reconstruit et change l'`UIDVALIDITY`. Un octet retourné ne doit pas
        // rendre une boîte inouvrable.
        let sain = encode_index(&etat(7, 9)).expect("encodable");
        let mut refuses = 0_u32;
        let mut acceptes = 0_u32;
        for position in 0..sain.len() {
            for masque in [0xFF_u8, 0x01, 0x80] {
                let mut corrompu = sain.clone();
                corrompu[position] ^= masque;
                match decode_index(&corrompu) {
                    Ok(_) => acceptes = acceptes.saturating_add(1),
                    Err(_) => refuses = refuses.saturating_add(1),
                }
            }
        }
        assert!(refuses > 0, "aucune corruption n'a été détectée");
        assert!(
            acceptes > 0,
            "toutes les corruptions ont été refusées : le balayage ne traverse pas le chemin nominal"
        );
    }

    #[test]
    fn des_octets_qui_ne_sont_pas_un_message_sont_refuses() {
        assert!(decode_index(b"pas un message").is_err());
        // On assère le MESSAGE plutôt qu'un `matches!` : ce dernier engendre un
        // bras `_ => false` que rien n'emprunte, et le 100 % de C2 le compterait
        // à jamais découvert.
        let erreur = decode_index(&[]).expect_err("refusé");
        assert!(alloc::format!("{erreur}").contains("illisible"), "{erreur}");
    }
}
