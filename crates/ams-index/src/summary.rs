//! Le résumé d'une boîte, replié sur ses noms de fichiers.

use crate::{MessageName, Uid};

/// Ce qu'un parcours de boîte apprend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxSummary {
    /// L'UID à donner au prochain message.
    ///
    /// Un de plus que le plus grand rencontré, ou [`Uid::FIRST`] si la boîte
    /// n'en portait aucun. **Saturé à `u32::MAX`** : au-delà, c'est
    /// l'`UIDVALIDITY` qui doit changer, et réattribuer un UID déjà servi
    /// montrerait à un client un message pour un autre.
    pub next_uid: Uid,
    /// Messages portant déjà un UID.
    pub numbered: u32,
    /// Messages sans UID — déposés par un autre outil, ou par une version
    /// antérieure. Le stockage doit les renommer pour les adopter.
    pub unnumbered: u32,
    /// Noms que la grammaire refuse. Ils ne sont **pas** des messages.
    pub unreadable: u32,
    /// Le plus grand UID rencontré a-t-il atteint `u32::MAX` ?
    ///
    /// Vrai signifie que la boîte est **pleine** au sens d'IMAP : il n'y a plus
    /// d'UID à attribuer sans changer d'`UIDVALIDITY`.
    pub exhausted: bool,
}

/// Replie les noms d'une boîte en un résumé.
///
/// # C'est un repliement, pas une table
///
/// Rien n'est retenu : ni les noms, ni les UID. Une boîte de cent mille messages
/// se résume donc dans une mémoire constante, et il n'y a aucune capacité à
/// choisir — donc aucune à mal choisir.
///
/// Ce que cela ne donne pas : la correspondance UID → fichier, dont IMAP a besoin
/// pour un `FETCH`. Elle appartient au stockage, qui peut allouer.
#[must_use]
pub fn summarise<'a, I>(noms: I) -> MailboxSummary
where
    I: Iterator<Item = &'a [u8]>,
{
    let mut plus_grand: Option<Uid> = None;
    let mut numbered = 0_u32;
    let mut unnumbered = 0_u32;
    let mut unreadable = 0_u32;

    for nom in noms {
        let Ok(lu) = MessageName::parse(nom) else {
            unreadable = unreadable.saturating_add(1);
            continue;
        };
        match lu.uid() {
            Some(uid) => {
                numbered = numbered.saturating_add(1);
                if plus_grand.is_none_or(|connu| uid > connu) {
                    plus_grand = Some(uid);
                }
            }
            None => unnumbered = unnumbered.saturating_add(1),
        }
    }

    let (next_uid, exhausted) = match plus_grand {
        None => (Uid::FIRST, false),
        // `next` rend `None` à `u32::MAX` : la boîte n'a plus d'UID à donner, et
        // le taire ferait réattribuer un numéro déjà servi.
        Some(connu) => connu
            .next()
            .map_or((connu, true), |suivant| (suivant, false)),
    };

    MailboxSummary {
        next_uid,
        numbered,
        unnumbered,
        unreadable,
        exhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::summarise;
    use crate::Uid;

    fn resumer(noms: &[&[u8]]) -> super::MailboxSummary {
        summarise(noms.iter().copied())
    }

    #[test]
    fn une_boite_vide_commence_au_premier_uid() {
        let resume = resumer(&[]);
        assert_eq!(resume.next_uid, Uid::FIRST);
        assert_eq!(resume.numbered, 0);
        assert_eq!(resume.unnumbered, 0);
        assert_eq!(resume.unreadable, 0);
        assert!(!resume.exhausted);
    }

    #[test]
    fn le_prochain_uid_suit_le_plus_grand_rencontre() {
        // L'ORDRE DE LECTURE DU RÉPERTOIRE N'INFLUE PAS : c'est un maximum, pas
        // un compteur. Un fichier restauré depuis une sauvegarde ne décale rien.
        let resume = resumer(&[b"a,U=3", b"b,U=1", b"c,U=7", b"d,U=2"]);
        assert_eq!(resume.next_uid.value(), 8);
        assert_eq!(resume.numbered, 4);

        let inverse = resumer(&[b"c,U=7", b"d,U=2", b"a,U=3", b"b,U=1"]);
        assert_eq!(inverse, resume);
    }

    #[test]
    fn les_messages_sans_uid_sont_comptes_a_part() {
        // Le stockage doit les renommer pour les adopter.
        let resume = resumer(&[b"a,U=5", b"depose-par-un-autre-outil", b"c:2,S"]);
        assert_eq!(resume.numbered, 1);
        assert_eq!(resume.unnumbered, 2);
        assert_eq!(resume.next_uid.value(), 6);
    }

    #[test]
    fn ce_qui_n_est_pas_un_nom_n_est_pas_un_message() {
        let resume = resumer(&[b"", b"a/b", b"bon,U=2", b"c:9,S"]);
        assert_eq!(resume.unreadable, 3);
        assert_eq!(resume.numbered, 1);
        assert_eq!(resume.next_uid.value(), 3);
    }

    #[test]
    fn une_boite_au_dernier_uid_se_declare_epuisee() {
        // Au-delà, c'est l'`UIDVALIDITY` qui doit changer : réattribuer un
        // numéro déjà servi montrerait à un client un message pour un autre.
        let mut nom = std::vec::Vec::from(b"a,U=".as_slice());
        nom.extend_from_slice(b"4294967295");
        let resume = resumer(&[&nom]);
        assert!(resume.exhausted);
        assert_eq!(resume.next_uid.value(), u32::MAX);
    }

    #[test]
    fn le_resume_se_copie_et_se_debogue() {
        let resume = resumer(&[b"a,U=1"]);
        let copie = resume;
        assert_eq!(copie, resume);
        assert_ne!(copie, resumer(&[]));
        assert!(!std::format!("{resume:?}").is_empty());
    }
}
