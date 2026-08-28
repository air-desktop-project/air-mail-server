//! Ce que les noms de fichiers ne portent PAS, et qu'il faut donc écrire.

use core::num::NonZeroU32;

use crate::{MailboxSummary, Uid};

/// Combien d'UID sont réservés d'avance à chaque écriture de l'index.
///
/// # Pourquoi réserver, et pourquoi c'est gratuit
///
/// Écrire l'index à chaque remise coûterait deux `fsync` de plus par message.
/// Ne l'écrire qu'à l'ouverture laisserait un trou : mille messages remis, puis
/// un arrêt, puis leurs fichiers effacés à la main — la boîte serait vide, le
/// filigrane serait resté à un, et les UID recommenceraient à un.
///
/// La réservation ferme ce trou pour un `fsync` toutes les 256 remises. Ce
/// qu'elle coûte en échange, ce sont des **trous dans la numérotation** après un
/// arrêt brutal : jusqu'à 255 UID sautés. La RFC 9051 §2.3.1.1 les autorise
/// explicitement. Un trou ne coûte rien à personne ; un UID réattribué montre à
/// un client un message pour un autre.
pub const UID_RESERVATION: u32 = 256;

/// L'`UIDVALIDITY` d'une boîte (RFC 9051 §2.3.1.1).
///
/// **Jamais nul** : la RFC l'interdit, et un zéro serait indistinguable d'un
/// champ absent dans un fichier binaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UidValidity(NonZeroU32);

impl UidValidity {
    /// La plus petite validité qui existe.
    pub const MIN: Self = Self(NonZeroU32::MIN);

    /// Construit une validité, si elle n'est pas nulle.
    #[must_use]
    pub const fn new(valeur: u32) -> Option<Self> {
        match NonZeroU32::new(valeur) {
            Some(non_nul) => Some(Self(non_nul)),
            None => None,
        }
    }

    /// Sa valeur.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0.get()
    }
}

/// L'état d'une boîte qu'aucun nom de fichier ne peut porter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxState {
    /// L'`UIDVALIDITY`.
    pub uid_validity: UidValidity,
    /// Le **filigrane haut** des UID : aucun UID déjà servi n'est ≥ à celui-ci.
    ///
    /// Ce n'est pas « le prochain UID » : c'est une borne qui ne redescend
    /// jamais, même quand le message qui portait le plus grand UID disparaît.
    pub uid_next: Uid,
}

/// Ce que la confrontation de l'index et des fichiers a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconciliation {
    /// L'état à retenir, et à réécrire.
    pub state: MailboxState,
    /// L'`UIDVALIDITY` a-t-elle dû changer ?
    ///
    /// **Vrai veut dire que tous les clients resynchroniseront la boîte
    /// entière.** C'est le prix d'un index perdu, et il doit être annoncé plutôt
    /// que subi en silence.
    pub uid_validity_changed: bool,
}

/// Confronte l'index relu aux fichiers présents.
///
/// # Les deux cas, et pourquoi ils diffèrent autant
///
/// **L'index est là** : les UID des fichiers sont exacts — ils sont dans les
/// noms — et l'index apporte la seule chose qu'ils ne portent pas, le filigrane.
/// On retient le plus grand des deux, et l'`UIDVALIDITY` ne bouge pas.
///
/// **L'index a disparu** : les UID des fichiers restent exacts, mais plus rien
/// ne dit quels UID ont DÉJÀ ÉTÉ SERVIS puis effacés. Les réattribuer montrerait
/// à un client, sous un numéro qu'il croit connaître, un message qui n'est pas
/// celui-là. C'est exactement le cas que l'`UIDVALIDITY` sert à signaler : elle
/// change, et les clients repartent de zéro. Coûteux, honnête, et prévu par la
/// RFC.
#[must_use]
pub fn reconcile(
    stored: Option<MailboxState>,
    scan: &MailboxSummary,
    fresh_validity: UidValidity,
) -> Reconciliation {
    match stored {
        Some(connu) => Reconciliation {
            state: MailboxState {
                uid_validity: connu.uid_validity,
                // Le plus grand des deux : le filigrane écrit peut être en
                // avance (réservation), et le parcours peut l'être aussi si des
                // messages ont été remis sans que l'index soit réécrit.
                uid_next: connu.uid_next.max(scan.next_uid),
            },
            uid_validity_changed: false,
        },
        None => Reconciliation {
            state: MailboxState {
                uid_validity: fresh_validity,
                uid_next: scan.next_uid,
            },
            uid_validity_changed: true,
        },
    }
}

/// Le filigrane à ÉCRIRE pour couvrir `uid_next` et les remises à venir.
///
/// Saturé : à `u32::MAX`, la boîte n'a plus d'UID à donner, et c'est
/// [`MailboxSummary::exhausted`] qui le dit.
#[must_use]
pub fn reserved_watermark(uid_next: Uid) -> Uid {
    Uid::new(uid_next.value().saturating_add(UID_RESERVATION)).unwrap_or(uid_next)
}

#[cfg(test)]
mod tests {
    use super::{MailboxState, UID_RESERVATION, UidValidity, reconcile, reserved_watermark};
    use crate::{MailboxSummary, Uid};

    fn validite(valeur: u32) -> UidValidity {
        UidValidity::new(valeur).expect("non nulle")
    }

    fn parcours(next: u32) -> MailboxSummary {
        MailboxSummary {
            next_uid: Uid::new(next).expect("non nul"),
            numbered: 0,
            unnumbered: 0,
            unreadable: 0,
            exhausted: false,
        }
    }

    #[test]
    fn une_validite_nulle_n_existe_pas() {
        // La RFC 9051 §2.3.1.1 l'interdit, et dans un fichier binaire un zéro
        // serait indistinguable d'un champ absent.
        assert_eq!(UidValidity::new(0), None);
        assert_eq!(validite(7).value(), 7);
    }

    #[test]
    fn la_plus_petite_validite_vaut_un() {
        // Elle sert de dernier recours à qui doit rendre une validité sans
        // pouvoir échouer — et zéro est interdit.
        assert_eq!(UidValidity::MIN.value(), 1);
    }

    #[test]
    fn avec_un_index_la_validite_ne_bouge_pas() {
        let connu = MailboxState {
            uid_validity: validite(1000),
            uid_next: Uid::new(500).expect("non nul"),
        };
        let vu = reconcile(Some(connu), &parcours(100), validite(2000));
        assert!(!vu.uid_validity_changed);
        assert_eq!(vu.state.uid_validity, validite(1000));
        // LE FILIGRANE NE REDESCEND PAS : les fichiers 100..500 ont pu être
        // effacés, et leurs UID ont bel et bien été servis.
        assert_eq!(vu.state.uid_next, Uid::new(500).expect("non nul"));
    }

    #[test]
    fn un_parcours_en_avance_l_emporte_sur_un_filigrane_perime() {
        // Des messages remis sans que l'index ait été réécrit : c'est le cas
        // NORMAL entre deux réservations.
        let connu = MailboxState {
            uid_validity: validite(1000),
            uid_next: Uid::new(100).expect("non nul"),
        };
        let vu = reconcile(Some(connu), &parcours(400), validite(2000));
        assert_eq!(vu.state.uid_next, Uid::new(400).expect("non nul"));
        assert!(!vu.uid_validity_changed);
    }

    #[test]
    fn sans_index_la_validite_change_et_c_est_dit() {
        // Sans filigrane, plus rien ne dit quels UID ont été servis puis
        // effacés. Les réattribuer montrerait à un client un message pour un
        // autre ; changer l'`UIDVALIDITY` le lui dit.
        let vu = reconcile(None, &parcours(42), validite(2000));
        assert!(vu.uid_validity_changed);
        assert_eq!(vu.state.uid_validity, validite(2000));
        assert_eq!(vu.state.uid_next, Uid::new(42).expect("non nul"));
    }

    #[test]
    fn la_reservation_couvre_les_remises_a_venir() {
        let depart = Uid::new(10).expect("non nul");
        assert_eq!(
            reserved_watermark(depart).value(),
            10_u32.saturating_add(UID_RESERVATION)
        );
    }

    #[test]
    fn une_boite_pleine_ne_reserve_plus_rien() {
        // À `u32::MAX`, il n'y a plus d'UID à donner. Enjamber par saturation
        // rendrait le même numéro deux fois.
        let plein = Uid::new(u32::MAX).expect("non nul");
        assert_eq!(reserved_watermark(plein), plein);
    }

    #[test]
    fn les_types_se_comparent_et_se_deboguent() {
        let etat = MailboxState {
            uid_validity: validite(1),
            uid_next: Uid::FIRST,
        };
        // Pas d'assertion sur `Debug` : la crate est `no_std` SANS `alloc`,
        // donc sans `format!`. Un helper écrit pour le contourner n'aurait
        // qu'un bras emprunté, et le 100 % de C2 compterait l'autre découvert.
        assert_eq!(etat, etat);
        assert_ne!(
            etat,
            MailboxState {
                uid_validity: validite(2),
                ..etat
            }
        );
        assert!(validite(1) < validite(2));
    }
}
