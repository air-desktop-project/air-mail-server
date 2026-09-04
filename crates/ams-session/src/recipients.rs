//! Les destinataires acceptés d'une transaction, retenus SANS allocation.
//!
//! # Pourquoi la session les retient, alors qu'elle ne retient rien d'autre
//!
//! Parce qu'ils appartiennent à la **transaction**, et que la transaction vit
//! ici. La boucle, elle, ne voit ni `MAIL`, ni `RSET`, ni la fin d'un message :
//! elle ne saurait pas quand vider sa propre liste. Une liste qu'on oublie de
//! vider livrerait le message suivant aux destinataires du précédent — le pire
//! défaut qu'un serveur de courrier puisse avoir.
//!
//! # Deux bornes plutôt qu'une, et elles ne disent pas la même chose
//!
//! [`RECIPIENTS_MAX`] borne le NOMBRE, [`ARENA_OCTETS`] borne la PLACE. La
//! seconde n'est pas une redondance : cent adresses de deux cents octets ne
//! tiennent pas dans le même espace que cent adresses de vingt. Quand l'une ou
//! l'autre est atteinte, la réponse est la même — `452`, que la RFC 5321
//! §4.5.3.1.10 prévoit exactement pour cela.

use ams_proto_smtp::Notify;

/// Combien de destinataires une transaction peut retenir.
///
/// Cent, qui est le MINIMUM que la RFC 5321 §4.5.3.1.8 impose d'accepter. En
/// retenir moins serait non conforme ; en retenir plus n'aiderait personne, et
/// coûterait de la mémoire par connexion.
pub const RECIPIENTS_MAX: usize = 100;

/// La place que les adresses se partagent.
///
/// Huit kibioctets, soit quatre-vingts octets par destinataire au maximum
/// permis. Une adresse réelle en fait trente ; celle qui n'entre pas est
/// refusée par un `452`, jamais par un débordement (C3).
pub const ARENA_OCTETS: usize = 8192;

/// Les destinataires acceptés, à plat.
///
/// Les adresses sont concaténées dans `arene`, et `fins` porte l'indice de fin
/// de chacune. Pas de tableau de tranches : une tranche porte une durée de vie,
/// et une durée de vie dans une structure qu'on remet à zéro est une invitation
/// à se tromper.
pub struct Recipients {
    arene: [u8; ARENA_OCTETS],
    /// Où commence l'adresse de chaque destinataire, dans l'arène.
    ///
    /// # ON L'ÉCRIT, ON NE LE DEVINE PLUS
    ///
    /// Le début se déduisait de la fin du destinataire précédent. C'était vrai
    /// tant que l'arène ne portait QUE des adresses — et elle porte aussi les
    /// `ORCPT` (§4.2 de RFC 3461), écrits entre deux adresses par
    /// [`Recipients::poser_le_rapport`].
    ///
    /// L'adresse qui SUIVAIT un `ORCPT` était donc rendue avec celui-ci collé
    /// devant. Elle ne routait plus vers personne, partait en file comme une
    /// adresse d'ailleurs, et la transaction entière finissait refusée. Tout
    /// message d'un MTA qui parle DSN — c'est-à-dire Postfix, et les autres — à
    /// DEUX destinataires ou plus était perdu de cette façon.
    debuts: [usize; RECIPIENTS_MAX],
    fins: [usize; RECIPIENTS_MAX],
    /// Ce que chaque destinataire a demandé du sort de son message (RFC 3461
    /// §4.1), et son adresse d'origine (§4.2).
    ///
    /// # POURQUOI PAR DESTINATAIRE, ET NON PAR MESSAGE
    ///
    /// Deux `RCPT` d'une même transaction peuvent demander deux choses
    /// différentes — l'un un rapport de succès, l'autre le silence — et c'est
    /// tout l'objet de §4.1. Une seule valeur par transaction ferait honorer
    /// celle du dernier `RCPT` pour tout le monde.
    rapports: [Rapport; RECIPIENTS_MAX],
    combien: usize,
    utilise: usize,
}

/// Ce qu'un destinataire a demandé, et d'où il vient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rapport {
    /// Ce dont on doit rendre compte (§4.1).
    pub notify: Notify,
    /// La fin de l'adresse d'origine dans l'arène, et sa longueur.
    ///
    /// Zéro : le pair n'en a pas donné, et c'est le cas ordinaire.
    orcpt_fin: usize,
    orcpt_len: usize,
}

impl Rapport {
    /// L'adresse d'origine, si le pair en a donné une.
    #[must_use]
    const fn vide() -> Self {
        Self {
            notify: Notify::DEFAUT,
            orcpt_fin: 0,
            orcpt_len: 0,
        }
    }
}

impl Recipients {
    /// Une liste vide.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            arene: [0; ARENA_OCTETS],
            debuts: [0; RECIPIENTS_MAX],
            fins: [0; RECIPIENTS_MAX],
            rapports: [Rapport::vide(); RECIPIENTS_MAX],
            combien: 0,
            utilise: 0,
        }
    }

    /// Oublie tout.
    ///
    /// **Le tampon n'est pas effacé**, seulement les compteurs : ce qui reste
    /// est inatteignable — [`Self::iter`] ne parcourt que `combien` entrées — et
    /// l'effacer coûterait huit kibioctets à chaque `MAIL FROM`. Ce ne sont pas
    /// des secrets : ce sont des adresses que le pair vient d'envoyer en clair.
    pub const fn clear(&mut self) {
        self.combien = 0;
        self.utilise = 0;
    }

    /// Combien de destinataires sont retenus.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.combien
    }

    /// N'y a-t-il aucun destinataire ?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.combien == 0
    }

    /// Retient une adresse, si elle tient.
    ///
    /// Rend `false` quand l'une des deux bornes est atteinte — l'appelant en
    /// fait un `452`, et **rien n'est écrit à moitié** : une adresse tronquée
    /// livrerait à quelqu'un d'autre.
    #[must_use]
    pub fn push(&mut self, morceaux: &[&[u8]]) -> bool {
        let longueur: usize = morceaux.iter().map(|part| part.len()).sum();
        // `saturating_add` plutôt que `checked_add` : la somme ne peut pas
        // déborder — l'arène fait huit kibioctets — et un `checked_add`
        // ouvrirait une branche d'erreur qu'aucun test ne peut atteindre. En
        // saturant, la borne ci-dessous répond de toute façon non.
        let fin = self.utilise.saturating_add(longueur);

        // LES DEUX BORNES, EN DEUX EMPRUNTS. Chacune est un `get_mut` plutôt
        // qu'une comparaison suivie d'un `get_mut` : la comparaison rendrait le
        // `get_mut` infaillible, donc son bras d'échec inatteignable — et une
        // garde qu'aucun test ne peut emprunter n'est pas une garde.
        //
        // L'ORDRE COMPTE : la case d'abord. Écrire les octets puis découvrir
        // qu'il n'y a plus de case laisserait l'arène entamée pour rien.
        let Some(case) = self.fins.get_mut(self.combien) else {
            return false;
        };
        let debut = self.utilise;
        let Some(cible) = self.arene.get_mut(self.utilise..fin) else {
            return false;
        };

        // `split_at_mut` ne peut pas paniquer ici : la somme des morceaux fait
        // exactement la longueur de `cible`, par construction de `fin`.
        let mut reste = cible;
        for part in morceaux {
            let (tete, suite) = reste.split_at_mut(part.len());
            tete.copy_from_slice(part);
            reste = suite;
        }

        *case = fin;
        // `fins` et `debuts` ont la même taille : la case existe puisque celle
        // de `fins` existait. La dire par un `if let` ouvrirait une branche que
        // rien ne peut emprunter.
        for place in self.debuts.iter_mut().skip(self.combien).take(1) {
            *place = debut;
        }
        self.combien = self.combien.saturating_add(1);
        self.utilise = fin;
        true
    }

    /// Retient ce que le DERNIER destinataire accepté a demandé (RFC 3461).
    ///
    /// L'adresse d'origine va dans la même arène que les adresses : rien ne
    /// croît, et la borne des huit kibioctets vaut pour les deux. Si elle n'y
    /// tient pas, elle est OUBLIÉE plutôt que tronquée — un `Original-Recipient`
    /// à moitié écrit désignerait quelqu'un d'autre.
    pub fn poser_le_rapport(&mut self, notify: Notify, orcpt: &[u8]) {
        let Some(dernier) = self.combien.checked_sub(1) else {
            return;
        };
        let mut rapport = Rapport {
            notify,
            orcpt_fin: 0,
            orcpt_len: 0,
        };
        if !orcpt.is_empty() {
            let fin = self.utilise.saturating_add(orcpt.len());
            if let Some(cible) = self.arene.get_mut(self.utilise..fin) {
                cible.copy_from_slice(orcpt);
                rapport.orcpt_fin = fin;
                rapport.orcpt_len = orcpt.len();
                self.utilise = fin;
            }
        }
        // **PAS DE GARDE ICI** : `push` ne peut pas porter `combien` au-delà de
        // `RECIPIENTS_MAX` — c'est sa case de `fins` qui l'en empêche —, donc
        // `dernier` désigne toujours une case. Un `if let` y ouvrirait une
        // branche que rien ne pourrait emprunter.
        for place in self.rapports.iter_mut().skip(dernier).take(1) {
            *place = rapport;
        }
    }

    /// Ce que le destinataire de rang `rang` a demandé.
    #[must_use]
    pub fn rapport(&self, rang: usize) -> Option<(Notify, &[u8])> {
        let rapport = self.rapports.get(rang).filter(|_| rang < self.combien)?;
        let debut = rapport.orcpt_fin.saturating_sub(rapport.orcpt_len);
        let orcpt = self.arene.get(debut..rapport.orcpt_fin).unwrap_or_default();
        Some((rapport.notify, orcpt))
    }

    /// Les adresses retenues, dans l'ordre où elles ont été acceptées.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        // **CHAQUE ADRESSE PORTE SON DÉBUT ET SA FIN**, et le début ne se déduit
        // plus de la fin de la précédente : un `ORCPT` peut s'être écrit entre
        // les deux, et il n'appartient à aucune des deux.
        self.debuts
            .iter()
            .zip(self.fins.iter())
            .take(self.combien)
            .filter_map(|(&debut, &fin)| self.arene.get(debut..fin))
    }
}

impl Default for Recipients {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ARENA_OCTETS, RECIPIENTS_MAX, Recipients};
    use ams_proto_smtp::Notify;

    fn liste(adresses: &[&[u8]]) -> Recipients {
        let mut retenus = Recipients::new();
        for adresse in adresses {
            assert!(retenus.push(&[adresse]));
        }
        retenus
    }

    /// **LE DÉFAUT QUE SEUL UN VRAI MTA POUVAIT MONTRER.**
    ///
    /// L'`ORCPT` (§4.2 de RFC 3461) s'écrit dans la MÊME arène que les adresses,
    /// entre celle du destinataire qui l'a demandé et celle du suivant. Le début
    /// d'une adresse se déduisait de la fin de la précédente : celle qui suivait
    /// un `ORCPT` ressortait donc avec lui collé devant.
    ///
    /// Elle ne routait plus vers personne, partait en file comme une adresse
    /// d'ailleurs, et la transaction ENTIÈRE finissait refusée par `554`. Tout
    /// message d'un MTA qui parle DSN — Postfix en tête — à deux destinataires ou
    /// plus était perdu ainsi.
    #[test]
    fn une_adresse_qui_suit_un_orcpt_ressort_entiere() {
        let mut retenus = Recipients::new();
        assert!(retenus.push(&[&b"jean@example.com"[..]]));
        retenus.poser_le_rapport(Notify::DEFAUT, b"rfc822;origine@ailleurs.test");
        assert!(retenus.push(&[&b"marie@example.com"[..]]));

        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(
            vus,
            std::vec![&b"jean@example.com"[..], b"marie@example.com"],
            "l'adresse suivante ne porte pas l'`ORCPT` du précédent"
        );
    }

    /// Et l'`ORCPT` lui-même se relit toujours, à sa place.
    #[test]
    fn l_orcpt_se_relit_apres_l_adresse_suivante() {
        let mut retenus = Recipients::new();
        assert!(retenus.push(&[&b"jean@example.com"[..]]));
        retenus.poser_le_rapport(Notify::DEFAUT, b"rfc822;origine@ailleurs.test");
        assert!(retenus.push(&[&b"marie@example.com"[..]]));

        let (_, orcpt) = retenus.rapport(0).expect("un rapport au premier");
        assert_eq!(orcpt, b"rfc822;origine@ailleurs.test");
    }

    #[test]
    fn les_adresses_ressortent_dans_l_ordre() {
        let retenus = liste(&[b"jean@example.com", b"paul@example.org"]);
        assert_eq!(retenus.len(), 2);
        assert!(!retenus.is_empty());
        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(
            vus,
            std::vec![&b"jean@example.com"[..], b"paul@example.org"]
        );
    }

    #[test]
    fn une_adresse_se_compose_de_plusieurs_morceaux() {
        // C'est ainsi que la session écrit `local@domaine` sans rien assembler
        // ailleurs — elle n'a pas d'endroit où assembler.
        let mut retenus = Recipients::new();
        assert!(retenus.push(&[b"jean", b"@", b"example.com"]));
        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(vus, std::vec![&b"jean@example.com"[..]]);
    }

    #[test]
    fn une_liste_neuve_ou_videe_ne_rend_rien() {
        let mut retenus = liste(&[b"jean@example.com"]);
        retenus.clear();
        assert!(retenus.is_empty());
        assert_eq!(retenus.iter().count(), 0);
        assert_eq!(Recipients::default().iter().count(), 0);
    }

    #[test]
    fn la_borne_de_nombre_arrete_avant_de_deborder() {
        let mut retenus = Recipients::new();
        for _ in 0..RECIPIENTS_MAX {
            assert!(retenus.push(&[b"a@b.co"]));
        }
        assert!(!retenus.push(&[b"a@b.co"]));
        assert_eq!(retenus.len(), RECIPIENTS_MAX);
    }

    #[test]
    fn la_borne_de_place_arrete_aussi_et_n_ecrit_rien_a_moitie() {
        // Cent adresses de deux cents octets ne tiennent pas là où cent adresses
        // de vingt tiennent : la borne de nombre ne suffit pas.
        let longue = [b'a'; 1000];
        let mut retenus = Recipients::new();
        let mut posees = 0_usize;
        while retenus.push(&[&longue]) {
            posees = posees.saturating_add(1);
        }
        assert!(posees < RECIPIENTS_MAX, "la place aurait dû borner avant");
        assert_eq!(posees, ARENA_OCTETS / 1000);
        // RIEN N'EST ÉCRIT À MOITIÉ : une adresse tronquée livrerait à quelqu'un
        // d'autre. Toutes celles qui sont là sont entières.
        for adresse in retenus.iter() {
            assert_eq!(adresse.len(), 1000);
        }
    }

    #[test]
    fn une_adresse_plus_grande_que_l_arene_est_refusee_seule() {
        let enorme = [b'a'; ARENA_OCTETS + 1];
        let mut retenus = Recipients::new();
        assert!(!retenus.push(&[&enorme]));
        assert!(retenus.is_empty());
    }

    #[test]
    fn on_peut_recommencer_apres_avoir_vide() {
        let mut retenus = liste(&[b"jean@example.com"]);
        retenus.clear();
        assert!(retenus.push(&[b"paul@example.org"]));
        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(vus, std::vec![&b"paul@example.org"[..]]);
    }

    /// **UNE ADRESSE D'ORIGINE QUI NE TIENT PAS EST OUBLIÉE**, et non tronquée.
    ///
    /// Un `Original-Recipient` à moitié écrit désignerait quelqu'un d'autre —
    /// et ce champ ressort dans un rapport que le déposant lira.
    #[test]
    fn une_adresse_d_origine_qui_ne_tient_pas_est_oubliee() {
        let mut liste = Recipients::new();
        // On remplit l'arène jusqu'à ce qu'il n'y reste plus la place.
        let bourrage = [b'a'; 512];
        while liste.push(&[&bourrage]) {}
        assert!(
            liste.rapport(0).is_some(),
            "au moins une adresse est passée"
        );

        let dernier = (0..RECIPIENTS_MAX)
            .take_while(|rang| liste.rapport(*rang).is_some())
            .count()
            .saturating_sub(1);
        liste.poser_le_rapport(Notify::DEFAUT, &bourrage);
        let (notify, orcpt) = liste.rapport(dernier).expect("un rapport");
        assert!(notify.on_failure(), "ce qu'on demandait est retenu");
        assert!(orcpt.is_empty(), "l'adresse d'origine a été oubliée");
    }

    /// **SANS DESTINATAIRE, IL N'Y A RIEN À QUOI RATTACHER UN RAPPORT.**
    ///
    /// L'appelant ne pose un rapport qu'après un `RCPT` accepté ; la garde tient
    /// quand même, et le dire ici évite d'avoir à le supposer.
    #[test]
    fn un_rapport_sans_destinataire_ne_se_pose_pas() {
        let mut liste = Recipients::new();
        liste.poser_le_rapport(Notify::DEFAUT, b"marie@x.test");
        assert_eq!(liste.rapport(0), None);

        assert!(liste.push(&[b"marie@x.test"]));
        liste.poser_le_rapport(Notify::DEFAUT, b"marie+liste@x.test");
        let (notify, orcpt) = liste.rapport(0).expect("un rapport");
        assert!(notify.on_failure() && !notify.never());
        assert_eq!(orcpt, b"marie+liste@x.test");
        // Au-delà de ce qui a été accepté, il n'y a rien.
        assert_eq!(liste.rapport(1), None);
    }
}
