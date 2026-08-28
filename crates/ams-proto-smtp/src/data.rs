//! La phase de données : `<CRLF>.<CRLF>`, et le point échappé (RFC 5321 §4.5.2).
//!
//! # C'est ici que vit la contrebande SMTP
//!
//! La faille de 2023 ne tient pas à un débordement : elle tient à ce que deux
//! serveurs ne coupent pas le flux au même endroit. Un relais sortant lit
//! `\n.\r\n` comme du texte ; le serveur entrant le lit comme une fin de message,
//! et interprète ce qui suit comme de NOUVELLES COMMANDES — `MAIL FROM`,
//! `RCPT TO`, `DATA`. Le second message part alors avec le SPF, le DKIM et le
//! DMARC du relais.
//!
//! Deux règles ferment cela, et il faut les deux :
//!
//! 1. **La fin de message est `<CRLF>.<CRLF>`, et rien d'autre.** Pas `\n.\n`,
//!    pas `\r.\r\n`, pas `\r\n.\r`.
//! 2. **Aucun CR ni LF isolé n'est accepté dans les données.** La première règle
//!    seule ne suffit pas : tant qu'un octet de fin de ligne ambigu traverse le
//!    serveur, le voisin d'en face peut le lire autrement.
//!
//! Normaliser plutôt que refuser reviendrait à décider ce que l'expéditeur a
//! voulu dire — et à se retrouver en désaccord avec le prochain saut.

use crate::{Error, Limits};

use core::fmt;

/// Ce qui rend des données de message irrecevables.
///
/// Trois causes, et trois seulement. Un type dédié plutôt qu'[`Error`] : celui-ci
/// en compte deux douzaines, dont aucune ne peut venir d'ici, et les mélanger
/// obligerait chaque appelant à écrire un bras qu'il ne peut pas atteindre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFault {
    /// Un `CR` ou un `LF` isolé — **la faille de la contrebande SMTP**.
    BareLineEnding,
    /// Une ligne dépasse [`Limits::max_text_line_octets`].
    LineTooLong {
        /// La borne franchie.
        limit: usize,
    },
    /// Le message dépasse la taille annoncée par `SIZE`.
    MessageTooLarge {
        /// La borne franchie.
        limit: u64,
    },
}

impl fmt::Display for DataFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataFault::BareLineEnding => f.write_str("CR ou LF isolé dans les données"),
            DataFault::LineTooLong { limit } => {
                write!(f, "ligne de message de plus de {limit} octets")
            }
            DataFault::MessageTooLarge { limit } => {
                write!(f, "message de plus de {limit} octets")
            }
        }
    }
}

impl From<DataFault> for Error {
    fn from(fault: DataFault) -> Self {
        Error::Data(fault)
    }
}

/// Ce que le récepteur rend à chaque appel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'i> {
    /// Des octets du message, **déjà dé-échappés**. Jamais vide.
    Content(&'i [u8]),
    /// La fin du message a été atteinte.
    Complete,
    /// L'entrée est épuisée ; il en faut d'autre.
    NeedMore,
}

/// Où en est la lecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    /// Au début d'une ligne — début du message, ou juste après un CRLF.
    LineStart,
    /// Au milieu d'une ligne.
    InLine,
    /// Un `CR` a été consommé sans être émis ; seul un `LF` peut suivre.
    AfterCr,
    /// Un `.` en début de ligne a été consommé sans être émis.
    AfterDot,
    /// `.` puis `CR` en début de ligne ; seul un `LF` peut suivre.
    AfterDotCr,
    /// Le message est terminé.
    Done,
}

/// Lit la phase de données, **sans entrée-sortie et sans allouer**.
///
/// L'appelant fournit les octets qu'il a lus ; le récepteur rend les morceaux de
/// message, empruntés à l'entrée. Les seuls octets qu'il rend sans les emprunter
/// sont un `\r\n` constant, quand le `CR` et le `LF` sont arrivés dans deux
/// lectures différentes.
#[derive(Debug, Clone)]
pub struct DataReceiver {
    scan: Scan,
    line_octets: usize,
    content_octets: u64,
    max_line: usize,
    max_message: u64,
}

impl DataReceiver {
    /// Ouvre la lecture d'un message.
    #[must_use]
    pub fn new(limits: &Limits, max_message_octets: u64) -> Self {
        Self {
            scan: Scan::LineStart,
            line_octets: 0,
            content_octets: 0,
            max_line: limits.max_text_line_octets,
            max_message: max_message_octets,
        }
    }

    /// Le nombre d'octets de message rendus jusqu'ici.
    #[must_use]
    pub fn content_octets(&self) -> u64 {
        self.content_octets
    }

    /// Le message est-il terminé ?
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.scan == Scan::Done
    }

    /// Consomme des octets d'entrée, et rend un événement.
    ///
    /// Rend aussi le nombre d'octets **consommés** — qui n'est pas celui des
    /// octets émis : un point échappé est consommé sans être rendu, et la fin de
    /// message aussi.
    ///
    /// # Il progresse toujours
    ///
    /// Sur une entrée **non vide**, cet appel consomme au moins un octet, ou rend
    /// [`Event::Complete`]. C'est ce qui permet à l'appelant d'écrire sa boucle
    /// sans garde-fou : sans cette garantie, un récepteur qui rendrait
    /// « il m'en faut plus » sans rien consommer ferait tourner la boucle à vide,
    /// et un pair pourrait l'y enfermer avec trois octets.
    ///
    /// # Errors
    ///
    /// [`DataFault`]. Une faute est **définitive** : le récepteur ne doit plus
    /// être sollicité, et le message ne peut plus être accepté.
    pub fn next<'i>(&mut self, input: &'i [u8]) -> Result<(Event<'i>, usize), DataFault> {
        if let Some(resolu) = self.resolve_pending(input)? {
            return Ok(resolu);
        }
        self.scan_run(input)
    }

    /// Traite l'état laissé en suspens par l'appel précédent.
    ///
    /// Rend `None` quand il n'y a rien en suspens et que la boucle principale
    /// doit prendre la main.
    fn resolve_pending<'i>(
        &mut self,
        input: &'i [u8],
    ) -> Result<Option<(Event<'i>, usize)>, DataFault> {
        match self.scan {
            Scan::Done => return Ok(Some((Event::Complete, 0))),
            Scan::LineStart | Scan::InLine => return Ok(None),
            Scan::AfterCr | Scan::AfterDot | Scan::AfterDotCr => {}
        }
        let Some(&premier) = input.first() else {
            return Ok(Some((Event::NeedMore, 0)));
        };
        match self.scan {
            Scan::AfterCr => {
                if premier != b'\n' {
                    return Err(DataFault::BareLineEnding);
                }
                // Les DEUX octets sont comptés ici, le `CR` compris : il ne
                // l'avait pas été quand il a été retenu (cf. `scan_run`).
                self.consume_wire(2)?;
                self.emit(2)?;
                self.end_line();
                // Le `CR` avait été consommé sans être émis : on rend les deux
                // ensemble, depuis une constante, puisqu'ils viennent de deux
                // lectures différentes et qu'aucune tranche d'entrée ne les tient.
                Ok(Some((Event::Content(b"\r\n"), 1)))
            }
            Scan::AfterDotCr => {
                if premier != b'\n' {
                    return Err(DataFault::BareLineEnding);
                }
                self.scan = Scan::Done;
                Ok(Some((Event::Complete, 1)))
            }
            // `Scan::AfterDot` : le point était échappé. Il n'est pas émis, et
            // l'octet courant appartient à la ligne — la boucle principale le
            // traitera.
            _ => match premier {
                // Le `CR` n'est pas compté tant qu'il n'est pas confirmé.
                b'\r' => {
                    self.scan = Scan::AfterDotCr;
                    Ok(Some((Event::NeedMore, 1)))
                }
                b'\n' => Err(DataFault::BareLineEnding),
                _ => {
                    self.scan = Scan::InLine;
                    Ok(None)
                }
            },
        }
    }

    /// Parcourt l'entrée jusqu'à la première discontinuité.
    fn scan_run<'i>(&mut self, input: &'i [u8]) -> Result<(Event<'i>, usize), DataFault> {
        let mut rang = 0_usize;
        while let Some(&octet) = input.get(rang) {
            match (self.scan, octet) {
                (_, b'\n') => return Err(DataFault::BareLineEnding),
                (_, b'\r') => match input.get(rang.saturating_add(1)) {
                    Some(b'\n') => {
                        self.consume_wire(2)?;
                        self.emit(2)?;
                        self.end_line();
                        rang = rang.saturating_add(2);
                    }
                    // Un `CR` suivi d'autre chose que `LF` : isolé, donc refusé.
                    Some(_) => return Err(DataFault::BareLineEnding),
                    // Le `CR` termine l'entrée : on le retient, sans l'émettre
                    // NI LE COMPTER. Le compter ici et non dans le cas où il est
                    // suivi d'autre chose ferait dépendre la faute rendue de
                    // l'endroit où la lecture a été coupée — et une faute qui
                    // change avec le découpage, c'est la contrebande SMTP en
                    // miniature. Trouvé par `fuzz_ams_smtp_data`.
                    None => {
                        self.scan = Scan::AfterCr;
                        return Ok((self.cut(input, rang), rang.saturating_add(1)));
                    }
                },
                (Scan::LineStart, b'.') => return self.on_leading_dot(input, rang),
                _ => {
                    self.consume_wire(1)?;
                    self.emit(1)?;
                    self.scan = Scan::InLine;
                    rang = rang.saturating_add(1);
                }
            }
        }
        Ok((self.cut(input, rang), rang))
    }

    /// Un `.` en début de ligne : fin de message, ou point échappé.
    fn on_leading_dot<'i>(
        &mut self,
        input: &'i [u8],
        rang: usize,
    ) -> Result<(Event<'i>, usize), DataFault> {
        self.consume_wire(1)?;
        let apres = rang.saturating_add(1);
        match input.get(apres) {
            Some(b'\r') => match input.get(apres.saturating_add(1)) {
                Some(b'\n') => {
                    // `<CRLF>.<CRLF>` — et RIEN d'autre ne termine un message.
                    if rang == 0 {
                        self.scan = Scan::Done;
                        Ok((Event::Complete, 3))
                    } else {
                        // Rendre d'abord le contenu accumulé ; l'appel suivant
                        // retombera ici avec `rang == 0` et conclura.
                        self.line_octets = self.line_octets.saturating_sub(1);
                        Ok((self.cut(input, rang), rang))
                    }
                }
                Some(_) => Err(DataFault::BareLineEnding),
                // Idem : le `CR` retenu n'est pas compté.
                None => {
                    self.scan = Scan::AfterDotCr;
                    Ok((self.cut(input, rang), apres.saturating_add(1)))
                }
            },
            Some(b'\n') => Err(DataFault::BareLineEnding),
            // Point ÉCHAPPÉ : il est consommé, jamais émis (RFC 5321 §4.5.2).
            Some(_) => {
                self.scan = Scan::InLine;
                Ok((self.cut(input, rang), apres))
            }
            None => {
                self.scan = Scan::AfterDot;
                Ok((self.cut(input, rang), apres))
            }
        }
    }

    /// Rend le morceau `input[..fin]`, ou `NeedMore` s'il est vide.
    fn cut<'i>(&self, input: &'i [u8], fin: usize) -> Event<'i> {
        let morceau = input.get(..fin).unwrap_or_default();
        if morceau.is_empty() {
            Event::NeedMore
        } else {
            Event::Content(morceau)
        }
    }

    /// Compte `n` octets lus sur le fil, et vérifie la borne de ligne.
    fn consume_wire(&mut self, n: usize) -> Result<(), DataFault> {
        self.line_octets = self.line_octets.saturating_add(n);
        // La borne de la RFC 5321 §4.5.3.1.6 compte le CRLF ; on le réserve.
        if self.line_octets > self.max_line {
            return Err(DataFault::LineTooLong {
                limit: self.max_line,
            });
        }
        Ok(())
    }

    /// Compte `n` octets rendus, et vérifie la borne de message.
    fn emit(&mut self, n: u64) -> Result<(), DataFault> {
        self.content_octets = self.content_octets.saturating_add(n);
        if self.content_octets > self.max_message {
            return Err(DataFault::MessageTooLarge {
                limit: self.max_message,
            });
        }
        Ok(())
    }

    /// Une ligne s'achève.
    fn end_line(&mut self) {
        self.line_octets = 0;
        self.scan = Scan::LineStart;
    }
}

#[cfg(test)]
mod tests {
    use super::{DataFault, DataReceiver, Event};
    use crate::Limits;

    /// Ce qu'une lecture complète a produit.
    #[derive(Debug, PartialEq, Eq)]
    enum Lecture {
        /// Le message, dé-échappé.
        Message(std::vec::Vec<u8>),
        /// Le flux s'est arrêté sans `<CRLF>.<CRLF>`.
        Tronque,
    }

    /// Lit `flux` en le donnant par tranches de `taille`, comme le ferait une
    /// boucle qui lit une socket.
    fn lire(flux: &[u8], taille: usize, max_message: u64) -> Result<Lecture, DataFault> {
        lire_avec(flux, taille, &Limits::DEFAULT, max_message)
    }

    fn lire_avec(
        flux: &[u8],
        taille: usize,
        limits: &Limits,
        max_message: u64,
    ) -> Result<Lecture, DataFault> {
        let mut receveur = DataReceiver::new(limits, max_message);
        let mut sortie = std::vec::Vec::new();
        let mut debut = 0_usize;
        let mut fin = 0_usize;
        loop {
            if debut == fin {
                if fin == flux.len() {
                    return Ok(Lecture::Tronque);
                }
                fin = flux.len().min(fin.saturating_add(taille));
            }
            let (evenement, consomme) = receveur.next(&flux[debut..fin])?;
            match evenement {
                Event::Complete => return Ok(Lecture::Message(sortie)),
                Event::Content(morceau) => sortie.extend_from_slice(morceau),
                Event::NeedMore => {}
            }
            // L'INVARIANTE DE PROGRÈS, éprouvée à chaque appel : sans elle, ce
            // pilote — comme une vraie boucle — tournerait à vide.
            //
            // La condition est SIMPLE, et pas `consomme > 0 || conclu` : un `||`
            // court-circuite, et son membre droit resterait à jamais découvert
            // puisque le gauche est toujours vrai. On conclut donc avant.
            assert!(consomme > 0, "le récepteur n'a ni consommé ni conclu");
            debut = debut.saturating_add(consomme);
        }
    }

    /// Le même flux, lu avec **toutes** les tailles de tranche possibles.
    ///
    /// C'est là que vivent les défauts : un terminateur coupé entre deux lectures
    /// n'est pas le même problème qu'un terminateur entier.
    fn lire_de_toutes_les_facons(flux: &[u8], max_message: u64) -> Result<Lecture, DataFault> {
        let mut reference: Option<Result<Lecture, DataFault>> = None;
        for taille in 1..=flux.len() {
            let obtenu = lire(flux, taille, max_message);
            match &reference {
                None => reference = Some(obtenu),
                Some(attendu) => assert_eq!(
                    &obtenu, attendu,
                    "tranche de {taille} octets : résultat différent"
                ),
            }
        }
        reference.expect("un flux non vide")
    }

    fn message(octets: &[u8]) -> Lecture {
        Lecture::Message(octets.to_vec())
    }

    // ── Le cas ordinaire ────────────────────────────────────────────────────

    #[test]
    fn un_message_se_lit_a_l_identique_quelle_que_soit_la_taille_des_lectures() {
        assert_eq!(
            lire_de_toutes_les_facons(b"From: moi\r\n\r\nbonjour\r\n.\r\n", 1024),
            Ok(message(b"From: moi\r\n\r\nbonjour\r\n"))
        );
    }

    #[test]
    fn un_message_vide_est_licite() {
        // `DATA` suivi immédiatement de `.` : un message sans une ligne.
        assert_eq!(lire_de_toutes_les_facons(b".\r\n", 1024), Ok(message(b"")));
    }

    #[test]
    fn le_point_echappe_est_retire() {
        // RFC 5321 §4.5.2 : le premier point d'une ligne qui en porte est supprimé.
        assert_eq!(
            lire_de_toutes_les_facons(b"..cache\r\n.\r\n", 1024),
            Ok(message(b".cache\r\n"))
        );
        assert_eq!(
            lire_de_toutes_les_facons(b"...deux\r\n.\r\n", 1024),
            Ok(message(b"..deux\r\n"))
        );
    }

    #[test]
    fn une_ligne_a_point_non_echappee_perd_son_point() {
        // La RFC dit « le premier caractère est supprimé » sans condition : un
        // expéditeur qui n'échappe pas voit sa ligne modifiée, et c'est la règle.
        assert_eq!(
            lire_de_toutes_les_facons(b".pas-echappe\r\n.\r\n", 1024),
            Ok(message(b"pas-echappe\r\n"))
        );
    }

    #[test]
    fn un_flux_sans_terminateur_ne_rend_pas_de_message() {
        assert_eq!(
            lire_de_toutes_les_facons(b"jamais fini\r\n", 1024),
            Ok(Lecture::Tronque)
        );
        // Y compris quand il s'arrête au milieu du terminateur.
        assert_eq!(
            lire_de_toutes_les_facons(b"a\r\n.\r", 1024),
            Ok(Lecture::Tronque)
        );
        assert_eq!(
            lire_de_toutes_les_facons(b"a\r\n.", 1024),
            Ok(Lecture::Tronque)
        );
        assert_eq!(
            lire_de_toutes_les_facons(b"a\r", 1024),
            Ok(Lecture::Tronque)
        );
    }

    // ── La contrebande SMTP ─────────────────────────────────────────────────

    #[test]
    fn aucune_variante_du_terminateur_n_est_acceptee() {
        // CHACUNE de ces suites est une fin de message pour au moins une
        // implémentation déployée. Ici, aucune ne l'est : elles portent toutes
        // un CR ou un LF isolé, et sont refusées AVANT d'être interprétées.
        for contrebande in [
            b"a\n.\n".as_slice(), // tout en LF
            b"a\r\n.\n",          // terminateur en LF seul
            b"a\n.\r\n",          // ligne en LF, terminateur conforme
            b"a\r.\r\n",          // ligne en CR seul
            b"a\r\n.\r\r\n",      // CR doublé dans le terminateur
        ] {
            assert_eq!(
                lire_de_toutes_les_facons(contrebande, 1024),
                Err(DataFault::BareLineEnding),
                "{contrebande:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn le_message_contrebande_est_refuse_avant_d_etre_coupe() {
        // La forme complète de l'attaque : un pair fait passer un SECOND message
        // en pariant que le serveur suivant coupera le flux ailleurs. Le refus
        // tombe sur le LF isolé, donc avant toute interprétation.
        let attaque = b"Subject: legitime\r\n\r\ncorps\r\n\n.\r\nMAIL FROM:<usurpe@example>\r\n";
        assert_eq!(
            lire_de_toutes_les_facons(attaque, 65536),
            Err(DataFault::BareLineEnding)
        );
    }

    #[test]
    fn un_point_seul_suivi_d_autre_chose_qu_un_crlf_est_refuse() {
        assert_eq!(
            lire_de_toutes_les_facons(b"a\r\n.\rx\r\n.\r\n", 1024),
            Err(DataFault::BareLineEnding)
        );
    }

    // ── Les bornes ──────────────────────────────────────────────────────────

    #[test]
    fn une_ligne_trop_longue_est_refusee() {
        // RFC 5321 §4.5.3.1.6 : 1000 octets, CRLF compris.
        let etroites = Limits {
            max_text_line_octets: 6,
            ..Limits::DEFAULT
        };
        assert_eq!(
            lire_avec(b"abcd\r\n.\r\n", 3, &etroites, 1024),
            Ok(message(b"abcd\r\n"))
        );
        assert_eq!(
            lire_avec(b"abcde\r\n.\r\n", 3, &etroites, 1024),
            Err(DataFault::LineTooLong { limit: 6 })
        );
    }

    #[test]
    fn le_point_echappe_compte_dans_la_longueur_de_ligne() {
        // Il occupe bien un octet SUR LE FIL, même s'il n'entre pas dans le
        // message : le borner sur le message laisserait passer une ligne plus
        // longue que ce que la RFC autorise.
        let etroites = Limits {
            max_text_line_octets: 6,
            ..Limits::DEFAULT
        };
        assert_eq!(
            lire_avec(b"..abcd\r\n.\r\n", 3, &etroites, 1024),
            Err(DataFault::LineTooLong { limit: 6 })
        );
    }

    #[test]
    fn la_borne_de_ligne_ne_se_contourne_pas_en_coupant_l_entree() {
        // Une borne qu'on esquive en découpant l'entrée autrement n'est pas une
        // borne. Ces trois flux passent par les trois endroits où un octet est
        // compté, et chacun est lu de deux façons.
        //
        // Un `CR` RETENU n'y figure pas, et c'est voulu : il n'est compté qu'une
        // fois confirmé comme moitié d'un CRLF. Le compter plus tôt ferait
        // dépendre la faute rendue de l'endroit où la lecture a été coupée.
        for (flux, max_ligne) in [
            (b"ab".as_slice(), 1), // un octet ordinaire
            (b".", 0),             // le point de début de ligne
            (b"abc\r\n", 4),       // le CRLF, compté pour deux
        ] {
            let etroites = Limits {
                max_text_line_octets: max_ligne,
                ..Limits::DEFAULT
            };
            // Deux découpages : octet par octet, puis d'un seul tenant. Ils ne
            // passent pas par les mêmes états, donc pas par les mêmes contrôles.
            for decoupe in [1_usize, flux.len()] {
                let mut receveur = DataReceiver::new(&etroites, 1024);
                let mut resultat = Ok(());
                let mut rang = 0_usize;
                while rang < flux.len() {
                    let fin = flux.len().min(rang.saturating_add(decoupe));
                    match receveur.next(&flux[rang..fin]) {
                        Ok((_, consomme)) => rang = rang.saturating_add(consomme.max(1)),
                        Err(faute) => {
                            resultat = Err(faute);
                            break;
                        }
                    }
                }
                assert_eq!(
                    resultat,
                    Err(DataFault::LineTooLong { limit: max_ligne }),
                    "{flux:?} sous une borne de {max_ligne}, par tranches de {decoupe}"
                );
            }
        }
    }

    #[test]
    fn un_message_trop_grand_est_refuse() {
        assert_eq!(
            lire_de_toutes_les_facons(b"abcd\r\n.\r\n", 6),
            Ok(message(b"abcd\r\n"))
        );
        // Le CRLF franchit la borne : il compte pour deux.
        assert_eq!(
            lire_de_toutes_les_facons(b"abcde\r\n.\r\n", 6),
            Err(DataFault::MessageTooLarge { limit: 6 })
        );
        // Un octet ORDINAIRE la franchit aussi. Ce n'est pas le même endroit du
        // code, et une borne vérifiée à un seul endroit se contourne par l'autre.
        assert_eq!(
            lire_de_toutes_les_facons(b"abc\r\n.\r\n", 2),
            Err(DataFault::MessageTooLarge { limit: 2 })
        );
    }

    // ── L'état du récepteur ─────────────────────────────────────────────────

    #[test]
    fn le_receveur_dit_ou_il_en_est() {
        let mut receveur = DataReceiver::new(&Limits::DEFAULT, 1024);
        assert!(!receveur.is_complete());
        assert_eq!(receveur.content_octets(), 0);

        let (evenement, consomme) = receveur.next(b"abc\r\n").expect("recevable");
        assert_eq!(evenement, Event::Content(b"abc\r\n"));
        assert_eq!(consomme, 5);
        assert_eq!(receveur.content_octets(), 5);

        let (evenement, consomme) = receveur.next(b".\r\n").expect("recevable");
        assert_eq!(evenement, Event::Complete);
        assert_eq!(consomme, 3);
        assert!(receveur.is_complete());

        // Une fois terminé, il le reste, et ne consomme plus rien.
        assert_eq!(receveur.next(b"n'importe quoi"), Ok((Event::Complete, 0)));
    }

    #[test]
    fn une_entree_vide_demande_simplement_la_suite() {
        let mut receveur = DataReceiver::new(&Limits::DEFAULT, 1024);
        assert_eq!(receveur.next(b""), Ok((Event::NeedMore, 0)));
        // Y compris quand un octet est en suspens.
        let (_, consomme) = receveur.next(b"a\r").expect("recevable");
        assert_eq!(consomme, 2);
        assert_eq!(receveur.next(b""), Ok((Event::NeedMore, 0)));
    }

    #[test]
    fn les_types_se_copient_et_se_deboguent() {
        let receveur = DataReceiver::new(&Limits::DEFAULT, 1024);
        let copie = receveur.clone();
        assert_eq!(copie.content_octets(), receveur.content_octets());
        assert!(!std::format!("{receveur:?}").is_empty());
        assert!(!std::format!("{:?}", Event::Complete).is_empty());
        assert_ne!(Event::Complete, Event::NeedMore);

        for fault in [
            DataFault::BareLineEnding,
            DataFault::LineTooLong { limit: 1000 },
            DataFault::MessageTooLarge { limit: 10 },
        ] {
            let texte = std::format!("{fault}");
            assert!(
                texte.len() > 10,
                "{fault:?} : « {texte} » est trop laconique"
            );
            assert_eq!(crate::Error::from(fault), crate::Error::Data(fault));
        }
    }
}
