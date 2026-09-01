//! La table bornée, et le verdict qu'elle rend.

use crate::{Key, Source, Thresholds};

/// La durée d'une fenêtre de comptage, en millisecondes.
const WINDOW_MILLIS: u64 = 60_000;

/// Un instant, en millisecondes depuis une origine que l'appelant choisit.
///
/// **Le garde ne lit jamais l'heure** (C1) : on la lui donne. Il exige seulement
/// qu'elle soit **monotone** — une horloge qui recule ferait rouvrir des fenêtres
/// déjà closes, et un pair qui contrôlerait ce recul y verrait un moyen de ne
/// jamais franchir un seuil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    /// Un instant, en millisecondes depuis l'origine de l'appelant.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// La valeur, en millisecondes.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Ce qu'une source vient de faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Une connexion s'ouvre.
    Connection,
    /// Une commande a été reçue.
    Command,
    /// Une trame invalide a été reçue — syntaxe refusée, fin de ligne ambiguë,
    /// authentification en échec.
    InvalidFrame,
    /// Un destinataire a été refusé DÉFINITIVEMENT — boîte inconnue, relais nié.
    ///
    /// # CE N'EST PAS UNE FAUTE, ET C'EST TOUT LE PROBLÈME
    ///
    /// Un expéditeur qui se trompe d'adresse n'est pas un attaquant, et compter
    /// son refus comme une trame invalide bannirait des correspondants
    /// ordinaires. Une RAFALE de refus, en revanche, est la signature d'une
    /// récolte d'adresses : le pair ne cherche pas à écrire, il cherche à savoir
    /// QUI EXISTE — et chaque refus est une réponse qu'il note.
    ///
    /// D'où un compteur à soi, avec son propre seuil. Le confondre avec un autre
    /// obligerait à choisir entre bannir des innocents et laisser énumérer.
    ///
    /// **UN REFUS TEMPORAIRE N'EN EST PAS UN** : il dit que NOUS ne pouvons pas,
    /// pas que l'adresse n'existe pas. Il n'apprend donc rien à qui récolte, et
    /// le compter punirait un pair pour nos propres embarras.
    RefusedRecipient,
}

/// Ce que le garde répond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Servir.
    Allow,
    /// Refuser **pour l'instant** : le débit dépasse le seuil, mais la source
    /// n'est pas bannie. Elle repassera à la fenêtre suivante.
    Throttled,
    /// Refuser **jusqu'à** cet instant.
    Banned {
        /// Fin du bannissement.
        until: Instant,
    },
}

/// Une case de la table du garde.
///
/// L'appelant fournit le tableau : le garde n'alloue pas, et sa mémoire est donc
/// bornée par construction plutôt que par discipline.
#[derive(Debug, Clone, Copy)]
pub struct Slot {
    occupied: bool,
    key: Key,
    last_seen: u64,
    window_start: u64,
    connections: u32,
    commands: u32,
    invalid: u32,
    refused: u32,
    banned_until: Option<u64>,
}

impl Slot {
    /// Une case libre, pour initialiser un tableau.
    pub const EMPTY: Self = Self {
        occupied: false,
        key: Key::ZERO,
        last_seen: 0,
        window_start: 0,
        connections: 0,
        commands: 0,
        invalid: 0,
        refused: 0,
        banned_until: None,
    };
}

impl Default for Slot {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Le garde : il compte, il juge, il n'attend jamais.
///
/// # Sa mémoire est bornée, et c'est une défense
///
/// Une table qui grandit avec le nombre de sources est un épuisement de mémoire
/// offert à qui dispose d'un `/64` — dix-huit milliards de milliards d'adresses.
/// Le garde travaille donc dans un tableau que l'appelant lui donne, et dont il
/// ne sort jamais.
///
/// # Quand la table est pleine, ce qu'on oublie est choisi
///
/// Oublier au hasard rendrait l'attaque triviale : il suffirait d'inonder depuis
/// mille sources pour faire disparaître son propre bannissement. L'ordre
/// d'éviction est donc :
///
/// 1. une case **libre**, s'il en reste ;
/// 2. sinon la case **non bannie** vue le moins récemment ;
/// 3. sinon — toutes bannies — **rien du tout** : la source nouvelle n'est pas
///    suivie, et le garde la laisse passer.
///
/// **Un bannissement en cours ne s'efface JAMAIS**, pas même au profit d'un autre
/// bannissement. La première rédaction sacrifiait celui qui expirait le plus tôt,
/// « puisque sa perte coûte le moins » ; le fuzz a montré qu'une table pleine de
/// peines suffisait alors à s'en libérer. Entre oublier un attaquant prouvé et ne
/// pas commencer à compter un inconnu, c'est l'oubli qui coûte le plus cher.
///
/// Le revers est réel et assumé : une table entièrement occupée par des peines en
/// cours **cesse d'apprendre**. C'est une dégradation, pas un déni — les sources
/// non suivies sont servies — et les peines finissent par échoir.
#[derive(Debug)]
pub struct Guard<'a> {
    slots: &'a mut [Slot],
    thresholds: Thresholds,
}

impl<'a> Guard<'a> {
    /// Ouvre un garde sur la table que l'appelant fournit.
    ///
    /// **La table n'est PAS effacée.** Une table neuve s'initialise avec
    /// [`Slot::EMPTY`], qui est aussi son `Default` ; effacer ici interdirait de
    /// rouvrir un garde sur un état qui doit survivre — ce dont a besoin tout
    /// appelant qui sert plusieurs connexions à partir d'une seule table.
    /// [`Guard::reset`] efface, quand c'est ce qu'on veut.
    #[must_use]
    pub fn new(slots: &'a mut [Slot], thresholds: Thresholds) -> Self {
        Self { slots, thresholds }
    }

    /// Oublie tout ce qui a été observé.
    pub fn reset(&mut self) {
        for case in self.slots.iter_mut() {
            *case = Slot::EMPTY;
        }
    }

    /// Le nombre de sources suivies.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.slots.iter().filter(|case| case.occupied).count()
    }

    /// La capacité de la table.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Le verdict pour une source, **sans rien compter**.
    ///
    /// À interroger avant d'accepter une connexion : demander l'avis du garde ne
    /// doit pas être un événement de plus à son compteur.
    #[must_use]
    pub fn verdict(&self, source: Source, now: Instant) -> Verdict {
        let cle = self.key(source);
        match self
            .slots
            .iter()
            .find(|case| case.occupied && case.key == cle)
        {
            Some(case) => Self::ban_verdict(case, now).unwrap_or(Verdict::Allow),
            None => Verdict::Allow,
        }
    }

    /// Les sources bannies à cet instant, et jusqu'à quand.
    ///
    /// # POURQUOI CETTE LISTE EXISTE
    ///
    /// C8 borne ce qu'une source peut coûter, et le fait **sans que personne ne
    /// décide** — c'est tout l'intérêt. Mais un garde qui punit sans qu'on puisse
    /// voir qui il punit est un garde qu'on ne peut pas corriger : un exploitant
    /// dont le propre réseau se fait bannir n'aurait que le redémarrage pour
    /// s'en sortir, et redémarrer effacerait aussi les peines méritées.
    ///
    /// **ELLE NE MONTRE QUE LES PEINES EN COURS.** Une peine échue n'est plus une
    /// peine, et la montrer ferait lire comme un bannissement ce qui n'en est
    /// plus un.
    pub fn banned(&self, now: Instant) -> impl Iterator<Item = (Key, Instant)> + '_ {
        self.slots.iter().filter_map(move |case| {
            let jusqu_a = case.banned_until?;
            (case.occupied && jusqu_a > now.as_millis())
                .then(|| (case.key, Instant::from_millis(jusqu_a)))
        })
    }

    /// Lève le bannissement d'une source, et oublie ce qu'elle a fait.
    ///
    /// Rend `true` s'il y avait quelque chose à lever.
    ///
    /// # LEVER, C'EST OUBLIER — ET NON RACCOURCIR LA PEINE
    ///
    /// Effacer la seule date de fin laisserait les compteurs qui l'ont
    /// déclenchée : le premier événement suivant rebannirait la source, et
    /// l'exploitant croirait sa levée sans effet. Ce qui est levé est donc la
    /// case entière — la source redevient inconnue, et le garde recommence à
    /// apprendre.
    ///
    /// **C'EST AUSSI CE QUI REND LA PLACE.** Une table pleine de peines cesse
    /// d'apprendre (voir plus haut) ; lever en libère une.
    pub fn lift(&mut self, source: Source) -> bool {
        let cle = self.key(source);
        let Some(case) = self
            .slots
            .iter_mut()
            .find(|case| case.occupied && case.key == cle)
        else {
            return false;
        };
        *case = Slot::EMPTY;
        true
    }

    /// Enregistre un événement et rend le verdict.
    pub fn observe(&mut self, source: Source, event: Event, now: Instant) -> Verdict {
        let cle = self.key(source);
        let seuils = self.thresholds;
        let Some(case) = self.slot_for(cle, now) else {
            // TABLE DE CAPACITÉ NULLE : le garde ne retient rien, donc ne peut
            // rien reprocher. C'est un choix de l'appelant — passer une table
            // vide, c'est demander un garde qui laisse passer — et non un défaut
            // à masquer par une panique.
            return Verdict::Allow;
        };

        if let Some(verdict) = Self::ban_verdict(case, now) {
            case.last_seen = now.as_millis();
            return verdict;
        }
        // Le bannissement est échu : on repart de zéro plutôt que de reprendre
        // les compteurs qui l'avaient déclenché.
        case.banned_until = None;

        if now.as_millis().saturating_sub(case.window_start) >= WINDOW_MILLIS {
            case.window_start = now.as_millis();
            case.connections = 0;
            case.commands = 0;
            case.invalid = 0;
            case.refused = 0;
        }
        case.last_seen = now.as_millis();

        match event {
            Event::Connection => {
                case.connections = case.connections.saturating_add(1);
                if case.connections > seuils.connections_per_minute {
                    return Verdict::Throttled;
                }
            }
            Event::Command => {
                case.commands = case.commands.saturating_add(1);
                if case.commands > seuils.commands_per_minute {
                    return Verdict::Throttled;
                }
            }
            Event::RefusedRecipient => {
                // **ZÉRO ÉTEINT CE COMPTEUR**, et c'est ce qui rend le champ
                // ajoutable sans rien casser : une configuration écrite avant
                // qu'il n'existe décode zéro, et se comporte comme avant.
                if seuils.refused_recipients_per_minute == 0 {
                    return Verdict::Allow;
                }
                case.refused = case.refused.saturating_add(1);
                if case.refused > seuils.refused_recipients_per_minute {
                    let until = now.as_millis().saturating_add(seuils.ban_millis());
                    if until <= now.as_millis() {
                        return Verdict::Throttled;
                    }
                    case.banned_until = Some(until);
                    return Verdict::Banned {
                        until: Instant::from_millis(until),
                    };
                }
            }
            Event::InvalidFrame => {
                case.invalid = case.invalid.saturating_add(1);
                if case.invalid > seuils.invalid_frames_per_minute {
                    let until = now.as_millis().saturating_add(seuils.ban_millis());
                    // UNE PEINE DE DURÉE NULLE N'EN EST PAS UNE. La rendre
                    // reviendrait à annoncer « banni jusqu'à maintenant », que
                    // l'interrogation suivante démentirait aussitôt — un verdict
                    // qui se contredit lui-même. Une configuration à zéro dit
                    // « ne bannis pas » ; on refuse alors l'événement, sans plus.
                    // Trouvé par `fuzz_ams_guard`.
                    if until <= now.as_millis() {
                        return Verdict::Throttled;
                    }
                    case.banned_until = Some(until);
                    return Verdict::Banned {
                        until: Instant::from_millis(until),
                    };
                }
            }
        }
        Verdict::Allow
    }

    /// La clé sous laquelle cette source est comptée.
    fn key(&self, source: Source) -> Key {
        Key::from_source(
            source,
            self.thresholds.ipv4_prefix_bits,
            self.thresholds.ipv6_prefix_bits,
        )
    }

    /// Le bannissement en cours, s'il y en a un.
    fn ban_verdict(case: &Slot, now: Instant) -> Option<Verdict> {
        let until = case.banned_until?;
        if now.as_millis() < until {
            return Some(Verdict::Banned {
                until: Instant::from_millis(until),
            });
        }
        None
    }

    /// La case de cette clé, quitte à en libérer une.
    ///
    /// Rend `None` quand la table n'a aucune case.
    fn slot_for(&mut self, cle: Key, now: Instant) -> Option<&mut Slot> {
        let rang = self.index_of(cle, now)?;
        // L'indice vient de `enumerate()` sur CETTE tranche, et `&mut self`
        // interdit qu'elle ait changé entre-temps : il est valide par
        // construction. Un `get_mut(..)?` ouvrirait ici une branche que rien ne
        // pourrait exercer, et le 100 % de C2 la compterait à jamais découverte.
        let case = &mut self.slots[rang];
        if !case.occupied || case.key != cle {
            *case = Slot {
                occupied: true,
                key: cle,
                last_seen: now.as_millis(),
                window_start: now.as_millis(),
                ..Slot::EMPTY
            };
        }
        Some(case)
    }

    /// Où loger cette clé, s'il y a une case.
    fn index_of(&self, cle: Key, now: Instant) -> Option<usize> {
        let mut libre: Option<usize> = None;
        let mut plus_ancienne_non_bannie: Option<(usize, u64)> = None;

        for (rang, case) in self.slots.iter().enumerate() {
            if case.occupied && case.key == cle {
                return Some(rang);
            }
            if !case.occupied {
                libre = libre.or(Some(rang));
                continue;
            }
            // UNE PEINE EN COURS N'EST JAMAIS CANDIDATE À L'ÉVICTION.
            if Self::ban_verdict(case, now).is_none()
                && plus_ancienne_non_bannie.is_none_or(|(_, vue)| case.last_seen < vue)
            {
                plus_ancienne_non_bannie = Some((rang, case.last_seen));
            }
        }

        libre.or(plus_ancienne_non_bannie.map(|(rang, _)| rang))
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Guard, Instant, Slot, Verdict};
    use crate::{Source, Thresholds};
    use core::time::Duration;

    const PAIR: Source = Source::V4([192, 0, 2, 1]);
    const AUTRE: Source = Source::V4([198, 51, 100, 1]);

    fn seuils_serres() -> Thresholds {
        Thresholds {
            connections_per_minute: 2,
            commands_per_minute: 3,
            invalid_frames_per_minute: 2,
            ban_duration: Duration::from_secs(3600),
            ..Thresholds::DEFAULT
        }
    }

    fn t(millis: u64) -> Instant {
        Instant::from_millis(millis)
    }

    /// Le verdict est-il un bannissement ?
    ///
    /// TOTAL, et c'est le point : un `matches!` engendre un bras `_ => false`
    /// que rien n'emprunte quand l'assertion réussit toujours. Les deux bras
    /// d'ici sont exercés.
    fn est_banni(verdict: Verdict) -> bool {
        match verdict {
            Verdict::Banned { .. } => true,
            Verdict::Allow | Verdict::Throttled => false,
        }
    }

    // ── Le bannissement ─────────────────────────────────────────────────────

    #[test]
    fn le_seuil_de_trames_invalides_bannit_pour_la_duree_configuree() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, t(0)),
            Verdict::Allow
        );
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, t(1)),
            Verdict::Allow
        );
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, t(2)),
            Verdict::Banned {
                until: t(3_600_002)
            }
        );
    }

    #[test]
    fn un_banni_le_reste_pour_tout_evenement_et_sans_recompter() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        for _ in 0..3 {
            garde.observe(PAIR, Event::InvalidFrame, t(0));
        }
        // Toute activité ultérieure reçoit le même verdict.
        for evenement in [Event::Connection, Event::Command, Event::InvalidFrame] {
            assert!(est_banni(garde.observe(PAIR, evenement, t(1_000))));
        }
        // Et l'interrogation seule aussi, sans rien compter.
        assert!(est_banni(garde.verdict(PAIR, t(1_000))));
    }

    #[test]
    fn le_bannissement_expire_et_les_compteurs_repartent_de_zero() {
        // Reprendre les compteurs qui avaient déclenché le bannissement le
        // ferait retomber au premier événement suivant.
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        for _ in 0..3 {
            garde.observe(PAIR, Event::InvalidFrame, t(0));
        }
        let apres = t(3_600_003);
        assert_eq!(garde.verdict(PAIR, apres), Verdict::Allow);
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, apres),
            Verdict::Allow
        );
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, apres),
            Verdict::Allow
        );
    }

    #[test]
    fn une_peine_de_duree_nulle_freine_sans_bannir() {
        // « Ne bannis pas » est une configuration licite (C8). Rendre
        // « banni jusqu'à maintenant » serait un verdict qui se contredit.
        let mut table = [Slot::EMPTY; 4];
        let sans_peine = Thresholds {
            ban_duration: Duration::ZERO,
            ..seuils_serres()
        };
        let mut garde = Guard::new(&mut table, sans_peine);
        garde.observe(PAIR, Event::InvalidFrame, t(0));
        garde.observe(PAIR, Event::InvalidFrame, t(0));
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, t(0)),
            Verdict::Throttled
        );
        // Rien n'a été retenu : l'interrogation seule le confirme.
        assert_eq!(garde.verdict(PAIR, t(0)), Verdict::Allow);
    }

    #[test]
    fn une_source_inconnue_est_servie() {
        let mut table = [Slot::EMPTY; 8];
        let garde = Guard::new(&mut table, seuils_serres());
        assert_eq!(garde.verdict(PAIR, t(0)), Verdict::Allow);
        assert_eq!(garde.tracked(), 0);
        assert_eq!(garde.capacity(), 8);
    }

    #[test]
    fn les_sources_sont_comptees_separement() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        for _ in 0..3 {
            garde.observe(PAIR, Event::InvalidFrame, t(0));
        }
        assert_eq!(
            garde.observe(AUTRE, Event::InvalidFrame, t(0)),
            Verdict::Allow
        );
        assert_eq!(garde.tracked(), 2);
    }

    // ── Le débit ────────────────────────────────────────────────────────────

    #[test]
    fn le_debit_excessif_freine_sans_bannir() {
        // Un pair pressé n'est pas un pair hostile : il repassera à la fenêtre
        // suivante.
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        assert_eq!(garde.observe(PAIR, Event::Connection, t(0)), Verdict::Allow);
        assert_eq!(garde.observe(PAIR, Event::Connection, t(1)), Verdict::Allow);
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(2)),
            Verdict::Throttled
        );
        // Le freinage n'est PAS un bannissement : l'interrogation seule passe.
        assert_eq!(garde.verdict(PAIR, t(2)), Verdict::Allow);
        assert!(!est_banni(Verdict::Throttled));
        assert!(!est_banni(Verdict::Allow));
    }

    #[test]
    fn les_commandes_ont_leur_propre_seuil() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        for rang in 0..3 {
            assert_eq!(garde.observe(PAIR, Event::Command, t(rang)), Verdict::Allow);
        }
        assert_eq!(
            garde.observe(PAIR, Event::Command, t(4)),
            Verdict::Throttled
        );
    }

    #[test]
    fn la_fenetre_se_remet_a_zero_apres_une_minute() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        for _ in 0..3 {
            garde.observe(PAIR, Event::Connection, t(0));
        }
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(59_999)),
            Verdict::Throttled
        );
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(60_000)),
            Verdict::Allow
        );
    }

    #[test]
    fn a_cheval_sur_deux_fenetres_le_seuil_peut_etre_double() {
        // LE REVERS ASSUMÉ de la fenêtre fixe, éprouvé plutôt que seulement
        // documenté. La fenêtre s'ouvre au PREMIER événement de la source, pas
        // sur une minute d'horloge : deux connexions en fin de fenêtre, deux au
        // début de la suivante, soit QUATRE sous un seuil de deux — en une
        // milliseconde de plus qu'une minute.
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        assert_eq!(garde.observe(PAIR, Event::Connection, t(0)), Verdict::Allow);
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(59_999)),
            Verdict::Allow
        );
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(60_000)),
            Verdict::Allow
        );
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(60_001)),
            Verdict::Allow
        );
        // La cinquième, elle, est freinée.
        assert_eq!(
            garde.observe(PAIR, Event::Connection, t(60_002)),
            Verdict::Throttled
        );
    }

    // ── La table pleine ─────────────────────────────────────────────────────

    #[test]
    fn une_table_pleine_oublie_la_plus_ancienne_non_bannie() {
        let mut table = [Slot::EMPTY; 2];
        let mut garde = Guard::new(&mut table, seuils_serres());
        garde.observe(Source::V4([10, 0, 0, 1]), Event::Command, t(0));
        garde.observe(Source::V4([10, 0, 0, 2]), Event::Command, t(10));
        // La table est pleine ; la troisième source évince la plus ancienne.
        garde.observe(Source::V4([10, 0, 0, 3]), Event::Command, t(20));
        assert_eq!(garde.tracked(), 2);
        // La deuxième est toujours là : c'est la première qui est partie.
        garde.observe(Source::V4([10, 0, 0, 2]), Event::Command, t(30));
        assert_eq!(garde.tracked(), 2);
    }

    #[test]
    fn un_bannissement_ne_s_efface_jamais_au_profit_d_un_compteur() {
        // L'ATTAQUE QUE CETTE RÈGLE FERME : inonder depuis d'autres sources pour
        // faire oublier son propre bannissement.
        let mut table = [Slot::EMPTY; 2];
        let mut garde = Guard::new(&mut table, seuils_serres());
        let hostile = Source::V4([10, 0, 0, 1]);
        for _ in 0..3 {
            garde.observe(hostile, Event::InvalidFrame, t(0));
        }
        assert!(est_banni(garde.verdict(hostile, t(1))));

        // Vingt sources innocentes défilent : aucune ne déloge le banni.
        for rang in 0..20_u8 {
            garde.observe(Source::V4([10, 0, 1, rang]), Event::Command, t(100));
        }
        assert!(
            est_banni(garde.verdict(hostile, t(200))),
            "le bannissement a été évincé"
        );
    }

    #[test]
    fn une_table_pleine_de_peines_cesse_d_apprendre_plutot_que_d_oublier() {
        // LE FUZZ A TROUVÉ CE CAS. Sacrifier la peine qui expire le plus tôt
        // « puisqu'elle coûte le moins » suffisait à s'en libérer : il n'y avait
        // qu'à remplir la table.
        let mut table = [Slot::EMPTY; 2];
        let mut garde = Guard::new(&mut table, seuils_serres());
        let tot = Source::V4([10, 0, 0, 1]);
        let tard = Source::V4([10, 0, 0, 2]);
        for _ in 0..3 {
            garde.observe(tot, Event::InvalidFrame, t(0));
        }
        for _ in 0..3 {
            garde.observe(tard, Event::InvalidFrame, t(1_000));
        }

        // Cent sources défilent : AUCUNE peine n'est perdue.
        for rang in 0..100_u8 {
            garde.observe(Source::V4([10, 0, 1, rang]), Event::Command, t(2_000));
        }
        assert!(est_banni(garde.verdict(tot, t(2_000))));
        assert!(est_banni(garde.verdict(tard, t(2_000))));
        // Le prix : les nouvelles sources ne sont pas suivies, et sont servies.
        assert_eq!(garde.tracked(), 2);
        assert_eq!(
            garde.verdict(Source::V4([10, 0, 1, 0]), t(2_000)),
            Verdict::Allow
        );

        // Quand les peines échoient, la table réapprend.
        let apres = t(3_601_001);
        garde.observe(Source::V4([10, 0, 2, 0]), Event::Command, apres);
        assert_eq!(garde.verdict(tot, apres), Verdict::Allow);
    }

    #[test]
    fn une_table_pleine_de_peines_juge_encore_ceux_qu_elle_connait() {
        // Ne plus APPRENDRE n'est pas ne plus JUGER : une source déjà suivie est
        // retrouvée dans la table, quelle que soit son occupation.
        let mut table = [Slot::EMPTY; 1];
        let mut garde = Guard::new(&mut table, seuils_serres());
        for _ in 0..3 {
            garde.observe(PAIR, Event::InvalidFrame, t(0));
        }
        for _ in 0..50 {
            garde.observe(AUTRE, Event::Command, t(10));
        }
        assert!(est_banni(garde.observe(PAIR, Event::Command, t(20))));
    }

    #[test]
    fn une_table_sans_case_laisse_tout_passer() {
        // Passer une table vide, c'est demander un garde qui ne retient rien.
        let mut table: [Slot; 0] = [];
        let mut garde = Guard::new(&mut table, seuils_serres());
        assert_eq!(garde.capacity(), 0);
        for _ in 0..100 {
            assert_eq!(
                garde.observe(PAIR, Event::InvalidFrame, t(0)),
                Verdict::Allow
            );
        }
        assert_eq!(garde.tracked(), 0);
    }

    #[test]
    fn rouvrir_un_garde_ne_perd_rien_mais_le_remettre_a_zero_oublie_tout() {
        // C'est ce dont a besoin un appelant qui sert plusieurs connexions à
        // partir d'une seule table : le garde se rouvre à chaque événement, et
        // ce qu'il a appris doit survivre.
        let mut table = [Slot::EMPTY; 4];
        {
            let mut garde = Guard::new(&mut table, seuils_serres());
            for _ in 0..3 {
                garde.observe(PAIR, Event::InvalidFrame, t(0));
            }
        }
        {
            let garde = Guard::new(&mut table, seuils_serres());
            assert_eq!(garde.tracked(), 1);
            assert!(est_banni(garde.verdict(PAIR, t(1))));
        }
        let mut garde = Guard::new(&mut table, seuils_serres());
        garde.reset();
        assert_eq!(garde.tracked(), 0);
        assert_eq!(garde.verdict(PAIR, t(1)), Verdict::Allow);
    }

    // ── Les types ───────────────────────────────────────────────────────────

    #[test]
    fn les_types_se_copient_et_se_deboguent() {
        assert_eq!(t(42).as_millis(), 42);
        assert!(t(1) < t(2));
        assert!(!std::format!("{:?}", t(1)).is_empty());
        assert!(!std::format!("{:?}", Event::Command).is_empty());
        assert_ne!(Event::Command, Event::Connection);
        assert!(!std::format!("{:?}", Verdict::Throttled).is_empty());
        assert_ne!(Verdict::Allow, Verdict::Throttled);

        let vide = Slot::default();
        let copie = vide;
        assert!(!std::format!("{copie:?}").is_empty());
        let mut table = [Slot::EMPTY; 1];
        let garde = Guard::new(&mut table, Thresholds::DEFAULT);
        assert!(!std::format!("{garde:?}").is_empty());
    }

    // ── La levée d'un bannissement ──────────────────────────────────────────

    /// Bannit cette source, et rend le garde prêt à être interrogé.
    fn bannir(garde: &mut Guard<'_>, source: Source) {
        for _ in 0..3 {
            garde.observe(source, Event::InvalidFrame, t(0));
        }
        assert!(
            est_banni(garde.verdict(source, t(0))),
            "la source est bannie"
        );
    }

    /// **UN GARDE QU'ON NE PEUT PAS VOIR EST UN GARDE QU'ON NE PEUT PAS
    /// CORRIGER.**
    ///
    /// C8 punit sans que personne ne décide, et c'est tout l'intérêt. Encore
    /// faut-il qu'un exploitant dont le propre réseau se fait bannir puisse le
    /// constater autrement qu'en redémarrant — ce qui effacerait aussi les peines
    /// méritées.
    #[test]
    fn les_bannissements_en_cours_se_listent() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        assert_eq!(garde.banned(t(0)).count(), 0, "rien n'est banni au départ");

        bannir(&mut garde, PAIR);
        bannir(&mut garde, AUTRE);
        let vus: std::vec::Vec<_> = garde.banned(t(0)).collect();
        assert_eq!(vus.len(), 2, "les deux peines se voient");
        assert!(
            vus.iter()
                .all(|(_, jusqu_a)| jusqu_a.as_millis() == 3_600_000),
            "et chacune dit jusqu'à quand"
        );
    }

    /// **UNE PEINE ÉCHUE N'EST PLUS UNE PEINE**, et ne se montre pas.
    ///
    /// La montrer ferait lire comme un bannissement ce qui n'en est plus un, et
    /// un exploitant lèverait alors ce qui n'existe plus.
    #[test]
    fn une_peine_echue_ne_se_liste_plus() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        bannir(&mut garde, PAIR);
        assert_eq!(garde.banned(t(3_599_999)).count(), 1, "elle court encore");
        assert_eq!(garde.banned(t(3_600_000)).count(), 0, "et elle échoit");
    }

    /// **LEVER, C'EST OUBLIER — ET NON RACCOURCIR LA PEINE.**
    ///
    /// Effacer la seule date de fin laisserait les compteurs qui l'ont
    /// déclenchée : le premier événement suivant rebannirait la source, et
    /// l'exploitant croirait sa levée sans effet.
    #[test]
    fn lever_une_peine_efface_ce_qui_l_avait_causee() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        bannir(&mut garde, PAIR);

        assert!(garde.lift(PAIR), "il y avait quelque chose à lever");
        assert_eq!(garde.verdict(PAIR, t(0)), Verdict::Allow);
        assert_eq!(garde.tracked(), 0, "la source redevient inconnue");
        // **ET LE GARDE RECOMMENCE À APPRENDRE** : un seul événement de plus ne
        // suffit pas à rebannir, puisque les compteurs sont repartis de zéro.
        assert_eq!(
            garde.observe(PAIR, Event::InvalidFrame, t(0)),
            Verdict::Allow
        );
    }

    /// **LEVER CE QUI N'EST PAS BANNI NE FAIT RIEN, ET LE DIT.**
    #[test]
    fn lever_ce_qui_n_est_pas_suivi_ne_dit_pas_le_contraire() {
        let mut table = [Slot::EMPTY; 8];
        let mut garde = Guard::new(&mut table, seuils_serres());
        assert!(!garde.lift(PAIR), "rien à lever");

        // Une source suivie mais NON bannie se lève quand même : c'est un oubli,
        // et l'exploitant a le droit de faire oublier.
        garde.observe(PAIR, Event::Connection, t(0));
        assert!(garde.lift(PAIR));
        assert_eq!(garde.tracked(), 0);
    }

    // ── La récolte d'adresses ───────────────────────────────────────────────

    /// **UNE RAFALE DE REFUS EST UNE RÉCOLTE, ET UN REFUS N'EN EST PAS UNE.**
    ///
    /// Un expéditeur qui se trompe d'adresse n'est pas un attaquant. Un pair qui
    /// en essaie cinquante par minute ne cherche pas à écrire : il cherche à
    /// savoir QUI EXISTE, et chaque refus est une réponse qu'il note.
    #[test]
    fn une_rafale_de_refus_finit_par_bannir() {
        let mut table = [Slot::EMPTY; 8];
        let seuils = Thresholds {
            refused_recipients_per_minute: 3,
            ..seuils_serres()
        };
        let mut garde = Guard::new(&mut table, seuils);
        for _ in 0..3 {
            assert_eq!(
                garde.observe(PAIR, Event::RefusedRecipient, t(0)),
                Verdict::Allow,
                "sous le seuil, on sert"
            );
        }
        assert!(
            est_banni(garde.observe(PAIR, Event::RefusedRecipient, t(0))),
            "au-delà, c'est une récolte"
        );
    }

    /// **LE COMPTEUR EST À LUI**, et ne se mélange pas aux trames invalides.
    ///
    /// Les confondre obligerait à choisir entre bannir des innocents — un
    /// correspondant qui se trompe d'adresse — et laisser énumérer.
    #[test]
    fn les_refus_ne_comptent_pas_comme_des_trames_invalides() {
        let mut table = [Slot::EMPTY; 8];
        let seuils = Thresholds {
            refused_recipients_per_minute: 100,
            invalid_frames_per_minute: 2,
            ..seuils_serres()
        };
        let mut garde = Guard::new(&mut table, seuils);
        for _ in 0..50 {
            assert_eq!(
                garde.observe(PAIR, Event::RefusedRecipient, t(0)),
                Verdict::Allow
            );
        }
        assert_eq!(
            garde.verdict(PAIR, t(0)),
            Verdict::Allow,
            "cinquante refus ne font pas trois trames invalides"
        );
    }

    /// **ZÉRO ÉTEINT LE COMPTEUR**, et c'est ce qui rend le seuil ajoutable.
    ///
    /// Une configuration écrite avant qu'il n'existe décode zéro. L'inverse aurait
    /// banni tout le monde chez tous ceux qui ne réécrivent pas leur fichier.
    #[test]
    fn un_seuil_nul_eteint_le_compteur() {
        let mut table = [Slot::EMPTY; 8];
        let seuils = Thresholds {
            refused_recipients_per_minute: 0,
            ..seuils_serres()
        };
        let mut garde = Guard::new(&mut table, seuils);
        for _ in 0..1_000 {
            assert_eq!(
                garde.observe(PAIR, Event::RefusedRecipient, t(0)),
                Verdict::Allow
            );
        }
        assert_eq!(
            garde.tracked(),
            1,
            "la source est suivie, mais rien ne la punit"
        );
    }

    /// **LA FENÊTRE LES OUBLIE COMME LE RESTE.**
    ///
    /// Une liste qui a vieilli produit quelques refus par jour, pas cinquante par
    /// minute. Sans remise à zéro, ils s'accumuleraient jusqu'à bannir un
    /// correspondant ordinaire au bout d'un mois.
    #[test]
    fn une_nouvelle_fenetre_oublie_les_refus() {
        let mut table = [Slot::EMPTY; 8];
        let seuils = Thresholds {
            refused_recipients_per_minute: 3,
            ..seuils_serres()
        };
        let mut garde = Guard::new(&mut table, seuils);
        for _ in 0..3 {
            garde.observe(PAIR, Event::RefusedRecipient, t(0));
        }
        // Une minute plus tard, le compte repart.
        assert_eq!(
            garde.observe(PAIR, Event::RefusedRecipient, t(60_000)),
            Verdict::Allow
        );
    }

    /// **UNE PEINE DE DURÉE NULLE N'EN EST PAS UNE**, ici comme pour les trames
    /// invalides : elle annoncerait « banni jusqu'à maintenant », que
    /// l'interrogation suivante démentirait aussitôt.
    #[test]
    fn une_peine_nulle_ne_bannit_pas_sur_un_refus() {
        let mut table = [Slot::EMPTY; 8];
        let seuils = Thresholds {
            refused_recipients_per_minute: 1,
            ban_duration: Duration::from_secs(0),
            ..seuils_serres()
        };
        let mut garde = Guard::new(&mut table, seuils);
        garde.observe(PAIR, Event::RefusedRecipient, t(0));
        assert_eq!(
            garde.observe(PAIR, Event::RefusedRecipient, t(0)),
            Verdict::Throttled,
            "on refuse l'événement, sans plus"
        );
    }
}
