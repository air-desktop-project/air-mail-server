// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'on retient des paquets ÉMIS, et comment on en déclare perdus —
//! §6 et annexe A de RFC 9002.
//!
//! # SANS CE MODULE, UNE POIGNÉE DE MAIN NE FINIT PAS
//!
//! QUIC n'a pas de retransmission automatique : un paquet perdu est perdu, et
//! c'est à l'émetteur de s'en apercevoir puis de renvoyer ce qu'il contenait.
//! Les trois pièces qui l'entourent existaient déjà — [`ams_proto_quic::Rtt`]
//! mesure le trajet, [`ams_proto_quic::Congestion`] borne le débit,
//! [`ams_proto_quic::Received`] fabrique les `ACK` que l'on ENVOIE. Manquait
//! celle qui se souvient de ce qu'on a envoyé.
//!
//! # CE MODULE NE SAIT PAS CE QU'IL Y AVAIT DANS UN PAQUET
//!
//! Il retient un numéro, une date, une taille et deux drapeaux — rien de plus.
//! **Retenir aussi les trames doublerait la mémoire d'une connexion** et
//! ferait de ce module le propriétaire de données qu'il ne relit jamais. Quand
//! il déclare un paquet perdu, il en rend le NUMÉRO ; c'est l'appelant, qui a
//! composé les trames, qui sait ce qu'il faut recomposer.
//!
//! # UN ESPACE À LA FOIS
//!
//! §12.3 de RFC 9000 : `Initial`, `Handshake` et applicatif se numérotent
//! séparément, et §6.1 raisonne « within the same packet number space ». Un
//! seul objet pour les trois compterait des seuils de réordonnancement entre
//! des numéros qui n'ont rien à voir. On en tient donc un par espace, et la
//! décision de prendre le plus proche des délais appartient à l'appelant.

use ams_proto_quic::{Ack, GRANULARITY_US, PACKET_THRESHOLD, Rtt};

use crate::error::{Error, Reason};

/// Combien de paquets on retient en vol, par espace.
///
/// # C'EST NOTRE BORNE, ET LA DÉPASSER N'EST PAS GRAVE
///
/// Refuser d'émettre au-delà ne perd rien : cela plafonne le débit, exactement
/// comme le fait déjà le contrôleur de congestion. **C'est l'inverse d'une
/// borne en réception**, où ce qu'on ne retient pas est perdu pour de bon.
///
/// Deux cent cinquante-six paquets d'au moins 1200 octets font plus de trois
/// cents kibioctets en vol — bien au-delà de ce qu'une fenêtre de congestion
/// atteint sur les liens qu'un serveur de courrier voit.
pub const SENT_MAX: usize = 256;

/// Le multiplicateur du seuil temporel, en huitièmes (§6.1.2).
///
/// « The RECOMMENDED time threshold (kTimeThreshold), expressed as an RTT
/// multiplier, is 9/8. » On le porte en huitièmes pour rester en entiers : un
/// flottant ici introduirait un arrondi là où la RFC parle d'une fraction
/// exacte.
const SEUIL_TEMPOREL_HUITIEMES: u64 = 9;

/// Ce qu'on retient d'un paquet émis (§A.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Emis {
    /// Son numéro, dans l'espace de ce suivi.
    numero: u64,
    /// Quand il est parti, en microsecondes.
    parti_a: u64,
    /// Ce qu'il occupait sur le fil.
    octets: u64,
    /// Sollicite-t-il un acquittement (§2) ?
    sollicite: bool,
    /// Compte-t-il dans les octets en vol (§2) ?
    ///
    /// **UN PAQUET QUI NE PORTE QUE DES `ACK` N'EST PAS EN VOL.** §2 : « Packets
    /// that contain only ACK frames do not count toward congestion control
    /// limits. » Les compter ferait rétrécir la fenêtre à chaque acquittement
    /// qu'on envoie.
    en_vol: bool,
}

/// Ce qu'un `ACK` vient d'acquitter de neuf.
///
/// # POURQUOI UN RÉSUMÉ, ET NON LA LISTE
///
/// §A.7 n'a besoin que de cela : les octets pour la congestion, le plus grand
/// nouvellement acquitté et sa date pour l'échantillon de trajet, et le drapeau
/// qui dit si l'un d'eux sollicitait un acquittement. Rendre la liste entière
/// obligerait l'appelant à la parcourir pour recalculer ce qu'on sait déjà.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Acked {
    /// Combien de paquets ont été acquittés pour la première fois.
    pub count: usize,
    /// Combien d'octets EN VOL cela représentait.
    pub bytes: u64,
    /// Le plus grand nouvellement acquitté et sa date d'envoi.
    ///
    /// **L'ÉCHANTILLON DE TRAJET NE SE PREND QUE SUR LUI** (§5.1) : « an
    /// endpoint generates an RTT sample on receiving an ACK frame that meets
    /// the following two conditions: the largest acknowledged packet number is
    /// newly acknowledged, and at least one of the newly acknowledged packets
    /// was ack-eliciting. » Mesurer sur un autre donnerait un trajet trop long,
    /// puisque cet autre a pu attendre chez le pair.
    pub largest: Option<(u64, u64)>,
    /// L'un des nouveaux sollicitait-il un acquittement ?
    pub eliciting: bool,
}

/// Ce que §6.1 vient de déclarer perdu.
#[derive(Debug, Clone, Copy)]
pub struct Lost {
    /// Les numéros perdus, dans l'ordre où ils avaient été émis.
    numeros: [u64; SENT_MAX],
    /// Combien.
    combien: usize,
    /// Combien d'octets en vol cela représentait.
    octets: u64,
    /// La date du plus ancien et du plus récent des perdus qui SOLLICITAIENT un
    /// acquittement et comptaient en vol.
    ///
    /// **C'EST CE QUE §7.6 DEMANDE** pour reconnaître une congestion
    /// persistante : deux paquets sollicitants, séparés d'assez de temps, tous
    /// perdus. Les autres ne comptent pas — un paquet qu'on n'attendait pas
    /// d'acquitter ne prouve rien sur le chemin.
    fenetre: Option<(u64, u64)>,
}

impl Lost {
    /// Les numéros déclarés perdus.
    #[must_use]
    pub fn numbers(&self) -> &[u64] {
        self.numeros.get(..self.combien).unwrap_or_default()
    }

    /// Combien d'octets en vol ils représentaient.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.octets
    }

    /// Y a-t-il eu quoi que ce soit ?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.combien == 0
    }

    /// La durée entre le plus ancien et le plus récent des perdus sollicitants
    /// (§7.6) — `None` s'il y en a moins de deux.
    ///
    /// L'appelant la compare à [`ams_proto_quic::Congestion::persistent_congestion_duration`].
    #[must_use]
    pub fn persistent_window(&self) -> Option<u64> {
        let (plus_vieux, plus_neuf) = self.fenetre?;
        match plus_neuf > plus_vieux {
            true => Some(plus_neuf.saturating_sub(plus_vieux)),
            // Un seul paquet ne fait pas une fenêtre : §7.6 veut « two
            // ack-eliciting packets », et deux dates identiques ne prouvent
            // rien sur la durée.
            false => None,
        }
    }
}

/// Les paquets émis d'un espace, et ce qu'on en déduit.
#[derive(Debug, Clone, Copy)]
pub struct Sent {
    /// Ce qui est parti et n'est pas encore acquitté.
    ///
    /// **UN TABLEAU, ET NON UNE CARTE** : `ams-quic` n'alloue pas, et un
    /// parcours de deux cent cinquante-six entrées à chaque `ACK` coûte moins
    /// qu'une allocation.
    paquets: [Option<Emis>; SENT_MAX],
    /// Le plus grand numéro acquitté, s'il y en a un (§A.10).
    plus_grand_acquitte: Option<u64>,
    /// Les octets en vol.
    en_vol: u64,
    /// Quand le prochain paquet pourra être déclaré perdu (§6.1.2).
    perte_a: Option<u64>,
    /// Quand le dernier paquet sollicitant un acquittement est parti (§A.5).
    dernier_sollicitant: Option<u64>,
}

impl Default for Sent {
    fn default() -> Self {
        Self::new()
    }
}

impl Sent {
    /// Un espace neuf, dont rien n'est encore parti.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            paquets: [None; SENT_MAX],
            plus_grand_acquitte: None,
            en_vol: 0,
            perte_a: None,
            dernier_sollicitant: None,
        }
    }

    /// Les octets en vol de cet espace.
    #[must_use]
    pub const fn in_flight(&self) -> u64 {
        self.en_vol
    }

    /// Quand le prochain paquet pourra être déclaré perdu (§6.1.2).
    #[must_use]
    pub const fn loss_time(&self) -> Option<u64> {
        self.perte_a
    }

    /// Reste-t-il quelque chose qui sollicite un acquittement ?
    ///
    /// §A.8 : le délai de sondage ne s'arme que s'il y a de quoi sonder.
    #[must_use]
    pub fn has_eliciting(&self) -> bool {
        self.paquets.iter().flatten().any(|paquet| paquet.sollicite)
    }

    /// Quand sonder, faute d'acquittement (§6.2.1).
    ///
    /// `essais` est le nombre de sondages déjà tentés — il DOUBLE le délai à
    /// chaque fois, ce qui est le seul frein d'un émetteur qui n'entend plus
    /// rien.
    ///
    /// Rend `None` quand rien n'attend d'acquittement : sonder sans rien à
    /// sonder réveillerait la connexion pour ne rien dire.
    #[must_use]
    pub fn pto_deadline(&self, rtt: &Rtt, delai_max: u64, essais: u32) -> Option<u64> {
        let depuis = self.dernier_sollicitant?;
        Some(depuis.saturating_add(rtt.pto(delai_max, essais)))
    }

    /// Un paquet vient de partir (§A.5).
    ///
    /// # UN NUMÉRO NE SE RÉEMPLOIE PAS, ET C'EST VÉRIFIÉ ICI
    ///
    /// §12.3 de RFC 9000 : « A QUIC endpoint MUST NOT reuse a packet number
    /// within the same packet number space. » Rien n'obligeait ce module à le
    /// vérifier — c'est l'appelant qui numérote. Mais **une seconde entrée pour
    /// un même numéro ferait compter deux fois les mêmes octets** au moment de
    /// l'acquittement, et la comptabilité des octets en vol dériverait sans que
    /// rien ne le dise : cela se verrait dans un débit qui s'écroule, et nulle
    /// part ailleurs.
    ///
    /// C'est un essai automatisé qui l'a montré, en soumettant deux fois le
    /// même numéro : le module l'acceptait.
    ///
    /// # Errors
    ///
    /// [`Reason::TooManyHoles`] quand on retient déjà [`SENT_MAX`] paquets — **c'est
    /// notre borne, pas une faute du pair**, et l'appelant a le droit de
    /// simplement ne pas émettre. [`Reason::PacketNumberReused`] pour un numéro
    /// déjà en vol.
    pub fn on_sent(
        &mut self,
        numero: u64,
        parti_a: u64,
        octets: u64,
        sollicite: bool,
        en_vol: bool,
    ) -> Result<(), Error> {
        // Le même parcours sert aux deux questions : la place libre, et le
        // numéro déjà pris. En faire deux coûterait deux fois le prix pour la
        // même réponse.
        let mut libre = None;
        for (rang, place) in self.paquets.iter().enumerate() {
            match place {
                Some(deja) if deja.numero == numero => {
                    return Err(Error::new(Reason::PacketNumberReused));
                }
                Some(_) => {}
                None if libre.is_none() => libre = Some(rang),
                None => {}
            }
        }
        let place = libre
            .and_then(|rang| self.paquets.get_mut(rang))
            .ok_or(Error::new(Reason::TooManyHoles))?;
        *place = Some(Emis {
            numero,
            parti_a,
            octets,
            sollicite,
            en_vol,
        });
        if en_vol {
            self.en_vol = self.en_vol.saturating_add(octets);
        }
        // §A.5 : seule la date d'un paquet SOLLICITANT arme le sondage. Un
        // paquet qui ne demande rien ne se fait pas attendre.
        if sollicite {
            self.dernier_sollicitant = Some(parti_a);
        }
        Ok(())
    }

    /// Un `ACK` est arrivé (§A.7).
    ///
    /// # LES INTERVALLES SE LISENT UNE FOIS, ET ON EN GARDE LE PLUS PETIT
    ///
    /// §19.3 les écrit du plus grand au plus petit, en différences. Les
    /// reparcourir pour chaque paquet retenu coûterait `n × m` ; on les déplie
    /// donc une fois, dans un tableau borné par ce que §19.3 permet d'écrire.
    ///
    /// # Errors
    ///
    /// [`Reason::TooManyHoles`] si l'`ACK` porte plus d'intervalles que
    /// [`ams_proto_quic::RANGES_MAX`], ou s'il est mal formé.
    pub fn on_ack(&mut self, ack: &Ack<'_>, deja: bool) -> Result<Acked, Error> {
        let (intervalles, combien) = deplier(ack)?;
        let vus = intervalles.get(..combien).unwrap_or_default();

        let mut acquis = Acked::default();
        for place in &mut self.paquets {
            let Some(paquet) = place else {
                continue;
            };
            if !vus
                .iter()
                .any(|(bas, haut)| paquet.numero >= *bas && paquet.numero <= *haut)
            {
                continue;
            }
            acquis.count = acquis.count.saturating_add(1);
            if paquet.en_vol {
                acquis.bytes = acquis.bytes.saturating_add(paquet.octets);
                self.en_vol = self.en_vol.saturating_sub(paquet.octets);
            }
            acquis.eliciting |= paquet.sollicite;
            if paquet.numero == ack.largest {
                acquis.largest = Some((paquet.numero, paquet.parti_a));
            }
            *place = None;
        }

        // §A.7 : le plus grand acquitté ne recule pas, même si un `ACK` arrive
        // dans le désordre.
        self.plus_grand_acquitte = Some(match self.plus_grand_acquitte {
            Some(connu) => connu.max(ack.largest),
            None => ack.largest,
        });
        // **UN `ACK` QUI N'ACQUITTE RIEN DE NEUF NE MESURE RIEN** (§5.1), et le
        // dire ici évite à chaque appelant de le redécouvrir.
        if deja {
            acquis.largest = None;
        }
        Ok(acquis)
    }

    /// Déclare perdu ce que §6.1 condamne, et rend leurs numéros (§A.10).
    ///
    /// # DEUX SEUILS, ET IL SUFFIT D'UN
    ///
    /// §6.1 : un paquet est perdu s'il n'est pas acquitté, qu'il est parti avant
    /// un paquet qui l'a été, ET qu'il est soit trop loin derrière
    /// ([`PACKET_THRESHOLD`]), soit parti depuis trop longtemps (§6.1.2).
    ///
    /// Les deux existent parce qu'aucun ne suffit : le seuil de rang ne dit rien
    /// quand plus rien n'arrive, et le seuil de temps est lent quand le débit est
    /// élevé.
    ///
    /// **RIEN N'EST PERDU TANT QUE RIEN N'EST ACQUITTÉ.** §A.10 l'affirme dès sa
    /// première ligne : sans point de comparaison, « parti avant un paquet
    /// acquitté » n'a pas de sens.
    pub fn detect_lost(&mut self, rtt: &Rtt, maintenant: u64) -> Lost {
        let mut perdus = Lost {
            numeros: [0; SENT_MAX],
            combien: 0,
            octets: 0,
            fenetre: None,
        };
        let Some(plus_grand) = self.plus_grand_acquitte else {
            return perdus;
        };
        // §6.1.2 : `9/8 × max(latest_rtt, smoothed_rtt)`, jamais moins que la
        // granularité de l'horloge — un seuil plus fin que ce qu'on sait mesurer
        // déclarerait perdu ce qui vient d'arriver.
        let delai = rtt
            .latest()
            .max(rtt.smoothed())
            .saturating_mul(SEUIL_TEMPOREL_HUITIEMES)
            .checked_div(8)
            .unwrap_or(0)
            .max(GRANULARITY_US);
        // **`checked_sub`, ET NON `saturating_sub`.** §A.10 pose
        // `lost_send_time = now - loss_delay` ; quand l'horloge n'a pas encore
        // atteint le délai, cette date est AVANT l'origine, et rien n'a pu être
        // émis si tôt. Saturer à zéro donnerait au contraire `parti_a <= 0`,
        // vrai pour tout paquet émis à l'instant zéro — qui serait alors
        // déclaré perdu dès le premier acquittement.
        //
        // Un essai l'a montré, et ce n'était pas une bizarrerie d'essai : une
        // horloge monotone commence près de zéro, et ce sont les tout premiers
        // paquets d'une connexion — ceux de la poignée de main — qui auraient
        // été retransmis pour rien.
        let avant = maintenant.checked_sub(delai);
        self.perte_a = None;

        for place in &mut self.paquets {
            let Some(paquet) = *place else {
                continue;
            };
            // §A.10 : ce qui est parti APRÈS le plus grand acquitté ne se juge
            // pas — rien ne dit encore qu'il aurait dû arriver.
            if paquet.numero > plus_grand {
                continue;
            }
            let trop_loin = plus_grand >= paquet.numero.saturating_add(PACKET_THRESHOLD);
            let trop_vieux = avant.is_some_and(|seuil| paquet.parti_a <= seuil);
            if !(trop_loin || trop_vieux) {
                // Pas encore perdu : on retient QUAND il le sera, pour armer un
                // délai plutôt que de repasser sans cesse.
                let quand = paquet.parti_a.saturating_add(delai);
                self.perte_a = Some(match self.perte_a {
                    Some(deja) => deja.min(quand),
                    None => quand,
                });
                continue;
            }
            *place = None;
            // **PAS DE GARDE ICI** : on ne peut pas perdre plus de paquets
            // qu'on n'en retient, et le tableau en tient autant. Un `get_mut`
            // rendrait une variante vide que rien ne peut atteindre.
            perdus.numeros[perdus.combien] = paquet.numero;
            perdus.combien = perdus.combien.saturating_add(1);
            if paquet.en_vol {
                perdus.octets = perdus.octets.saturating_add(paquet.octets);
                self.en_vol = self.en_vol.saturating_sub(paquet.octets);
            }
            // §7.6 : seuls les sollicitants EN VOL bornent la fenêtre de
            // congestion persistante.
            if paquet.sollicite && paquet.en_vol {
                perdus.fenetre = Some(match perdus.fenetre {
                    Some((vieux, neuf)) => (vieux.min(paquet.parti_a), neuf.max(paquet.parti_a)),
                    None => (paquet.parti_a, paquet.parti_a),
                });
            }
        }
        perdus
    }

    /// Cet espace est abandonné (§A.11), et rend les octets qu'il tenait en vol.
    ///
    /// **CELA N'ARRIVE QU'AUX DEUX PREMIERS ESPACES** : §4.9 de RFC 9001 jette
    /// les clés `Initial` puis `Handshake`, jamais celles de l'espace
    /// applicatif. Les paquets qui restaient ne seront jamais acquittés, et les
    /// attendre figerait le sondage.
    pub const fn discard(&mut self) -> u64 {
        let rendus = self.en_vol;
        *self = Self::new();
        rendus
    }
}

/// Déplie les intervalles d'un `ACK` en couples `(bas, haut)`, inclus.
///
/// # POURQUOI UN TABLEAU PLUTÔT QUE L'ITÉRATEUR
///
/// §19.3 écrit les intervalles du plus grand au plus petit, en différences :
/// chacun ne se connaît qu'après le précédent. Les reparcourir pour chacun des
/// paquets retenus coûterait le produit des deux, et l'itérateur ne se rembobine
/// pas.
fn deplier(ack: &Ack<'_>) -> Result<([(u64, u64); RANGES_LUS], usize), Error> {
    let mal = || Error::new(Reason::TooManyHoles);
    let mut vus = [(0_u64, 0_u64); RANGES_LUS];
    // §19.3 : le premier intervalle descend depuis le plus grand acquitté.
    let mut bas = ack.smallest().map_err(|_| mal())?;
    // `RANGES_LUS` n'est pas nul : la première place existe toujours.
    vus[0] = (bas, ack.largest);
    let mut combien = 1_usize;

    for intervalle in ack.ranges() {
        let intervalle = intervalle.map_err(|_| mal())?;
        // §19.3.1, et les DEUX qu'on retranche ne sont pas un détail : un
        // intervalle est séparé du précédent par au moins un numéro NON
        // acquitté, sans quoi les deux n'en feraient qu'un. Le `gap` compte
        // donc les manquants moins un, et il faut rendre ce un — plus le
        // numéro qui borne le précédent.
        let haut = bas
            .checked_sub(intervalle.gap)
            .and_then(|reste| reste.checked_sub(2))
            .ok_or_else(mal)?;
        let dessous = haut.checked_sub(intervalle.length).ok_or_else(mal)?;
        let place = vus.get_mut(combien).ok_or_else(mal)?;
        *place = (dessous, haut);
        bas = dessous;
        combien = combien.saturating_add(1);
    }
    Ok((vus, combien))
}

/// Combien d'intervalles on accepte de lire dans un `ACK` reçu.
///
/// **C'EST NOTRE BORNE, ET ELLE EST CELLE QU'ON ÉCRIT SOI-MÊME.** Un pair qui en
/// envoie davantage décrit un réseau plus troué que tout ce qu'on sait tenir ; le
/// refuser vaut mieux que de lire à moitié un acquittement, ce qui ferait
/// déclarer perdus des paquets qui ne le sont pas.
const RANGES_LUS: usize = ams_proto_quic::RANGES_MAX;

#[cfg(test)]
mod tests;
