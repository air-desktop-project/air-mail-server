// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le journal des changements d'une boîte : **ce qui a changé depuis le point
//! N**, déduit en comparant ce que le répertoire montre à ce qu'on avait vu.
//!
//! # POURQUOI IL SE DÉDUIT, ET NE S'ÉCRIT PAS À CHAQUE CHANGEMENT
//!
//! Une dizaine de chemins modifient une boîte — remise, IMAP `STORE`,
//! `EXPUNGE`, `MOVE`, POP3, l'API, l'outil — et rien ne les fait passer par un
//! point commun. Demander à chacun d'écrire au journal, c'est garantir qu'un
//! jour l'un l'oubliera, et qu'une application manquera un changement sans que
//! rien ne le dise. **Dans un Maildir, le nom du fichier fait foi** : l'UID et
//! les drapeaux y sont écrits. Il suffit donc de relire les noms et de comparer
//! — un changement fait par Thunderbird, à la main, ou perdu dans un plantage
//! entre un `rename` et une écriture de journal, se retrouve de la même façon.
//!
//! # CE QUE CELA COÛTE, ET QU'ON ACCEPTE
//!
//! Un changement DÉFAIT entre deux comparaisons — lu, puis remis non lu — ne
//! laisse pas de trace. L'état final du client est juste quand même, et c'est
//! ce qu'une synchronisation promet.
//!
//! # LE MODÈLE EST CELUI D'IMAP
//!
//! Un point (`modseq`) par changement, strictement croissant ; pour chaque
//! message présent, le point de son dernier changement ; pour chaque message
//! disparu, le point de sa disparition — CONDSTORE et QRESYNC (RFC 7162). Le
//! même journal pourra servir IMAP un jour.
//!
//! Cette crate ne lit aucun répertoire et ne connaît aucune heure : l'appelant
//! lui donne ce que le disque montre, et le point de départ d'un journal neuf.

use alloc::vec::Vec;

use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_journal_capnp::journal;
use crate::codec::Error;

/// Combien de disparitions le journal retient.
///
/// **DIX MILLE** : de quoi couvrir des semaines de courrier ordinaire sans
/// resynchroniser. Au-delà, les plus anciennes s'oublient, le plancher monte,
/// et un client resté absent plus longtemps relit la boîte une fois — c'est le
/// prix d'un journal borné, et un journal sans borne grossirait pour toujours.
pub const VANISHED_MAX: usize = 10_000;

/// Un message présent, et le point de son dernier changement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Present {
    /// Son UID.
    pub uid: u32,
    /// Ses drapeaux, en bits — seulement pour savoir s'ils ont bougé.
    pub flags: u16,
    /// Le point de son arrivée ou de son dernier changement de drapeaux.
    pub modseq: u64,
}

/// Un message disparu, et le point de sa disparition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disparu {
    /// Son UID.
    pub uid: u32,
    /// Le point de sa disparition.
    pub modseq: u64,
}

/// Le journal d'une boîte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    /// L'`UIDVALIDITY` de la boîte quand il a été tenu.
    pub uid_validity: u32,
    /// Le dernier point attribué.
    pub modseq: u64,
    /// Le plus ancien point encore servi : un curseur plus ancien est
    /// [`Perime`].
    pub floor: u64,
    /// Les messages présents, par UID croissant.
    pub messages: Vec<Present>,
    /// Les disparitions retenues, par point croissant.
    pub vanished: Vec<Disparu>,
}

/// Ce qui a changé depuis un point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// Les UID arrivés ou dont les drapeaux ont changé, par point croissant.
    /// Le client distingue les deux : il connaît ou non l'UID.
    pub changed: Vec<u32>,
    /// Les UID disparus.
    pub vanished: Vec<u32>,
    /// Le point jusqu'où ce delta va : c'est le curseur suivant.
    pub modseq: u64,
    /// Il reste des changements après `modseq`.
    pub more: bool,
}

/// Le curseur est plus ancien que ce que le journal retient — ou il n'en vient
/// pas : le client doit relire la boîte entière.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perime;

impl Journal {
    /// Un journal neuf, qui part de `depart`.
    ///
    /// **`depart` DOIT DÉPASSER TOUT POINT QU'UN CLIENT A PU VOIR** : un journal
    /// perdu puis recréé qui repartirait de zéro répondrait « rien de neuf » à un
    /// curseur d'avant, alors que tout a pu changer. L'appelant donne l'heure en
    /// millisecondes : elle a toujours dépassé le point d'un journal qui
    /// n'avance que d'un par changement.
    #[must_use]
    pub const fn new(uid_validity: u32, depart: u64) -> Self {
        Self {
            uid_validity,
            modseq: depart,
            floor: depart,
            messages: Vec::new(),
            vanished: Vec::new(),
        }
    }

    /// Le journal d'une boîte qui n'en avait pas : tout ce que le répertoire
    /// montre est rangé au point de départ.
    ///
    /// **RIEN N'Y EST « ARRIVÉ »** : ces messages étaient là avant le journal.
    /// Aucun client ne tient un curseur de ce journal-ci, et le premier qu'il
    /// obtiendra sera ce point de départ — d'où la synchronisation complète
    /// que tout client fait d'abord, puis les deltas.
    #[must_use]
    pub fn initial(uid_validity: u32, depart: u64, vus: &[(u32, u16)]) -> Self {
        let mut vus = vus.to_vec();
        vus.sort_unstable_by_key(|&(uid, _)| uid);
        vus.dedup_by_key(|&mut (uid, _)| uid);
        let mut neuf = Self::new(uid_validity, depart);
        neuf.messages = vus
            .into_iter()
            .map(|(uid, flags)| Present {
                uid,
                flags,
                modseq: depart,
            })
            .collect();
        neuf
    }

    /// Compare ce que le répertoire montre — `(uid, drapeaux)`, dans n'importe
    /// quel ordre — à ce que le journal avait vu, et attribue un point à chaque
    /// différence. Rend `true` si quelque chose a changé.
    ///
    /// Un `uid_validity` différent veut dire que les UID ne désignent plus les
    /// mêmes messages : le journal repart d'un point neuf, et tout curseur
    /// d'avant devient [`Perime`].
    pub fn reconcile(&mut self, uid_validity: u32, depart: u64, vus: &[(u32, u16)]) -> bool {
        let mut vus = vus.to_vec();
        vus.sort_unstable_by_key(|&(uid, _)| uid);
        vus.dedup_by_key(|&mut (uid, _)| uid);

        if uid_validity != self.uid_validity {
            let depart = depart.max(self.modseq.saturating_add(1));
            *self = Self::initial(uid_validity, depart, &vus);
            return true;
        }

        let anciens = core::mem::take(&mut self.messages);
        let mut neufs = Vec::with_capacity(vus.len());
        let mut change = false;
        let (mut i, mut j) = (0_usize, 0_usize);
        loop {
            let vu = vus.get(j).copied();
            let Some(ancien) = anciens.get(i).copied() else {
                // Plus rien de connu : ce qui reste à voir est arrivé.
                let Some((uid, flags)) = vu else {
                    break;
                };
                let modseq = self.suivant();
                neufs.push(Present { uid, flags, modseq });
                change = true;
                j = j.saturating_add(1);
                continue;
            };
            match vu {
                // Le même message : ses drapeaux ont-ils bougé ?
                Some((uid, flags)) if uid == ancien.uid => {
                    if ancien.flags == flags {
                        neufs.push(ancien);
                    } else {
                        let modseq = self.suivant();
                        neufs.push(Present { uid, flags, modseq });
                        change = true;
                    }
                    i = i.saturating_add(1);
                    j = j.saturating_add(1);
                }
                // Un vu, avant le prochain connu : il est arrivé.
                Some((uid, flags)) if uid < ancien.uid => {
                    let modseq = self.suivant();
                    neufs.push(Present { uid, flags, modseq });
                    change = true;
                    j = j.saturating_add(1);
                }
                // Un connu que le répertoire ne montre plus — il est avant le
                // prochain vu, ou il n'y a plus rien à voir : il a disparu.
                _ => {
                    let modseq = self.suivant();
                    self.vanished.push(Disparu {
                        uid: ancien.uid,
                        modseq,
                    });
                    change = true;
                    i = i.saturating_add(1);
                }
            }
        }
        self.messages = neufs;
        self.borner();
        change
    }

    /// Ce qui a changé après `since` : au plus `limite` UID changés et
    /// `disparus_max` UID disparus, par point croissant.
    ///
    /// # Errors
    ///
    /// [`Perime`] si `since` est sous le plancher — des disparitions d'avant
    /// lui ont été oubliées — ou au-dessus du dernier point attribué : il ne
    /// vient pas de ce journal.
    pub fn since(&self, since: u64, limite: usize, disparus_max: usize) -> Result<Delta, Perime> {
        if since < self.floor || since > self.modseq {
            return Err(Perime);
        }
        let (limite, disparus_max) = (limite.max(1), disparus_max.max(1));
        // Les deux sortes d'événements, fondues et rangées par point : c'est
        // l'ordre dans lequel ils se sont produits, et donc celui du curseur.
        let mut evenements: Vec<(u64, Option<u32>, Option<u32>)> = self
            .messages
            .iter()
            .filter(|present| present.modseq > since)
            .map(|present| (present.modseq, Some(present.uid), None))
            .chain(
                self.vanished
                    .iter()
                    .filter(|disparu| disparu.modseq > since)
                    .map(|disparu| (disparu.modseq, None, Some(disparu.uid))),
            )
            .collect();
        evenements.sort_unstable_by_key(|&(modseq, _, _)| modseq);

        let mut delta = Delta {
            changed: Vec::new(),
            vanished: Vec::new(),
            modseq: self.modseq,
            more: false,
        };
        let mut dernier = since;
        for (modseq, change, disparu) in evenements {
            if delta.changed.len() >= limite || delta.vanished.len() >= disparus_max {
                // **LE CURSEUR EST LE DERNIER POINT RENDU**, et non le dernier
                // attribué : le client reprendra exactement là.
                delta.more = true;
                delta.modseq = dernier;
                break;
            }
            delta.changed.extend(change);
            delta.vanished.extend(disparu);
            dernier = modseq;
        }
        Ok(delta)
    }

    /// Le point suivant.
    fn suivant(&mut self) -> u64 {
        self.modseq = self.modseq.saturating_add(1);
        self.modseq
    }

    /// Oublie les disparitions les plus anciennes au-delà de [`VANISHED_MAX`],
    /// et monte le plancher jusqu'à la dernière oubliée.
    fn borner(&mut self) {
        let trop = self.vanished.len().saturating_sub(VANISHED_MAX);
        if trop == 0 {
            return;
        }
        let derniere = self
            .vanished
            .drain(..trop)
            .map(|oubliee| oubliee.modseq)
            .max()
            .unwrap_or(self.floor);
        self.floor = self.floor.max(derniere);
    }
}

/// Lit un journal.
///
/// # CE QUI EST REFUSÉ
///
/// Tout ce qu'un journal tenu par [`Journal::reconcile`] ne peut pas être : un
/// plancher au-dessus du dernier point, des UID présents qui ne croissent pas
/// strictement, un point hors de `[plancher, dernier]`, des disparitions qui
/// ne croissent pas strictement ou qui tombent sous le plancher. **Un journal
/// refusé n'est pas une panne** : l'appelant en recrée un, et les clients
/// resynchronisent une fois.
///
/// # Errors
///
/// [`Error`].
pub fn decode_journal(octets: &[u8]) -> Result<Journal, Error> {
    let mauvais = |quoi: &str| Error::Malformed(alloc::format!("journal : {quoi}"));
    let mut reste = octets;
    // **UNE BORNE PROPORTIONNELLE AU FICHIER**, et non celle de la
    // configuration : un journal de cinquante mille messages pèse un
    // mégaoctet. Le double de sa taille en mots suffit à tout parcourir, et
    // empêche encore un fichier corrompu de faire tourner le décodeur en rond.
    let limite = octets
        .len()
        .saturating_div(8)
        .saturating_mul(2)
        .saturating_add(64);
    let message = serialize::read_message_from_flat_slice(
        &mut reste,
        ReaderOptions {
            traversal_limit_in_words: Some(limite),
            nesting_limit: 8,
        },
    )?;
    let lu: journal::Reader<'_> = message.get_root()?;

    let modseq = lu.get_modseq();
    let floor = lu.get_floor();
    if floor > modseq {
        return Err(mauvais("plancher au-dessus du dernier point"));
    }
    // **PAS DE BORNE SUR LE NOMBRE DE MESSAGES** : celle du parcours, qui suit
    // la taille du fichier, empêche déjà un fichier corrompu d'en annoncer plus
    // qu'il n'en porte.
    let lus = lu.get_messages()?;
    let mut messages = Vec::with_capacity(usize::try_from(lus.len()).unwrap_or(0));
    for present in lus.iter() {
        let entree = Present {
            uid: present.get_uid(),
            flags: present.get_flags(),
            modseq: present.get_modseq(),
        };
        if messages
            .last()
            .is_some_and(|avant: &Present| avant.uid >= entree.uid)
        {
            return Err(mauvais("UID présents hors d'ordre"));
        }
        if entree.modseq < floor || entree.modseq > modseq {
            return Err(mauvais("point d'un message hors bornes"));
        }
        messages.push(entree);
    }
    let lus = lu.get_vanished()?;
    if usize::try_from(lus.len()).unwrap_or(usize::MAX) > VANISHED_MAX {
        return Err(mauvais("trop de disparitions"));
    }
    let mut vanished = Vec::with_capacity(usize::try_from(lus.len()).unwrap_or(0));
    for disparu in lus.iter() {
        let entree = Disparu {
            uid: disparu.get_uid(),
            modseq: disparu.get_modseq(),
        };
        if vanished
            .last()
            .is_some_and(|avant: &Disparu| avant.modseq >= entree.modseq)
        {
            return Err(mauvais("disparitions hors d'ordre"));
        }
        if entree.modseq <= floor || entree.modseq > modseq {
            return Err(mauvais("point d'une disparition hors bornes"));
        }
        vanished.push(entree);
    }
    Ok(Journal {
        uid_validity: lu.get_uid_validity(),
        modseq,
        floor,
        messages,
        vanished,
    })
}

/// Écrit un journal.
///
/// # Errors
///
/// [`Error`] si l'encodage échoue — ce qui n'arrive que sur un défaut de la
/// bibliothèque.
pub fn encode_journal(tenu: &Journal) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut ecrit = message.init_root::<journal::Builder<'_>>();
        ecrit.set_uid_validity(tenu.uid_validity);
        ecrit.set_modseq(tenu.modseq);
        ecrit.set_floor(tenu.floor);
        let mut liste = ecrit
            .reborrow()
            .init_messages(u32::try_from(tenu.messages.len()).unwrap_or(u32::MAX));
        for (rang, present) in tenu.messages.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_uid(present.uid);
            case.set_flags(present.flags);
            case.set_modseq(present.modseq);
        }
        let mut liste = ecrit.init_vanished(u32::try_from(tenu.vanished.len()).unwrap_or(u32::MAX));
        for (rang, disparu) in tenu.vanished.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_uid(disparu.uid);
            case.set_modseq(disparu.modseq);
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

#[cfg(test)]
mod tests;
