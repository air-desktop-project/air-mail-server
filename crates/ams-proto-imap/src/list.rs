// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les arguments d'un `LIST` (RFC 9051 §6.3.9).
//!
//! # `LIST` A DEUX FORMES, ET LA SECONDE N'EST PAS UNE EXTENSION
//!
//! `LIST "" *` est celle que tout le monde connaît. RFC 9051 en a fait entrer
//! une seconde dans le protocole de base — ce que RFC 5258 appelait
//! LIST-EXTENDED :
//!
//! ```text
//! LIST (SUBSCRIBED) "" * RETURN (SUBSCRIBED)
//! ```
//!
//! Les deux mots se ressemblent et ne disent pas la même chose. **Devant, c'est
//! un FILTRE** : ne rends que les boîtes auxquelles je suis abonné. **Derrière,
//! c'est un RENSEIGNEMENT** : rends-les toutes, et dis-moi lesquelles je suis.
//! Un client qui veut peupler son panneau latéral demande le filtre ; un client
//! qui veut afficher des cases à cocher demande le renseignement. Les confondre
//! rendrait à l'un la liste de l'autre.
//!
//! # UNE OPTION QU'ON NE SERT PAS SE REFUSE
//!
//! `RECURSIVEMATCH`, `REMOTE`, `STATUS (…)` : ce module les REFUSE au lieu de
//! les ignorer. Ignorer une option de sélection rendrait une liste plus longue
//! que ce que le client a demandé, et il la croirait filtrée. §6.3.9.7 le dit
//! d'ailleurs pour `RECURSIVEMATCH` : sans option de base, c'est une faute.
//!
//! # PLUSIEURS MOTIFS SE DEMANDENT EN UNE FOIS
//!
//! `LIST "" ("INBOX" "Travail/%")` est dans la grammaire de §9, et c'est ce
//! qu'un client envoie pour ouvrir son panneau en une commande au lieu de trois.
//! **Une boîte qui répond à deux motifs ne se rend qu'une fois** : la duplication
//! ferait apparaître deux lignes pour une seule boîte.

use crate::error::Error;
use crate::mailbox::MAILBOX_NAME_MAX;
use crate::status::StatusItems;

/// Combien de motifs un seul `LIST` peut porter.
///
/// Chaque motif fait un parcours de plus sur toutes les boîtes du compte. La
/// borne est celle du travail qu'une commande peut demander, pas celle de la
/// grammaire.
pub const LIST_PATTERNS_MAX: usize = 16;

/// Les arguments d'un `LIST`, une fois lus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct List<'a> {
    /// Ne rendre que les boîtes abonnées ?
    subscribed_only: bool,
    /// Marquer `\Subscribed` sur ce qu'on rend ?
    report_subscribed: bool,
    /// Le `STATUS` de chaque boîte rendue, si le client l'a demandé.
    status: Option<StatusItems>,
    /// Les motifs, dans l'ordre où ils ont été écrits.
    motifs: [&'a [u8]; LIST_PATTERNS_MAX],
    /// Combien de `motifs` valent.
    combien: usize,
}

impl<'a> List<'a> {
    /// `(SUBSCRIBED)` était-il devant ? — le FILTRE.
    #[must_use]
    pub fn subscribed_only(&self) -> bool {
        self.subscribed_only
    }

    /// `RETURN (SUBSCRIBED)` était-il derrière ? — le RENSEIGNEMENT.
    #[must_use]
    pub fn report_subscribed(&self) -> bool {
        self.report_subscribed
    }

    /// Ce que `RETURN (STATUS (…))` demande de chaque boîte rendue.
    ///
    /// # POURQUOI CETTE OPTION EXISTE
    ///
    /// Un client qui ouvre son panneau veut la liste ET le compte de non-lus de
    /// chaque boîte. Sans elle, c'est un `LIST` puis un `STATUS` par boîte —
    /// vingt allers-retours là où un seul suffit, sur une connexion dont la
    /// latence est celle d'Internet.
    #[must_use]
    pub fn status(&self) -> Option<StatusItems> {
        self.status
    }

    /// Les motifs demandés.
    #[must_use]
    pub fn patterns(&self) -> &[&'a [u8]] {
        self.motifs.get(..self.combien).unwrap_or_default()
    }

    /// Lit les arguments d'un `LIST`.
    ///
    /// La référence est lue et jetée : ce serveur n'a qu'un espace de noms, et
    /// `NAMESPACE` le dit. Elle doit néanmoins ÊTRE LÀ — sa place dans la
    /// grammaire est ce qui distingue le motif de l'option de sélection.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedList`] si la forme n'est pas celle de §6.3.9, si l'on y
    /// demande une option que ce serveur ne sert pas, ou si un motif est plus
    /// long que le plus long nom de boîte — un tel motif ne pourrait désigner
    /// aucune boîte.
    pub fn parse(arguments: &'a [u8]) -> Result<Self, Error> {
        let reste = arguments.trim_ascii();
        // 1. L'option de sélection, si elle est là. UNE PARENTHÈSE EN TÊTE NE
        //    PEUT ÊTRE QUE CELA : un nom de boîte n'en porte pas (§5.1), et un
        //    motif non plus.
        let (subscribed_only, reste) = match reste.first() {
            Some(b'(') => {
                let (dedans, suite) = entre_parentheses(reste)?;
                (options_de_selection(dedans)?, suite)
            }
            _ => (false, reste),
        };

        // 2. La référence, qu'on lit pour la jeter.
        let (_, reste) = un_mot(reste)?;

        // 3. Le ou les motifs.
        let (motifs, combien, reste) = if reste.trim_ascii_start().starts_with(b"(") {
            plusieurs_motifs(reste.trim_ascii_start())?
        } else {
            let (motif, suite) = un_mot(reste)?;
            if motif.len() > MAILBOX_NAME_MAX {
                return Err(Error::MalformedList);
            }
            // LE MÊME MOTIF PARTOUT, ET UN SEUL QUI COMPTE : `combien` vaut
            // un, et `patterns()` ne rend que celui-là. Poser le motif à la
            // première place demanderait une garde sur un tableau dont on sait
            // qu'il n'est pas vide — et une garde inatteignable n'est pas une
            // garde.
            ([motif; LIST_PATTERNS_MAX], 1, suite)
        };

        // 4. Le `RETURN (…)`, s'il est là.
        let reste = reste.trim_ascii();
        let report_subscribed = if reste.is_empty() {
            (false, None)
        } else {
            let (mot, suite) = un_mot(reste)?;
            if !mot.eq_ignore_ascii_case(b"RETURN") {
                return Err(Error::MalformedList);
            }
            let (dedans, apres) = entre_parentheses(suite.trim_ascii_start())?;
            if !apres.trim_ascii().is_empty() {
                return Err(Error::MalformedList);
            }
            options_de_retour(dedans)?
        };

        Ok(Self {
            subscribed_only,
            report_subscribed: report_subscribed.0,
            status: report_subscribed.1,
            motifs,
            combien,
        })
    }
}

/// Lit ce qu'une parenthèse ouvrante enferme, et rend le reste après elle.
///
/// # UN SEUL NIVEAU D'EMBOÎTEMENT, ET IL A UN NOM
///
/// `RETURN (STATUS (MESSAGES UNSEEN))` est la seule forme de §6.3.9 qui emboîte
/// des parenthèses. On compte donc les niveaux plutôt que de chercher la
/// première fermante — qui refermerait le `STATUS` et laisserait la liste
/// ouverte —, et l'on s'arrête à deux : un troisième ne voudrait rien dire.
fn entre_parentheses(reste: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let corps = reste.strip_prefix(b"(").ok_or(Error::MalformedList)?;
    let mut niveau = 0_usize;
    let mut fin = None;
    for (rang, octet) in corps.iter().enumerate() {
        match *octet {
            b'(' => {
                niveau = niveau.saturating_add(1);
                if niveau > 1 {
                    return Err(Error::MalformedList);
                }
            }
            b')' if niveau == 0 => {
                fin = Some(rang);
                break;
            }
            b')' => niveau = niveau.saturating_sub(1),
            _ => {}
        }
    }
    let fin = fin.ok_or(Error::MalformedList)?;
    Ok((
        corps.get(..fin).unwrap_or_default(),
        corps.get(fin.saturating_add(1)..).unwrap_or_default(),
    ))
}

/// Lit le premier mot, guillemets défaits, et rend le reste.
fn un_mot(reste: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let reste = reste.trim_ascii_start();
    if reste.is_empty() {
        return Err(Error::MalformedList);
    }
    if let Some(corps) = reste.strip_prefix(b"\"") {
        // UNE CHAÎNE DE `LIST` NE S'ÉCHAPPE PAS : un nom de boîte ne porte ni
        // `"` ni `\` (§5.1 tel que ce serveur le restreint), et un motif non
        // plus. Chercher le guillemet suivant suffit donc, et la contre-oblique
        // qu'on n'interprète pas ne pourra pas fabriquer un nom qu'on n'a pas lu.
        let fin = corps
            .iter()
            .position(|octet| *octet == b'"')
            .ok_or(Error::MalformedList)?;
        return Ok((
            corps.get(..fin).unwrap_or_default(),
            corps.get(fin.saturating_add(1)..).unwrap_or_default(),
        ));
    }
    let fin = reste
        .iter()
        .position(|octet| *octet == b' ')
        .unwrap_or(reste.len());
    Ok((
        reste.get(..fin).unwrap_or_default(),
        reste.get(fin..).unwrap_or_default(),
    ))
}

/// Ce qu'une liste de motifs rend : les motifs, combien il y en a, et le reste
/// de la commande après la parenthèse fermante.
type Motifs<'a> = ([&'a [u8]; LIST_PATTERNS_MAX], usize, &'a [u8]);

/// Lit une liste de motifs entre parenthèses.
fn plusieurs_motifs(reste: &[u8]) -> Result<Motifs<'_>, Error> {
    let (dedans, suite) = entre_parentheses(reste)?;
    let mut motifs = [&[] as &[u8]; LIST_PATTERNS_MAX];
    let mut combien = 0_usize;
    let mut dedans = dedans;
    loop {
        dedans = dedans.trim_ascii_start();
        if dedans.is_empty() {
            break;
        }
        let (motif, apres) = un_mot(dedans)?;
        if motif.len() > MAILBOX_NAME_MAX {
            return Err(Error::MalformedList);
        }
        let Some(place) = motifs.get_mut(combien) else {
            return Err(Error::MalformedList);
        };
        *place = motif;
        combien = combien.saturating_add(1);
        dedans = apres;
    }
    // `LIST "" ()` NE DEMANDE RIEN. §6.3.9 dit que la réponse est alors vide,
    // et non que la commande est fautive : le client a écrit ce qu'il voulait.
    Ok((motifs, combien, suite))
}

/// Lit les options de sélection, et rend `true` si `SUBSCRIBED` y est.
fn options_de_selection(dedans: &[u8]) -> Result<bool, Error> {
    let mut abonnees = false;
    for mot in dedans.split(|octet| *octet == b' ') {
        if mot.is_empty() {
            continue;
        }
        if !mot.eq_ignore_ascii_case(b"SUBSCRIBED") {
            return Err(Error::MalformedList);
        }
        abonnees = true;
    }
    Ok(abonnees)
}

/// Lit les options de retour : `SUBSCRIBED`, et le `STATUS` s'il y est.
///
/// `CHILDREN` est admis SANS RIEN CHANGER : `\HasChildren` ou `\HasNoChildren`
/// est déjà écrit sur chaque ligne, que le client l'ait demandé ou non (§7.3.1).
/// Le refuser ferait échouer une commande dont la réponse est déjà celle qu'elle
/// demande.
///
/// # `STATUS` PORTE SA PROPRE LISTE, ET ON NE DÉCOUPE DONC PAS SUR L'ESPACE
///
/// `RETURN (SUBSCRIBED STATUS (MESSAGES UNSEEN))` : le troisième mot ouvre une
/// parenthèse, et ce qu'elle enferme n'est pas fait d'options de retour. Le
/// parcours avance donc mot à mot, et saute la liste entière quand il en
/// rencontre une.
fn options_de_retour(dedans: &[u8]) -> Result<(bool, Option<StatusItems>), Error> {
    let mut abonnees = false;
    let mut status = None;
    let mut reste = dedans;
    loop {
        reste = reste.trim_ascii_start();
        if reste.is_empty() {
            return Ok((abonnees, status));
        }
        let fin = reste
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(reste.len());
        let mot = reste.get(..fin).unwrap_or_default();
        reste = reste.get(fin..).unwrap_or_default();
        if mot.eq_ignore_ascii_case(b"SUBSCRIBED") {
            abonnees = true;
            continue;
        }
        if mot.eq_ignore_ascii_case(b"CHILDREN") {
            continue;
        }
        if !mot.eq_ignore_ascii_case(b"STATUS") {
            return Err(Error::MalformedList);
        }
        // DEUX `STATUS` NE VOUDRAIENT PAS DIRE DEUX RÉPONSES : §6.3.9.7 n'en
        // prévoit qu'un, et le second écraserait le premier sans qu'on sache
        // lequel le client attendait.
        if status.is_some() {
            return Err(Error::MalformedList);
        }
        let reste_sans_espace = reste.trim_ascii_start();
        let fin_liste = reste_sans_espace
            .iter()
            .position(|octet| *octet == b')')
            .ok_or(Error::MalformedList)?;
        // `fin_liste` VIENT D'UN `position` SUR CETTE MÊME TRANCHE : la borne
        // existe, et `unwrap_or_default` porte cette impossibilité dans la
        // bibliothèque standard plutôt que dans une garde qu'aucune entrée ne
        // peut emprunter.
        let liste = reste_sans_espace.get(..=fin_liste).unwrap_or_default();
        status = Some(StatusItems::parse(liste).map_err(|_| Error::MalformedList)?);
        reste = reste_sans_espace
            .get(fin_liste.saturating_add(1)..)
            .unwrap_or_default();
    }
}

#[cfg(test)]
mod tests;
