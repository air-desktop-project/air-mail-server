// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les critères d'un `SEARCH` (RFC 9051 §6.4.4).
//!
//! # UN ARBRE SANS ALLOCATION, ET SANS CYCLE POSSIBLE
//!
//! `NOT`, `OR` et les parenthèses font de `SEARCH` une expression, donc un
//! arbre — et C1 interdit d'allouer ici. Les nœuds vivent dans un tableau de
//! taille fixe, et se désignent par leur indice.
//!
//! **Un nœud ne référence que des nœuds d'indice STRICTEMENT INFÉRIEUR**, parce
//! qu'un enfant est rangé avant son parent. Ce n'est pas une convention qu'on
//! espère tenir : c'est la seule façon dont le tableau se remplit, et elle rend
//! le cycle impossible. L'évaluation descend donc toujours vers des indices plus
//! petits, et se termine sans qu'on ait à compter les tours.
//!
//! # CE QUI EST SERVI
//!
//! Ce qui se décide avec ce que la boîte sait déjà — drapeaux, taille, date
//! d'arrivée, UID, rang — et ce qui demande de LIRE le message : `SUBJECT`,
//! `FROM`, `TO`, `CC`, `BCC`, `HEADER`, `BODY`, `TEXT`.
//!
//! **CES DERNIERS NE SE DÉCIDENT PAS ICI.** Cette crate ne lit aucun message
//! (C1) : elle rend le critère, et l'appelant répond à la question qu'il pose.
//! C'est pourquoi [`Search::matches`] prend une fermeture — le nœud dit QUOI
//! chercher et OÙ, celui qui a le message dit si ça s'y trouve.

use crate::error::Error;
use crate::flags::Flags;
use crate::limits::Limits;
use crate::sequence::SequenceSet;

/// Combien de nœuds une expression peut porter.
pub const SEARCH_KEYS_MAX: usize = 64;

/// Combien de niveaux d'imbrication on accepte.
///
/// **Sans cette borne, `NOT NOT NOT …` ferait descendre l'analyseur aussi
/// profond que le client le demande**, et la pile n'est pas extensible. Huit
/// suffisent à toute requête qu'un humain écrit, et le refus est explicite.
pub const SEARCH_DEPTH_MAX: usize = 8;

/// Un nœud de l'expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Noeud<'a> {
    /// `ALL` — vrai de tout message.
    Tout,
    /// `SEEN`, `UNSEEN`, `ANSWERED`… : un drapeau, présent ou absent.
    Drapeau { drapeau: Flags, present: bool },
    /// `LARGER n` : strictement plus grand.
    PlusGrand(u64),
    /// `SMALLER n` : strictement plus petit.
    PlusPetit(u64),
    /// `BEFORE date` : arrivé avant ce jour.
    Avant(u64),
    /// `ON date` : arrivé ce jour-là.
    Le(u64),
    /// `SINCE date` : arrivé ce jour-là ou après.
    Depuis(u64),
    /// `UID <ensemble>`.
    Uid(SequenceSet<'a>),
    /// Un ensemble de numéros de séquence, écrit sans mot-clé.
    Rang(SequenceSet<'a>),
    /// `NOT <clef>`.
    Non(u16),
    /// `OR <clef> <clef>`.
    Ou(u16, u16),
    /// Deux clefs juxtaposées : les deux doivent être vraies.
    Et(u16, u16),
    /// `SUBJECT`, `BODY`, `HEADER <champ>`… : un texte à trouver dans le
    /// message.
    Contenu {
        portee: SearchScope,
        /// Le champ visé, pour une portée d'en-tête. Vide ailleurs.
        champ: &'a [u8],
        texte: &'a [u8],
    },
}

/// Ce à quoi l'appelant répond pour les critères qui lisent le message.
///
/// La portée, le champ visé — vide hors d'un en-tête — et le texte cherché.
pub type SearchReader<'r> = &'r mut dyn FnMut(SearchScope, &[u8], &[u8]) -> bool;

/// Où un critère cherche son texte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    /// Dans un champ d'en-tête nommé.
    Header,
    /// Dans le corps.
    Body,
    /// Dans l'en-tête ET le corps (§6.4.4).
    Text,
}

/// Ce qu'il faut savoir d'un message pour décider s'il correspond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Son rang dans la boîte, à partir de un.
    pub sequence: u32,
    /// Son UID.
    pub uid: u32,
    /// Sa taille en octets.
    pub size: u64,
    /// Ses drapeaux.
    pub flags: Flags,
    /// Sa date d'arrivée, en secondes depuis l'époque.
    pub internal_date: u64,
}

/// Une expression de recherche, lue et prête à décider.
#[derive(Debug, Clone, Copy)]
pub struct Search<'a> {
    noeuds: [Noeud<'a>; SEARCH_KEYS_MAX],
    len: u16,
    racine: u16,
}

impl Search<'static> {
    /// Une expression qui ne désigne AUCUN message.
    ///
    /// Elle sert d'issue à qui ne saurait plus lire une expression qu'il a
    /// pourtant validée : ne rien désigner est la seule réponse qui ne mente
    /// pas. C'est le pendant de [`SequenceSet::EMPTY`].
    pub const NONE: Self = Self {
        noeuds: [Noeud::Rang(SequenceSet::EMPTY); SEARCH_KEYS_MAX],
        len: 1,
        racine: 0,
    };
}

impl<'a> Search<'a> {
    /// Lit les critères d'un `SEARCH`.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedSearch`] si la forme n'est pas celle de §6.4.4,
    /// [`Error::UnsupportedSearchKey`] pour un critère reconnu mais non servi,
    /// [`Error::SearchTooComplex`] au-delà des bornes, ou les erreurs d'ensemble
    /// de numéros.
    pub fn parse(arguments: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let mut lecteur = Lecteur {
            reste: arguments.trim_ascii(),
            noeuds: [Noeud::Tout; SEARCH_KEYS_MAX],
            len: 0,
            limits,
        };
        // §6.4.4 : plusieurs clefs juxtaposées se conjoignent.
        let mut racine = lecteur.clef(0)?;
        while !lecteur.reste.trim_ascii_start().is_empty() {
            let suivante = lecteur.clef(0)?;
            racine = lecteur.ranger(Noeud::Et(racine, suivante))?;
        }
        Ok(Self {
            noeuds: lecteur.noeuds,
            len: lecteur.len,
            racine,
        })
    }

    /// Ce message correspond-il ?
    #[must_use]
    /// `contient` répond aux critères qui demandent de LIRE le message : on lui
    /// donne la portée, le champ visé — vide hors d'un en-tête — et le texte
    /// cherché. Cette crate ne lit aucun message (C1), et ne saurait donc pas y
    /// répondre elle-même.
    ///
    /// # UNE FERMETURE DYNAMIQUE, ET NON GÉNÉRIQUE
    ///
    /// Une fonction générique est recopiée une fois par appelant, et chaque
    /// copie porte ses propres chemins d'erreur — dont aucun appelant n'emprunte
    /// la totalité. C'est du code livré que rien ne regarde, dans une crate qui
    /// se veut mince. Un appel indirect par expression coûte moins que cela.
    pub fn matches(
        &self,
        message: &Candidate,
        star_sequence: u32,
        star_uid: u32,
        contient: SearchReader<'_>,
    ) -> bool {
        self.evaluer(self.racine, message, star_sequence, star_uid, contient)
    }

    /// Combien de nœuds l'expression porte.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Une expression est-elle vide ? Jamais : `parse` en refuse une.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Évalue un nœud.
    ///
    /// **La récursion descend vers des indices strictement plus petits**, ce que
    /// la construction garantit : elle se termine donc, et il n'y a pas de
    /// compteur de tours à tenir.
    fn evaluer(
        &self,
        indice: u16,
        message: &Candidate,
        star_seq: u32,
        star_uid: u32,
        contient: SearchReader<'_>,
    ) -> bool {
        // ON PARCOURT LE TABLEAU ENTIER POUR EN TIRER UN NŒUD.
        //
        // `self.noeuds.get(indice)` rendrait un `Option` dont le `None` est
        // impossible — un nœud ne nomme que des indices que `ranger` a remplis —
        // et une garde inatteignable n'est pas une garde. Le parcours, lui, est
        // total : il n'a pas de cas « et sinon ». C'est le même raisonnement que
        // « vingt chiffres majorent tout `u64`, et la boucle les parcourt tous »,
        // et il coûte soixante-quatre comparaisons, bornées comme le tableau.
        let mut noeud = Noeud::Tout;
        for (rang, candidat) in (0_u16..).zip(self.noeuds.iter()) {
            if rang == indice {
                noeud = *candidat;
            }
        }
        match noeud {
            Noeud::Tout => true,
            Noeud::Drapeau { drapeau, present } => message.flags.contains(drapeau) == present,
            Noeud::PlusGrand(seuil) => message.size > seuil,
            Noeud::PlusPetit(seuil) => message.size < seuil,
            Noeud::Avant(jour) => jour_de(message.internal_date) < jour,
            Noeud::Le(jour) => jour_de(message.internal_date) == jour,
            Noeud::Depuis(jour) => jour_de(message.internal_date) >= jour,
            Noeud::Uid(ensemble) => ensemble.contains(message.uid, star_uid),
            Noeud::Rang(ensemble) => ensemble.contains(message.sequence, star_seq),
            Noeud::Non(clef) => !self.evaluer(clef, message, star_seq, star_uid, contient),
            Noeud::Ou(gauche, droite) => {
                self.evaluer(gauche, message, star_seq, star_uid, contient)
                    || self.evaluer(droite, message, star_seq, star_uid, contient)
            }
            Noeud::Et(gauche, droite) => {
                self.evaluer(gauche, message, star_seq, star_uid, contient)
                    && self.evaluer(droite, message, star_seq, star_uid, contient)
            }
            // UN TEXTE VIDE EST VRAI DE TOUT MESSAGE (§6.4.4) : `SEARCH BODY ""`
            // désigne tout, et c'est ce que la RFC demande. Le passer au magasin
            // lui ferait lire un message pour rien.
            Noeud::Contenu {
                portee,
                champ,
                texte,
            } => match portee {
                SearchScope::Header if texte.is_empty() => contient(portee, champ, texte),
                _ if texte.is_empty() => true,
                _ => contient(portee, champ, texte),
            },
        }
    }
}

/// L'état de la lecture.
struct Lecteur<'a, 'l> {
    reste: &'a [u8],
    noeuds: [Noeud<'a>; SEARCH_KEYS_MAX],
    /// **Un `u16`, et non un `usize`** : c'est le type des indices que les
    /// nœuds portent, et le faire coïncider retire une conversion qui ne
    /// pouvait pas échouer — donc une garde qu'aucune entrée n'aurait
    /// empruntée.
    len: u16,
    limits: &'l Limits,
}

impl<'a> Lecteur<'a, '_> {
    /// Range un nœud et rend son indice.
    fn ranger(&mut self, noeud: Noeud<'a>) -> Result<u16, Error> {
        let indice = self.len;
        let place = self
            .noeuds
            .get_mut(usize::from(indice))
            .ok_or(Error::SearchTooComplex {
                limit: SEARCH_KEYS_MAX,
            })?;
        *place = noeud;
        self.len = self.len.saturating_add(1);
        Ok(indice)
    }

    /// Le mot suivant, séparateur consommé.
    fn mot(&mut self) -> &'a [u8] {
        let reste = self.reste.trim_ascii_start();
        // Une parenthèse est un mot à elle seule, collée ou non.
        if let Some((&premier, suite)) = reste.split_first()
            && matches!(premier, b'(' | b')')
        {
            self.reste = suite;
            return reste.get(..1).unwrap_or_default();
        }
        let fin = reste
            .iter()
            .position(|octet| matches!(*octet, b' ' | b'(' | b')'))
            .unwrap_or(reste.len());
        self.reste = reste.get(fin..).unwrap_or_default();
        reste.get(..fin).unwrap_or_default()
    }

    /// Lit une chaîne de recherche : un atome, ou une chaîne citée.
    ///
    /// # UN ÉCHAPPEMENT NE SE DÉFAIT PAS ICI
    ///
    /// Le nœud EMPRUNTE le texte de la commande — c'est ce qui permet à cette
    /// crate de ne rien allouer. Défaire un `\"` demanderait de recopier le
    /// texte quelque part, et ce quelque part n'existe pas. C'est donc un refus
    /// de service, et non une faute : la forme est licite.
    fn chaine(&mut self) -> Result<&'a [u8], Error> {
        let reste = self.reste.trim_ascii_start();
        if reste.first().copied() != Some(b'"') {
            let mot = self.mot();
            // Une parenthèse n'est pas un texte, et un texte manquant non plus.
            if mot.is_empty() || matches!(mot, b"(" | b")") {
                return Err(Error::MalformedSearch);
            }
            return Ok(mot);
        }
        let dedans = reste.get(1..).unwrap_or_default();
        let fin = dedans
            .iter()
            .position(|octet| *octet == b'"')
            .ok_or(Error::MalformedSearch)?;
        let texte = dedans.get(..fin).unwrap_or_default();
        if texte.contains(&b'\\') {
            return Err(Error::UnsupportedSearchKey);
        }
        self.reste = dedans.get(fin.saturating_add(1)..).unwrap_or_default();
        Ok(texte)
    }

    /// Lit une clef, et rend l'indice de sa racine.
    fn clef(&mut self, profondeur: usize) -> Result<u16, Error> {
        if profondeur > SEARCH_DEPTH_MAX {
            return Err(Error::SearchTooDeep {
                limit: SEARCH_DEPTH_MAX,
            });
        }
        let mot = self.mot();
        if mot.is_empty() {
            return Err(Error::MalformedSearch);
        }
        // Une liste entre parenthèses est une conjonction.
        if mot == b"(" {
            let mut racine = self.clef(profondeur.saturating_add(1))?;
            loop {
                let avant = self.reste;
                let mot = self.mot();
                if mot == b")" {
                    return Ok(racine);
                }
                if mot.is_empty() {
                    return Err(Error::MalformedSearch);
                }
                // Ce n'était pas la fin : on rend le mot à la lecture.
                self.reste = avant;
                let suivante = self.clef(profondeur.saturating_add(1))?;
                racine = self.ranger(Noeud::Et(racine, suivante))?;
            }
        }
        if mot == b")" {
            return Err(Error::MalformedSearch);
        }
        if mot.eq_ignore_ascii_case(b"NOT") {
            let clef = self.clef(profondeur.saturating_add(1))?;
            return self.ranger(Noeud::Non(clef));
        }
        if mot.eq_ignore_ascii_case(b"OR") {
            let gauche = self.clef(profondeur.saturating_add(1))?;
            let droite = self.clef(profondeur.saturating_add(1))?;
            return self.ranger(Noeud::Ou(gauche, droite));
        }
        if mot.eq_ignore_ascii_case(b"ALL") {
            return self.ranger(Noeud::Tout);
        }
        if let Some((drapeau, present)) = drapeau_de(mot) {
            return self.ranger(Noeud::Drapeau { drapeau, present });
        }
        if mot.eq_ignore_ascii_case(b"LARGER") || mot.eq_ignore_ascii_case(b"SMALLER") {
            let taille = nombre(self.mot()).ok_or(Error::MalformedSearch)?;
            return self.ranger(if mot.eq_ignore_ascii_case(b"LARGER") {
                Noeud::PlusGrand(taille)
            } else {
                Noeud::PlusPetit(taille)
            });
        }
        for (nom, faire) in [
            (&b"BEFORE"[..], Noeud::Avant as fn(u64) -> Noeud<'a>),
            (b"ON", Noeud::Le as fn(u64) -> Noeud<'a>),
            (b"SINCE", Noeud::Depuis as fn(u64) -> Noeud<'a>),
        ] {
            if mot.eq_ignore_ascii_case(nom) {
                let jour = date(self.mot()).ok_or(Error::MalformedSearch)?;
                return self.ranger(faire(jour));
            }
        }
        if let Some((portee, nomme)) = portee_de(mot) {
            // `HEADER` nomme son champ AVANT le texte : deux mots, et non un.
            let champ = match nomme {
                Some(champ) => champ,
                None => self.chaine()?,
            };
            let texte = self.chaine()?;
            return self.ranger(Noeud::Contenu {
                portee,
                champ,
                texte,
            });
        }
        if mot.eq_ignore_ascii_case(b"UID") {
            let ensemble = SequenceSet::parse(self.mot(), self.limits)?;
            return self.ranger(Noeud::Uid(ensemble));
        }
        // Ce qui reste est soit un ensemble de numéros, soit un critère qu'on ne
        // sert pas. **Les distinguer par la forme, et non par une liste de
        // mots-clefs** : un mot-clef qu'on oublierait deviendrait un ensemble
        // illisible, donc une faute de syntaxe, alors que c'est un refus.
        if mot.iter().all(|octet| octet.is_ascii_alphabetic()) {
            return Err(Error::UnsupportedSearchKey);
        }
        let ensemble = SequenceSet::parse(mot, self.limits)?;
        self.ranger(Noeud::Rang(ensemble))
    }
}

/// La portée qu'un mot-clef désigne, et le champ qu'il vise.
///
/// `None` veut dire « c'est le client qui nomme le champ » : `HEADER` est le
/// seul dans ce cas, et le confondre avec les autres ferait lire le TEXTE
/// cherché comme un nom de champ.
fn portee_de(mot: &[u8]) -> Option<(SearchScope, Option<&'static [u8]>)> {
    /// Un mot-clef, la portée qu'il désigne, et le champ qu'il vise.
    type Entree = (&'static [u8], SearchScope, Option<&'static [u8]>);
    const TABLE: [Entree; 8] = [
        (b"SUBJECT", SearchScope::Header, Some(b"subject")),
        (b"FROM", SearchScope::Header, Some(b"from")),
        (b"TO", SearchScope::Header, Some(b"to")),
        (b"CC", SearchScope::Header, Some(b"cc")),
        (b"BCC", SearchScope::Header, Some(b"bcc")),
        // LE SEUL DONT LE CLIENT NOMME LE CHAMP.
        (b"HEADER", SearchScope::Header, None),
        (b"BODY", SearchScope::Body, Some(b"")),
        (b"TEXT", SearchScope::Text, Some(b"")),
    ];
    let mut trouve = None;
    for (nom, portee, champ) in TABLE {
        if mot.eq_ignore_ascii_case(nom) {
            trouve = Some((portee, champ));
        }
    }
    trouve
}

/// Le drapeau qu'un mot-clef désigne, et s'il doit être présent.
fn drapeau_de(mot: &[u8]) -> Option<(Flags, bool)> {
    const TABLE: [(&[u8], Flags); 5] = [
        (b"SEEN", Flags::SEEN),
        (b"ANSWERED", Flags::ANSWERED),
        (b"FLAGGED", Flags::FLAGGED),
        (b"DELETED", Flags::DELETED),
        (b"DRAFT", Flags::DRAFT),
    ];
    for (nom, drapeau) in TABLE {
        if mot.eq_ignore_ascii_case(nom) {
            return Some((drapeau, true));
        }
        // `UNSEEN`, `UNANSWERED`… : le même, nié.
        if mot.len() == nom.len().saturating_add(2)
            && mot
                .get(..2)
                .is_some_and(|debut| debut.eq_ignore_ascii_case(b"UN"))
            && mot
                .get(2..)
                .is_some_and(|fin| fin.eq_ignore_ascii_case(nom))
        {
            return Some((drapeau, false));
        }
    }
    None
}

/// Lit un nombre décimal, sans débordement.
fn nombre(mot: &[u8]) -> Option<u64> {
    if mot.is_empty() || !mot.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut valeur = 0_u64;
    for chiffre in mot {
        valeur = valeur
            .checked_mul(10)?
            .checked_add(u64::from(chiffre.saturating_sub(b'0')))?;
    }
    Some(valeur)
}

/// Lit une date `1-Jan-2026`, et rend le nombre de jours depuis l'époque.
///
/// Les guillemets sont admis : la RFC les autorise autour d'une date, et
/// plusieurs clients en mettent toujours.
fn date(mot: &[u8]) -> Option<u64> {
    let mot = mot.strip_prefix(b"\"").unwrap_or(mot);
    let mot = mot.strip_suffix(b"\"").unwrap_or(mot);
    let mut morceaux = mot.split(|octet| *octet == b'-');
    // `split` rend toujours au moins un morceau : demander « et s'il n'y en
    // avait aucun ? » serait une garde qu'aucune entrée ne peut emprunter. Un
    // morceau absent est un morceau vide, que `nombre` et `mois_de` refusent
    // déjà.
    let jour = nombre(morceaux.next().unwrap_or_default())?;
    let mois = mois_de(morceaux.next().unwrap_or_default())?;
    let annee = nombre(morceaux.next().unwrap_or_default())?;
    if morceaux.next().is_some() || !(1..=31).contains(&jour) || !(1970..=9999).contains(&annee) {
        return None;
    }
    Some(jours_depuis_l_epoque(annee, mois, jour))
}

/// Le rang d'un mois, à partir de un.
fn mois_de(mot: &[u8]) -> Option<u64> {
    const MOIS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    MOIS.iter()
        .position(|nom| mot.eq_ignore_ascii_case(nom))
        .map(|rang| (rang as u64).saturating_add(1))
}

/// Le jour d'une date en secondes depuis l'époque.
fn jour_de(secondes: u64) -> u64 {
    secondes / 86_400
}

/// Le nombre de jours entre l'époque et une date civile.
///
/// L'algorithme de Howard Hinnant, réciproque de celui qui écrit
/// `INTERNALDATE` : il déplace l'origine au 1er mars, ce qui met le jour
/// bissextile en fin d'année où il ne décale plus rien.
fn jours_depuis_l_epoque(annee: u64, mois: u64, jour: u64) -> u64 {
    let annee = if mois <= 2 {
        annee.saturating_sub(1)
    } else {
        annee
    };
    let ere = annee / 400;
    let an_de_l_ere = annee.saturating_sub(ere.saturating_mul(400));
    let mois_decale = if mois > 2 {
        mois.saturating_sub(3)
    } else {
        mois.saturating_add(9)
    };
    let jour_de_l_an = (mois_decale.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(jour.saturating_sub(1));
    let jour_de_l_ere = an_de_l_ere
        .saturating_mul(365)
        .saturating_add(an_de_l_ere / 4)
        .saturating_sub(an_de_l_ere / 100)
        .saturating_add(jour_de_l_an);
    ere.saturating_mul(146_097)
        .saturating_add(jour_de_l_ere)
        .saturating_sub(719_468)
}

#[cfg(test)]
mod tests;
