//! Ce qu'un `FETCH` demande (RFC 9051 §6.4.5).
//!
//! # Le sous-ensemble servi, et pourquoi c'en est un
//!
//! `FETCH` est la commande la plus vaste d'IMAP : elle sait rendre une
//! enveloppe analysée, une structure MIME arborescente, une partie de partie de
//! message. Ce module en lit **ce qu'un client qui télécharge les messages
//! entiers demande** : les drapeaux, l'UID, la taille, la date d'arrivée, et le
//! message ou l'une de ses deux moitiés.
//!
//! `ENVELOPE` et `BODYSTRUCTURE` s'y ajoutent — ce que demande un client qui
//! n'affiche qu'une liste de messages et leurs pièces jointes.
//!
//! Les parties désignées s'y ajoutent : `BODY[1]`, `BODY[1.2.MIME]`,
//! `BODY[3.TEXT]`.
//!
//! Ce qui reste **reconnu et refusé** — `RFC822`, `BINARY`, `HEADER.FIELDS (…)`
//! — n'est pas une erreur de syntaxe : le client sait alors qu'il doit demander
//! autrement, au lieu de chercher la faute dans ce qu'il a écrit.
//!
//! # LA DEMANDE PARTIELLE EST UNE SURFACE
//!
//! `BODY[]<1000.500>` demande cinq cents octets à partir du millième. Un
//! décalage et une longueur venus du réseau, appliqués à un message dont on ne
//! connaît la taille qu'après : c'est exactement la forme d'un débordement. Ils
//! sont lus comme des `u32` qui ne débordent pas, et c'est à celui qui sert de
//! les rapporter à la taille réelle.
//!
//! # `PEEK` N'EST PAS UNE VARIANTE COSMÉTIQUE
//!
//! `BODY[]` marque le message comme lu ; `BODY.PEEK[]` ne le marque pas
//! (§6.4.5). Confondre les deux fait qu'un client qui prévisualise marque tout
//! comme lu — un défaut qu'on ne remarque qu'une fois le mal fait.

use crate::{Error, Limits, SequenceSet};

/// Combien de niveaux au plus une partie désignée peut porter.
///
/// **Aucune RFC ne le borne.** C'est la profondeur d'un chemin venu du réseau,
/// et il est retenu dans un tableau de taille fixe : ce qui est accepté doit
/// tenir dans ce qui le retient.
pub const SECTION_DEPTH_MAX: usize = 8;

/// Le chemin d'une partie : `1`, `1.2`, `3.1.4` (§6.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartPath {
    numeros: [u32; SECTION_DEPTH_MAX],
    len: usize,
}

impl PartPath {
    /// Le chemin vide, qui ne désigne aucune partie.
    pub const EMPTY: Self = Self {
        numeros: [0; SECTION_DEPTH_MAX],
        len: 0,
    };

    /// Les numéros du chemin, dans l'ordre.
    #[must_use]
    pub fn numbers(&self) -> &[u32] {
        self.numeros.get(..self.len).unwrap_or_default()
    }
}

/// Ce qu'on demande d'une partie désignée (§6.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartWhat {
    /// `[1]` — son contenu.
    Content,
    /// `[1.MIME]` — ses lignes d'en-tête MIME.
    Mime,
    /// `[1.HEADER]` — l'en-tête du message qu'elle encapsule.
    Header,
    /// `[1.TEXT]` — le corps du message qu'elle encapsule.
    Text,
}

/// La partie du message demandée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// `[]` — le message entier, en-têtes compris.
    Full,
    /// `[HEADER]` — le bloc d'en-tête, ligne vide comprise.
    Header,
    /// `[TEXT]` — le corps seul.
    Text,
    /// `[1]`, `[1.2.MIME]` — une partie désignée.
    Part {
        /// Où elle se trouve dans l'arbre.
        path: PartPath,
        /// Ce qu'on veut d'elle.
        what: PartWhat,
    },
}

/// Une demande partielle, `<décalage.longueur>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partial {
    /// Le décalage, en octets. Zéro est permis.
    pub offset: u32,
    /// La longueur demandée. **Jamais zéro** : la grammaire dit `nz-number`.
    pub length: u32,
}

/// Un élément de `FETCH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchItem {
    /// `UID` — l'identifiant durable.
    Uid,
    /// `FLAGS` — les marques.
    Flags,
    /// `INTERNALDATE` — la date d'arrivée.
    InternalDate,
    /// `ENVELOPE` : ce que l'en-tête dit du message (§7.5.2).
    Envelope,
    /// `BODYSTRUCTURE` : la structure MIME du message (§7.5.2).
    BodyStructure,
    /// `RFC822.SIZE` — la taille, en octets.
    Rfc822Size,
    /// `BODY[…]` ou `BODY.PEEK[…]`.
    Body {
        /// Quelle partie.
        section: Section,
        /// `PEEK` : ne pas marquer le message comme lu.
        peek: bool,
        /// La demande partielle, s'il y en a une.
        partial: Option<Partial>,
    },
}

/// Le nombre d'éléments qu'une commande `FETCH` peut porter.
///
/// La borne de la configuration ne peut pas la dépasser : ces éléments sont
/// retenus dans un tableau de taille fixe, et ce qui est accepté doit tenir dans
/// ce qui le retient.
pub const FETCH_ITEMS_MAX: usize = 64;

/// Une commande `FETCH` lue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fetch<'a> {
    set: SequenceSet<'a>,
    items: [FetchItem; FETCH_ITEMS_MAX],
    count: usize,
}

impl<'a> Fetch<'a> {
    /// Les messages visés.
    #[must_use]
    pub fn set(&self) -> SequenceSet<'a> {
        self.set
    }

    /// Le texte de l'ensemble, tel qu'il a été écrit.
    ///
    /// Un appelant qui doit RETENIR l'ensemble après avoir rendu la main ne peut
    /// pas garder un emprunt sur la commande : il en recopie le texte, et le
    /// relit quand il en a besoin.
    #[must_use]
    pub fn set_text(&self) -> &'a [u8] {
        self.set.as_bytes()
    }

    /// Ce qui est demandé de chacun.
    #[must_use]
    pub fn items(&self) -> &[FetchItem] {
        self.items.get(..self.count).unwrap_or_default()
    }

    /// Lit les arguments d'un `FETCH`.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedFetch`] si la forme n'est pas celle de §6.4.5,
    /// [`Error::UnsupportedFetchItem`] pour un élément reconnu mais non servi,
    /// [`Error::TooManyFetchItems`] au-delà de la borne, ou les erreurs
    /// d'ensemble de numéros.
    pub fn parse(arguments: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let arguments = arguments.trim_ascii();
        let rang = arguments
            .iter()
            .position(|octet| *octet == b' ')
            .ok_or(Error::MalformedFetch)?;
        let set = SequenceSet::parse(arguments.get(..rang).unwrap_or_default(), limits)?;
        let demande = arguments
            .get(rang.saturating_add(1)..)
            .unwrap_or_default()
            .trim_ascii();

        // `FAST` est le seul raccourci servi : les deux autres, `ALL` et
        // `FULL`, demandent une enveloppe analysée qu'on ne compose pas encore.
        let liste: &[u8] = if demande.eq_ignore_ascii_case(b"FAST") {
            b"FLAGS INTERNALDATE RFC822.SIZE"
        } else if demande.eq_ignore_ascii_case(b"ALL") || demande.eq_ignore_ascii_case(b"FULL") {
            return Err(Error::UnsupportedFetchItem);
        } else {
            demande
        };

        // Une liste entre parenthèses, ou un élément seul.
        let liste = match (liste.first(), liste.last()) {
            (Some(b'('), Some(b')')) => liste
                .get(1..liste.len().saturating_sub(1))
                .unwrap_or_default(),
            // Une parenthèse d'un seul côté n'est pas une liste.
            (Some(b'('), _) | (_, Some(b')')) => return Err(Error::MalformedFetch),
            _ => liste,
        };

        let plafond = limits.max_fetch_items.min(FETCH_ITEMS_MAX);
        let mut items = [FetchItem::Uid; FETCH_ITEMS_MAX];
        let mut count = 0_usize;
        // ON RANGE PAR APPARIEMENT, et non par indice : `zip` s'arrête de
        // lui-même à la plus courte des deux suites, ce qui retire la question
        // « et si le tableau était plein ? » — donc une garde qu'aucune entrée
        // ne pourrait faire céder.
        let mut mots = liste
            .split(|octet| *octet == b' ')
            .filter(|mot| !mot.is_empty());
        for (place, mot) in items.iter_mut().take(plafond).zip(mots.by_ref()) {
            *place = lire_un(mot)?;
            count = count.saturating_add(1);
        }
        // S'il en reste, c'est qu'il y en avait trop.
        if mots.next().is_some() {
            return Err(Error::TooManyFetchItems { limit: plafond });
        }
        if count == 0 {
            return Err(Error::MalformedFetch);
        }
        Ok(Self { set, items, count })
    }
}

/// Lit un élément.
fn lire_un(mot: &[u8]) -> Result<FetchItem, Error> {
    if mot.eq_ignore_ascii_case(b"UID") {
        return Ok(FetchItem::Uid);
    }
    if mot.eq_ignore_ascii_case(b"FLAGS") {
        return Ok(FetchItem::Flags);
    }
    if mot.eq_ignore_ascii_case(b"INTERNALDATE") {
        return Ok(FetchItem::InternalDate);
    }
    if mot.eq_ignore_ascii_case(b"RFC822.SIZE") {
        return Ok(FetchItem::Rfc822Size);
    }
    if mot.eq_ignore_ascii_case(b"ENVELOPE") {
        return Ok(FetchItem::Envelope);
    }
    if mot.eq_ignore_ascii_case(b"BODYSTRUCTURE") {
        return Ok(FetchItem::BodyStructure);
    }
    // Reconnus, et refusés : le client sait alors qu'il doit demander
    // autrement, au lieu de chercher la faute dans ce qu'il a écrit.
    if mot.eq_ignore_ascii_case(b"BODY")
        || mot.eq_ignore_ascii_case(b"RFC822")
        || mot.eq_ignore_ascii_case(b"RFC822.HEADER")
        || mot.eq_ignore_ascii_case(b"RFC822.TEXT")
        || mot.eq_ignore_ascii_case(b"BINARY")
    {
        return Err(Error::UnsupportedFetchItem);
    }
    lire_un_corps(mot)
}

/// Lit un `BODY[…]` ou un `BODY.PEEK[…]`, avec sa demande partielle.
fn lire_un_corps(mot: &[u8]) -> Result<FetchItem, Error> {
    let reste = mot
        .get(..4)
        .filter(|debut| debut.eq_ignore_ascii_case(b"BODY"))
        .and_then(|_| mot.get(4..))
        .ok_or(Error::MalformedFetch)?;
    let (peek, reste) = match reste.get(..5) {
        Some(mot) if mot.eq_ignore_ascii_case(b".PEEK") => {
            (true, reste.get(5..).unwrap_or_default())
        }
        _ => (false, reste),
    };
    let ouvrante = reste.first().filter(|octet| **octet == b'[');
    let Some(fermante) = reste.iter().position(|octet| *octet == b']') else {
        // Une section qu'on n'a pas su découper est presque toujours une
        // section qu'on ne sert pas — `HEADER.FIELDS (…)` en porte une espace,
        // que le découpage en mots a déjà coupée. On le dit ainsi plutôt que
        // d'accuser le client d'une faute de syntaxe.
        return Err(if ouvrante.is_some() {
            Error::UnsupportedFetchItem
        } else {
            Error::MalformedFetch
        });
    };
    if ouvrante.is_none() {
        return Err(Error::MalformedFetch);
    }
    let section = match reste.get(1..fermante).unwrap_or_default() {
        b"" => Section::Full,
        nom if nom.eq_ignore_ascii_case(b"HEADER") => Section::Header,
        nom if nom.eq_ignore_ascii_case(b"TEXT") => Section::Text,
        nom => lire_une_partie_designee(nom)?,
    };
    let apres = reste.get(fermante.saturating_add(1)..).unwrap_or_default();
    let partial = if apres.is_empty() {
        None
    } else {
        Some(lire_une_partie(apres)?)
    };
    Ok(FetchItem::Body {
        section,
        peek,
        partial,
    })
}

/// Lit un chemin de partie : `1`, `1.2`, `3.1.MIME` (§6.4.5).
///
/// # CE QU'ON NE SAIT PAS LIRE N'EST PAS UNE FAUTE DU CLIENT
///
/// `HEADER.FIELDS (…)`, un chemin plus profond que ce qu'on retient : la
/// commande est correcte, c'est ce serveur qui ne la sert pas. On le dit par
/// `UnsupportedFetchItem`. En revanche `1..2` ou `1.0` sont des fautes de
/// syntaxe, et les confondre ferait chercher au client une erreur là où il n'y
/// en a pas — ou l'inverse.
fn lire_une_partie_designee(nom: &[u8]) -> Result<Section, Error> {
    let mut chemin = PartPath::EMPTY;
    let mut what = PartWhat::Content;
    let mut reste = nom;
    loop {
        let (morceau, suite) = match reste.iter().position(|octet| *octet == b'.') {
            Some(rang) => (
                reste.get(..rang).unwrap_or_default(),
                Some(reste.get(rang.saturating_add(1)..).unwrap_or_default()),
            ),
            None => (reste, None),
        };
        // Un mot-clé ferme le chemin : rien ne peut le suivre.
        if let Some(vu) = mot_clef(morceau) {
            if chemin.len == 0 || suite.is_some() {
                return Err(Error::MalformedFetch);
            }
            what = vu;
            break;
        }
        let numero = nombre(morceau)?;
        // `nz-number` : il n'y a pas de partie zéro.
        if numero == 0 {
            return Err(Error::MalformedFetch);
        }
        let Some(place) = chemin.numeros.get_mut(chemin.len) else {
            return Err(Error::UnsupportedFetchItem);
        };
        *place = numero;
        chemin.len = chemin.len.saturating_add(1);
        match suite {
            Some(suite) => reste = suite,
            None => break,
        }
    }
    Ok(Section::Part { path: chemin, what })
}

/// Le mot-clef qui ferme un chemin de partie, s'il en est un.
fn mot_clef(morceau: &[u8]) -> Option<PartWhat> {
    if morceau.eq_ignore_ascii_case(b"MIME") {
        return Some(PartWhat::Mime);
    }
    if morceau.eq_ignore_ascii_case(b"HEADER") {
        return Some(PartWhat::Header);
    }
    if morceau.eq_ignore_ascii_case(b"TEXT") {
        return Some(PartWhat::Text);
    }
    None
}

/// Lit `<décalage.longueur>`.
fn lire_une_partie(texte: &[u8]) -> Result<Partial, Error> {
    let corps = texte
        .strip_prefix(b"<")
        .and_then(|reste| reste.strip_suffix(b">"))
        .ok_or(Error::MalformedFetch)?;
    let rang = corps
        .iter()
        .position(|octet| *octet == b'.')
        .ok_or(Error::MalformedFetch)?;
    let offset = nombre(corps.get(..rang).unwrap_or_default())?;
    let length = nombre(corps.get(rang.saturating_add(1)..).unwrap_or_default())?;
    // `nz-number` : demander zéro octet n'est pas une demande.
    if length == 0 {
        return Err(Error::MalformedFetch);
    }
    Ok(Partial { offset, length })
}

/// Lit un entier décimal qui tient dans un `u32`.
fn nombre(texte: &[u8]) -> Result<u32, Error> {
    if texte.is_empty() || !texte.iter().all(u8::is_ascii_digit) {
        return Err(Error::MalformedFetch);
    }
    let mut valeur = 0_u32;
    for octet in texte {
        // UN DÉCALAGE QUI DÉBORDE N'EST PAS UN GRAND DÉCALAGE. Reparti de zéro,
        // il rendrait le début d'un message là où le client en demandait la fin.
        valeur = valeur
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(u32::from(octet.wrapping_sub(b'0'))))
            .ok_or(Error::MalformedFetch)?;
    }
    Ok(valeur)
}

#[cfg(test)]
mod tests;
