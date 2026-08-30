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
//! Et le CHOIX de champs : `BODY[HEADER.FIELDS (FROM SUBJECT)]`, ce qu'un client
//! demande pour peupler une liste de messages sans tout télécharger.
//!
//! Ce qui reste **reconnu et refusé** — `RFC822`, `BINARY`, un nom de champ cité
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
    /// `[1.HEADER.FIELDS (…)]` — un CHOIX de ses champs.
    ///
    /// **Les noms ne sont pas ici**, et c'est délibéré : un élément de `FETCH`
    /// est retenu dans un tableau de taille fixe, et y loger une liste de noms
    /// ferait porter à chaque élément la place que le plus gourmand demanderait.
    /// Ils vivent à côté, un par élément — voir [`Fetch::header_names`].
    HeaderFields {
        /// `.NOT` : tous les autres.
        except: bool,
    },
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
    /// `[HEADER.FIELDS (…)]` — un CHOIX de champs d'en-tête.
    ///
    /// Les noms vivent à côté : voir [`PartWhat::HeaderFields`].
    HeaderFields {
        /// `.NOT` : tous les autres.
        except: bool,
    },
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
    /// La liste de noms de chaque élément, empruntée aux arguments.
    ///
    /// # POURQUOI À CÔTÉ, ET NON DANS L'ÉLÉMENT
    ///
    /// Les éléments sont retenus dans un tableau de taille fixe. Y loger une
    /// liste de noms ferait porter à CHACUN la place que le plus gourmand
    /// demanderait — soixante-quatre fois, pour une liste qu'un seul élément
    /// porte d'ordinaire.
    noms: [&'a [u8]; FETCH_ITEMS_MAX],
}

impl<'a> Fetch<'a> {
    /// Les noms que l'élément de rang `index` choisit, ou une tranche vide.
    ///
    /// Les noms sont séparés par des blancs, tels que le client les a écrits.
    #[must_use]
    pub fn header_names(&self, index: usize) -> &'a [u8] {
        self.noms.get(index).copied().unwrap_or_default()
    }

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
        let mut noms: [&[u8]; FETCH_ITEMS_MAX] = [b""; FETCH_ITEMS_MAX];
        let mut mots = Mots::new(liste);
        for ((place, ou), mot) in items
            .iter_mut()
            .zip(noms.iter_mut())
            .take(plafond)
            .zip(mots.by_ref())
        {
            let (item, choisis) = lire_un(mot)?;
            *place = item;
            *ou = choisis;
            count = count.saturating_add(1);
        }
        // S'il en reste, c'est qu'il y en avait trop.
        if mots.next().is_some() {
            return Err(Error::TooManyFetchItems { limit: plafond });
        }
        if count == 0 {
            return Err(Error::MalformedFetch);
        }
        Ok(Self {
            set,
            items,
            count,
            noms,
        })
    }
}

/// Lit un élément.
fn lire_un(mot: &[u8]) -> Result<(FetchItem, &[u8]), Error> {
    if mot.eq_ignore_ascii_case(b"UID") {
        return Ok((FetchItem::Uid, b""));
    }
    if mot.eq_ignore_ascii_case(b"FLAGS") {
        return Ok((FetchItem::Flags, b""));
    }
    if mot.eq_ignore_ascii_case(b"INTERNALDATE") {
        return Ok((FetchItem::InternalDate, b""));
    }
    if mot.eq_ignore_ascii_case(b"RFC822.SIZE") {
        return Ok((FetchItem::Rfc822Size, b""));
    }
    if mot.eq_ignore_ascii_case(b"ENVELOPE") {
        return Ok((FetchItem::Envelope, b""));
    }
    if mot.eq_ignore_ascii_case(b"BODYSTRUCTURE") {
        return Ok((FetchItem::BodyStructure, b""));
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
fn lire_un_corps(mot: &[u8]) -> Result<(FetchItem, &[u8]), Error> {
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
    let (section, noms) = lire_une_section(reste.get(1..fermante).unwrap_or_default())?;
    let apres = reste.get(fermante.saturating_add(1)..).unwrap_or_default();
    let partial = if apres.is_empty() {
        None
    } else {
        Some(lire_une_partie(apres)?)
    };
    Ok((
        FetchItem::Body {
            section,
            peek,
            partial,
        },
        noms,
    ))
}

/// Lit ce qui tient entre les crochets d'un `BODY[…]`.
fn lire_une_section(nom: &[u8]) -> Result<(Section, &[u8]), Error> {
    // UNE LISTE DE NOMS SE RECONNAÎT AU BLANC QUI LA PRÉCÈDE, et c'est le seul
    // endroit d'une section où un blanc puisse figurer.
    let Some((tete, reste)) = couper_au_blanc(nom) else {
        return lire_une_section_simple(nom).map(|section| (section, &b""[..]));
    };
    let noms = lire_les_noms(reste)?;
    let (chemin, except) = decouper_le_choix(tete)?;
    if chemin.is_empty() {
        return Ok((Section::HeaderFields { except }, noms));
    }
    // `false` : `1.HEADER.FIELDS` a DÉJÀ son mot-clef, et un second — `1.MIME`
    // suivi d'une liste — ne veut rien dire.
    let (path, _) = lire_un_chemin(chemin, false)?;
    Ok((
        Section::Part {
            path,
            what: PartWhat::HeaderFields { except },
        },
        noms,
    ))
}

/// Une section sans liste de noms.
fn lire_une_section_simple(nom: &[u8]) -> Result<Section, Error> {
    if nom.is_empty() {
        return Ok(Section::Full);
    }
    if nom.eq_ignore_ascii_case(b"HEADER") {
        return Ok(Section::Header);
    }
    if nom.eq_ignore_ascii_case(b"TEXT") {
        return Ok(Section::Text);
    }
    // UN CHOIX SANS LISTE N'EN EST PAS UN : `HEADER.FIELDS` tout seul ne
    // désigne rien, et le prendre pour un chemin de partie ferait chercher au
    // client une erreur là où il n'y en a pas.
    if decouper_le_choix(nom).is_ok() {
        return Err(Error::MalformedFetch);
    }
    lire_une_partie_designee(nom)
}

/// Sépare le chemin du mot-clef `HEADER.FIELDS[.NOT]` qui le termine.
fn decouper_le_choix(tete: &[u8]) -> Result<(&[u8], bool), Error> {
    for (suffixe, except) in [
        (&b"HEADER.FIELDS.NOT"[..], true),
        (&b"HEADER.FIELDS"[..], false),
    ] {
        let Some(rang) = tete.len().checked_sub(suffixe.len()) else {
            continue;
        };
        let avant = tete.get(..rang).unwrap_or_default();
        let fin = tete.get(rang..).unwrap_or_default();
        if fin.eq_ignore_ascii_case(suffixe) {
            return Ok((avant.strip_suffix(b".").unwrap_or(avant), except));
        }
    }
    Err(Error::MalformedFetch)
}

/// Lit `(nom nom nom)` et rend ce qu'il y a dedans.
fn lire_les_noms(texte: &[u8]) -> Result<&[u8], Error> {
    let dedans = texte
        .strip_prefix(b"(")
        .and_then(|reste| reste.strip_suffix(b")"))
        .ok_or(Error::MalformedFetch)?;
    if dedans.trim_ascii().is_empty() {
        return Err(Error::MalformedFetch);
    }
    for octet in dedans {
        if matches!(*octet, b' ' | b'\t') {
            continue;
        }
        // UN NOM CITÉ EST RECEVABLE, ET ON NE LE SERT PAS. `header-fld-name` est
        // un `astring` : `"From"` et `{4}\r\nFrom` sont des formes licites. On
        // ne sait pas les déciter, et rendre le nom tel quel donnerait un choix
        // qui ne désigne pas ce que le client a demandé. C'est donc un REFUS de
        // service, et non une faute — les confondre ferait chercher au client
        // une erreur là où il n'y en a pas.
        if matches!(*octet, b'"' | b'\\' | b'{') {
            return Err(Error::UnsupportedFetchItem);
        }
        // Hors de là, un nom de champ est un atome (RFC 5322 §3.6.8) : ni
        // blanc, ni deux-points — celui-ci les sépare.
        if !est_ftext(*octet) {
            return Err(Error::MalformedFetch);
        }
    }
    Ok(dedans)
}

/// Un octet qui peut faire un nom de champ (RFC 5322 §3.6.8).
fn est_ftext(octet: u8) -> bool {
    (33..=57).contains(&octet) || (59..=126).contains(&octet)
}

/// Coupe au premier blanc : le mot, et ce qui suit, élagué.
fn couper_au_blanc(texte: &[u8]) -> Option<(&[u8], &[u8])> {
    let rang = texte
        .iter()
        .position(|octet| matches!(*octet, b' ' | b'\t'))?;
    Some((
        texte.get(..rang).unwrap_or_default(),
        texte.get(rang..).unwrap_or_default().trim_ascii_start(),
    ))
}

/// Les mots d'une liste d'éléments, crochets et parenthèses respectés.
///
/// # POURQUOI ON NE COUPE PAS SUR TOUS LES BLANCS
///
/// `BODY[HEADER.FIELDS (FROM TO)]` porte des blancs À L'INTÉRIEUR d'un élément.
/// Couper dessus rendait deux morceaux dont aucun n'était lisible — et c'est
/// exactement ce qui faisait refuser `HEADER.FIELDS` comme « non servi ».
struct Mots<'a> {
    reste: &'a [u8],
}

impl<'a> Mots<'a> {
    fn new(liste: &'a [u8]) -> Self {
        Self { reste: liste }
    }
}

impl<'a> Iterator for Mots<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let debut = self.reste.iter().position(|octet| *octet != b' ')?;
        let reste = self.reste.get(debut..).unwrap_or_default();
        let mut profondeur = 0_usize;
        let mut fin = reste.len();
        for (rang, octet) in reste.iter().enumerate() {
            match *octet {
                b'[' | b'(' => profondeur = profondeur.saturating_add(1),
                b']' | b')' => profondeur = profondeur.saturating_sub(1),
                b' ' if profondeur == 0 => {
                    fin = rang;
                    break;
                }
                _ => {}
            }
        }
        self.reste = reste.get(fin..).unwrap_or_default();
        reste.get(..fin)
    }
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
    let (path, what) = lire_un_chemin(nom, true)?;
    Ok(Section::Part { path, what })
}

/// Lit un chemin de partie, avec ou sans le mot-clef qui peut le fermer.
///
/// # Errors
///
/// [`Error::MalformedFetch`] si le chemin n'a pas la forme ;
/// [`Error::UnsupportedFetchItem`] s'il est plus profond que ce qu'on retient.
fn lire_un_chemin(nom: &[u8], mots_clefs: bool) -> Result<(PartPath, PartWhat), Error> {
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
            if !mots_clefs || chemin.len == 0 || suite.is_some() {
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
    Ok((chemin, what))
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
