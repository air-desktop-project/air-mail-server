//! Ce qu'une session IMAP dit, et ce qu'elle refuse.

use ams_proto_imap::{Flags, Limits, PartWhat, SearchScope, StoreMode};
use ams_sasl::Credentials;

use super::{Action, BinarySize, Mailbox, Mailboxes, MessageInfo, Session, State, TAG_MAX_OCTETS};
use crate::Authenticator;

const BORNES: Limits = Limits::DEFAULT;

/// Le seul compte que la politique de test connaisse.
#[derive(Debug, Clone)]
struct UnCompte;

impl Authenticator for UnCompte {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        credentials.authentication_identity == b"jean" && credentials.password == b"ouvre-toi"
    }
}

/// Une boîte d'épreuve.
///
/// **Un seul type pour tous les cas**, y compris celui d'un message disparu : une
/// méthode générique est recopiée pour chaque type qui l'instancie, et le
/// compteur de couverture compte chaque copie. Deux types de boîte doubleraient
/// donc la surface à couvrir, pour éprouver la même chose.
#[derive(Debug, Clone)]
pub struct Boite {
    /// `None` : un message que le magasin annonce et ne rend pas.
    messages: std::vec::Vec<Option<MessageInfo>>,
    /// Se laisse-t-elle modifier ? `Archives` ne le fait pas.
    modifiable: bool,
    /// Le rang d'un message qui S'EFFACE ENTRE L'INSTANTANÉ ET L'ÉCRITURE.
    ///
    /// Ce n'est pas la même disparition qu'un `None` dans `messages` : celui-là
    /// n'est jamais choisi, puisqu'il n'a pas d'`info`. Celui-ci est choisi, et
    /// s'évanouit quand on écrit — ce qu'une boîte lue sans verrou ne peut pas
    /// exclure, et ce dont §6.4.6 dit qu'il ne faut pas faire une erreur.
    /// `0` : aucun.
    evanescent: u32,
    /// Grandira-t-elle au prochain regard ? `Vivante` le fait, une fois.
    grandit: bool,
    /// Combien de messages cette boîte a effacés, vu du dehors.
    efface: std::rc::Rc<std::cell::Cell<u32>>,
    /// L'UID d'un message qui REFUSE de s'effacer.
    ///
    /// C'est le cas qu'un magasin réel rencontre : entre l'instantané et
    /// l'ordre, une autre session a retiré la marque `\Deleted`, et le magasin
    /// refuse alors d'effacer plutôt que de perdre du courrier. `0` : aucun.
    tetu: u32,
}

impl Mailbox for Boite {
    fn exists(&self) -> u32 {
        u32::try_from(self.messages.len()).unwrap_or(u32::MAX)
    }
    fn uid_validity(&self) -> u32 {
        42
    }
    fn uid_next(&self) -> u32 {
        self.messages
            .iter()
            .flatten()
            .last()
            .map_or(1, |dernier| dernier.uid.saturating_add(1))
    }
    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let rang = usize::try_from(sequence.checked_sub(1)?).unwrap_or(usize::MAX);
        self.messages.get(rang).copied().flatten()
    }
    fn header_octets(&self, sequence: u32) -> u64 {
        // Deux cinquièmes de la taille : de quoi distinguer les trois sections.
        self.info(sequence)
            .map_or(0, |info| info.size.saturating_mul(2) / 5)
    }
    fn sent_day(&self, sequence: u32) -> Option<u64> {
        // LE PREMIER MESSAGE PORTE UNE DATE, LES AUTRES NON : c'est ce qui
        // éprouve à la fois la comparaison et le « sans date, rien ne
        // correspond » de §6.4.4. Le 15 janvier 2026, en jours depuis l'époque.
        match sequence {
            1 => Some(20_468),
            _ => None,
        }
    }

    fn refresh(&mut self) -> u32 {
        // LA BOÎTE D'ÉPREUVE GRANDIT D'UN MESSAGE À CHAQUE REGARD, tant qu'on le
        // lui demande : c'est ce qui permet d'éprouver qu'un `* n EXISTS` ne se
        // dit qu'une fois par changement.
        if self.grandit {
            self.messages.push(Some(MessageInfo {
                uid: 40,
                size: 100,
                flags: Flags::NONE,
                internal_date: 0,
            }));
            self.grandit = false;
        }
        self.exists()
    }

    fn permanent_flags(&self) -> Flags {
        if self.modifiable {
            Flags::SEEN
                .with(Flags::ANSWERED)
                .with(Flags::FLAGGED)
                .with(Flags::DELETED)
                .with(Flags::DRAFT)
                .with(Flags::MDN_SENT)
                .with(Flags::FORWARDED)
                .with(Flags::JUNK)
                .with(Flags::NON_JUNK)
                .with(Flags::PHISHING)
        } else {
            Flags::NONE
        }
    }
    fn envelope(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        // L'enveloppe d'épreuve nomme le message, et rien de plus : c'est
        // l'écoulement qu'on éprouve ici, pas la composition.
        let Some(info) = self.info(sequence) else {
            return 0;
        };
        let mut texte = std::vec::Vec::from(&b"(NIL NIL ((NIL NIL \"m"[..]);
        texte.extend_from_slice(std::format!("{}", info.uid).as_bytes());
        texte.extend_from_slice(b"\" \"x.test\")) NIL NIL NIL NIL NIL NIL NIL)");
        ecouler_le_texte(&texte, offset, out)
    }

    fn part_span(&self, sequence: u32, path: &[u32], what: PartWhat) -> Option<(u64, u64)> {
        // La boîte d'épreuve n'a qu'une partie : c'est le PLOMBAGE qu'on
        // éprouve ici — ce que la session écrit d'une partie présente, et d'une
        // partie absente —, pas la résolution d'un chemin, qui vit dans
        // `ams-mime` et y est éprouvée.
        let info = self.info(sequence)?;
        match (path, what) {
            ([1], PartWhat::Content) => Some((10, info.size)),
            ([1], PartWhat::Mime) => Some((0, 10)),
            _ => None,
        }
    }

    fn binary_size(&self, sequence: u32, path: &[u32]) -> BinarySize {
        // LA BOÎTE D'ÉPREUVE PORTE TROIS CAS, et trois seulement : une partie
        // qui se décode, une dont l'encodage résiste, et une qui n'existe pas.
        // Ce qu'on éprouve ici est le câblage — ce que la session écrit de
        // chacun —, pas le décodage, qui vit dans `ams-mime`.
        if self.info(sequence).is_none() {
            return BinarySize::Absent;
        }
        match path {
            [] | [1] => BinarySize::Octets(BINAIRE.len() as u64),
            [2] => BinarySize::UnknownEncoding,
            _ => BinarySize::Absent,
        }
    }

    fn binary(&self, sequence: u32, path: &[u32], raw: u64, out: &mut [u8]) -> (u64, usize) {
        if !matches!(self.binary_size(sequence, path), BinarySize::Octets(_)) {
            return (0, 0);
        }
        let reste = BINAIRE
            .get(usize::try_from(raw).unwrap_or(usize::MAX)..)
            .unwrap_or_default();
        // ON N'EN REND QU'UN PEU À LA FOIS : c'est ce que fait un vrai magasin,
        // qui s'arrête à une frontière de groupe, et c'est ce qui éprouve la
        // reprise.
        let voulu = reste.len().min(out.len()).min(4);
        for (place, octet) in out.iter_mut().zip(reste.get(..voulu).unwrap_or_default()) {
            *place = *octet;
        }
        (u64::try_from(voulu).unwrap_or(0), voulu)
    }

    fn contains(&self, sequence: u32, scope: SearchScope, field: &[u8], needle: &[u8]) -> bool {
        // LA BOÎTE D'ÉPREUVE PORTE UN SEUL MESSAGE-TYPE : ce qu'on éprouve ici
        // est le PLOMBAGE — que la session pose la bonne question et rende la
        // bonne réponse —, pas la lecture d'un message, qui vit dans le magasin.
        if self.info(sequence).is_none() {
            return false;
        }
        const SUJET: &[u8] = b"la facture de mars";
        const CORPS: &[u8] = b"le corps du message";
        let ou: &[u8] = match scope {
            SearchScope::Header if field.eq_ignore_ascii_case(b"subject") => SUJET,
            // Un champ qu'on ne porte pas : il n'existe pas.
            SearchScope::Header => return false,
            SearchScope::Body => CORPS,
            SearchScope::Text => SUJET,
        };
        if needle.is_empty() {
            return true;
        }
        ou.windows(needle.len()).any(|fenetre| {
            fenetre
                .iter()
                .zip(needle)
                .all(|(vu, cherche)| vu.eq_ignore_ascii_case(cherche))
        })
    }

    fn header_fields_len(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
    ) -> Option<u64> {
        let mut sortie = [0_u8; 512];
        let ecrits = self.choisir(sequence, path, names, except, &mut sortie)?;
        Some(u64::try_from(ecrits).unwrap_or(u64::MAX))
    }

    fn header_fields(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
        offset: u64,
        out: &mut [u8],
    ) -> usize {
        let mut sortie = [0_u8; 512];
        let Some(ecrits) = self.choisir(sequence, path, names, except, &mut sortie) else {
            return 0;
        };
        ecouler_le_texte(sortie.get(..ecrits).unwrap_or_default(), offset, out)
    }

    fn body_structure(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(info) = self.info(sequence) else {
            return 0;
        };
        let mut texte = std::vec::Vec::from(&b"(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" "[..]);
        texte.extend_from_slice(std::format!("{}", info.size).as_bytes());
        texte.extend_from_slice(b" 1 NIL NIL NIL NIL)");
        ecouler_le_texte(&texte, offset, out)
    }

    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        // Le message d'épreuve est fait de son rang, répété.
        let Some(info) = self.info(sequence) else {
            return 0;
        };
        let reste = info.size.saturating_sub(offset);
        let voulu = usize::try_from(reste).unwrap_or(usize::MAX).min(out.len());
        let place = out.get_mut(..voulu).unwrap_or_default();
        place.fill(b'0'.saturating_add(u8::try_from(sequence % 10).unwrap_or(0)));
        place.len()
    }
    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32> {
        // La boîte d'épreuve ne copie que vers elle-même, comme le magasin
        // réel : c'est la seule boîte qui existe.
        if !mailbox.eq_ignore_ascii_case(b"INBOX") {
            return None;
        }
        let info = self.info(sequence)?;
        // Le têtu ne se copie pas non plus : de quoi éprouver qu'une copie
        // manquée n'emporte pas les autres.
        if info.uid == self.tetu {
            return None;
        }
        let neuf = self.uid_next();
        self.messages
            .push(message(neuf, info.size, info.flags, info.internal_date));
        self.efface.set(self.efface.get());
        Some(neuf)
    }

    fn undo_copies(&mut self, mailbox: &[u8], premier: u32, dernier: u32) {
        if !mailbox.eq_ignore_ascii_case(b"INBOX") {
            return;
        }
        self.messages
            .retain(|message| message.is_none_or(|info| info.uid < premier || info.uid > dernier));
    }

    fn remove(&mut self, sequence: u32) -> bool {
        // Retirer, c'est effacer sans regarder la marque — et la boîte
        // d'épreuve n'en regarde pas non plus.
        let Ok(rang) = usize::try_from(sequence.saturating_sub(1)) else {
            return false;
        };
        if rang >= self.messages.len() || !self.modifiable {
            return false;
        }
        self.messages.remove(rang);
        true
    }

    fn expunge(&mut self, sequence: u32) -> bool {
        if !self.modifiable {
            return false;
        }
        let Some(rang) = usize::try_from(sequence.saturating_sub(1)).ok() else {
            return false;
        };
        if rang >= self.messages.len() {
            return false;
        }
        // Le têtu ne s'efface pas : sa marque a été retirée entre-temps.
        if self
            .info(sequence)
            .is_some_and(|info| info.uid == self.tetu)
        {
            return false;
        }
        // Le message évanescent s'efface tout seul avant qu'on l'atteigne : il
        // n'est plus là, ce qui est bien ce que `true` veut dire.
        self.messages.remove(rang);
        self.efface.set(self.efface.get().saturating_add(1));
        true
    }

    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags> {
        if !self.modifiable || sequence == self.evanescent {
            return None;
        }
        let rang = usize::try_from(sequence.checked_sub(1)?).unwrap_or(usize::MAX);
        let message = self.messages.get_mut(rang)?.as_mut()?;
        message.flags = match mode {
            StoreMode::Replace => flags,
            StoreMode::Add => message.flags.with(flags),
            StoreMode::Remove => message.flags.without(flags),
        };
        Some(message.flags)
    }
}

/// Un message d'épreuve.
fn message(uid: u32, size: u64, flags: Flags, internal_date: u64) -> Option<MessageInfo> {
    Some(MessageInfo {
        uid,
        size,
        flags,
        internal_date,
    })
}

/// Ce qu'une validation produit, vu du test : l'UID, les drapeaux, la date.
type Valide = std::rc::Rc<std::cell::Cell<Option<(u32, Flags, Option<u64>)>>>;

/// Ce qu'un dépôt a reçu, vu du test.
type Ecrit = std::rc::Rc<std::cell::RefCell<std::vec::Vec<u8>>>;

/// Ce que `CREATE … (USE (…))` a fait retenir au magasin : un usage par boîte.
type Designes =
    std::rc::Rc<std::cell::RefCell<std::vec::Vec<(std::vec::Vec<u8>, ams_proto_imap::SpecialUse)>>>;

/// Un dépôt d'épreuve : il retient ce qu'on lui écrit, et le partage.
#[derive(Debug, Default)]
pub struct Depot {
    /// Ce qui a été écrit, pour que le test le relise.
    ecrit: Ecrit,
    /// Ce dépôt refuse-t-il d'écrire ? De quoi éprouver un magasin qui lâche.
    refuse: bool,
    /// Ce dépôt refuse-t-il de se valider ?
    invalide: bool,
    /// Le prochain UID de la boîte.
    uid: u32,
    /// Ce que la validation a produit, pour que le test le relise.
    valide: Valide,
}

impl super::Deposit for Depot {
    fn write(&mut self, chunk: &[u8]) -> bool {
        if self.refuse {
            return false;
        }
        self.ecrit.borrow_mut().extend_from_slice(chunk);
        true
    }

    fn commit(self, flags: Flags, date: Option<u64>) -> Option<u32> {
        if self.invalide {
            return None;
        }
        self.valide.set(Some((self.uid, flags, date)));
        Some(self.uid)
    }

    fn abort(self) {
        self.ecrit.borrow_mut().clear();
    }
}

/// Le nom sous lequel un abonnement s'inscrit : `INBOX` s'écrit comme le client
/// veut, et ne fait qu'un abonnement.
fn nom_abonne(name: &[u8]) -> std::vec::Vec<u8> {
    match name.eq_ignore_ascii_case(b"INBOX") {
        true => std::vec::Vec::from(&b"INBOX"[..]),
        false => name.to_vec(),
    }
}

/// Quatre boîtes, dont une trouée.
///
/// Le compteur d'effacements est PARTAGÉ avec l'appelant : une boîte d'épreuve
/// meurt avec la session qui la tient, et `CLOSE` efface au moment précis où
/// elle meurt. Sans ce compteur, ce que `CLOSE` a fait ne serait observable
/// nulle part.
#[derive(Debug, Clone, Default)]
pub struct Boites {
    efface: std::rc::Rc<std::cell::Cell<u32>>,
    /// Ce qu'un dépôt a reçu, partagé avec le test.
    ecrit: Ecrit,
    /// Ce qu'une validation a produit, partagé avec le test.
    valide: Valide,
    /// Les boîtes créées pendant la session.
    creees: std::rc::Rc<std::cell::RefCell<std::vec::Vec<std::vec::Vec<u8>>>>,
    /// Les boîtes effacées : celles qui restent nommées sont `\Noselect`.
    effacees: std::rc::Rc<std::cell::RefCell<std::vec::Vec<std::vec::Vec<u8>>>>,
    /// Les abonnements du compte, comme un magasin réel les retiendrait.
    abonnees: std::rc::Rc<std::cell::RefCell<std::vec::Vec<std::vec::Vec<u8>>>>,
    /// Les usages désignés, comme le magasin réel les retient (RFC 6154).
    usages: Designes,
}

impl Mailboxes for Boites {
    type Open = Boite;

    fn name<'n>(
        &self,
        _user: &[u8],
        index: usize,
        out: &'n mut [u8],
    ) -> Option<super::Listing<'n>> {
        // Les boîtes créées s'ajoutent à celles qui sont là de tout temps, et
        // les effacées s'en retirent.
        let creees = self.creees.borrow();
        let effacees = self.effacees.borrow();
        let nom = [&b"INBOX"[..], b"Archives", b"Archives/2026"]
            .get(index)
            .copied()
            .or_else(|| {
                creees
                    .get(index.saturating_sub(3))
                    .map(std::vec::Vec::as_slice)
            })?;
        let longueur = nom.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        // Seule `Archives` a une fille, `Archives/2026`.
        let has_children = nom == b"Archives";
        let special = self
            .usages
            .borrow()
            .iter()
            .find(|(connu, _)| connu.as_slice() == nom)
            .map_or(ams_proto_imap::SpecialUse::NONE, |(_, usage)| *usage);
        Some(super::Listing {
            name: out.get(..longueur)?,
            selectable: !effacees.iter().any(|vide| vide == nom),
            has_children,
            special,
        })
    }

    fn rename(&self, _user: &[u8], from: &[u8], to: &[u8]) -> super::Renaming {
        if to.starts_with(b"Impossible") {
            return super::Renaming::Refusee;
        }
        let connue = |nom: &[u8]| {
            matches!(nom, b"Archives" | b"Archives/2026")
                || self.creees.borrow().iter().any(|connu| connu == nom)
        };
        // `INBOX` se renomme : cela la vide, elle ne disparaît pas.
        if !from.eq_ignore_ascii_case(b"INBOX") && !connue(from) {
            return super::Renaming::Absente;
        }
        if connue(to) {
            return super::Renaming::DejaLa;
        }
        // Les filles suivent.
        let mut creees = self.creees.borrow_mut();
        let mut nouvelles = std::vec::Vec::new();
        for connu in creees.iter() {
            if connu == from {
                nouvelles.push(to.to_vec());
            } else if connu.starts_with(from) && connu.get(from.len()) == Some(&b'/') {
                let mut neuf = to.to_vec();
                neuf.extend_from_slice(connu.get(from.len()..).unwrap_or_default());
                nouvelles.push(neuf);
            } else {
                nouvelles.push(connu.clone());
            }
        }
        if from == b"Archives" || from.eq_ignore_ascii_case(b"INBOX") {
            nouvelles.push(to.to_vec());
        }
        *creees = nouvelles;
        super::Renaming::Faite
    }

    fn delete(&self, _user: &[u8], name: &[u8]) -> super::Deletion {
        if name.starts_with(b"Impossible") {
            return super::Deletion::Refusee;
        }
        let connue = matches!(name, b"Archives" | b"Archives/2026")
            || self.creees.borrow().iter().any(|connu| connu == name);
        if !connue || self.effacees.borrow().iter().any(|vide| vide == name) {
            return super::Deletion::Absente;
        }
        // `Archives` a une fille : elle se vide sans disparaître.
        if name == b"Archives" {
            self.effacees.borrow_mut().push(name.to_vec());
            return super::Deletion::Videe;
        }
        self.creees.borrow_mut().retain(|connu| connu != name);
        if name == b"Archives/2026" {
            self.effacees.borrow_mut().push(name.to_vec());
        }
        super::Deletion::Faite
    }

    fn create(
        &self,
        _user: &[u8],
        name: &[u8],
        usage: ams_proto_imap::SpecialUse,
    ) -> super::Creation {
        // La boîte d'épreuve refuse ce qui la fâche, comme un magasin réel.
        if name.starts_with(b"Impossible") {
            return super::Creation::Refusee;
        }
        // RFC 6154 §3 : un usage ne vaut que pour une boîte.
        if usage.any()
            && self
                .usages
                .borrow()
                .iter()
                .any(|(autre, pris)| autre.as_slice() != name && pris.contains(usage))
        {
            return super::Creation::UsageDejaPris;
        }
        let deja = matches!(name, b"Archives" | b"Archives/2026" | b"Trouee" | b"Tetue")
            || self.creees.borrow().iter().any(|connu| connu == name);
        if deja {
            return super::Creation::DejaLa;
        }
        // §6.3.4 : créer `A/B` crée aussi `A`, comme le magasin réel.
        let mut creees = self.creees.borrow_mut();
        let mut parcouru = std::vec::Vec::new();
        for composant in name.split(|octet| *octet == b'/') {
            if !parcouru.is_empty() {
                parcouru.push(b'/');
            }
            parcouru.extend_from_slice(composant);
            if !creees.contains(&parcouru) {
                creees.push(parcouru.clone());
            }
        }
        // L'usage se RETIENT, comme le magasin réel l'écrit dans `ams-usages`.
        if usage.any() {
            self.usages.borrow_mut().push((name.to_vec(), usage));
        }
        super::Creation::Faite
    }

    type Deposit = Depot;

    fn append(&self, _user: &[u8], name: &[u8]) -> Option<Depot> {
        // `Refusante` accepte le dépôt et le perd en route ; `Ingrate` l'accepte
        // et refuse de le valider. Les deux existent parce que ce sont deux
        // façons différentes d'échouer.
        let connue = matches!(name, b"INBOX" | b"Archives" | b"Refusante" | b"Ingrate");
        connue.then(|| Depot {
            ecrit: std::rc::Rc::clone(&self.ecrit),
            refuse: name == b"Refusante",
            invalide: name == b"Ingrate",
            uid: 31,
            valide: std::rc::Rc::clone(&self.valide),
        })
    }

    fn subscribe(&self, _user: &[u8], name: &[u8]) -> super::Subscription {
        // `Tetue` existe et refuse : c'est la troisième issue, celle d'un
        // magasin qui n'a pas pu écrire.
        if name == b"Tetue" {
            return super::Subscription::Refusee;
        }
        // ON VALIDE À L'ABONNEMENT : ce qui n'existe pas ne s'abonne pas.
        let connue = name.eq_ignore_ascii_case(b"INBOX")
            || matches!(name, b"Archives" | b"Archives/2026")
            || self.creees.borrow().iter().any(|connu| connu == name);
        if !connue {
            return super::Subscription::Absente;
        }
        let nom = nom_abonne(name);
        let mut abonnees = self.abonnees.borrow_mut();
        if !abonnees.contains(&nom) {
            abonnees.push(nom);
        }
        super::Subscription::Faite
    }

    fn unsubscribe(&self, _user: &[u8], name: &[u8]) -> super::Subscription {
        if name == b"Tetue" {
            return super::Subscription::Refusee;
        }
        // AUCUNE VÉRIFICATION D'EXISTENCE : c'est ainsi qu'on se débarrasse d'un
        // abonnement orphelin.
        let nom = nom_abonne(name);
        self.abonnees.borrow_mut().retain(|connu| *connu != nom);
        super::Subscription::Faite
    }

    fn is_subscribed(&self, _user: &[u8], name: &[u8]) -> bool {
        self.abonnees.borrow().contains(&nom_abonne(name))
    }

    fn orphan<'n>(&self, _user: &[u8], index: usize, out: &'n mut [u8]) -> Option<&'n [u8]> {
        let creees = self.creees.borrow();
        let abonnees = self.abonnees.borrow();
        let nom = abonnees
            .iter()
            .filter(|nom| {
                !nom.eq_ignore_ascii_case(b"INBOX")
                    && !matches!(nom.as_slice(), b"Archives" | b"Archives/2026")
                    && !creees.iter().any(|connu| connu == *nom)
            })
            .nth(index)?;
        let longueur = nom.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        out.get(..longueur)
    }

    fn open(&self, _user: &[u8], name: &[u8]) -> Option<Boite> {
        let messages = match name {
            b"INBOX" => std::vec![
                message(10, 100, Flags::NONE, 1_787_987_311),
                message(20, 200, Flags::SEEN, 1_787_987_400),
                message(30, 300, Flags::ANSWERED, 1_787_987_500),
            ],
            // Celle-ci reçoit un message pendant qu'on la regarde : c'est ce
            // qu'un `IDLE` doit voir.
            b"Vivante" => std::vec![message(10, 100, Flags::NONE, 0)],
            // Celle-ci en annonce trois, et n'en rend que deux : le deuxième a
            // disparu sous nos pieds.
            b"Trouee" => std::vec![
                message(1, 10, Flags::NONE, 0),
                None,
                message(3, 10, Flags::NONE, 0),
            ],
            // Assez de messages aux UID espacés pour que leur ensemble, une
            // fois comprimé en plages, ne tienne pas dans ce qu'une session
            // retient — c'est ce qui éprouve qu'un résultat `SAVE` trop morcelé
            // est ABANDONNÉ plutôt que tronqué.
            b"Foisonnante" => (0..400)
                .map(|rang: u32| {
                    message(rang.saturating_mul(2).saturating_add(1), 10, Flags::NONE, 0)
                })
                .collect(),
            // Assez de messages aux UID espacés pour que leur ensemble ne
            // tienne pas dans ce qu'on accepte d'écrire pour un `COPYUID`.
            b"Eparse" => (0..60)
                .map(|rang: u32| {
                    message(rang.saturating_mul(2).saturating_add(1), 10, Flags::NONE, 0)
                })
                .collect(),
            // Trois messages aux UID QUI SE SUIVENT : de quoi éprouver qu'un
            // ensemble se comprime en plage plutôt qu'en liste.
            b"Suite" => std::vec![
                message(5, 100, Flags::NONE, 0),
                message(6, 100, Flags::NONE, 0),
                message(7, 100, Flags::NONE, 0),
            ],
            // Trois messages ordinaires, dont le deuxième refusera de s'effacer.
            b"Tetue" => std::vec![
                message(10, 100, Flags::NONE, 0),
                message(20, 200, Flags::NONE, 0),
                message(30, 300, Flags::NONE, 0),
            ],
            // Deux messages aux UID les plus grands qui soient : de quoi
            // composer une plage de vingt-six octets, plus longue qu'un tampon
            // qui a pourtant suffi à l'en-tête.
            b"Grande" => std::vec![
                message(u32::MAX.saturating_sub(1), 10, Flags::NONE, 0),
                message(u32::MAX, 10, Flags::NONE, 0),
            ],
            b"Archives" | b"Archives/2026" => std::vec::Vec::new(),
            _ => return None,
        };
        // `Archives` ne se modifie pas : de quoi éprouver un `SELECT` qui
        // répond `[READ-ONLY]` sans qu'on ait dit `EXAMINE`.
        Some(Boite {
            messages,
            modifiable: !name.starts_with(b"Archives"),
            // Dans la boîte trouée, le troisième s'efface quand on écrit.
            evanescent: if name == b"Trouee" { 3 } else { 0 },
            grandit: name == b"Vivante",
            efface: std::rc::Rc::clone(&self.efface),
            // Dans la boîte têtue, le message d'UID 20 refuse de s'effacer.
            tetu: if name == b"Tetue" { 20 } else { 0 },
        })
    }
}

/// Une session, chiffrée ou non.
fn nouvelle(chiffree: bool) -> Session<UnCompte, Boites> {
    let mut session = Session::new(BORNES, true, UnCompte, Boites::default());
    if chiffree {
        session.on_tls_established();
    }
    session
}

/// Traite une commande et rend la réponse en clair.
fn dire(session: &mut Session<UnCompte, Boites>, commande: &[u8]) -> (std::string::String, Action) {
    let mut sortie = [0_u8; 1024];
    let tour = session.handle(commande, &mut sortie).expect("traitable");
    (
        std::string::String::from_utf8_lossy(tour.reply()).into_owned(),
        tour.action(),
    )
}

// ── LA BANNIÈRE ET LES CAPACITÉS ────────────────────────────────────────────

#[test]
fn la_banniere_annonce_ce_qu_on_sait_faire() {
    let mut sortie = [0_u8; 256];
    let banniere = nouvelle(false).greeting(&mut sortie).expect("composable");
    let texte = std::string::String::from_utf8_lossy(banniere).into_owned();
    assert!(texte.starts_with(
        "* OK [CAPABILITY IMAP4rev2 LITERAL- IDLE SPECIAL-USE CREATE-SPECIAL-USE STARTTLS \
         LOGINDISABLED]"
    ));
    assert!(texte.ends_with("service ready\r\n"), "{texte}");
}

/// **§6.2.3 : tant que la connexion n'est pas protégée, on l'annonce.** Et une
/// fois protégée, c'est `AUTH=PLAIN` qui apparaît.
#[test]
fn les_capacites_suivent_le_chiffrement() {
    let (clair, _) = dire(&mut nouvelle(false), b"a001 CAPABILITY\r\n");
    assert!(clair.contains("LOGINDISABLED"), "{clair}");
    assert!(clair.contains("STARTTLS"), "{clair}");
    assert!(!clair.contains("AUTH=PLAIN"), "{clair}");

    let (chiffre, _) = dire(&mut nouvelle(true), b"a001 CAPABILITY\r\n");
    assert!(chiffre.contains("AUTH=PLAIN"), "{chiffre}");
    assert!(!chiffre.contains("LOGINDISABLED"), "{chiffre}");
    assert!(!chiffre.contains("STARTTLS"), "{chiffre}");
    // Une réponse non sollicitée, puis la conclusion.
    assert!(chiffre.starts_with("* CAPABILITY "), "{chiffre}");
    assert!(
        chiffre.ends_with("a001 OK CAPABILITY completed\r\n"),
        "{chiffre}"
    );
}

/// **Annoncer `STARTTLS` sans savoir le faire ferait mentir la bannière.**
#[test]
fn sans_materiel_starttls_n_est_pas_annonce() {
    let mut session = Session::new(BORNES, false, UnCompte, Boites::default());
    let (texte, _) = dire(&mut session, b"a001 CAPABILITY\r\n");
    assert!(!texte.contains("STARTTLS"), "{texte}");
    let (refus, action) = dire(&mut session, b"a002 STARTTLS\r\n");
    assert!(
        refus.starts_with("a002 NO STARTTLS is not available"),
        "{refus}"
    );
    assert_eq!(action, Action::Continue);
}

// ── LE CHIFFREMENT ──────────────────────────────────────────────────────────

/// **Ce qui a été dit en clair a pu être dit par quelqu'un d'autre** : après la
/// poignée de main, tout ce qui précède est oublié (§6.2.1).
#[test]
fn starttls_efface_tout_ce_qui_precede() {
    let mut session = nouvelle(false);
    let (reponse, action) = dire(&mut session, b"a001 STARTTLS\r\n");
    assert!(
        reponse.starts_with("a001 OK Begin TLS negotiation now"),
        "{reponse}"
    );
    assert_eq!(action, Action::StartTls);

    session.on_tls_established();
    assert!(session.is_encrypted());
    assert_eq!(session.state(), State::NotAuthenticated);
    assert!(session.user().is_empty());

    // Et on ne monte pas deux fois.
    let (refus, _) = dire(&mut session, b"a002 STARTTLS\r\n");
    assert!(
        refus.starts_with("a002 BAD TLS is already active"),
        "{refus}"
    );
}

// ── UN MOT DE PASSE NE TRAVERSE PAS UNE CONNEXION EN CLAIR ──────────────────

/// **Annoncer sans refuser laisserait un client mal écrit envoyer le mot de
/// passe quand même**, et l'annonce n'aurait servi qu'à se donner bonne
/// conscience.
#[test]
fn c_est_ici_que_le_mot_de_passe_en_clair_est_refuse() {
    let mut session = nouvelle(false);
    let (refus, _) = dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    assert!(
        refus.starts_with("a001 NO [PRIVACYREQUIRED] Encryption required before LOGIN"),
        "{refus}"
    );
    assert_eq!(session.state(), State::NotAuthenticated);

    // `AUTHENTICATE PLAIN` fait la même chose en base64, qui n'est pas un
    // chiffrement : même refus.
    let (refus, _) = dire(&mut session, b"a002 AUTHENTICATE PLAIN\r\n");
    assert!(
        refus.starts_with("a002 NO [PRIVACYREQUIRED] Encryption required before AUTHENTICATE"),
        "{refus}"
    );
}

#[test]
fn un_login_juste_authentifie() {
    let mut session = nouvelle(true);
    let (reponse, action) = dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    assert!(reponse.starts_with("a001 OK Authenticated"), "{reponse}");
    assert_eq!(action, Action::Continue);
    assert_eq!(session.state(), State::Authenticated);
    assert_eq!(session.user(), b"jean");
}

/// Les trois écritures d'un argument valent la même chose.
#[test]
fn un_login_se_lit_sous_ses_trois_ecritures() {
    for commande in [
        &b"a001 LOGIN jean ouvre-toi\r\n"[..],
        b"a001 LOGIN \"jean\" \"ouvre-toi\"\r\n",
        b"a001 LOGIN {4+}\r\njean {9+}\r\nouvre-toi\r\n",
    ] {
        let mut session = nouvelle(true);
        let (reponse, _) = dire(&mut session, commande);
        assert!(
            reponse.contains("OK Authenticated"),
            "{commande:?} : {reponse}"
        );
    }
}

/// **Le refus ne dit pas ce qui a manqué** : « utilisateur inconnu » et « mot de
/// passe faux » sont deux réponses différentes, et cette différence est un
/// annuaire pour qui la mesure.
#[test]
fn un_login_faux_est_refuse_sans_rien_dire() {
    let mut sortie = [0_u8; 512];
    for commande in [
        &b"a001 LOGIN jean mauvais\r\n"[..],
        b"a001 LOGIN inconnu ouvre-toi\r\n",
    ] {
        let mut session = nouvelle(true);
        let tour = session.handle(commande, &mut sortie).expect("traitable");
        let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
        assert!(
            texte.starts_with("a001 NO [AUTHENTICATIONFAILED] Authentication credentials invalid"),
            "{texte}"
        );
        // Compté comme une faute : mille essais par minute, c'est ce qu'un
        // garde doit voir passer.
        assert!(tour.peer_fault(), "{commande:?}");
        assert_eq!(session.state(), State::NotAuthenticated);
    }
}

#[test]
fn un_login_mal_forme_est_une_faute_de_syntaxe() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a001 LOGIN jean\r\n"[..],
        b"a001 LOGIN\r\n",
        b"a001 LOGIN jean ouvre-toi de trop\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD LOGIN expects"),
            "{commande:?} : {texte}"
        );
    }
}

// ── SASL ────────────────────────────────────────────────────────────────────

#[test]
fn authenticate_plain_en_deux_temps() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    let tour = session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(tour.reply(), b"+ \r\n");
    assert_eq!(tour.action(), Action::ReadAuthResponse);

    // base64 de "\0jean\0ouvre-toi"
    let tour = session
        .on_auth_response(b"AGplYW4Ab3V2cmUtdG9p", &mut sortie)
        .expect("traitable");
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(texte.starts_with("a001 OK Authenticated"), "{texte}");
    assert_eq!(session.state(), State::Authenticated);
    assert_eq!(session.user(), b"jean");
}

/// RFC 4959 : la réponse initiale évite un aller-retour.
#[test]
fn authenticate_plain_avec_reponse_initiale() {
    let mut session = nouvelle(true);
    let (texte, action) = dire(
        &mut session,
        b"a001 AUTHENTICATE PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
    );
    assert!(texte.starts_with("a001 OK Authenticated"), "{texte}");
    assert_eq!(action, Action::Continue);
    assert_eq!(session.user(), b"jean");
}

/// **Un client qui se ravise n'est pas un client fautif** : le lui reprocher
/// gonflerait un compteur qui doit rester celui des vraies fautes.
#[test]
fn un_echange_annule_n_est_pas_une_faute_d_authentification() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    let tour = session
        .on_auth_response(b"*", &mut sortie)
        .expect("traitable");
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(
        texte.starts_with("a001 BAD Authentication cancelled"),
        "{texte}"
    );
    assert_eq!(session.state(), State::NotAuthenticated);
}

#[test]
fn une_reponse_sasl_hors_echange_est_refusee() {
    let mut sortie = [0_u8; 512];
    assert_eq!(
        nouvelle(true).on_auth_response(b"AGplYW4=", &mut sortie),
        Err(super::Error::NotInAuthExchange)
    );
}

#[test]
fn une_commande_pendant_un_echange_sasl_est_refusee() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(
        session.handle(b"a002 NOOP\r\n", &mut sortie),
        Err(super::Error::NotInCommandPhase)
    );
}

#[test]
fn un_mecanisme_inconnu_est_refuse_sans_etre_une_faute() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 AUTHENTICATE GSSAPI\r\n");
    assert!(
        texte.starts_with("a001 NO Unsupported authentication mechanism"),
        "{texte}"
    );
}

#[test]
fn un_authenticate_mal_forme_est_une_faute() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a001 AUTHENTICATE\r\n"[..],
        b"a001 AUTHENTICATE PLAIN aaa bbb\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains("BAD AUTHENTICATE"), "{commande:?} : {texte}");
    }
}

#[test]
fn une_reponse_sasl_illisible_est_refusee() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    let tour = session
        .on_auth_response(b"pas du base64 !", &mut sortie)
        .expect("traitable");
    assert!(tour.peer_fault());
    // Et une base64 correcte qui ne porte pas du `PLAIN`.
    let mut autre = nouvelle(true);
    autre
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut sortie)
        .expect("traitable");
    let tour = autre
        .on_auth_response(b"YWJj", &mut sortie)
        .expect("traitable");
    assert!(tour.peer_fault());
}

// ── LES ÉTATS ───────────────────────────────────────────────────────────────

/// **`SELECT` avant authentification est une commande parfaitement formée** :
/// c'est l'état qui la refuse, pas la grammaire.
#[test]
fn c_est_l_etat_qui_refuse_pas_la_grammaire() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 SELECT INBOX\r\n");
    assert!(
        texte.starts_with("a001 BAD Command is not allowed before authentication"),
        "{texte}"
    );

    let (texte, _) = dire(&mut session, b"a002 FETCH 1 BODY[]\r\n");
    assert!(
        texte.starts_with("a002 BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

/// Une fois authentifié, on ne se présente plus : ces deux-là ne valent que
/// dans l'état non authentifié (§6.2).
///
/// `STARTTLS` n'y figure pas, et c'est une conséquence : **on ne peut pas être
/// authentifié sans être chiffré**, donc une session authentifiée reçoit « TLS
/// is already active » avant qu'aucune question d'état ne se pose.
#[test]
fn les_commandes_de_presentation_ne_valent_plus_apres_authentification() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    assert_eq!(session.state(), State::Authenticated);
    for (commande, attendu) in [
        (
            &b"a003 LOGIN jean ouvre-toi\r\n"[..],
            "LOGIN is not allowed in this state",
        ),
        (
            b"a004 AUTHENTICATE PLAIN\r\n",
            "AUTHENTICATE is not allowed in this state",
        ),
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains(attendu), "{commande:?} : {texte}");
    }
}

/// Un identifiant plus long que ce qu'un compte peut porter ne correspond à
/// aucun compte : le refus est le même que pour un mot de passe faux, et il ne
/// dit pas davantage.
#[test]
fn des_identifiants_demesures_sont_refuses_comme_les_autres() {
    let mut session = nouvelle(true);
    let mut commande = std::vec::Vec::from(&b"a001 LOGIN "[..]);
    commande.resize(commande.len() + 200, b'x');
    commande.extend_from_slice(b" ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(texte.contains("NO [AUTHENTICATIONFAILED]"), "{texte}");

    // Et une réponse initiale SASL plus longue que ce qu'on décode.
    let mut commande = std::vec::Vec::from(&b"a002 AUTHENTICATE PLAIN "[..]);
    commande.resize(commande.len() + 2000, b'A');
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(texte.contains("NO [AUTHENTICATIONFAILED]"), "{texte}");
}

// ── LES BOÎTES ──────────────────────────────────────────────────────────────

/// Ouvre une session authentifiée avec `INBOX` sélectionnée.
fn selectionnee() -> Session<UnCompte, Boites> {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT INBOX\r\n");
    session
}

/// **Un client qui ne reçoit pas `UIDVALIDITY` ne peut pas savoir si les UID
/// qu'il a retenus valent encore**, et resynchronise tout.
#[test]
fn select_dit_tout_ce_que_le_client_ne_sait_pas() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, action) = dire(&mut session, b"a002 SELECT INBOX\r\n");
    for ligne in [
        "* 3 EXISTS\r\n",
        "* OK [UIDVALIDITY 42] UIDVALIDITY\r\n",
        "* OK [UIDNEXT 31] UIDNEXT\r\n",
        "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \
         $MDNSent $Forwarded $Junk $NonJunk $Phishing)\r\n",
        "* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \
         $MDNSent $Forwarded $Junk $NonJunk $Phishing)] Flags permitted\r\n",
        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n",
        "a002 OK [READ-WRITE] SELECT completed\r\n",
    ] {
        assert!(texte.contains(ligne), "{ligne:?} manque dans :\n{texte}");
    }
    assert_eq!(action, Action::Continue);
    assert_eq!(session.state(), State::Selected);
    assert_eq!(session.selected(), b"INBOX");
}

/// **`PERMANENTFLAGS` dit ce qui SURVIT à la session.** En lecture seule, rien
/// ne survit — et le dire évite qu'un client croie avoir marqué un message.
#[test]
fn examine_ouvre_en_lecture_seule_et_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 EXAMINE INBOX\r\n");
    assert!(
        texte.contains("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n"),
        "{texte}"
    );
    assert!(
        texte.contains("a002 OK [READ-ONLY] EXAMINE completed\r\n"),
        "{texte}"
    );
    assert_eq!(session.state(), State::Selected);
}

/// **`[READ-WRITE]` est une promesse, et c'est la boîte qui la tient.** Un
/// magasin qui ne sait rien écrire ferait mentir `SELECT` : le client
/// n'apprendrait qu'en essayant que rien ne se modifie.
#[test]
fn une_boite_qui_ne_se_modifie_pas_est_annoncee_en_lecture_seule() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SELECT Archives\r\n");
    assert!(
        texte.contains("a002 OK [READ-ONLY] SELECT completed\r\n"),
        "{texte}"
    );
    assert!(
        texte.contains("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n"),
        "{texte}"
    );
    assert_eq!(session.state(), State::Selected);
}

/// **§6.3.2 : un `SELECT` qui échoue FERME la boîte précédente.** Le client se
/// retrouve authentifié sans sélection, et il doit le savoir — `[CLOSED]`
/// compris, puisque la boîte a bel et bien été fermée.
#[test]
fn un_select_qui_echoue_ferme_la_boite_precedente() {
    let mut session = selectionnee();
    assert_eq!(session.state(), State::Selected);
    let (texte, _) = dire(&mut session, b"a003 SELECT Inconnue\r\n");
    assert_eq!(
        texte,
        "* OK [CLOSED] Previous mailbox is now closed\r\n\
         a003 NO [NONEXISTENT] Mailbox does not exist\r\n"
    );
    assert_eq!(session.state(), State::Authenticated);
    assert!(session.selected().is_empty());

    // SANS BOÎTE OUVERTE, IL N'Y A RIEN À FERMER, et donc rien à dire.
    let (encore, _) = dire(&mut session, b"a004 SELECT Inconnue\r\n");
    assert_eq!(encore, "a004 NO [NONEXISTENT] Mailbox does not exist\r\n");
}

/// **`[CLOSED]` EST UNE FRONTIÈRE** (§7.1) : tout ce qui la précède parle de la
/// boîte fermée, tout ce qui la suit parle de la nouvelle.
#[test]
fn rouvrir_une_boite_dit_que_la_precedente_est_fermee() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 SELECT Archives\r\n");
    assert!(
        texte.starts_with("* OK [CLOSED] Previous mailbox is now closed\r\n* 0 EXISTS"),
        "{texte}"
    );
    // `EXAMINE` la pose aussi.
    let (examine, _) = dire(&mut session, b"a004 EXAMINE INBOX\r\n");
    assert!(
        examine.starts_with("* OK [CLOSED] Previous mailbox is now closed\r\n"),
        "{examine}"
    );

    // LA PREMIÈRE SÉLECTION N'EN PORTE PAS : il n'y avait rien à fermer.
    let mut neuve = nouvelle(true);
    dire(&mut neuve, b"a001 LOGIN jean ouvre-toi\r\n");
    let (premiere, _) = dire(&mut neuve, b"a002 SELECT INBOX\r\n");
    assert!(!premiere.contains("[CLOSED]"), "{premiere}");

    // ET APRÈS UN `CLOSE`, NON PLUS : §7.1 dit qu'il n'y a pas lieu de la
    // rendre quand la commande ferme sans rien ouvrir.
    dire(&mut neuve, b"a003 CLOSE\r\n");
    let (apres, _) = dire(&mut neuve, b"a004 SELECT INBOX\r\n");
    assert!(!apres.contains("[CLOSED]"), "{apres}");
}

#[test]
fn close_et_unselect_referment_la_boite() {
    for (commande, conclusion) in [
        (&b"a003 CLOSE\r\n"[..], "a003 OK CLOSE completed"),
        (b"a003 UNSELECT\r\n", "a003 OK UNSELECT completed"),
    ] {
        let mut session = selectionnee();
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.starts_with(conclusion), "{texte}");
        assert_eq!(session.state(), State::Authenticated);
        assert!(session.selected().is_empty());
    }
}

/// **`*` traverse la hiérarchie ; `%` s'arrête au séparateur** (§6.3.9). Les
/// confondre ferait rendre à `%` les boîtes d'un sous-dossier.
#[test]
fn les_deux_jokers_de_list_ne_disent_pas_la_meme_chose() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (tout, _) = dire(&mut session, b"a002 LIST \"\" *\r\n");
    assert!(
        tout.contains("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n"),
        "{tout}"
    );
    assert!(
        tout.contains("* LIST (\\HasChildren) \"/\" \"Archives\"\r\n"),
        "{tout}"
    );
    assert!(
        tout.contains("* LIST (\\HasNoChildren) \"/\" \"Archives/2026\"\r\n"),
        "{tout}"
    );

    let (plat, _) = dire(&mut session, b"a003 LIST \"\" %\r\n");
    assert!(plat.contains("\"/\" \"INBOX\"\r\n"), "{plat}");
    assert!(plat.contains("\"/\" \"Archives\"\r\n"), "{plat}");
    assert!(
        !plat.contains("Archives/2026"),
        "`%` ne traverse pas le séparateur :\n{plat}"
    );

    // Un motif littéral ne rend que ce qu'il nomme.
    let (une, _) = dire(&mut session, b"a004 LIST \"\" INBOX\r\n");
    assert_eq!(une.matches("* LIST").count(), 1, "{une}");
    // Et un motif qui ne correspond à rien ne rend rien.
    let (aucune, _) = dire(&mut session, b"a005 LIST \"\" Rien*\r\n");
    assert!(!aucune.contains("* LIST"), "{aucune}");
    assert!(aucune.contains("a005 OK LIST completed"), "{aucune}");
}

/// Les sous-dossiers s'ouvrent aussi, et un message de rang zéro n'existe pas.
#[test]
fn les_bords_de_la_boite_d_epreuve_se_visitent() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SELECT Archives/2026\r\n");
    assert!(texte.contains("* 0 EXISTS"), "{texte}");
    // Le rang zéro n'est pas un message : l'ensemble le refuse avant d'y
    // toucher, et la boîte le refuserait aussi.
    let (texte, _) = dire(&mut session, b"a003 FETCH 0 UID\r\n");
    assert!(texte.contains("BAD FETCH"), "{texte}");
}

#[test]
fn status_dit_ce_qu_une_boite_contient_sans_l_ouvrir() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(
        &mut session,
        b"a002 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY)\r\n",
    );
    assert!(
        texte.contains("* STATUS \"INBOX\" (MESSAGES 3 UIDNEXT 31 UIDVALIDITY 42)\r\n"),
        "{texte}"
    );
    assert!(texte.contains("a002 OK STATUS completed"), "{texte}");
    // La session n'a pas été sélectionnée pour autant.
    assert_eq!(session.state(), State::Authenticated);

    let (absente, _) = dire(&mut session, b"a003 STATUS Inconnue (MESSAGES)\r\n");
    assert!(absente.starts_with("a003 NO [NONEXISTENT]"), "{absente}");
}

/// **`STATUS` sur la boîte SÉLECTIONNÉE répond, et sans la rouvrir.** §6.3.11 le
/// déconseille au client, mais le client le fait — et un magasin qui verrouille
/// se heurterait à son propre verrou, pour nier une boîte qu'il tient ouverte.
#[test]
fn status_repond_aussi_de_la_boite_ouverte() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT INBOX\r\n");
    let (texte, _) = dire(
        &mut session,
        b"a003 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY)\r\n",
    );
    assert!(
        texte.contains("* STATUS \"INBOX\" (MESSAGES 3 UIDNEXT 31 UIDVALIDITY 42)\r\n"),
        "{texte}"
    );
    // Et la sélection n'a pas bougé.
    assert_eq!(session.state(), State::Selected);
    assert_eq!(session.selected(), b"INBOX");

    // Une AUTRE boîte, elle, s'ouvre pour la question.
    let (autre, _) = dire(
        &mut session,
        b"a004 STATUS Archives (MESSAGES UIDNEXT UIDVALIDITY)\r\n",
    );
    assert!(
        autre.contains("* STATUS \"Archives\" (MESSAGES 0 UIDNEXT 1 UIDVALIDITY 42)\r\n"),
        "{autre}"
    );
    assert_eq!(session.selected(), b"INBOX");
}

/// **Les octets d'un message traversent la session sans y séjourner.** C'est la
/// boucle qui les écrit sur le fil ; la session ne fait que les emprunter à la
/// boîte ouverte, et n'en garde rien.
#[test]
fn la_session_lit_par_la_boite_ouverte() {
    let mut session = nouvelle(true);
    let mut tampon = [0_u8; 8];

    // Sans boîte ouverte, il n'y a rien à lire.
    assert_eq!(session.read_selected(1, 0, &mut tampon), 0);
    assert_eq!(session.read_envelope(1, 0, &mut tampon), 0);
    assert_eq!(session.read_body_structure(1, 0, &mut tampon), 0);

    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT INBOX\r\n");
    assert_eq!(session.read_selected(1, 0, &mut tampon), 8);
    // La boîte d'épreuve rend le rang du message, répété.
    assert_eq!(&tampon, b"11111111");
    // Un rang qui n'existe pas ne rend rien.
    assert_eq!(session.read_selected(99, 0, &mut tampon), 0);
    // Les deux analyses se lisent par le même chemin.
    assert!(session.read_envelope(1, 0, &mut tampon) > 0);
    assert_eq!(session.read_envelope(99, 0, &mut tampon), 0);
    assert!(session.read_body_structure(1, 0, &mut tampon) > 0);
    assert_eq!(session.read_body_structure(99, 0, &mut tampon), 0);
}

#[test]
fn les_commandes_de_boite_mal_formees_sont_des_fautes() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for (commande, attendu) in [
        (&b"a002 SELECT\r\n"[..], "SELECT expects"),
        (b"a003 STATUS\r\n", "STATUS expects"),
        (b"a004 LIST \"\"\r\n", "LIST arguments are not well formed"),
        (b"a005 LIST a b c\r\n", "LIST arguments are not well formed"),
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains(attendu), "{commande:?} : {texte}");
    }
    // UN ESPACE EST ADMIS — « Sent Messages » est un nom ordinaire —, et la
    // réponse cite le nom. Ce qui est refusé, c'est ce qui casserait la réponse.
    let (espace, _) = dire(&mut session, b"a006 SELECT \"a b\"\r\n");
    assert!(espace.contains("NO [NONEXISTENT]"), "{espace}");
    let (guillemet, _) = dire(&mut session, b"a006 SELECT \"a\\\"b\"\r\n");
    assert!(guillemet.contains("SELECT expects"), "{guillemet}");
    // Un argument que la grammaire n'a pas su lire.
    let (texte, _) = dire(&mut session, b"a007 SELECT \"sans fin\r\n");
    assert!(texte.contains("SELECT expects"), "{texte}");
    // Un nom plus long que ce que la session retient.
    let mut trop = std::vec::Vec::from(&b"a008 SELECT "[..]);
    trop.resize(trop.len() + 300, b'x');
    trop.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &trop);
    assert!(texte.contains("SELECT expects"), "{texte}");
}

/// Les commandes de boîte demandent d'être authentifié.
#[test]
fn les_commandes_de_boite_demandent_l_authentification() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a001 SELECT INBOX\r\n"[..],
        b"a002 LIST \"\" *\r\n",
        b"a003 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY)\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed before authentication"),
            "{commande:?} : {texte}"
        );
    }
    // Et celles qui demandent une boîte ouverte le disent.
    dire(&mut session, b"a004 LOGIN jean ouvre-toi\r\n");
    for commande in [
        &b"a005 CLOSE\r\n"[..],
        b"a006 FETCH 1 UID\r\n",
        b"a007 UID FETCH 1 UID\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed unless a mailbox is selected"),
            "{commande:?} : {texte}"
        );
    }
}

/// Les commandes valables partout le sont vraiment partout.
#[test]
fn les_commandes_de_tous_les_etats_passent_partout() {
    for chiffree in [false, true] {
        let mut session = nouvelle(chiffree);
        let (texte, action) = dire(&mut session, b"a001 NOOP\r\n");
        assert!(texte.starts_with("a001 OK NOOP completed"), "{texte}");
        assert_eq!(action, Action::Continue);
        let (texte, _) = dire(&mut session, b"a002 CAPABILITY\r\n");
        assert!(texte.contains("* CAPABILITY IMAP4rev2"), "{texte}");
    }
}

#[test]
fn logout_dit_adieu_puis_conclut() {
    let mut session = nouvelle(true);
    let (texte, action) = dire(&mut session, b"a001 LOGOUT\r\n");
    assert_eq!(
        texte,
        "* BYE IMAP4rev2 server logging out\r\na001 OK LOGOUT completed\r\n"
    );
    assert_eq!(action, Action::Close);
    assert_eq!(session.state(), State::Logout);

    let mut sortie = [0_u8; 512];
    assert_eq!(
        session.handle(b"a002 NOOP\r\n", &mut sortie),
        Err(super::Error::SessionClosed)
    );
}

/// Reconnus, mais pas servis : la différence entre un client qui se rabat et un
/// client qui abandonne.
#[test]
fn les_verbes_retires_par_rev2_sont_refuses_en_le_disant() {
    let mut session = nouvelle(true);
    for commande in [&b"a001 LSUB \"\" *\r\n"[..], b"a002 CHECK\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command removed in IMAP4rev2"),
            "{commande:?} : {texte}"
        );
    }
}

// ── CE QU'ON N'A PAS SU LIRE ────────────────────────────────────────────────

/// **Si le tag est irrecevable, il n'y a rien à désigner** — et le recopier pour
/// le dire serait précisément l'injection que sa validation ferme.
#[test]
fn un_tag_illisible_fait_repondre_sans_tag() {
    let mut session = nouvelle(true);
    for commande in [
        &b"a*1 NOOP\r\n"[..],
        b"+ NOOP\r\n",
        b" NOOP\r\n",
        b"a001\r\nb\r\n NOOP\r\n",
    ] {
        let mut sortie = [0_u8; 512];
        let tour = session.handle(commande, &mut sortie).expect("traitable");
        let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
        assert!(
            texte.starts_with("* BAD Malformed tag"),
            "{commande:?} : {texte}"
        );
        assert!(tour.peer_fault());
    }
}

#[test]
fn un_verbe_inconnu_se_dit_avec_le_tag() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 XYZZY\r\n");
    assert!(texte.starts_with("a001 BAD Unknown command"), "{texte}");
    let (texte, _) = dire(&mut session, b"a002\r\n");
    assert!(texte.starts_with("a002 BAD Missing command"), "{texte}");
    // Un tag trop long est une faute de lecture comme une autre.
    let mut long = std::vec::Vec::from(&b"a"[..]);
    long.resize(TAG_MAX_OCTETS + 1, b'a');
    long.extend_from_slice(b" NOOP\r\n");
    let (texte, _) = dire(&mut session, &long);
    assert!(texte.starts_with("* BAD Malformed tag"), "{texte}");
}

// ── LE RESTE ────────────────────────────────────────────────────────────────

/// **`BYE` est la seule réponse qu'un serveur puisse émettre sans qu'une
/// commande l'ait demandée** (§7.1.5), et c'est exactement le cas quand le garde
/// écarte un pair.
#[test]
fn l_indisponibilite_se_dit_sans_tag() {
    let mut sortie = [0_u8; 128];
    assert_eq!(
        nouvelle(false)
            .unavailable(&mut sortie)
            .expect("composable"),
        b"* BYE [UNAVAILABLE] Service temporarily unavailable\r\n"
    );
}

/// **On ne sait plus où la commande se termine** : reprendre la lecture
/// laisserait le client choisir ce qu'on lira comme une commande.
#[test]
fn une_commande_indecodable_se_dit_avant_de_raccrocher() {
    let mut sortie = [0_u8; 128];
    assert_eq!(
        nouvelle(false)
            .cannot_parse(&mut sortie)
            .expect("composable"),
        b"* BAD Command could not be parsed; closing connection\r\n"
    );
    // Les deux ont aussi besoin de place.
    let mut court = [0_u8; 4];
    let session = nouvelle(false);
    assert!(session.unavailable(&mut court).is_err());
    assert!(session.cannot_parse(&mut court).is_err());
}

#[test]
fn la_demande_de_continuation_s_ecrit() {
    let mut sortie = [0_u8; 64];
    assert_eq!(
        nouvelle(false)
            .literal_continuation(&mut sortie)
            .expect("composable"),
        b"+ ready for literal\r\n"
    );
}

/// Le genre d'une issue, en TOTAL : chaque variante a son bras, et chacun est
/// emprunté par un test. Un `matches!` dans une assertion laisserait au
/// contraire un bras que rien n'atteint jamais, puisque l'assertion réussit — un
/// trou de couverture né du test lui-même.
fn genre(issue: &Result<super::Turn<'_>, super::Error>) -> &'static str {
    match issue {
        Ok(_) => "réponse",
        Err(super::Error::Reply(_)) => "tampon",
        Err(super::Error::NotInCommandPhase) => "hors phase",
        Err(super::Error::SessionClosed) => "close",
        Err(super::Error::NotInAuthExchange) => "hors échange",
    }
}

/// **Le tampon peut céder n'importe où**, et une réponse à moitié écrite ne
/// vaut rien : on essaie donc TOUTES les tailles, pour chaque forme de réponse.
/// Certaines en écrivent deux lignes, d'autres composent une liste, d'autres
/// encore répondent sans tag — et chacune a ses propres endroits où manquer.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    /// Conduit la session jusqu'à la commande, puis la rejoue en tampon borné.
    fn court(avant: &[&[u8]], commande: &'static [u8], chiffree: bool) {
        let mut assez = [0_u8; 1024];
        let mut reference = nouvelle(chiffree);
        for prealable in avant {
            reference.handle(prealable, &mut assez).expect("traitable");
        }
        let entier = reference
            .handle(commande, &mut assez)
            .expect("traitable")
            .reply()
            .len();
        for taille in 0..entier {
            let mut session = nouvelle(chiffree);
            let mut grand = [0_u8; 1024];
            for prealable in avant {
                session.handle(prealable, &mut grand).expect("traitable");
            }
            let mut petit = std::vec![0_u8; taille];
            let issue = session.handle(commande, &mut petit);
            assert_eq!(genre(&issue), "tampon", "{commande:?} taille {taille}");
        }
    }

    court(&[], b"a001 NOOP\r\n", true);
    court(&[], b"a001 CAPABILITY\r\n", true);
    court(&[], b"a001 CAPABILITY\r\n", false);
    court(&[], b"a001 LOGOUT\r\n", true);
    court(&[], b"a001 STARTTLS\r\n", false);
    court(&[], b"a001 STARTTLS\r\n", true);
    court(&[], b"a001 LOGIN jean ouvre-toi\r\n", true);
    court(&[], b"a001 LOGIN jean ouvre-toi\r\n", false);
    court(&[], b"a001 LOGIN jean mauvais\r\n", true);
    court(&[], b"a001 LOGIN jean\r\n", true);
    court(&[], b"a001 AUTHENTICATE PLAIN\r\n", true);
    court(
        &[],
        b"a001 AUTHENTICATE PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
        true,
    );
    court(&[], b"a001 AUTHENTICATE GSSAPI\r\n", true);
    court(&[], b"a001 AUTHENTICATE\r\n", true);
    court(&[], b"a001 SELECT INBOX\r\n", true);
    court(&[], b"a001 FETCH 1 BODY[]\r\n", true);
    court(&[], b"a001 LSUB \"\" *\r\n", true);
    court(&[], b"a001 XYZZY\r\n", true);
    court(&[], b"a*1 NOOP\r\n", true);
    court(
        &[b"a000 LOGIN jean ouvre-toi\r\n"],
        b"a001 SELECT INBOX\r\n",
        true,
    );
    // Les commandes de boîte écrivent plusieurs lignes, et chacune peut manquer
    // de place à un endroit différent.
    const APRES_LOGIN: &[&[u8]] = &[b"a000 LOGIN jean ouvre-toi\r\n"];
    const APRES_SELECT: &[&[u8]] = &[b"a000 LOGIN jean ouvre-toi\r\n", b"a000 SELECT INBOX\r\n"];
    court(APRES_LOGIN, b"a001 IDLE\r\n", true);
    court(APRES_LOGIN, b"a001 EXAMINE INBOX\r\n", true);
    court(APRES_LOGIN, b"a001 SELECT Inconnue\r\n", true);
    court(APRES_LOGIN, b"a001 SELECT\r\n", true);
    court(APRES_LOGIN, b"a001 LIST \"\" *\r\n", true);
    court(
        APRES_LOGIN,
        b"a001 LIST \"\" INBOX RETURN (STATUS (MESSAGES UNSEEN))\r\n",
        true,
    );
    court(
        APRES_LOGIN,
        b"a001 STATUS INBOX (MESSAGES UNSEEN)\r\n",
        true,
    );
    // Une re-sélection écrit `[CLOSED]` avant tout le reste, qu'elle
    // aboutisse ou non.
    court(APRES_SELECT, b"a001 SELECT Archives\r\n", true);
    court(APRES_SELECT, b"a001 SELECT Inconnue\r\n", true);
    court(APRES_SELECT, b"a001 UID FETCH 20 FLAGS\r\n", true);
    court(APRES_LOGIN, b"a001 LIST \"\" \"\"\r\n", true);
    const APRES_ABONNEMENT: &[&[u8]] = &[
        b"a000 LOGIN jean ouvre-toi\r\n",
        b"a000 SUBSCRIBE Archives\r\n",
    ];
    court(
        APRES_ABONNEMENT,
        b"a001 LIST \"\" * RETURN (SUBSCRIBED)\r\n",
        true,
    );
    const APRES_ORPHELIN: &[&[u8]] = &[
        b"a000 LOGIN jean ouvre-toi\r\n",
        b"a000 CREATE Passagere\r\n",
        b"a000 SUBSCRIBE Passagere\r\n",
        b"a000 DELETE Passagere\r\n",
    ];
    court(APRES_ORPHELIN, b"a001 LIST (SUBSCRIBED) \"\" *\r\n", true);
    // RFC 6154 : une ligne qui porte des USAGES est plus longue, et le tampon
    // peut donc céder à un endroit de plus — entre les attributs et le nom.
    court(
        &[
            b"a000 LOGIN jean ouvre-toi\r\n",
            b"a000 CREATE Brouillons (USE (\\Drafts))\r\n",
        ],
        b"a001 LIST \"\" *\r\n",
        true,
    );
    court(
        &[
            b"a000 LOGIN jean ouvre-toi\r\n",
            b"a000 CREATE Brouillons (USE (\\Drafts))\r\n",
        ],
        b"a001 LIST (SPECIAL-USE) \"\" *\r\n",
        true,
    );
    court(APRES_LOGIN, b"a001 LIST \"\"\r\n", true);
    court(APRES_LOGIN, b"a001 STATUS INBOX (MESSAGES)\r\n", true);
    court(APRES_LOGIN, b"a001 STATUS Inconnue (MESSAGES)\r\n", true);
    court(APRES_LOGIN, b"a001 CREATE test\r\n", true);
    court(APRES_SELECT, b"a001 CLOSE\r\n", true);
    court(APRES_SELECT, b"a001 FETCH 1 UID\r\n", true);
    court(APRES_SELECT, b"a001 UID FETCH 1 UID\r\n", true);
    court(APRES_SELECT, b"a001 UID STORE 1 (\\Seen)\r\n", true);
    court(APRES_SELECT, b"a001 FETCH 1 ENVELOPE\r\n", true);
    court(
        APRES_SELECT,
        b"a001 FETCH 1 (BODY[] BODY[HEADER])\r\n",
        true,
    );
    court(APRES_SELECT, b"a001 EXPUNGE\r\n", true);

    // Les deux écritures qui ne passent pas par `handle`.
    let session = nouvelle(false);
    let mut assez = [0_u8; 256];
    let banniere = session.greeting(&mut assez).expect("composable").len();
    for taille in 0..banniere {
        let mut petit = std::vec![0_u8; taille];
        assert!(session.greeting(&mut petit).is_err(), "taille {taille}");
    }
    let continuation = session
        .literal_continuation(&mut assez)
        .expect("composable")
        .len();
    for taille in 0..continuation {
        let mut petit = std::vec![0_u8; taille];
        assert!(
            session.literal_continuation(&mut petit).is_err(),
            "taille {taille}"
        );
    }

    // Et la réponse à un défi SASL.
    let mut session = nouvelle(true);
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut assez)
        .expect("traitable");
    let mut petit = [0_u8; 4];
    assert_eq!(
        genre(&session.on_auth_response(b"AGplYW4Ab3V2cmUtdG9p", &mut petit)),
        "tampon"
    );
    let mut session = nouvelle(true);
    session
        .handle(b"a001 AUTHENTICATE PLAIN\r\n", &mut assez)
        .expect("traitable");
    assert_eq!(genre(&session.on_auth_response(b"*", &mut petit)), "tampon");
}

/// Le genre d'une issue d'émission, en TOTAL — chaque bras est emprunté.
fn genre_d_emission(issue: &Result<Option<super::FetchChunk<'_>>, super::Error>) -> &'static str {
    match issue {
        Ok(None) => "fini",
        Ok(Some(super::FetchChunk::Bytes(_))) => "octets",
        Ok(Some(super::FetchChunk::Message { .. })) => "message",
        Err(super::Error::Reply(_)) => "tampon",
        Err(_) => "autre",
    }
}

/// **Le tampon peut céder pendant l'émission aussi**, et une réponse `FETCH` à
/// moitié écrite désynchroniserait le client tout autant.
///
/// On conduit l'émission jusqu'au morceau `k` avec un grand tampon, puis on
/// offre au morceau `k` toutes les tailles jusqu'à la sienne : sans cela, la
/// première faute masquerait tous les morceaux suivants.
#[test]
fn un_tampon_trop_court_pendant_l_emission_le_dit() {
    // Certaines émissions demandent qu'on ait d'abord marqué : un `EXPUNGE` sur
    // une boîte où rien n'est marqué n'écrit que sa conclusion.
    fn prete(preambule: &[u8]) -> Session<UnCompte, Boites> {
        let mut session = selectionnee();
        if !preambule.is_empty() {
            ecouler(&mut session, preambule);
        }
        session
    }

    for (preambule, commande) in [
        // Le deuxième message porte un drapeau : sans lui, `FLAGS ()` n'écrit
        // rien, et la place ne peut pas manquer là où il faut l'éprouver.
        (
            &b""[..],
            &b"a003 FETCH 2 (UID FLAGS INTERNALDATE RFC822.SIZE)\r\n"[..],
        ),
        (b"", b"a003 FETCH 1 BODY[]\r\n"),
        (b"", b"a003 FETCH 1 BODY[HEADER]<2.3>\r\n"),
        (b"", b"a003 FETCH 1:2 (UID BODY.PEEK[TEXT])\r\n"),
        (
            b"a003 STORE 1:2 +FLAGS.SILENT (\\Deleted)\r\n",
            b"a004 EXPUNGE\r\n",
        ),
        // L'UID qu'un `UID FETCH` porte SANS QU'ON LE DEMANDE s'écrit en tête,
        // et la place peut manquer là aussi.
        (b"", b"a003 UID FETCH 20 FLAGS\r\n"),
        // Un `ESEARCH` qui porte des comptes : son en-tête est le plus long
        // morceau que ce serveur compose d'un seul geste.
        (b"", b"a003 SEARCH RETURN (MIN MAX COUNT) ALL\r\n"),
        (b"", b"a003 SEARCH RETURN (SAVE) ALL\r\n"),
    ] {
        // Combien de morceaux, et de quelle taille chacun.
        let mut assez = [0_u8; 2048];
        let mut reference = prete(preambule);
        reference.handle(commande, &mut assez).expect("traitable");
        let mut tailles = std::vec::Vec::new();
        while let Some(morceau) = reference.next_fetch(&mut assez).expect("émettable") {
            tailles.push(match morceau {
                super::FetchChunk::Bytes(octets) => octets.len(),
                super::FetchChunk::Message { .. } => 0,
            });
        }

        for (rang, longueur) in tailles.iter().enumerate() {
            for taille in 0..*longueur {
                let mut session = prete(preambule);
                session.handle(commande, &mut assez).expect("traitable");
                for _ in 0..rang {
                    session.next_fetch(&mut assez).expect("émettable");
                }
                let mut petit = std::vec![0_u8; taille];
                assert_eq!(
                    genre_d_emission(&session.next_fetch(&mut petit)),
                    "tampon",
                    "{commande:?} morceau {rang} taille {taille}"
                );
            }
        }
    }
}

/// Les trois autres genres d'issue, pour que chaque bras du classement soit
/// emprunté.
#[test]
fn chaque_genre_d_issue_se_produit() {
    let mut assez = [0_u8; 512];
    let mut session = nouvelle(true);
    assert_eq!(
        genre(&session.handle(b"a001 NOOP\r\n", &mut assez)),
        "réponse"
    );
    session
        .handle(b"a002 AUTHENTICATE PLAIN\r\n", &mut assez)
        .expect("traitable");
    assert_eq!(
        genre(&session.handle(b"a003 NOOP\r\n", &mut assez)),
        "hors phase"
    );
    let mut session = nouvelle(true);
    session
        .handle(b"a001 LOGOUT\r\n", &mut assez)
        .expect("traitable");
    assert_eq!(
        genre(&session.handle(b"a002 NOOP\r\n", &mut assez)),
        "close"
    );
    assert_eq!(
        genre(&nouvelle(true).on_auth_response(b"x", &mut assez)),
        "hors échange"
    );
}

#[test]
fn ce_qui_se_deroule_se_montre() {
    // La session, elle, ne s'affiche pas et ne se recopie pas : elle peut tenir
    // un dépôt en cours, c'est-à-dire un fichier ouvert.
    assert!(!std::format!("{:?}", State::Selected).is_empty());
    assert_eq!(State::Selected, State::Selected);
    assert_ne!(Action::Continue, Action::Close);
    for erreur in [
        super::Error::Reply(ams_proto_imap::Error::MissingTag),
        super::Error::NotInCommandPhase,
        super::Error::SessionClosed,
        super::Error::NotInAuthExchange,
    ] {
        assert!(std::format!("{erreur}").len() > 10, "{erreur:?}");
    }
}

// ── FETCH ───────────────────────────────────────────────────────────────────

/// Écoule un `FETCH` et rend ce que l'appelant écrirait sur le fil.
fn ecouler(session: &mut Session<UnCompte, Boites>, commande: &[u8]) -> std::string::String {
    let mut sortie = [0_u8; 2048];
    let tour = session.handle(commande, &mut sortie).expect("traitable");
    // LA RÉPONSE DU TOUR VIENT D'ABORD, comme la boucle l'écrit : un `MOVE` y
    // loge son `* OK [COPYUID …]`, que §6.4.8 veut AVANT les `EXPUNGE`. La
    // mettre à la fin ferait passer un ordre faux pour un ordre bon.
    let debut = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert_eq!(tour.action(), Action::SendFetch, "{debut}");
    let mut fil = debut;
    let mut morceaux = [0_u8; 2048];
    while let Some(morceau) = session.next_fetch(&mut morceaux).expect("émettable") {
        match morceau {
            super::FetchChunk::Bytes(octets) => {
                fil.push_str(&std::string::String::from_utf8_lossy(octets));
            }
            super::FetchChunk::Message {
                sequence,
                offset,
                length,
            } => {
                fil.push_str(&std::format!("<{sequence}:{offset}+{length}>"));
            }
        }
    }
    fil
}

/// Chaque bras du classement d'émission est emprunté par un cas réel.
#[test]
fn chaque_genre_d_emission_se_produit() {
    let mut session = selectionnee();
    let mut sortie = [0_u8; 2048];
    assert_eq!(genre_d_emission(&session.next_fetch(&mut sortie)), "fini");
    session
        .handle(b"a003 FETCH 1 BODY[]\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(genre_d_emission(&session.next_fetch(&mut sortie)), "octets");
    assert_eq!(
        genre_d_emission(&session.next_fetch(&mut sortie)),
        "message"
    );
    let mut court = [0_u8; 1];
    assert_eq!(genre_d_emission(&session.next_fetch(&mut court)), "tampon");
    // Un `next_fetch` hors émission ne rend rien, et ce n'est pas une faute.
    let mut vierge = nouvelle(true);
    assert_eq!(genre_d_emission(&vierge.next_fetch(&mut sortie)), "fini");
}

#[test]
fn un_fetch_sans_corps_tient_sur_une_ligne_par_message() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1:2 (UID FLAGS RFC822.SIZE)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (UID 10 FLAGS () RFC822.SIZE 100)\r\n\
         * 2 FETCH (UID 20 FLAGS (\\Seen) RFC822.SIZE 200)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

#[test]
fn la_date_d_arrivee_s_ecrit_a_la_facon_d_imap() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 INTERNALDATE\r\n");
    assert!(
        fil.contains("* 1 FETCH (INTERNALDATE \"29-Aug-2026 07:08:31 +0000\")\r\n"),
        "{fil}"
    );
}

/// **La session ne lit jamais un message** : elle rend un intervalle, et c'est
/// l'appelant qui l'écoule.
#[test]
fn un_corps_se_rend_en_intervalle_precede_de_sa_longueur() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BODY[]\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[] {100}\r\n<1:0+100>)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

/// Les trois sections désignent trois intervalles, et le découpage vient du
/// magasin.
#[test]
fn les_trois_sections_designent_trois_intervalles() {
    let mut session = selectionnee();
    // `header_octets` vaut deux cinquièmes de la taille : 40 pour le premier.
    assert!(
        ecouler(&mut session, b"a003 FETCH 1 BODY[HEADER]\r\n")
            .contains("BODY[HEADER] {40}\r\n<1:0+40>")
    );
    assert!(
        ecouler(&mut session, b"a004 FETCH 1 BODY[TEXT]\r\n")
            .contains("BODY[TEXT] {60}\r\n<1:40+60>")
    );
    assert!(
        ecouler(&mut session, b"a005 FETCH 1 BODY[]\r\n").contains("BODY[] {100}\r\n<1:0+100>")
    );
}

/// **C'est ici que le débordement s'arrête** : le décalage vient du réseau, la
/// taille du magasin, et les additionner sans précaution donnerait un intervalle
/// qui déborde du fichier.
#[test]
fn c_est_ici_que_la_demande_partielle_est_ramenee_dans_le_message() {
    let mut session = selectionnee();
    // Une tranche ordinaire.
    assert!(
        ecouler(&mut session, b"a003 FETCH 1 BODY[]<10.20>\r\n")
            .contains("BODY[]<10> {20}\r\n<1:10+20>"),
        "une tranche ordinaire"
    );
    // Une longueur qui dépasse la fin est ramenée à ce qui reste.
    assert!(
        ecouler(&mut session, b"a004 FETCH 1 BODY[]<90.1000>\r\n")
            .contains("BODY[]<90> {10}\r\n<1:90+10>"),
        "une longueur qui dépasse"
    );
    // Un décalage AU-DELÀ de la fin ne rend rien, et ne lit rien.
    let fil = ecouler(&mut session, b"a005 FETCH 1 BODY[]<4294967295.1>\r\n");
    assert!(fil.contains("BODY[]<4294967295> {0}\r\n<1:100+0>"), "{fil}");
    // Et dans une section, le décalage part du début de la SECTION.
    assert!(
        ecouler(&mut session, b"a006 FETCH 1 BODY[TEXT]<5.10>\r\n")
            .contains("BODY[TEXT]<5> {10}\r\n<1:45+10>"),
        "un décalage dans une section"
    );
}

/// **`PEEK` n'est pas une variante cosmétique** : sans lui, le message est
/// marqué comme lu, et les `FLAGS` de la même réponse doivent le dire.
#[test]
fn un_corps_sans_peek_marque_le_message_comme_lu() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (FLAGS BODY[])\r\n");
    assert!(fil.contains("FLAGS (\\Seen)"), "{fil}");

    // Avec `PEEK`, rien ne change.
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (FLAGS BODY.PEEK[])\r\n");
    assert!(fil.contains("FLAGS ()"), "{fil}");
}

/// **L'étoile ne veut pas dire la même chose dans les deux modes** : le plus
/// grand numéro de séquence, ou le plus grand UID.
#[test]
fn uid_fetch_designe_par_uid_et_rend_le_rang() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID FETCH 20:30 UID\r\n");
    assert_eq!(
        fil,
        "* 2 FETCH (UID 20)\r\n* 3 FETCH (UID 30)\r\n\
         a003 OK UID FETCH completed\r\n"
    );
    // `*` vaut le plus grand UID, pas le nombre de messages.
    let fil = ecouler(&mut session, b"a004 UID FETCH 25:* UID\r\n");
    assert_eq!(fil, "* 3 FETCH (UID 30)\r\na004 OK UID FETCH completed\r\n");
    // EN NUMÉROS DE SÉQUENCE, `25:*` DÉSIGNE LE DERNIER MESSAGE, et c'est la
    // RFC qui le veut : l'intervalle n'est pas ordonné (§9), donc `25:*` vaut
    // ici `3:25`, qui contient le troisième. Un serveur qui rendrait le vide
    // ferait perdre au client le message qu'il cherchait justement.
    let fil = ecouler(&mut session, b"a005 FETCH 25:* UID\r\n");
    assert_eq!(fil, "* 3 FETCH (UID 30)\r\na005 OK FETCH completed\r\n");
}

/// **`UID` porte un verbe, et pas n'importe lequel.** Un verbe inconnu se refuse
/// en le disant, plutôt que de laisser le client croire à une syntaxe fautive.
#[test]
fn un_uid_dont_le_verbe_est_inconnu_se_refuse_en_le_disant() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID CHERCHE 1\r\n");
    assert!(
        texte.contains("NO [CANNOT] This UID command is not served yet"),
        "{texte}"
    );
    // Et `UID` sans rien derrière ne trouve pas de verbe.
    let (nu, _) = dire(&mut session, b"a004 UID\r\n");
    assert!(nu.contains("NO [CANNOT]"), "{nu}");
}

/// **DEUX CORPS DANS UNE MÊME COMMANDE S'ÉCOULENT L'UN APRÈS L'AUTRE.** C'était
/// refusé tant que la session recommençait sa ligne à chaque morceau ; depuis
/// qu'elle compte les éléments déjà écrits, elle reprend où elle s'était
/// arrêtée, et deux intervalles de fichier se suivent sans se mêler.
#[test]
fn deux_corps_dans_un_fetch_s_ecoulent_l_un_apres_l_autre() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 (BODY.PEEK[] BODY.PEEK[HEADER])\r\n",
    );
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[] {100}\r\n<1:0+100> BODY[HEADER] {40}\r\n<1:0+40>)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

impl Boite {
    /// Compose le choix de champs d'un message d'épreuve.
    ///
    /// L'en-tête d'épreuve est le même pour tous : ce qu'on éprouve ici est le
    /// PLOMBAGE, et la sélection elle-même vit dans `ams-mime`, où elle est
    /// éprouvée.
    fn choisir(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        self.info(sequence)?;
        // UN MESSAGE DISPARU N'A PLUS D'EN-TÊTE, et donc plus de choix : c'est
        // ce que fait le vrai magasin quand le fichier ne se lit plus.
        if sequence == self.evanescent {
            return None;
        }
        // Une partie désignée : seule la première existe.
        if !matches!(path, [] | [1]) {
            return None;
        }
        // LA BOÎTE D'ÉPREUVE COMPOSE À LA MAIN, et n'appelle pas `ams-mime` :
        // la session ne connaît pas cette crate, et lui en donner une pour un
        // essai ferait entrer l'analyse d'un message là où il n'y a que des
        // décisions de protocole.
        const CHAMPS: [(&[u8], &[u8]); 2] = [
            (b"From", b"From: jean@x.test\r\n"),
            (b"Subject", b"Subject: sujet\r\n"),
        ];
        let mut ecrits = 0_usize;
        for (nom, ligne) in CHAMPS {
            let choisi = names
                .split(|octet| *octet == b' ')
                .any(|vu| vu.eq_ignore_ascii_case(nom));
            if choisi == except {
                continue;
            }
            let fin = ecrits.saturating_add(ligne.len());
            out.get_mut(ecrits..fin)?.copy_from_slice(ligne);
            ecrits = fin;
        }
        let fin = ecrits.saturating_add(2);
        out.get_mut(ecrits..fin)?.copy_from_slice(b"\r\n");
        Some(fin)
    }
}

/// Ce que la boîte d'épreuve rend pour un `BINARY`.
const BINAIRE: &[u8] = b"contenu decode";

/// Écoule un texte déjà composé, comme une vraie boîte le ferait.
fn ecouler_le_texte(texte: &[u8], offset: u64, out: &mut [u8]) -> usize {
    let reste = texte
        .get(usize::try_from(offset).unwrap_or(usize::MAX)..)
        .unwrap_or_default();
    let combien = reste.len().min(out.len());
    for (place, octet) in out.iter_mut().zip(reste.get(..combien).unwrap_or_default()) {
        *place = *octet;
    }
    combien
}

#[test]
fn un_element_reconnu_mais_non_servi_se_dit_sans_accuser_le_client() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 FETCH 1 RFC822\r\n");
    assert!(
        texte.contains("NO [CANNOT] This FETCH item is not served yet"),
        "{texte}"
    );
}

// ── `ENVELOPE` ──────────────────────────────────────────────────────────────

/// **L'enveloppe s'écoule**, comme un corps : sa longueur est choisie par celui
/// qui a écrit le message, et la faire tenir dans un tampon reviendrait à
/// décider d'avance combien de destinataires un message a le droit d'avoir.
#[test]
fn l_enveloppe_s_ecoule_dans_la_reponse() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 ENVELOPE\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (ENVELOPE (NIL NIL ((NIL NIL \"m10\" \"x.test\")) \
         NIL NIL NIL NIL NIL NIL NIL))\r\na003 OK FETCH completed\r\n"
    );
}

/// **L'enveloppe se découpe sans changer de résultat**, comme la ligne d'un
/// `ESEARCH` : elle s'écoule, et le découpage est une affaire de tampon, pas de
/// contenu. Le morceau qui l'ANNONCE, lui, s'écrit d'un seul geste : un tampon
/// trop court pour lui le dit.
#[test]
fn l_enveloppe_se_decoupe_sans_changer_de_resultat() {
    let attendu = "* 1 FETCH (ENVELOPE (NIL NIL ((NIL NIL \"m10\" \"x.test\")) \
                   NIL NIL NIL NIL NIL NIL NIL))\r\na003 OK FETCH completed\r\n";
    let mut reference = selectionnee();
    assert_eq!(
        ecouler(&mut reference, b"a003 FETCH 1 ENVELOPE\r\n"),
        attendu
    );

    for taille in 1..=48_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(b"a003 FETCH 1 ENVELOPE\r\n", &mut grand)
            .expect("traitable");
        let mut fil = std::string::String::new();
        let mut petit = std::vec![0_u8; taille];
        let mut refuse = false;
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("une enveloppe n'est pas un corps")
                }
                Err(erreur) => {
                    assert!(
                        matches!(erreur, super::Error::Reply(_)),
                        "taille {taille} : {erreur:?}"
                    );
                    refuse = true;
                    break;
                }
            }
        }
        if !refuse {
            assert_eq!(fil, attendu, "taille {taille}");
        }
    }
}

/// **UN ÉLÉMENT QUI S'ÉCOULE N'EST PAS FORCÉMENT LE DERNIER.** Ce qui suit doit
/// venir APRÈS lui, sans quoi le client lirait les octets du message comme du
/// protocole.
#[test]
fn ce_qui_suit_un_element_ecoule_vient_apres_lui() {
    let mut session = selectionnee();
    let enveloppe = ecouler(&mut session, b"a003 FETCH 1 (ENVELOPE UID)\r\n");
    assert_eq!(
        enveloppe,
        "* 1 FETCH (ENVELOPE (NIL NIL ((NIL NIL \"m10\" \"x.test\")) \
         NIL NIL NIL NIL NIL NIL NIL) UID 10)\r\na003 OK FETCH completed\r\n"
    );
    // Un corps, de même : le `UID` vient après les octets qu'on a annoncés.
    let corps = ecouler(&mut session, b"a004 FETCH 1 (BODY.PEEK[] UID)\r\n");
    assert_eq!(
        corps,
        "* 1 FETCH (BODY[] {100}\r\n<1:0+100> UID 10)\r\na004 OK FETCH completed\r\n"
    );
}

// ── Les parties désignées ───────────────────────────────────────────────────

/// **Une partie désignée s'écoule comme un corps**, et la réponse ÉCHOIT la
/// section demandée : c'est ainsi que le client rattache la donnée à sa demande
/// quand il en a posé plusieurs.
#[test]
fn une_partie_designee_s_ecoule_comme_un_corps() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BODY.PEEK[1]\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[1] {90}\r\n<1:10+90>)\r\na003 OK FETCH completed\r\n"
    );
    let mime = ecouler(&mut session, b"a004 FETCH 1 BODY.PEEK[1.MIME]\r\n");
    assert_eq!(
        mime,
        "* 1 FETCH (BODY[1.MIME] {10}\r\n<1:0+10>)\r\na004 OK FETCH completed\r\n"
    );
}

/// UNE PARTIE QUI N'EXISTE PAS VAUT `NIL`, et non une erreur : §6.4.5 l'admet,
/// et un client qui demande une partie vue dans une structure devenue périmée ne
/// fait rien de mal. Faire échouer sa commande entière le punirait de rien.
#[test]
fn une_partie_absente_vaut_nil() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (BODY.PEEK[7] UID)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[7] NIL UID 10)\r\na003 OK FETCH completed\r\n"
    );
}

/// **La portée de la partie suivante se redemande.** Deux parties dans la même
/// commande n'ont pas le même intervalle ; continuer sans repasser par le
/// magasin rendrait à la seconde ce qu'on avait trouvé pour la première.
#[test]
fn deux_parties_de_suite_ne_se_confondent_pas() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 (BODY.PEEK[7] BODY.PEEK[1.MIME])\r\n",
    );
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[7] NIL BODY[1.MIME] {10}\r\n<1:0+10>)\r\na003 OK FETCH completed\r\n"
    );
}

/// **La réponse échoit le chemin tel qu'il a été écrit** : plusieurs niveaux, et
/// le mot-clef qui les ferme. Sans cela, un client qui a posé deux demandes ne
/// saurait pas laquelle on lui rend.
#[test]
fn la_reponse_echoit_le_chemin_demande() {
    let mut session = selectionnee();
    for (commande, attendu) in [
        (&b"a003 FETCH 1 BODY.PEEK[1.2]\r\n"[..], "BODY[1.2] NIL"),
        (
            b"a004 FETCH 1 BODY.PEEK[2.HEADER]\r\n",
            "BODY[2.HEADER] NIL",
        ),
        (
            b"a005 FETCH 1 BODY.PEEK[3.1.TEXT]\r\n",
            "BODY[3.1.TEXT] NIL",
        ),
    ] {
        let fil = ecouler(&mut session, commande);
        assert!(fil.contains(attendu), "{commande:?} : {fil}");
    }
}

/// Un tampon trop court pour écrire `NIL` le dit, au lieu d'écrire une réponse
/// à moitié.
#[test]
fn un_tampon_trop_court_pour_une_partie_absente_le_dit() {
    for taille in 1..=32_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(b"a003 FETCH 1 (BODY.PEEK[7.2] UID)\r\n", &mut grand)
            .expect("traitable");
        let mut petit = std::vec![0_u8; taille];
        let mut fil = std::string::String::new();
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("une partie absente n'écoule rien")
                }
                Err(erreur) => {
                    assert!(matches!(erreur, super::Error::Reply(_)), "{erreur:?}");
                    break;
                }
            }
        }
        assert!(!fil.contains("BODY[7.2] N\r\n"), "taille {taille} : {fil}");
    }
}

/// La demande partielle s'applique à une partie comme au message entier, et ne
/// sort pas de la partie.
#[test]
fn une_demande_partielle_ne_sort_pas_de_la_partie() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BODY.PEEK[1]<5.1000>\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[1]<5> {85}\r\n<1:15+85>)\r\na003 OK FETCH completed\r\n"
    );
}

// ── Le choix de champs ──────────────────────────────────────────────────────

/// **UN CHOIX DE CHAMPS S'ANNONCE ET S'ÉCOULE**, et la réponse ÉCHOIT les noms
/// tels que le client les a écrits : c'est à cela qu'il rattache la donnée à sa
/// demande.
#[test]
fn un_choix_de_champs_s_annonce_et_s_ecoule() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 BODY.PEEK[HEADER.FIELDS (From)]\r\n",
    );
    assert_eq!(
        fil,
        "* 1 FETCH (BODY[HEADER.FIELDS (From)] {21}\r\nFrom: jean@x.test\r\n\r\n)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

/// `.NOT` renverse le choix, et la réponse le dit.
#[test]
fn le_choix_se_renverse_et_la_reponse_le_dit() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT (From)]\r\n",
    );
    assert!(fil.contains("BODY[HEADER.FIELDS.NOT (From)] {18}"), "{fil}");
    assert!(fil.contains("Subject: sujet"), "{fil}");
    assert!(!fil.contains("From: jean"), "{fil}");
}

/// Un choix sur une PARTIE se demande par son chemin, et la réponse l'échoit.
#[test]
fn un_choix_sur_une_partie_s_echoit_avec_son_chemin() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 BODY.PEEK[1.HEADER.FIELDS (From)]\r\n",
    );
    assert!(fil.contains("BODY[1.HEADER.FIELDS (From)] {21}"), "{fil}");
    // Et une partie qui n'existe pas vaut `NIL`, comme partout ailleurs.
    let absente = ecouler(
        &mut session,
        b"a004 FETCH 1 BODY.PEEK[7.HEADER.FIELDS (From)]\r\n",
    );
    assert!(
        absente.contains("BODY[7.HEADER.FIELDS (From)] NIL"),
        "{absente}"
    );
}

/// **LES NOMS SUIVENT LEUR ÉLÉMENT, ET LUI SEUL.** Deux choix dans une même
/// commande n'ont pas la même liste ; les confondre rendrait au second ce que le
/// premier avait demandé.
#[test]
fn deux_choix_ne_se_confondent_pas() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 (BODY.PEEK[HEADER.FIELDS (From)] BODY.PEEK[HEADER.FIELDS (Subject)])\r\n",
    );
    assert!(
        fil.contains("BODY[HEADER.FIELDS (From)] {21}\r\nFrom: jean@x.test"),
        "{fil}"
    );
    assert!(
        fil.contains("BODY[HEADER.FIELDS (Subject)] {18}\r\nSubject: sujet"),
        "{fil}"
    );
}

/// Le choix se découpe sans changer de résultat.
#[test]
fn le_choix_se_decoupe_sans_changer_de_resultat() {
    let mut reference = selectionnee();
    let attendu = ecouler(
        &mut reference,
        b"a003 FETCH 1 BODY.PEEK[HEADER.FIELDS (From Subject)]\r\n",
    );
    for taille in 1..=72_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(
                b"a003 FETCH 1 BODY.PEEK[HEADER.FIELDS (From Subject)]\r\n",
                &mut grand,
            )
            .expect("traitable");
        let mut fil = std::string::String::new();
        let mut petit = std::vec![0_u8; taille];
        let mut refuse = false;
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("un choix de champs n'est pas un intervalle du message")
                }
                Err(erreur) => {
                    assert!(matches!(erreur, super::Error::Reply(_)), "{erreur:?}");
                    refuse = true;
                    break;
                }
            }
        }
        if !refuse {
            assert_eq!(fil, attendu, "taille {taille}");
        }
    }
}

/// Une demande partielle s'applique au choix comme au reste.
#[test]
fn une_demande_partielle_s_applique_au_choix() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 BODY.PEEK[HEADER.FIELDS (From)]<6.5>\r\n",
    );
    assert!(
        fil.contains("BODY[HEADER.FIELDS (From)]<6> {5}\r\njean@"),
        "{fil}"
    );
}

/// Un tampon trop court pour écrire un choix SUR UNE PARTIE le dit : le chemin,
/// le point qui le sépare du mot-clef, et la liste s'écrivent d'un seul geste.
#[test]
fn un_tampon_trop_court_pour_un_choix_de_partie_le_dit() {
    for taille in 1..=48_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(
                b"a003 FETCH 1 BODY.PEEK[1.HEADER.FIELDS (From)]\r\n",
                &mut grand,
            )
            .expect("traitable");
        let mut petit = std::vec![0_u8; taille];
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(_)) => {}
                Err(erreur) => {
                    assert!(matches!(erreur, super::Error::Reply(_)), "{erreur:?}");
                    break;
                }
            }
        }
    }
}

/// **UN MESSAGE QUI DISPARAÎT PENDANT L'ÉMISSION N'A PLUS DE CHOIX** : `NIL`,
/// comme pour toute section absente. Le refuser ferait échouer la commande
/// entière pour un message que le client n'aura de toute façon plus.
#[test]
fn un_choix_sur_un_message_disparu_vaut_nil() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 3 BODY.PEEK[HEADER.FIELDS (From)]\r\n",
    );
    assert!(fil.contains("BODY[HEADER.FIELDS (From)] NIL"), "{fil}");
}

/// **CE QU'ON ACCEPTE DOIT TENIR DANS CE QUI LE RETIENT.** Une commande dont les
/// listes de noms débordent la réserve se refuse, plutôt que de servir un choix
/// amputé de ses derniers noms.
#[test]
fn trop_de_noms_se_refuse_en_le_disant() {
    let mut commande = std::string::String::from("a003 FETCH 1 (");
    for _ in 0..8 {
        commande.push_str("BODY.PEEK[HEADER.FIELDS (");
        for rang in 0..10 {
            commande.push_str(&std::format!("X-Bourrage-Assez-Long-{rang} "));
        }
        commande.push_str("From)] ");
    }
    commande.push_str("UID)\r\n");
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, commande.as_bytes());
    assert!(
        texte.contains("NO [LIMIT] Too many header field names"),
        "{texte}"
    );
}

// ── `BINARY` ────────────────────────────────────────────────────────────────

/// **UN LITTÉRAL8, ET NON UN LITTÉRAL.** `BINARY` rend des octets quelconques,
/// `NUL` compris — ce qu'un littéral ordinaire n'a pas le droit de porter (§4.3).
#[test]
fn le_binaire_s_annonce_par_un_litteral8() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BINARY.PEEK[1]\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BINARY[1] ~{14}\r\ncontenu decode)\r\na003 OK FETCH completed\r\n"
    );
}

/// La taille est celle du contenu DÉCODÉ, et elle ne s'écoule pas.
#[test]
fn la_taille_binaire_est_celle_du_contenu_decode() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (BINARY.SIZE[1] UID)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BINARY.SIZE[1] 14 UID 10)\r\na003 OK FETCH completed\r\n"
    );
}

/// **LA DEMANDE PARTIELLE PORTE SUR LE CONTENU DÉCODÉ**, et l'on n'y saute donc
/// pas par un déplacement dans le fichier : il faut décoder ce qu'on jette.
#[test]
fn une_demande_partielle_binaire_porte_sur_le_decode() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BINARY.PEEK[1]<8.6>\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BINARY[1]<8> ~{6}\r\ndecode)\r\na003 OK FETCH completed\r\n"
    );
}

/// **UN ENCODAGE QUI RÉSISTE FAIT ÉCHOUER LA DEMANDE** (§6.4.5). C'est le seul
/// endroit d'IMAP où un `FETCH` échoue pour ce qu'un message PORTE : rendre les
/// octets encodés en les faisant passer pour le contenu tromperait le client
/// sans qu'il puisse s'en apercevoir.
#[test]
fn un_encodage_qui_resiste_fait_echouer_la_demande() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BINARY.PEEK[2]\r\n");
    assert!(fil.contains("BINARY[2] NIL"), "{fil}");
    assert!(
        fil.contains("a003 NO [UNKNOWN-CTE] Cannot decode this part's transfer encoding"),
        "{fil}"
    );
    // La taille aussi : elle rend zéro — la grammaire veut un nombre — et
    // conclut par le même refus.
    let taille = ecouler(&mut session, b"a004 FETCH 1 BINARY.SIZE[2]\r\n");
    assert!(taille.contains("BINARY.SIZE[2] 0"), "{taille}");
    assert!(taille.contains("a004 NO [UNKNOWN-CTE]"), "{taille}");
}

/// Une section absente vaut `NIL`, et ne fait échouer personne.
#[test]
fn une_section_binaire_absente_vaut_nil() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (BINARY.PEEK[7] UID)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BINARY[7] NIL UID 10)\r\na003 OK FETCH completed\r\n"
    );
    // Et sa taille vaut zéro, faute de pouvoir valoir `NIL`.
    let taille = ecouler(&mut session, b"a004 FETCH 1 BINARY.SIZE[7]\r\n");
    assert_eq!(
        taille,
        "* 1 FETCH (BINARY.SIZE[7] 0)\r\na004 OK FETCH completed\r\n"
    );
}

/// Le découpage ne change pas le résultat, ici non plus.
#[test]
fn le_binaire_se_decoupe_sans_changer_de_resultat() {
    let mut reference = selectionnee();
    let attendu = ecouler(&mut reference, b"a003 FETCH 1 BINARY.PEEK[1]\r\n");
    for taille in 1..=48_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(b"a003 FETCH 1 BINARY.PEEK[1]\r\n", &mut grand)
            .expect("traitable");
        let mut fil = std::string::String::new();
        let mut petit = std::vec![0_u8; taille];
        let mut refuse = false;
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("un binaire n'est pas un intervalle du message")
                }
                Err(erreur) => {
                    assert!(matches!(erreur, super::Error::Reply(_)), "{erreur:?}");
                    refuse = true;
                    break;
                }
            }
        }
        if !refuse {
            assert_eq!(fil, attendu, "taille {taille}");
        }
    }
}

/// Un tampon trop court pour écrire un `BINARY` le dit, à chaque rang de son
/// annonce : le chemin, le décalage, le littéral8, et le `NIL` d'une absence.
#[test]
fn un_tampon_trop_court_pour_un_binaire_le_dit() {
    for commande in [
        &b"a003 FETCH 1 BINARY.PEEK[1]<3.4>\r\n"[..],
        b"a003 FETCH 1 BINARY.PEEK[7]\r\n",
        b"a003 FETCH 1 BINARY.SIZE[1]\r\n",
        b"a003 FETCH 1 BINARY.SIZE[7]\r\n",
    ] {
        for taille in 1..=40_usize {
            let mut session = selectionnee();
            let mut grand = [0_u8; 512];
            session.handle(commande, &mut grand).expect("traitable");
            let mut petit = std::vec![0_u8; taille];
            loop {
                match session.next_fetch(&mut petit) {
                    Ok(None) => break,
                    Ok(Some(_)) => {}
                    Err(erreur) => {
                        assert!(matches!(erreur, super::Error::Reply(_)), "{erreur:?}");
                        break;
                    }
                }
            }
        }
    }
}

// ── `BODYSTRUCTURE` ─────────────────────────────────────────────────────────

/// **La structure s'écoule par le même chemin que l'enveloppe.** Elle se compose
/// hors de la session, et la session ne fait que la faire passer.
#[test]
fn la_structure_s_ecoule_dans_la_reponse() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 BODYSTRUCTURE\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 100 1 \
         NIL NIL NIL NIL))\r\na003 OK FETCH completed\r\n"
    );
}

/// Les deux analyses d'un même message se suivent, chacune entière, et ce qui
/// vient après vient bien après.
#[test]
fn deux_analyses_du_meme_message_se_suivent() {
    let mut session = selectionnee();
    let fil = ecouler(
        &mut session,
        b"a003 FETCH 1 (ENVELOPE BODYSTRUCTURE UID)\r\n",
    );
    assert_eq!(
        fil,
        "* 1 FETCH (ENVELOPE (NIL NIL ((NIL NIL \"m10\" \"x.test\")) \
         NIL NIL NIL NIL NIL NIL NIL) \
         BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 100 1 NIL NIL NIL NIL) \
         UID 10)\r\na003 OK FETCH completed\r\n"
    );
}

/// La structure se découpe sans changer de résultat.
#[test]
fn la_structure_se_decoupe_sans_changer_de_resultat() {
    let mut reference = selectionnee();
    let attendu = ecouler(&mut reference, b"a003 FETCH 1 BODYSTRUCTURE\r\n");
    for taille in 1..=48_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(b"a003 FETCH 1 BODYSTRUCTURE\r\n", &mut grand)
            .expect("traitable");
        let mut fil = std::string::String::new();
        let mut petit = std::vec![0_u8; taille];
        let mut refuse = false;
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("une structure n'est pas un corps")
                }
                Err(erreur) => {
                    assert!(
                        matches!(erreur, super::Error::Reply(_)),
                        "taille {taille} : {erreur:?}"
                    );
                    refuse = true;
                    break;
                }
            }
        }
        if !refuse {
            assert_eq!(fil, attendu, "taille {taille}");
        }
    }
}

#[test]
fn un_fetch_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 FETCH 0 UID\r\n"[..],
        b"a004 FETCH 1\r\n",
        b"a005 FETCH\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD FETCH arguments are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

/// Un ensemble plus long que ce que la session retient n'est pas la demande d'un
/// client qui lit son courrier.
#[test]
fn un_ensemble_trop_long_a_retenir_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 FETCH 1"[..]);
    for _ in 0..600 {
        commande.extend_from_slice(b",1");
    }
    commande.extend_from_slice(b" UID\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Sequence set is too long"),
        "{texte}"
    );
}

/// Sur une boîte vide, un `FETCH` ne rend rien et ne se plaint pas.
#[test]
fn un_fetch_sur_une_boite_vide_ne_rend_rien() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Archives\r\n");
    let fil = ecouler(&mut session, b"a003 FETCH 1:* (UID BODY[])\r\n");
    assert_eq!(fil, "a003 OK FETCH completed\r\n");
}

/// Sans émission en cours, il n'y a rien à écouler.
#[test]
fn sans_fetch_en_cours_il_n_y_a_rien_a_ecouler() {
    let mut session = selectionnee();
    let mut sortie = [0_u8; 256];
    assert!(
        session
            .next_fetch(&mut sortie)
            .expect("émettable")
            .is_none()
    );
    // Et une boîte refermée pendant l'émission arrête celle-ci.
    let mut sortie = [0_u8; 2048];
    session
        .handle(b"a003 FETCH 1:* UID\r\n", &mut sortie)
        .expect("traitable");
    dire(&mut session, b"a004 CLOSE\r\n");
    let mut morceaux = [0_u8; 256];
    assert!(
        session
            .next_fetch(&mut morceaux)
            .expect("émettable")
            .is_none()
    );
}

/// **Un message qui n'est plus là est sauté**, et le reste est rendu. Un serveur
/// qui s'arrêterait là ferait perdre au client tout ce qui suit.
#[test]
fn un_message_disparu_est_saute_sans_arreter_le_fetch() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let fil = ecouler(&mut session, b"a003 FETCH 1:* UID\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (UID 1)\r\n* 3 FETCH (UID 3)\r\na003 OK FETCH completed\r\n"
    );
}

/// **Un magasin partagé en est un aussi** : la boucle n'en a qu'un pour mille
/// connexions, et la session le prend par valeur.
///
/// On l'éprouve SANS session : une session de plus serait une instanciation de
/// plus, donc une copie de tout son code à couvrir, pour vérifier deux
/// délégations.
#[test]
fn un_magasin_partage_se_passe_par_reference() {
    let boites = Boites::default();
    let partage = &boites;
    let mut place = [0_u8; 64];
    assert_eq!(
        Mailboxes::name(&partage, b"jean", 0, &mut place).map(|boite| boite.name),
        Some(&b"INBOX"[..])
    );
    assert!(Mailboxes::open(&partage, b"jean", b"INBOX").is_some());
    assert!(Mailboxes::open(&partage, b"jean", b"Inconnue").is_none());
    assert!(Mailboxes::append(&partage, b"jean", b"INBOX").is_some());
    assert!(Mailboxes::append(&partage, b"jean", b"Inconnue").is_none());
    assert_eq!(
        Mailboxes::create(
            &partage,
            b"jean",
            b"Archives",
            ams_proto_imap::SpecialUse::NONE
        ),
        super::Creation::DejaLa
    );
    assert_eq!(
        Mailboxes::delete(&partage, b"jean", b"Inconnue"),
        super::Deletion::Absente
    );
    assert_eq!(
        Mailboxes::rename(&partage, b"jean", b"Inconnue", b"Autre"),
        super::Renaming::Absente
    );
    assert_eq!(
        Mailboxes::subscribe(&partage, b"jean", b"Archives"),
        super::Subscription::Faite
    );
    assert!(Mailboxes::is_subscribed(&partage, b"jean", b"Archives"));
    assert_eq!(
        Mailboxes::orphan(&partage, b"jean", 0, &mut place),
        None,
        "une boîte qui existe n'est pas orpheline"
    );
    assert_eq!(
        Mailboxes::unsubscribe(&partage, b"jean", b"Archives"),
        super::Subscription::Faite
    );
}

/// Les commandes qui exigent un état le disent dans les deux sens.
#[test]
fn les_commandes_hors_etat_le_disent() {
    let mut session = nouvelle(true);
    // Avant authentification, celles qui demandent d'être authentifié.
    for commande in [&b"a001 CREATE test\r\n"[..], b"a002 NAMESPACE\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed before authentication"),
            "{commande:?} : {texte}"
        );
    }
    dire(&mut session, b"a003 LOGIN jean ouvre-toi\r\n");
    // Authentifié mais sans boîte, celles qui en demandent une.
    for commande in [&b"a004 EXPUNGE\r\n"[..], b"a005 SEARCH ALL\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed unless a mailbox is selected"),
            "{commande:?} : {texte}"
        );
    }
}

/// Un motif plus long que le plus long nom de boîte ne désigne rien.
#[test]
fn un_argument_de_list_demesure_est_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let mut commande = std::vec::Vec::from(&b"a002 LIST \"\" "[..]);
    commande.resize(commande.len() + 300, b'x');
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("BAD LIST arguments are not well formed"),
        "{texte}"
    );
}

// ── `STORE` ─────────────────────────────────────────────────────────────────

/// **Les trois verbes ne font pas la même chose**, et c'est tout l'intérêt.
#[test]
fn les_trois_verbes_de_store_ecrivent_ce_qu_ils_disent() {
    let mut session = selectionnee();
    // Le message 2 porte déjà `\Seen`.
    let ajout = ecouler(&mut session, b"a003 STORE 2 +FLAGS (\\Flagged)\r\n");
    assert_eq!(
        ajout,
        "* 2 FETCH (FLAGS (\\Seen \\Flagged))\r\na003 OK STORE completed\r\n"
    );
    let retrait = ecouler(&mut session, b"a004 STORE 2 -FLAGS (\\Seen)\r\n");
    assert_eq!(
        retrait,
        "* 2 FETCH (FLAGS (\\Flagged))\r\na004 OK STORE completed\r\n"
    );
    let remplacement = ecouler(&mut session, b"a005 STORE 2 FLAGS (\\Draft)\r\n");
    assert_eq!(
        remplacement,
        "* 2 FETCH (FLAGS (\\Draft))\r\na005 OK STORE completed\r\n"
    );
    // Et `FLAGS ()` efface tout.
    let efface = ecouler(&mut session, b"a006 STORE 2 FLAGS ()\r\n");
    assert_eq!(
        efface,
        "* 2 FETCH (FLAGS ())\r\na006 OK STORE completed\r\n"
    );
}

/// **`.SILENT` ne rend rien, et fait le travail quand même.**
#[test]
fn silent_ecrit_sans_rien_rendre() {
    let mut session = selectionnee();
    let silencieux = ecouler(&mut session, b"a003 STORE 1:3 +FLAGS.SILENT (\\Draft)\r\n");
    assert_eq!(silencieux, "a003 OK STORE completed\r\n");
    // Le travail est fait : un `FETCH` le montre.
    let apres = ecouler(&mut session, b"a004 FETCH 1 FLAGS\r\n");
    assert_eq!(
        apres,
        "* 1 FETCH (FLAGS (\\Draft))\r\na004 OK FETCH completed\r\n"
    );
}

/// **`UID STORE` désigne par UID, rend le rang, ET PORTE L'UID.**
///
/// §6.4.9 l'exige en nommant cette commande : sans l'UID, un client qui a
/// désigné ses messages par UID reçoit des rangs, et doit deviner lequel est
/// lequel — alors qu'il a choisi les UID pour ne pas avoir à le faire.
#[test]
fn uid_store_designe_par_uid_et_porte_l_uid() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID STORE 30 +FLAGS (\\Flagged)\r\n");
    assert_eq!(
        fil,
        "* 3 FETCH (UID 30 FLAGS (\\Answered \\Flagged))\r\n\
         a003 OK UID STORE completed\r\n"
    );
    // UN `STORE` ORDINAIRE, LUI, N'EN PORTE PAS : le client a désigné des rangs,
    // et c'est un rang qu'on lui rend. §6.4.6 ne demande que les drapeaux.
    let sans = ecouler(&mut session, b"a004 STORE 1 +FLAGS (\\Flagged)\r\n");
    assert_eq!(
        sans,
        "* 1 FETCH (FLAGS (\\Flagged))\r\na004 OK STORE completed\r\n"
    );
}

/// **UN `UID FETCH` PORTE L'UID QUE LE CLIENT N'A PAS DEMANDÉ** (§6.4.9), et ne
/// l'écrit pas deux fois quand il l'a demandé.
#[test]
fn uid_fetch_porte_l_uid_meme_sans_l_avoir_demande() {
    let mut session = selectionnee();
    let sans = ecouler(&mut session, b"a003 UID FETCH 20 FLAGS\r\n");
    assert_eq!(
        sans,
        "* 2 FETCH (UID 20 FLAGS (\\Seen))\r\na003 OK UID FETCH completed\r\n"
    );
    // Demandé, il ne s'écrit qu'une fois.
    let demande = ecouler(&mut session, b"a004 UID FETCH 20 (FLAGS UID)\r\n");
    assert_eq!(
        demande,
        "* 2 FETCH (FLAGS (\\Seen) UID 20)\r\na004 OK UID FETCH completed\r\n"
    );
    // Et un `FETCH` ordinaire n'en porte pas.
    let ordinaire = ecouler(&mut session, b"a005 FETCH 2 FLAGS\r\n");
    assert_eq!(
        ordinaire,
        "* 2 FETCH (FLAGS (\\Seen))\r\na005 OK FETCH completed\r\n"
    );
}

/// **Un message annoncé et disparu ne fait pas échouer la commande** (§6.4.6) :
/// le client l'apprend en ne recevant rien pour lui.
#[test]
fn un_message_disparu_ne_fait_pas_echouer_le_store() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    // Le deuxième n'a pas d'`info` : il n'est même pas choisi. Le troisième en
    // a une, et s'efface quand on écrit — deux disparitions différentes, et
    // aucune des deux ne fait échouer la commande.
    let fil = ecouler(&mut session, b"a003 STORE 1:3 +FLAGS (\\Seen)\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (FLAGS (\\Seen))\r\na003 OK STORE completed\r\n"
    );
}

/// **On ne promet que ce qui survit.** Un drapeau hors de `PERMANENTFLAGS`
/// serait écrit puis perdu, et le client ne l'apprendrait jamais.
#[test]
fn store_dans_une_boite_en_lecture_seule_se_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Archives\r\n");
    let (texte, action) = dire(&mut session, b"a003 STORE 1 +FLAGS (\\Seen)\r\n");
    assert!(
        texte.contains("NO [CANNOT] This flag does not persist in this mailbox"),
        "{texte}"
    );
    assert_eq!(action, Action::Continue);
}

/// **Un drapeau inconnu est un REFUS, pas un silence.**
#[test]
fn un_drapeau_inconnu_se_refuse_en_le_disant() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 STORE 1 +FLAGS ($Important)\r\n");
    assert!(
        texte.contains("NO [CANNOT] This flag cannot be stored"),
        "{texte}"
    );
}

#[test]
fn un_store_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 STORE\r\n"[..],
        b"a004 STORE 1\r\n",
        b"a005 STORE 1 MARKS (\\Seen)\r\n",
        b"a006 STORE x +FLAGS (\\Seen)\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD STORE arguments are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un ensemble trop long est refusé plutôt que tronqué.**
#[test]
fn un_ensemble_de_store_trop_long_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 STORE "[..]);
    for _ in 0..(super::SEQUENCE_TEXT_MAX / 2) {
        commande.extend_from_slice(b"1,");
    }
    commande.extend_from_slice(b"1 +FLAGS (\\Seen)\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Sequence set is too long"),
        "{texte}"
    );
}

/// **Un `STORE` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_store_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 STORE 1 +FLAGS (\\Seen)\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

/// **§6.4.5 : un corps rendu SANS `PEEK` marque le message comme lu**, et les
/// `FLAGS` de la même réponse le disent.
#[test]
fn un_corps_sans_peek_marque_le_message_et_le_dit() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 FETCH 1 (FLAGS BODY[])\r\n");
    assert_eq!(
        fil,
        "* 1 FETCH (FLAGS (\\Seen) BODY[] {100}\r\n<1:0+100>)\r\n\
         a003 OK FETCH completed\r\n"
    );
}

// ── `EXPUNGE` ───────────────────────────────────────────────────────────────

/// **Chaque `* n EXPUNGE` RENUMÉROTE ce qui suit** (§7.5.1). Effacer les
/// messages 1 et 3 d'une boîte de trois ne rend donc pas « 1 puis 3 », mais
/// « 1 puis 2 » : après le premier, l'ancien troisième est devenu le deuxième.
/// Un serveur qui annoncerait les rangs d'origine ferait effacer au client un
/// message qu'il voulait garder.
#[test]
fn expunge_renumerote_a_mesure_qu_il_efface() {
    let mut session = selectionnee();
    dire(&mut session, b"a003 STORE 1,3 +FLAGS (\\Deleted)\r\n");
    ecouler(&mut session, b"a003 STORE 1,3 +FLAGS (\\Deleted)\r\n");
    let fil = ecouler(&mut session, b"a004 EXPUNGE\r\n");
    assert_eq!(
        fil,
        "* 1 EXPUNGE\r\n* 2 EXPUNGE\r\na004 OK EXPUNGE completed\r\n"
    );
    // Il ne reste que l'ancien deuxième, devenu le premier.
    let reste = ecouler(&mut session, b"a005 FETCH 1:* UID\r\n");
    assert_eq!(reste, "* 1 FETCH (UID 20)\r\na005 OK FETCH completed\r\n");
}

/// **Rien de marqué, rien d'effacé** — et la commande réussit quand même.
#[test]
fn expunge_sans_rien_de_marque_n_efface_rien() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 EXPUNGE\r\n");
    assert_eq!(fil, "a003 OK EXPUNGE completed\r\n");
    let reste = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert!(reste.contains("* 3 FETCH (UID 30)"), "{reste}");
}

/// **`UID EXPUNGE` s'en tient à son ensemble** (§6.4.9) : ce qui est marqué mais
/// hors de l'ensemble RESTE. C'est la commande qu'un client utilise quand il
/// sait que d'autres sessions marquent la même boîte.
#[test]
fn uid_expunge_ne_touche_que_son_ensemble() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 STORE 1:3 +FLAGS (\\Deleted)\r\n");
    let fil = ecouler(&mut session, b"a004 UID EXPUNGE 20\r\n");
    assert_eq!(fil, "* 2 EXPUNGE\r\na004 OK UID EXPUNGE completed\r\n");
    let reste = ecouler(&mut session, b"a005 FETCH 1:* UID\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 10)\r\n* 2 FETCH (UID 30)\r\na005 OK FETCH completed\r\n"
    );
}

/// **`CLOSE` efface, `UNSELECT` non** (§6.4.2 et §6.4.4) : c'est la seule chose
/// qui les distingue, et les confondre ferait effacer du courrier à qui
/// demandait le contraire.
#[test]
fn close_efface_et_unselect_ne_touche_a_rien() {
    for (commande, efface) in [(&b"a004 CLOSE\r\n"[..], 1), (b"a004 UNSELECT\r\n", 0)] {
        let boites = Boites::default();
        let compteur = std::rc::Rc::clone(&boites.efface);
        let mut session = Session::new(BORNES, true, UnCompte, boites);
        session.on_tls_established();
        dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
        dire(&mut session, b"a002 SELECT INBOX\r\n");
        ecouler(&mut session, b"a003 STORE 2 +FLAGS (\\Deleted)\r\n");
        assert_eq!(compteur.get(), 0, "rien ne doit être effacé avant l'ordre");
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains("OK"), "{texte}");
        assert_eq!(compteur.get(), efface, "{commande:?} : {texte}");
    }
}

/// **Un magasin peut refuser d'effacer, et cela ne s'annonce pas.** Entre
/// l'instantané et l'ordre, une autre session a pu retirer la marque : effacer
/// alors, ce serait perdre du courrier. La session passe au suivant sans rien
/// dire — annoncer un effacement qui n'a pas eu lieu ferait perdre au client le
/// fil des numéros de séquence.
#[test]
fn un_message_qui_refuse_de_s_effacer_n_est_pas_annonce() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    ecouler(&mut session, b"a003 STORE 1:3 +FLAGS (\\Deleted)\r\n");
    // Le premier s'efface, le deuxième refuse, le troisième s'efface. Le
    // deuxième ayant pris la place du premier, le troisième est annoncé `2`.
    let fil = ecouler(&mut session, b"a004 EXPUNGE\r\n");
    assert_eq!(
        fil,
        "* 1 EXPUNGE\r\n* 2 EXPUNGE\r\na004 OK EXPUNGE completed\r\n"
    );
    // Et le têtu est bien celui qui reste.
    let reste = ecouler(&mut session, b"a005 FETCH 1:* UID\r\n");
    assert_eq!(reste, "* 1 FETCH (UID 20)\r\na005 OK FETCH completed\r\n");
}

/// **Un message que la boîte annonce sans le rendre n'est pas même choisi.**
/// C'est l'autre disparition, celle qui n'a pas d'`info` — et un parcours qui
/// s'arrêterait sur elle laisserait le reste de la boîte intact.
#[test]
fn un_trou_dans_la_boite_n_arrete_pas_l_effacement() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    ecouler(&mut session, b"a003 STORE 1 +FLAGS (\\Deleted)\r\n");
    let fil = ecouler(&mut session, b"a004 EXPUNGE\r\n");
    assert_eq!(fil, "* 1 EXPUNGE\r\na004 OK EXPUNGE completed\r\n");
}

/// **Une boîte en lecture seule n'efface rien**, et le dit.
#[test]
fn expunge_dans_une_boite_en_lecture_seule_se_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 EXAMINE INBOX\r\n");
    let (texte, action) = dire(&mut session, b"a003 EXPUNGE\r\n");
    assert!(
        texte.contains("NO [CANNOT] Mailbox is read-only"),
        "{texte}"
    );
    assert_eq!(action, Action::Continue);
}

/// **`CLOSE` sur une boîte ouverte en lecture seule n'efface rien** (§6.4.2).
#[test]
fn close_en_lecture_seule_n_efface_rien() {
    let boites = Boites::default();
    let compteur = std::rc::Rc::clone(&boites.efface);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 EXAMINE INBOX\r\n");
    dire(&mut session, b"a003 CLOSE\r\n");
    assert_eq!(compteur.get(), 0);
}

#[test]
fn un_expunge_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for (commande, attendu) in [
        (
            &b"a003 EXPUNGE 1:2\r\n"[..],
            "BAD EXPUNGE takes no arguments",
        ),
        (
            b"a004 UID EXPUNGE\r\n",
            "BAD UID EXPUNGE expects a sequence set",
        ),
        (
            b"a005 UID EXPUNGE x\r\n",
            "BAD EXPUNGE arguments are malformed",
        ),
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains(attendu), "{commande:?} : {texte}");
    }
}

/// **Un ensemble trop long est refusé plutôt que tronqué.**
#[test]
fn un_ensemble_d_expunge_trop_long_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 UID EXPUNGE "[..]);
    for _ in 0..(super::SEQUENCE_TEXT_MAX / 2) {
        commande.extend_from_slice(b"1,");
    }
    commande.extend_from_slice(b"1\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Sequence set is too long"),
        "{texte}"
    );
}

/// **Un `EXPUNGE` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_expunge_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 EXPUNGE\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

// ── `SEARCH` ────────────────────────────────────────────────────────────────

/// **IMAP4rev2 a remplacé `* SEARCH` par `* ESEARCH`** (§7.3.4), et les
/// résultats y sont un ENSEMBLE, pas une liste.
#[test]
fn search_rend_un_esearch_et_comprime_ses_resultats() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH ALL\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") ALL 1:3\r\na003 OK SEARCH completed\r\n"
    );
}

/// **Rien trouvé, rien annoncé** : `ESEARCH` omet `ALL` plutôt que de rendre un
/// ensemble vide, qui ne s'écrit pas.
#[test]
fn une_recherche_sans_resultat_omet_l_ensemble() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH ANSWERED DELETED\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\")\r\na003 OK SEARCH completed\r\n"
    );
}

/// Les plages non contiguës se séparent par une virgule.
#[test]
fn les_resultats_epars_se_separent() {
    let mut session = selectionnee();
    // Les messages 1 et 3 : deux plages d'un seul élément.
    let fil = ecouler(&mut session, b"a003 SEARCH OR 1 3\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") ALL 1,3\r\na003 OK SEARCH completed\r\n"
    );
}

/// **`UID SEARCH` rend des UID**, et le dit dans la réponse (§7.3.4).
#[test]
fn uid_search_rend_des_uid_et_l_annonce() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID SEARCH NOT SEEN\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") UID ALL 10,30\r\na003 OK UID SEARCH completed\r\n"
    );
}

#[test]
fn les_criteres_ordinaires_se_cherchent() {
    let mut session = selectionnee();
    for (commande, attendu) in [
        // Des trois messages d'épreuve, seul le deuxième est `\Seen` et seul le
        // troisième est `\Answered`.
        (&b"a003 SEARCH UNSEEN\r\n"[..], "ALL 1,3"),
        (b"a003 SEARCH SEEN\r\n", "ALL 2"),
        (b"a003 SEARCH LARGER 150\r\n", "ALL 2:3"),
        (b"a003 SEARCH SMALLER 250 SEEN\r\n", "ALL 2"),
        (b"a003 SEARCH NOT SEEN\r\n", "ALL 1,3"),
        (b"a003 SEARCH UID 20:*\r\n", "ALL 2:3"),
        (b"a003 SEARCH 2:*\r\n", "ALL 2:3"),
        (b"a003 SEARCH ANSWERED\r\n", "ALL 3"),
        (b"a003 SEARCH OR SEEN ANSWERED\r\n", "ALL 2:3"),
    ] {
        let fil = ecouler(&mut session, commande);
        assert!(fil.contains(attendu), "{commande:?} : {fil}");
    }
}

/// **Le jeu de caractères est optionnel, et rev2 impose UTF-8.** Chercher dans
/// un encodage qu'on ignore ferait rendre n'importe quoi.
#[test]
fn le_jeu_de_caracteres_se_lit_ou_se_refuse() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH CHARSET UTF-8 SEEN\r\n");
    assert!(fil.contains("ALL 2\r\n"), "{fil}");
    let aussi = ecouler(&mut session, b"a004 SEARCH CHARSET \"US-ASCII\" SEEN\r\n");
    assert!(aussi.contains("ALL 2\r\n"), "{aussi}");
    let (refus, _) = dire(&mut session, b"a005 SEARCH CHARSET ISO-8859-1 SEEN\r\n");
    assert!(
        refus.contains("NO [BADCHARSET (UTF-8 US-ASCII)]"),
        "{refus}"
    );
}

/// **Un critère qu'on ne sert pas est refusé, pas rendu faux.**
#[test]
fn un_critere_de_recherche_non_servi_se_refuse() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 SEARCH KEYWORD $Important\r\n");
    assert!(
        texte.contains("NO [CANNOT] This search key is not served yet"),
        "{texte}"
    );
}

// ── Chercher DANS les messages ──────────────────────────────────────────────

/// **LA SESSION NE LIT PAS LES MESSAGES** : elle passe la question à la boîte.
/// Ce qu'on éprouve ici est qu'elle pose la BONNE question et rend la bonne
/// réponse.
#[test]
fn un_critere_de_contenu_passe_par_la_boite() {
    let mut session = selectionnee();
    // La boîte d'épreuve porte « la facture de mars » en sujet.
    let trouve = ecouler(&mut session, b"a003 SEARCH SUBJECT facture\r\n");
    assert!(
        trouve.contains("* ESEARCH (TAG \"a003\") ALL 1:3"),
        "{trouve}"
    );
    // La casse ne compte pas (§6.4.4).
    let casse = ecouler(&mut session, b"a004 SEARCH SUBJECT FACTURE\r\n");
    assert!(casse.contains("ALL 1:3"), "{casse}");
    // Ce qui ne s'y trouve pas ne se trouve pas.
    let rien = ecouler(&mut session, b"a005 SEARCH SUBJECT devis\r\n");
    assert!(!rien.contains("ALL"), "{rien}");
}

/// Le corps et l'en-tête ne sont pas le même endroit.
#[test]
fn le_corps_et_l_en_tete_ne_sont_pas_le_meme_endroit() {
    let mut session = selectionnee();
    let corps = ecouler(&mut session, b"a003 SEARCH BODY corps\r\n");
    assert!(corps.contains("ALL 1:3"), "{corps}");
    // « corps » n'est pas dans le sujet.
    let sujet = ecouler(&mut session, b"a004 SEARCH SUBJECT corps\r\n");
    assert!(!sujet.contains("ALL"), "{sujet}");
    // Un champ que le message ne porte pas ne se trouve pas.
    let absent = ecouler(&mut session, b"a005 SEARCH HEADER X-Rien valeur\r\n");
    assert!(!absent.contains("ALL"), "{absent}");
}

/// Une chaîne citée garde ses blancs, jusque dans la session.
#[test]
fn une_chaine_citee_traverse_la_session() {
    let mut session = selectionnee();
    let trouve = ecouler(&mut session, b"a003 SEARCH SUBJECT \"facture de mars\"\r\n");
    assert!(trouve.contains("ALL 1:3"), "{trouve}");
    let rien = ecouler(&mut session, b"a004 SEARCH SUBJECT \"facture de juin\"\r\n");
    assert!(!rien.contains("ALL"), "{rien}");
}

/// Les critères de contenu se combinent avec les autres.
#[test]
fn un_critere_de_contenu_se_combine() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 SEARCH SEEN SUBJECT facture\r\n");
    assert!(fil.contains("ALL 2"), "{fil}");
    let nie = ecouler(&mut session, b"a004 SEARCH NOT SUBJECT facture\r\n");
    assert!(!nie.contains("ALL"), "{nie}");
}

#[test]
fn un_search_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 SEARCH\r\n"[..],
        b"a004 SEARCH NOT\r\n",
        b"a005 SEARCH (SEEN\r\n",
        b"a006 SEARCH LARGER x\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD SEARCH arguments are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un critère plus long que ce qu'on retient est refusé plutôt que tronqué.**
#[test]
fn un_critere_trop_long_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 SEARCH "[..]);
    commande.resize(commande.len() + super::SEQUENCE_TEXT_MAX + 1, b'x');
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Search criteria are too long"),
        "{texte}"
    );
}

/// **Une expression trop touffue est une borne, pas une faute de syntaxe.**
#[test]
fn une_expression_trop_touffue_se_refuse() {
    let mut session = selectionnee();
    let mut commande = std::vec::Vec::from(&b"a003 SEARCH "[..]);
    for _ in 0..100 {
        commande.extend_from_slice(b"SEEN ");
    }
    commande.extend_from_slice(b"\r\n");
    let (texte, _) = dire(&mut session, &commande);
    assert!(
        texte.contains("NO [CANNOT] Search expression is too complex"),
        "{texte}"
    );

    let mut profonde = std::vec::Vec::from(&b"a004 SEARCH "[..]);
    for _ in 0..32 {
        profonde.extend_from_slice(b"NOT ");
    }
    profonde.extend_from_slice(b"SEEN\r\n");
    let (aussi, _) = dire(&mut session, &profonde);
    assert!(
        aussi.contains("NO [CANNOT] Search expression is too complex"),
        "{aussi}"
    );
}

/// **Un `SEARCH` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_search_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SEARCH ALL\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

/// **Un message que la boîte annonce sans le rendre ne correspond à rien**, et
/// n'arrête pas le parcours.
#[test]
fn un_trou_dans_la_boite_n_arrete_pas_la_recherche() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let fil = ecouler(&mut session, b"a003 SEARCH ALL\r\n");
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a003\") ALL 1,3\r\na003 OK SEARCH completed\r\n"
    );
}

/// **Une commande de boîte hors sélection est hors d'état, pas hors de
/// service** : `BAD` et non `NO [UNAVAILABLE]`, parce que c'est le client qui
/// l'a demandée au mauvais moment.
#[test]
fn une_commande_de_boite_sans_selection_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 COPY 1 INBOX\r\n"[..], b"a003 MOVE 1 Archives\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD Command is not allowed unless a mailbox is selected"),
            "{commande:?} : {texte}"
        );
    }
}

/// **UNE LIGNE `ESEARCH` PEUT ÊTRE PLUS LONGUE QU'UN TAMPON.** C'est la seule
/// réponse du serveur qui ne tienne pas forcément dans un morceau : elle se
/// découpe, et **le découpage ne change pas ce que le client lit**. Un tampon
/// trop court pour avancer d'un seul octet le dit, plutôt que de rendre du vide
/// indéfiniment — ce qui serait une boucle sans fin chez l'appelant.
#[test]
fn une_recherche_se_decoupe_sans_changer_de_resultat() {
    let attendu = "* ESEARCH (TAG \"a003\") ALL 1,3\r\na003 OK SEARCH completed\r\n";
    let mut reference = selectionnee();
    assert_eq!(ecouler(&mut reference, b"a003 SEARCH OR 1 3\r\n"), attendu);

    for taille in 1..=64_usize {
        let mut session = selectionnee();
        let mut grand = [0_u8; 512];
        session
            .handle(b"a003 SEARCH OR 1 3\r\n", &mut grand)
            .expect("traitable");
        let mut fil = std::string::String::new();
        let mut petit = std::vec![0_u8; taille];
        let mut refuse = false;
        loop {
            match session.next_fetch(&mut petit) {
                Ok(None) => break,
                Ok(Some(super::FetchChunk::Bytes(octets))) => {
                    fil.push_str(&std::string::String::from_utf8_lossy(octets));
                }
                Ok(Some(super::FetchChunk::Message { .. })) => {
                    unreachable!("une recherche ne rend pas de corps")
                }
                Err(erreur) => {
                    assert!(
                        matches!(erreur, super::Error::Reply(_)),
                        "taille {taille} : {erreur:?}"
                    );
                    refuse = true;
                    break;
                }
            }
        }
        if !refuse {
            assert_eq!(fil, attendu, "taille {taille}");
        }
    }
}

/// **Un tampon peut suffire à l'en-tête et pas à la première plage.** Il faut le
/// dire, plutôt que de rendre indéfiniment du vide à un appelant qui l'écrira
/// indéfiniment — une boucle sans fin chez lui, née d'un tampon chez nous.
///
/// Le cas demande un tag court et des UID longs : `* ESEARCH (TAG "a") UID`
/// tient en vingt-trois octets, ` ALL 4294967294:4294967295` en demande
/// vingt-six.
#[test]
fn un_tampon_qui_suffit_a_l_entete_et_pas_a_la_plage_le_dit() {
    for taille in 23..=25_usize {
        let mut session = nouvelle(true);
        dire(&mut session, b"a LOGIN jean ouvre-toi\r\n");
        dire(&mut session, b"b SELECT Grande\r\n");
        let mut grand = [0_u8; 512];
        session
            .handle(b"a UID SEARCH ALL\r\n", &mut grand)
            .expect("traitable");
        let mut petit = std::vec![0_u8; taille];
        // Le premier morceau passe : c'est l'en-tête.
        let premier = session.next_fetch(&mut petit).expect("émettable");
        assert!(premier.is_some(), "taille {taille}");
        // Le second ne peut rien écrire, et le dit.
        let second = session.next_fetch(&mut petit);
        assert!(
            matches!(second, Err(super::Error::Reply(_))),
            "taille {taille} : {second:?}"
        );
    }
    // Vingt-six octets suffisent à la plage ; la conclusion étiquetée, elle,
    // en demande vingt-sept, et c'est un morceau comme les autres.
    let mut session = nouvelle(true);
    dire(&mut session, b"a LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"b SELECT Grande\r\n");
    let mut grand = [0_u8; 512];
    session
        .handle(b"a UID SEARCH ALL\r\n", &mut grand)
        .expect("traitable");
    let mut fil = std::string::String::new();
    let mut petit = [0_u8; 27];
    while let Some(morceau) = session.next_fetch(&mut petit).expect("émettable") {
        if let super::FetchChunk::Bytes(octets) = morceau {
            fil.push_str(&std::string::String::from_utf8_lossy(octets));
        }
    }
    assert_eq!(
        fil,
        "* ESEARCH (TAG \"a\") UID ALL 4294967294:4294967295\r\na OK UID SEARCH completed\r\n"
    );
}

// ── `COPY` ──────────────────────────────────────────────────────────────────

/// **§6.4.7 : `COPYUID` dit au client OÙ ses messages ont atterri**, et les deux
/// ensembles se lisent dans le même ordre.
#[test]
fn copy_rend_un_copyuid_qui_apparie_source_et_destination() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 1:2 INBOX\r\n");
    // 10 et 20 ne se suivent pas : deux plages d'un élément, séparées.
    assert_eq!(texte, "a003 OK [COPYUID 42 10,20 31:32] COPY completed\r\n");
    // Les copies sont bien là, à la suite.
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert!(fil.contains("* 4 FETCH (UID 31)"), "{fil}");
    assert!(fil.contains("* 5 FETCH (UID 32)"), "{fil}");
}

/// L'ensemble source est celui que le client a désigné, TROUS COMPRIS.
#[test]
fn copyuid_nomme_les_uid_epars_de_la_source() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 1,3 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 10,30 31:32] COPY completed\r\n");
}

/// **`UID COPY` désigne par UID**, et le dit dans sa conclusion.
#[test]
fn uid_copy_designe_par_uid() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID COPY 30 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 30 31] UID COPY completed\r\n");
}

/// **§6.4.7 : une destination qui n'existe pas se dit `[TRYCREATE]`.** C'est le
/// code qui apprend au client qu'un `CREATE` suivi du même `COPY` marcherait.
#[test]
fn une_destination_inconnue_se_dit_trycreate() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 1 Inconnue\r\n");
    assert!(
        texte.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{texte}"
    );
}

/// **§6.4.7 : un `COPY` n'est pas partiellement réussi.** Ce qui a été copié
/// avant l'échec est défait, et le client peut recommencer sans faire de
/// doublons.
#[test]
fn un_copy_qui_echoue_defait_ce_qu_il_avait_fait() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    // Le deuxième message refuse d'être copié ; le premier ne doit pas rester.
    let (texte, _) = dire(&mut session, b"a003 COPY 1:3 INBOX\r\n");
    assert!(
        texte.contains("NO Copy failed; no messages were copied"),
        "{texte}"
    );
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(fil.matches("* ").count(), 3, "{fil}");
}

/// Rien à copier n'est pas un échec, et ne s'accompagne d'aucun `COPYUID`.
#[test]
fn un_copy_qui_ne_designe_rien_reussit_sans_rien_dire() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 COPY 9 INBOX\r\n");
    assert_eq!(texte, "a003 OK COPY completed\r\n");
}

#[test]
fn un_copy_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 COPY\r\n"[..],
        b"a004 COPY 1\r\n",
        b"a005 COPY x INBOX\r\n",
        b"a006 COPY 1 \r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD COPY expects a sequence set and a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un ensemble source trop long fait OMETTRE `COPYUID`**, jamais le tronquer :
/// un ensemble tronqué désignerait d'autres messages que ceux qu'on a copiés.
#[test]
fn un_copyuid_qui_deborde_est_omis_entierement() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Eparse\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 1:* INBOX\r\n");
    assert_eq!(texte, "a003 OK COPY completed\r\n");
}

/// **Des UID qui se suivent se comprime en plage**, et non en liste.
#[test]
fn copyuid_comprime_une_source_contigue() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Suite\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 1:3 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 5:7 8:10] COPY completed\r\n");
}

/// **Un message que la boîte annonce sans le rendre n'est pas copié**, et
/// n'arrête pas la copie des autres.
#[test]
fn un_trou_dans_la_boite_n_arrete_pas_la_copie() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Trouee\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 1:3 INBOX\r\n");
    assert_eq!(texte, "a003 OK [COPYUID 42 1,3 4:5] COPY completed\r\n");
}

/// Le premier message qui échoue n'a rien à défaire derrière lui.
#[test]
fn un_copy_qui_echoue_au_premier_ne_defait_rien() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    let (texte, _) = dire(&mut session, b"a003 COPY 2 INBOX\r\n");
    assert!(
        texte.contains("NO Copy failed; no messages were copied"),
        "{texte}"
    );
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(fil.matches("* ").count(), 3, "{fil}");
}

/// Un `UID COPY` qui ne désigne rien réussit, et le nomme.
#[test]
fn un_uid_copy_qui_ne_designe_rien_le_nomme() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 UID COPY 999 INBOX\r\n");
    assert_eq!(texte, "a003 OK UID COPY completed\r\n");
}

/// Le débordement du `COPYUID` vaut aussi pour un `UID COPY`.
#[test]
fn un_uid_copy_qui_deborde_omet_aussi_son_copyuid() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Eparse\r\n");
    let (texte, _) = dire(&mut session, b"a003 UID COPY 1:* INBOX\r\n");
    assert_eq!(texte, "a003 OK UID COPY completed\r\n");
}

// ── `MOVE` ──────────────────────────────────────────────────────────────────

/// **§6.4.8 impose l'ordre des réponses** : d'abord `* OK [COPYUID …]`, qui dit
/// où les messages sont allés ; puis les `* n EXPUNGE`, qui disent qu'ils ne
/// sont plus là ; enfin la conclusion.
#[test]
fn move_dit_ou_avant_de_dire_que_ce_n_est_plus_la() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 MOVE 1:2 INBOX\r\n");
    assert_eq!(
        fil,
        "* OK [COPYUID 42 10,20 31:32] Moved\r\n\
         * 1 EXPUNGE\r\n* 1 EXPUNGE\r\n\
         a003 OK MOVE completed\r\n"
    );
    // Il reste l'ancien troisième et les deux copies.
    let reste = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 30)\r\n* 2 FETCH (UID 31)\r\n* 3 FETCH (UID 32)\r\n\
         a004 OK FETCH completed\r\n"
    );
}

/// **On retire par UID, même quand le client a désigné des rangs.** Retirer
/// renumérote : un ensemble de rangs cesserait de désigner ce qu'il désignait
/// dès le premier retrait, et l'on retirerait des messages que personne n'a
/// nommés.
#[test]
fn move_retire_ceux_qu_on_a_nommes_et_pas_leurs_voisins() {
    let mut session = selectionnee();
    // On déplace le PREMIER seulement : le deuxième ne doit pas suivre.
    let fil = ecouler(&mut session, b"a003 MOVE 1 INBOX\r\n");
    assert_eq!(
        fil,
        "* OK [COPYUID 42 10 31] Moved\r\n* 1 EXPUNGE\r\na003 OK MOVE completed\r\n"
    );
    let reste = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 20)\r\n* 2 FETCH (UID 30)\r\n* 3 FETCH (UID 31)\r\n\
         a004 OK FETCH completed\r\n"
    );
}

/// **`UID MOVE` désigne par UID**, et le dit dans sa conclusion.
#[test]
fn uid_move_designe_par_uid() {
    let mut session = selectionnee();
    let fil = ecouler(&mut session, b"a003 UID MOVE 30 INBOX\r\n");
    assert_eq!(
        fil,
        "* OK [COPYUID 42 30 31] Moved\r\n* 3 EXPUNGE\r\na003 OK UID MOVE completed\r\n"
    );
}

/// **§6.4.8 : une destination qui n'existe pas se dit `[TRYCREATE]`.**
#[test]
fn une_destination_inconnue_se_dit_trycreate_aussi_pour_move() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 MOVE 1 Inconnue\r\n");
    assert!(
        texte.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{texte}"
    );
}

/// **Un `MOVE` qui ne peut pas tout copier ne déplace rien**, et défait ses
/// copies : rien n'est retiré de la source.
#[test]
fn un_move_qui_echoue_ne_retire_rien() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Tetue\r\n");
    let (texte, _) = dire(&mut session, b"a003 MOVE 1:3 INBOX\r\n");
    assert!(
        texte.contains("NO Move failed; no messages were moved"),
        "{texte}"
    );
    let fil = ecouler(&mut session, b"a004 FETCH 1:* UID\r\n");
    assert_eq!(fil.matches("* ").count(), 3, "{fil}");
}

/// Rien à déplacer n'est pas un échec.
#[test]
fn un_move_qui_ne_designe_rien_reussit() {
    let mut session = selectionnee();
    let (texte, action) = dire(&mut session, b"a003 MOVE 9 INBOX\r\n");
    assert_eq!(texte, "a003 OK MOVE completed\r\n");
    assert_eq!(action, Action::Continue);
    let (aussi, _) = dire(&mut session, b"a004 UID MOVE 999 INBOX\r\n");
    assert_eq!(aussi, "a004 OK UID MOVE completed\r\n");
}

/// **Un ensemble qu'on ne saurait plus nommer fait REFUSER le déplacement**, et
/// défaire les copies : retirer au hasard serait perdre du courrier.
#[test]
fn un_move_dont_l_ensemble_est_trop_morcele_se_refuse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Eparse\r\n");
    let (texte, _) = dire(&mut session, b"a003 MOVE 1:* INBOX\r\n");
    assert!(
        texte.contains("NO [CANNOT] Move set is too fragmented"),
        "{texte}"
    );
    // La source est intacte : soixante messages, et pas un de plus.
    let fil = ecouler(&mut session, b"a004 SEARCH ALL\r\n");
    assert!(fil.contains("ALL 1:60"), "{fil}");
}

#[test]
fn un_move_mal_forme_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 MOVE\r\n"[..],
        b"a004 MOVE 1\r\n",
        b"a005 MOVE x INBOX\r\n",
        b"a006 MOVE 1 \r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD MOVE expects a sequence set and a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un `MOVE` hors sélection est hors d'état, pas hors de service.**
#[test]
fn un_move_sans_boite_ouverte_est_hors_d_etat() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 MOVE 1 INBOX\r\n");
    assert!(
        texte.contains("BAD Command is not allowed unless a mailbox is selected"),
        "{texte}"
    );
}

// ── `APPEND` ────────────────────────────────────────────────────────────────

/// Conduit un `APPEND` de bout en bout, et rend la conclusion.
fn deposer(
    session: &mut Session<UnCompte, Boites>,
    ligne: &[u8],
    message: &[u8],
) -> std::string::String {
    let mut sortie = [0_u8; 1024];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("un APPEND qu'on sait écouler");
    let tour = session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    if tour.action() != Action::ReadAppend {
        // Refusé avant d'avoir rien lu : c'est l'intérêt du synchronisant.
        return std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    }
    // On écoule par petits morceaux : c'est ce que fait la boucle.
    let mut reste = message;
    while !reste.is_empty() && session.append_remaining() > 0 {
        let coupe = reste.len().min(7);
        let pris = session.append_chunk(reste.get(..coupe).unwrap_or_default());
        reste = reste.get(pris..).unwrap_or_default();
    }
    let fin = session.end_append(&mut sortie).expect("traitable");
    std::string::String::from_utf8_lossy(fin.reply()).into_owned()
}

/// **§6.3.12 : `APPENDUID` dit où le message est allé.**
#[test]
fn append_depose_le_message_et_dit_ou() {
    let boites = Boites::default();
    let ecrit = std::rc::Rc::clone(&boites.ecrit);
    let valide = std::rc::Rc::clone(&boites.valide);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(
        &mut session,
        b"a002 APPEND INBOX {13}\r\n",
        b"Bonjour !\r\n\r\n",
    );
    assert_eq!(conclusion, "a002 OK [APPENDUID 42 31] APPEND completed\r\n");
    assert_eq!(&*ecrit.borrow(), b"Bonjour !\r\n\r\n");
    assert_eq!(valide.get(), Some((31, Flags::NONE, None)));
}

/// **Les drapeaux et la date suivent le message** (§6.3.12).
#[test]
fn les_drapeaux_et_la_date_arrivent_avec_le_message() {
    let boites = Boites::default();
    let valide = std::rc::Rc::clone(&boites.valide);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(
        &mut session,
        b"a002 APPEND INBOX (\\Seen \\Draft) \"29-Aug-2026 07:08:31 +0000\" {5}\r\n",
        b"salut",
    );
    assert!(conclusion.contains("OK [APPENDUID 42 31]"), "{conclusion}");
    let (uid, flags, date) = valide.get().expect("validé");
    assert_eq!(uid, 31);
    assert!(flags.contains(Flags::SEEN));
    assert!(flags.contains(Flags::DRAFT));
    assert_eq!(date, Some(1_787_987_311));
}

/// **On lit même ce qu'on refuse.** Les octets d'un littéral non synchronisant
/// arrivent quoi qu'on réponde ; ne pas les lire ferait lire un message comme
/// des commandes. Un littéral SYNCHRONISANT, lui, se refuse avant d'inviter :
/// inviter puis refuser ferait attendre le serveur pour des octets que le client
/// n'enverra jamais.
#[test]
fn une_boite_inconnue_se_dit_trycreate_apres_avoir_tout_lu() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    // Non synchronisant : les octets arrivent quoi qu'on réponde.
    let conclusion = deposer(&mut session, b"a002 APPEND Inconnue {5+}\r\n", b"salut");
    assert!(
        conclusion.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{conclusion}"
    );
    assert_eq!(session.append_remaining(), 0);

    // Le même, synchronisant : refusé sans qu'un octet ait été lu.
    let mut sortie = [0_u8; 1024];
    let ligne = &b"a003 APPEND Inconnue {5}\r\n"[..];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("écoulable");
    let tour = session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    assert_eq!(tour.action(), Action::Continue);
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(texte.contains("NO [TRYCREATE]"), "{texte}");
    assert_eq!(session.append_remaining(), 0);
}

/// **Un magasin qui lâche en route ne fait pas cesser la lecture** : les octets
/// restants sont un message, pas des commandes.
#[test]
fn un_magasin_qui_lache_ne_fait_pas_cesser_la_lecture() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(
        &mut session,
        b"a002 APPEND Refusante {9}\r\n",
        b"un message",
    );
    assert!(
        conclusion.contains("NO Append failed; the message was not stored"),
        "{conclusion}"
    );
    assert_eq!(session.append_remaining(), 0);
}

/// Un dépôt qui refuse de se valider est un échec, pas un succès muet.
#[test]
fn un_depot_qui_refuse_de_se_valider_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let conclusion = deposer(&mut session, b"a002 APPEND Ingrate {5}\r\n", b"salut");
    assert!(
        conclusion.contains("NO Append failed; the message was not stored"),
        "{conclusion}"
    );
}

/// **VALIDER UN MESSAGE TRONQUÉ serait déposer du courrier que personne n'a
/// envoyé.** Le pair a raccroché au milieu : rien ne se dépose.
#[test]
fn un_message_tronque_ne_se_depose_pas() {
    let boites = Boites::default();
    let ecrit = std::rc::Rc::clone(&boites.ecrit);
    let mut session = Session::new(BORNES, true, UnCompte, boites);
    session.on_tls_established();
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let mut sortie = [0_u8; 1024];
    let ligne = &b"a002 APPEND INBOX {20}\r\n"[..];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("écoulable");
    session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    session.append_chunk(b"court");
    assert_eq!(session.append_remaining(), 15);
    let fin = session.end_append(&mut sortie).expect("traitable");
    let conclusion = std::string::String::from_utf8_lossy(fin.reply()).into_owned();
    assert!(
        conclusion.contains("NO Append failed; the message was not stored"),
        "{conclusion}"
    );
    // Le dépôt a été abandonné : il n'en subsiste rien.
    assert!(ecrit.borrow().is_empty());
}

/// **Un `APPEND` avant authentification n'est pas un `APPEND`.**
#[test]
fn un_append_avant_authentification_est_refuse() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 1024];
    let ligne = &b"a001 APPEND INBOX {5}\r\n"[..];
    let append = ams_proto_imap::Append::parse(ligne, 1_000_000)
        .expect("lisible")
        .expect("écoulable");
    let tour = session
        .begin_append(ligne, &append, &mut sortie)
        .expect("traitable");
    let texte = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
    assert_eq!(tour.action(), Action::Continue);

    // Non synchronisant : les octets arrivent, on les jette, et l'on répond à la
    // fin.
    let conclusion = deposer(&mut session, b"a002 APPEND INBOX {5+}\r\n", b"salut");
    assert!(
        conclusion.contains("BAD Command is not allowed before authentication"),
        "{conclusion}"
    );
}

/// Conclure un `APPEND` qu'on n'a pas commencé n'est pas un `APPEND`.
#[test]
fn conclure_un_append_qui_n_existe_pas_est_une_faute() {
    let mut session = nouvelle(true);
    let mut sortie = [0_u8; 1024];
    let fin = session.end_append(&mut sortie).expect("traitable");
    let texte = std::string::String::from_utf8_lossy(fin.reply()).into_owned();
    assert!(texte.contains("BAD No APPEND in progress"), "{texte}");
    // Et écouler sans dépôt ne consomme rien.
    assert_eq!(session.append_chunk(b"x"), 0);
}

/// **Un `APPEND` qui passe par le chemin ordinaire n'est pas celui qu'on sait
/// écouler** : c'est un nom de boîte donné comme littéral, ou pas de littéral
/// du tout.
#[test]
fn un_append_du_chemin_ordinaire_se_refuse_en_le_disant() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 APPEND INBOX\r\n");
    assert!(
        texte.contains("BAD APPEND expects a mailbox name and a message literal"),
        "{texte}"
    );
}

// ── `CREATE` ────────────────────────────────────────────────────────────────

/// **Une boîte créée se voit** : `LIST` la rend, et `SELECT` l'ouvre.
#[test]
fn une_boite_creee_apparait_dans_la_liste() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE Brouillons\r\n");
    assert!(texte.contains("a002 OK CREATE completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        liste.contains("* LIST (\\HasNoChildren) \"/\" \"Brouillons\"\r\n"),
        "{liste}"
    );
}

/// **§6.3.4 : `INBOX` existe toujours**, et ne se crée donc pas.
#[test]
fn inbox_ne_se_cree_pas() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 CREATE INBOX\r\n"[..], b"a003 CREATE inbox\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("NO [ALREADYEXISTS] INBOX always exists"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Une boîte qui existe déjà se dit `[ALREADYEXISTS]`** (§6.3.4).
#[test]
fn une_boite_deja_la_se_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE Archives\r\n");
    assert!(
        texte.contains("NO [ALREADYEXISTS] Mailbox already exists"),
        "{texte}"
    );
    // Et deux fois la même création, aussi.
    dire(&mut session, b"a003 CREATE Neuve\r\n");
    let (deux, _) = dire(&mut session, b"a004 CREATE Neuve\r\n");
    assert!(deux.contains("NO [ALREADYEXISTS]"), "{deux}");
}

/// **Un nom qu'on ne sait pas transcrire est REFUSÉ, pas transformé.** Rendre au
/// client un nom qui n'est pas celui qu'il a demandé lui ferait chercher
/// longtemps — et transcrire, c'est ouvrir la porte à ce qu'on ne voit pas.
#[test]
fn un_nom_dangereux_se_refuse_sans_le_transformer() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for nom in [
        &b"\"../etc\""[..],
        b"\"a/../b\"",
        b"\"Sent.2026\"",
        b"\"a//b\"",
        b"\"/absolu\"",
        b"\"a%b\"",
    ] {
        let mut commande = std::vec::Vec::from(&b"a002 CREATE "[..]);
        commande.extend_from_slice(nom);
        commande.extend_from_slice(b"\r\n");
        let (texte, _) = dire(&mut session, &commande);
        assert!(
            texte.contains("NO [CANNOT] This mailbox name is not served"),
            "{:?} : {texte}",
            core::str::from_utf8(nom)
        );
    }
}

/// **« Sent Messages » est un nom de dossier des plus ordinaires**, et la
/// réponse le cite entre guillemets plutôt que de le rendre nu — deux mots là où
/// il y en a un se liraient mal.
#[test]
fn un_nom_avec_un_espace_se_cree_et_se_cite() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE \"Sent Messages\"\r\n");
    assert!(texte.contains("a002 OK CREATE completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        liste.contains("* LIST (\\HasNoChildren) \"/\" \"Sent Messages\"\r\n"),
        "{liste}"
    );
}

/// Un `/` final ne change pas la boîte désignée (§6.3.4).
#[test]
fn un_slash_final_ne_change_pas_la_boite() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE \"Archives/\"\r\n");
    assert!(texte.contains("NO [ALREADYEXISTS]"), "{texte}");
}

/// Un magasin qui refuse le dit, et ce n'est pas une faute du client.
#[test]
fn un_magasin_qui_refuse_de_creer_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 CREATE Impossible\r\n");
    assert!(texte.contains("NO Cannot create mailbox"), "{texte}");
}

#[test]
fn un_create_mal_forme_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 CREATE\r\n"[..], b"a003 CREATE \r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD CREATE expects a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un `CREATE` avant authentification n'est pas un `CREATE`.**
#[test]
fn un_create_avant_authentification_est_refuse() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 CREATE Brouillons\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}

/// **L'invariant qui porte tout le reste** : on ne peut pas être AUTHENTIFIÉ
/// sans être chiffré.
///
/// Le fuzz a trouvé une suite qu'il croyait le franchir ; c'était sa propriété
/// qui était mal dite. `LOGOUT` mène à l'état `Logout`, qui n'est ni
/// authentifié ni chiffré — et qui ne donne accès à rien. Ce qu'il faut exclure,
/// ce sont les deux états qui donnent accès au courrier.
#[test]
fn on_ne_peut_pas_etre_authentifie_sans_chiffrement() {
    let mut session = nouvelle(false);
    let flux: &[u8] = b"a001 C+APABILI\x00OX\r\na004 LOGOUT\r\n`BIL[ITY\r\n;0\x00\x00`a002v2e-t1 CAPABIa003 SELECT INBOX\r\na00\xcc\xdf\xb3\xb0\xb8\xb0\xaa\xab\r\n";
    let mut sortie = [0_u8; 4096];
    let mut lecteur = ams_proto_imap::CommandReader::new();
    let mut reste = flux;
    for _ in 0..20 {
        let Ok(ams_proto_imap::Need::Complete(longueur)) = lecteur.poll(reste, &BORNES) else {
            break;
        };
        let commande = reste.get(..longueur).unwrap_or_default();
        let Ok(_) = session.handle(commande, &mut sortie) else {
            break;
        };
        assert!(
            !matches!(session.state(), State::Authenticated | State::Selected)
                || session.is_encrypted(),
            "authentifié sans chiffrement après {:?}",
            std::string::String::from_utf8_lossy(commande)
        );
        reste = reste.get(longueur..).unwrap_or_default();
        lecteur.reset();
    }
}

// ── `DELETE` ────────────────────────────────────────────────────────────────

/// Une boîte sans fille disparaît, nom compris.
#[test]
fn une_boite_sans_fille_disparait() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Brouillons\r\n");
    let (texte, _) = dire(&mut session, b"a003 DELETE Brouillons\r\n");
    assert!(texte.contains("a003 OK DELETE completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a004 LIST \"\" *\r\n");
    assert!(!liste.contains("Brouillons"), "{liste}");
}

/// **§6.3.5 : une boîte qui a des filles ne disparaît pas.** Son courrier s'en
/// va, son nom demeure et se marque `\Noselect` — l'effacer romprait la
/// hiérarchie, et ses filles n'auraient plus de chemin.
#[test]
fn une_boite_qui_a_des_filles_garde_son_nom() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 DELETE Archives\r\n");
    assert!(texte.contains("a002 OK DELETE completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        liste.contains("* LIST (\\Noselect \\HasChildren) \"/\" \"Archives\"\r\n"),
        "{liste}"
    );
    // Et la fille est toujours atteignable.
    assert!(
        liste.contains("* LIST (\\HasNoChildren) \"/\" \"Archives/2026\"\r\n"),
        "{liste}"
    );
}

/// **§6.3.5 : `INBOX` ne s'efface pas.** C'est le seul endroit où le courrier
/// arrive.
#[test]
fn inbox_ne_s_efface_pas() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 DELETE INBOX\r\n"[..], b"a003 DELETE inbox\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("NO [CANNOT] INBOX cannot be deleted"),
            "{commande:?} : {texte}"
        );
    }
}

/// Une boîte qui n'existe pas se dit `[NONEXISTENT]`, y compris quand son nom
/// n'en est pas un.
#[test]
fn une_boite_absente_se_dit_nonexistent() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for nom in [&b"Inconnue"[..], b"\"../etc\"", b"\"a.b\""] {
        let mut commande = std::vec::Vec::from(&b"a002 DELETE "[..]);
        commande.extend_from_slice(nom);
        commande.extend_from_slice(b"\r\n");
        let (texte, _) = dire(&mut session, &commande);
        assert!(
            texte.contains("NO [NONEXISTENT] Mailbox does not exist"),
            "{:?} : {texte}",
            core::str::from_utf8(nom)
        );
    }
}

/// **On ne garde pas ouverte une boîte qu'on vient d'effacer** : la session en
/// tient un instantané qui ne désigne plus rien.
#[test]
fn effacer_la_boite_ouverte_la_referme() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Archives\r\n");
    assert_eq!(session.state(), State::Selected);
    let (texte, _) = dire(&mut session, b"a003 DELETE Archives\r\n");
    assert!(texte.contains("OK DELETE completed"), "{texte}");
    assert_eq!(session.state(), State::Authenticated);
    assert!(session.selected().is_empty());
}

/// Un magasin qui refuse le dit, et ce n'est pas une faute du client.
#[test]
fn un_magasin_qui_refuse_d_effacer_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Impossible2\r\n");
    let (texte, _) = dire(&mut session, b"a003 DELETE Impossible2\r\n");
    assert!(texte.contains("NO Cannot delete mailbox"), "{texte}");
}

#[test]
fn un_delete_mal_forme_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [&b"a002 DELETE\r\n"[..], b"a003 DELETE \r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD DELETE expects a mailbox name"),
            "{commande:?} : {texte}"
        );
    }
}

/// **Un `DELETE` avant authentification n'est pas un `DELETE`.**
#[test]
fn un_delete_avant_authentification_est_refuse() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 DELETE Brouillons\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}

// ── `RENAME` ────────────────────────────────────────────────────────────────

/// **§6.3.6 : les filles suivent.** Les laisser derrière ferait des boîtes dont
/// le chemin ne mène plus nulle part.
#[test]
fn renommer_une_mere_renomme_ses_filles() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Vieux/2026\r\n");
    dire(&mut session, b"a003 CREATE Vieux/2025\r\n");
    let (texte, _) = dire(&mut session, b"a004 RENAME Vieux Anciens\r\n");
    assert!(texte.contains("a004 OK RENAME completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a005 LIST \"\" *\r\n");
    assert!(liste.contains("\"Anciens/2026\""), "{liste}");
    assert!(liste.contains("\"Anciens/2025\""), "{liste}");
    assert!(!liste.contains("Vieux"), "{liste}");
}

/// **§6.3.6 : `INBOX` se renomme, et ne disparaît pas.** Son courrier s'en va
/// vers le nouveau nom ; elle reste, vide.
#[test]
fn renommer_inbox_la_vide_sans_la_faire_disparaitre() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 RENAME INBOX Sauvegarde\r\n");
    assert!(texte.contains("a002 OK RENAME completed"), "{texte}");
    let (liste, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(liste.contains("\"INBOX\""), "{liste}");
    assert!(liste.contains("\"Sauvegarde\""), "{liste}");
}

/// **Rien ne se renomme EN `INBOX`** : elle existe déjà, de tout temps.
#[test]
fn rien_ne_se_renomme_en_inbox() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 RENAME Archives INBOX\r\n");
    assert!(
        texte.contains("NO [ALREADYEXISTS] INBOX always exists"),
        "{texte}"
    );
}

/// **Une boîte ne se range pas sous elle-même.**
#[test]
fn une_boite_ne_se_range_pas_sous_elle_meme() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 RENAME Archives Archives/vieux\r\n");
    assert!(
        texte.contains("NO [CANNOT] A mailbox cannot be renamed under itself"),
        "{texte}"
    );
}

#[test]
fn les_deux_bouts_du_renommage_se_verifient() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    // La source doit exister.
    let (absente, _) = dire(&mut session, b"a002 RENAME Inconnue Autre\r\n");
    assert!(absente.contains("NO [NONEXISTENT]"), "{absente}");
    // Une source qu'on ne saurait pas transcrire n'existe pas non plus.
    let (fautive, _) = dire(&mut session, b"a003 RENAME \"a.b\" Autre\r\n");
    assert!(fautive.contains("NO [NONEXISTENT]"), "{fautive}");
    // La destination ne doit pas exister.
    let (deja, _) = dire(&mut session, b"a004 RENAME Archives \"Archives/2026\"\r\n");
    assert!(deja.contains("NO [CANNOT]"), "{deja}");
    let (prise, _) = dire(&mut session, b"a005 RENAME \"Archives/2026\" Archives\r\n");
    assert!(prise.contains("NO [ALREADYEXISTS]"), "{prise}");
    // Et elle doit être transcriptible.
    let (mauvaise, _) = dire(&mut session, b"a006 RENAME Archives \"../ailleurs\"\r\n");
    assert!(mauvaise.contains("NO [CANNOT]"), "{mauvaise}");
}

/// **On ne garde pas ouverte une boîte qui a changé de nom** — ni une de ses
/// filles.
#[test]
fn renommer_la_boite_ouverte_la_referme() {
    for (ouverte, renommee) in [
        (
            &b"a002 SELECT Archives\r\n"[..],
            &b"a003 RENAME Archives Vieux\r\n"[..],
        ),
        (
            b"a002 SELECT \"Archives/2026\"\r\n",
            b"a003 RENAME Archives Vieux\r\n",
        ),
    ] {
        let mut session = nouvelle(true);
        dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
        dire(&mut session, ouverte);
        assert_eq!(session.state(), State::Selected);
        let (texte, _) = dire(&mut session, renommee);
        assert!(texte.contains("OK RENAME completed"), "{texte}");
        assert_eq!(session.state(), State::Authenticated, "{ouverte:?}");
        assert!(session.selected().is_empty());
    }
}

/// Un magasin qui refuse le dit, et n'a rien changé.
#[test]
fn un_magasin_qui_refuse_de_renommer_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 RENAME Archives Impossible3\r\n");
    assert!(texte.contains("NO Cannot rename mailbox"), "{texte}");
}

#[test]
fn un_rename_mal_forme_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [
        &b"a002 RENAME\r\n"[..],
        b"a003 RENAME Archives\r\n",
        b"a004 RENAME a b c\r\n",
        b"a005 RENAME \"\" b\r\n",
        b"a006 RENAME a \"\"\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD RENAME expects two mailbox names"),
            "{commande:?} : {texte}"
        );
    }
    // Un nom plus long que ce que la session retient.
    let mut trop = std::vec::Vec::from(&b"a007 RENAME Archives \""[..]);
    trop.resize(trop.len() + super::MAILBOX_NAME_MAX + 8, b'x');
    trop.extend_from_slice(b"\"\r\n");
    let (texte, _) = dire(&mut session, &trop);
    assert!(
        texte.contains("BAD RENAME arguments are too long"),
        "{texte}"
    );
}

/// **Un `RENAME` avant authentification n'est pas un `RENAME`.**
#[test]
fn un_rename_avant_authentification_est_refuse() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 RENAME a b\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}

// ── `NAMESPACE`, `ENABLE`, et ce qu'un `LIST` doit dire ─────────────────────

/// **`NAMESPACE` DIT OÙ LES BOÎTES VIVENT** (§6.3.10), et `NIL` n'est pas « je ne
/// sais pas » : c'est « il n'y en a pas ». Un client qui lirait une liste vide
/// chercherait encore.
#[test]
fn namespace_dit_l_espace_et_l_absence_des_autres() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, action) = dire(&mut session, b"a002 NAMESPACE\r\n");
    assert_eq!(action, Action::Continue);
    assert_eq!(
        texte,
        "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\na002 OK NAMESPACE completed\r\n"
    );
}

/// Avant l'authentification, il n'y a pas d'espace à dire.
#[test]
fn namespace_avant_l_authentification_est_une_faute() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 NAMESPACE\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}

/// **`ENABLE` N'ACTIVE RIEN, ET LE DIT.** Se taire laisserait le client se
/// demander si la commande a été comprise.
#[test]
fn enable_n_active_rien_et_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 ENABLE CONDSTORE\r\n");
    assert_eq!(texte, "* ENABLED\r\na002 OK ENABLE completed\r\n");
}

/// **L'ÉTAT COMPTE** : §6.3.1 réserve `ENABLE` à l'état authentifié, AVANT toute
/// sélection — une extension activée en cours de session changerait ce que des
/// réponses déjà en vol signifient.
#[test]
fn enable_ne_s_active_pas_une_boite_ouverte() {
    let mut session = selectionnee();
    let (texte, _) = dire(&mut session, b"a003 ENABLE CONDSTORE\r\n");
    assert!(
        texte.contains("BAD ENABLE is not allowed while a mailbox is selected"),
        "{texte}"
    );
    // Et sans rien à activer, il n'y a rien à demander.
    let mut autre = nouvelle(true);
    dire(&mut autre, b"a001 LOGIN jean ouvre-toi\r\n");
    let (vide, _) = dire(&mut autre, b"a002 ENABLE\r\n");
    assert!(
        vide.contains("BAD ENABLE expects at least one capability"),
        "{vide}"
    );
    // Avant l'authentification non plus.
    let mut nue = nouvelle(true);
    let (tot, _) = dire(&mut nue, b"a001 ENABLE CONDSTORE\r\n");
    assert!(
        tot.contains("BAD Command is not allowed before authentication"),
        "{tot}"
    );
}

/// **TOUT `LIST` PORTE `\HasChildren` OU `\HasNoChildren`** (§7.3.1). Ne rien
/// dire obligerait le client à interroger chaque boîte pour savoir s'il faut
/// dessiner un triangle d'ouverture.
#[test]
fn un_list_dit_toujours_s_il_y_a_des_filles() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 LIST \"\" *\r\n");
    assert!(
        texte.contains("* LIST (\\HasNoChildren) \"/\" \"INBOX\""),
        "{texte}"
    );
    assert!(
        texte.contains("* LIST (\\HasChildren) \"/\" \"Archives\""),
        "{texte}"
    );
    assert!(
        texte.contains("* LIST (\\HasNoChildren) \"/\" \"Archives/2026\""),
        "{texte}"
    );
}

/// Une commande d'état qu'on ne sert pas se refuse avant l'authentification pour
/// ce qu'elle est — non authentifiée —, et non pour ce qu'elle demande.
#[test]
fn une_commande_de_boite_avant_l_authentification_est_une_faute() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 SUBSCRIBE Archives\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}

/// Un tampon trop court le dit, pour l'espace comme pour l'activation.
#[test]
fn un_tampon_trop_court_pour_ces_reponses_le_dit() {
    for commande in [&b"a002 NAMESPACE\r\n"[..], b"a002 ENABLE CONDSTORE\r\n"] {
        for taille in 1..=40_usize {
            let mut session = nouvelle(true);
            dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
            let mut petit = std::vec![0_u8; taille];
            // Ce qui ne tient pas se dit ; ce qui tient se rend.
            match session.handle(commande, &mut petit) {
                Ok(tour) => assert!(!tour.reply().is_empty()),
                Err(erreur) => assert!(matches!(erreur, super::Error::Reply(_)), "{erreur:?}"),
            }
        }
    }
}

/// Une boîte effacée SANS fille porte les deux marques aussi : elle ne s'ouvre
/// pas, et elle n'en a pas.
#[test]
fn une_boite_videe_sans_fille_porte_les_deux_marques() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 DELETE Archives/2026\r\n");
    let (texte, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        texte.contains("* LIST (\\Noselect \\HasNoChildren) \"/\" \"Archives/2026\""),
        "{texte}"
    );
}

/// Une boîte effacée qui avait des filles porte les deux marques : elle ne
/// s'ouvre pas, et elle en a.
#[test]
fn une_boite_videe_porte_les_deux_marques() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 DELETE Archives\r\n");
    let (texte, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        texte.contains("* LIST (\\Noselect \\HasChildren) \"/\" \"Archives\""),
        "{texte}"
    );
}

// ── `IDLE` ──────────────────────────────────────────────────────────────────

/// **LA CONTINUATION N'EST PAS UNE CONCLUSION.** `+ idling` dit que l'attente
/// commence ; la conclusion étiquetée ne vient qu'après le `DONE`.
#[test]
fn idle_ouvre_l_attente_sans_la_conclure() {
    let mut session = selectionnee();
    let mut sortie = [0_u8; 512];
    let tour = session
        .handle(b"a003 IDLE\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(tour.action(), Action::Idle);
    assert_eq!(
        std::string::String::from_utf8_lossy(tour.reply()),
        "+ idling\r\n"
    );
}

/// `DONE` conclut, et rien d'autre ne le fait.
#[test]
fn seul_done_conclut_l_attente() {
    let mut session = selectionnee();
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a003 IDLE\r\n", &mut sortie)
        .expect("traitable");
    let tour = session
        .end_idle(b"DONE\r\n", &mut sortie)
        .expect("conclusion");
    assert_eq!(tour.action(), Action::Continue);
    assert_eq!(
        std::string::String::from_utf8_lossy(tour.reply()),
        "a003 OK IDLE terminated\r\n"
    );
    // La casse ne compte pas ; ce qui n'est pas `DONE` est une faute.
    session
        .handle(b"a004 IDLE\r\n", &mut sortie)
        .expect("traitable");
    let minuscule = session
        .end_idle(b"done\r\n", &mut sortie)
        .expect("conclusion");
    assert!(
        std::string::String::from_utf8_lossy(minuscule.reply()).contains("a004 OK"),
        "la casse ne compte pas"
    );
    session
        .handle(b"a005 IDLE\r\n", &mut sortie)
        .expect("traitable");
    let autre = session
        .end_idle(b"a006 NOOP\r\n", &mut sortie)
        .expect("conclusion");
    assert!(
        std::string::String::from_utf8_lossy(autre.reply())
            .contains("BAD Expected DONE while idling"),
        "ce qui n'est pas DONE est une faute"
    );
}

/// **SEULE LA CROISSANCE SE DIT**, et elle ne se dit qu'une fois.
#[test]
fn seule_la_croissance_se_dit_et_une_seule_fois() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Vivante\r\n");
    let mut sortie = [0_u8; 512];
    session
        .handle(b"a003 IDLE\r\n", &mut sortie)
        .expect("traitable");

    // Le premier regard voit le message qui vient d'arriver.
    let ecrits = session.idle_poll(&mut sortie).expect("regard");
    assert_eq!(
        std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()),
        "* 2 EXISTS\r\n"
    );
    // Le second ne redit rien : le compte n'a pas changé.
    assert_eq!(session.idle_poll(&mut sortie).expect("regard"), 0);
}

/// **SANS BOÎTE OUVERTE, `IDLE` ATTEND SANS RIEN AVOIR À DIRE**, ce que §6.3.13
/// permet — c'est ce que fait un client qui garde sa connexion chaude.
#[test]
fn idle_sans_boite_ouverte_attend_sans_rien_dire() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let mut sortie = [0_u8; 512];
    let tour = session
        .handle(b"a002 IDLE\r\n", &mut sortie)
        .expect("traitable");
    assert_eq!(tour.action(), Action::Idle);
    assert_eq!(session.idle_poll(&mut sortie).expect("regard"), 0);
}

/// Avant l'authentification, il n'y a rien à attendre.
#[test]
fn idle_avant_l_authentification_est_une_faute() {
    let mut session = nouvelle(true);
    let (texte, _) = dire(&mut session, b"a001 IDLE\r\n");
    assert!(
        texte.contains("BAD Command is not allowed before authentication"),
        "{texte}"
    );
}

/// **ON RACCROCHE EN LE DISANT** : abandonner sans un mot laisserait le client
/// croire qu'il idle encore, et attendre du courrier qui ne viendrait jamais.
#[test]
fn une_attente_trop_longue_se_dit() {
    let session = selectionnee();
    let mut sortie = [0_u8; 512];
    let adieu = session.idle_timed_out(&mut sortie).expect("congé");
    assert_eq!(
        std::string::String::from_utf8_lossy(adieu),
        "* BYE Idle timeout\r\n"
    );
}

/// Un tampon trop court le dit, pour l'attente comme pour le reste.
#[test]
fn un_tampon_trop_court_pour_l_attente_le_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Vivante\r\n");
    for taille in 0..12_usize {
        let mut petit = std::vec![0_u8; taille];
        assert!(session.idle_timed_out(&mut petit).is_err(), "{taille}");
        let mut autre = nouvelle(true);
        dire(&mut autre, b"a001 LOGIN jean ouvre-toi\r\n");
        dire(&mut autre, b"a002 SELECT Vivante\r\n");
        let mut place = std::vec![0_u8; taille];
        assert!(autre.idle_poll(&mut place).is_err(), "regard {taille}");
    }
}

// ── `SUBSCRIBE`, `UNSUBSCRIBE` ET LES ABONNEMENTS DE `LIST` ─────────────────

/// **L'ABONNEMENT EST DU COMPTE**, et `LIST` le rend quand on le lui demande.
#[test]
fn un_abonnement_se_pose_et_se_voit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (pose, _) = dire(&mut session, b"a002 SUBSCRIBE Archives\r\n");
    assert_eq!(pose, "a002 OK SUBSCRIBE completed\r\n");

    // Sans qu'on le demande, la liste ne dit rien de l'abonnement.
    let (muette, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(!muette.contains("\\Subscribed"), "{muette}");

    // Le RENSEIGNEMENT : tout, et lesquelles.
    let (dit, _) = dire(&mut session, b"a004 LIST \"\" * RETURN (SUBSCRIBED)\r\n");
    assert!(
        dit.contains("* LIST (\\Subscribed \\HasChildren) \"/\" \"Archives\"\r\n"),
        "{dit}"
    );
    assert!(dit.contains("\"INBOX\""), "{dit}");

    // Le FILTRE : rien d'autre.
    let (filtre, _) = dire(&mut session, b"a005 LIST (SUBSCRIBED) \"\" *\r\n");
    assert_eq!(
        filtre,
        "* LIST (\\Subscribed \\HasChildren) \"/\" \"Archives\"\r\n\
         a005 OK LIST completed\r\n"
    );
}

/// **SE RÉABONNER N'EST PAS UNE FAUTE**, et se désabonner de ce à quoi l'on
/// n'est pas abonné non plus : l'état demandé est déjà celui qu'on a.
#[test]
fn repeter_un_abonnement_n_est_pas_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SUBSCRIBE Archives\r\n");
    let (encore, _) = dire(&mut session, b"a003 SUBSCRIBE Archives\r\n");
    assert_eq!(encore, "a003 OK SUBSCRIBE completed\r\n");

    let (retire, _) = dire(&mut session, b"a004 UNSUBSCRIBE Archives\r\n");
    assert_eq!(retire, "a004 OK UNSUBSCRIBE completed\r\n");
    let (deja, _) = dire(&mut session, b"a005 UNSUBSCRIBE Archives\r\n");
    assert_eq!(deja, "a005 OK UNSUBSCRIBE completed\r\n");

    // Et la liste filtrée ne rend plus rien.
    let (vide, _) = dire(&mut session, b"a006 LIST (SUBSCRIBED) \"\" *\r\n");
    assert_eq!(vide, "a006 OK LIST completed\r\n");
}

/// **ON VALIDE À L'ABONNEMENT** : une boîte qui n'existe pas ne s'abonne pas.
#[test]
fn on_ne_s_abonne_pas_a_ce_qui_n_existe_pas() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (absente, _) = dire(&mut session, b"a002 SUBSCRIBE Fantome\r\n");
    assert_eq!(absente, "a002 NO [NONEXISTENT] No such mailbox\r\n");

    // Mais SE DÉSABONNER d'une boîte disparue marche, et c'est le point : sans
    // cela, un abonnement orphelin serait indélogeable.
    let (retire, _) = dire(&mut session, b"a003 UNSUBSCRIBE Fantome\r\n");
    assert_eq!(retire, "a003 OK UNSUBSCRIBE completed\r\n");
}

/// **UN ABONNEMENT SURVIT À L'EFFACEMENT DE SA BOÎTE** (§6.3.7), et le filtre
/// le rend marqué `\NonExistent` (§6.3.9.6).
#[test]
fn un_abonnement_survit_a_l_effacement_de_sa_boite() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Passagere\r\n");
    dire(&mut session, b"a003 SUBSCRIBE Passagere\r\n");
    dire(&mut session, b"a004 DELETE Passagere\r\n");

    let (filtre, _) = dire(&mut session, b"a005 LIST (SUBSCRIBED) \"\" *\r\n");
    assert_eq!(
        filtre,
        "* LIST (\\Subscribed \\NonExistent \\HasNoChildren) \"/\" \"Passagere\"\r\n\
         a005 OK LIST completed\r\n"
    );
    // Sans le filtre, une boîte qui n'existe pas ne paraît pas : `LIST` rend ce
    // qui EST, et c'est le filtre seul qui demande aussi ce qui n'est plus.
    let (tout, _) = dire(&mut session, b"a006 LIST \"\" * RETURN (SUBSCRIBED)\r\n");
    assert!(!tout.contains("Passagere"), "{tout}");
    // Et un motif qui ne lui correspond pas ne la rend pas non plus.
    let (ailleurs, _) = dire(&mut session, b"a007 LIST (SUBSCRIBED) \"\" Arch*\r\n");
    assert_eq!(ailleurs, "a007 OK LIST completed\r\n");
}

/// Ce que le magasin refuse se dit, et ce qui n'est pas un nom de boîte aussi.
#[test]
fn un_abonnement_refuse_se_dit() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (refus, _) = dire(&mut session, b"a002 SUBSCRIBE Tetue\r\n");
    assert_eq!(refus, "a002 NO Cannot subscribe to mailbox\r\n");
    let (autre, _) = dire(&mut session, b"a003 UNSUBSCRIBE Tetue\r\n");
    assert_eq!(autre, "a003 NO Cannot unsubscribe from mailbox\r\n");

    for commande in [
        &b"a004 SUBSCRIBE ../ailleurs\r\n"[..],
        b"a005 UNSUBSCRIBE ../ailleurs\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("NO [CANNOT] This mailbox name is not served"),
            "{commande:?} : {texte}"
        );
    }
    for commande in [&b"a006 SUBSCRIBE\r\n"[..], b"a007 UNSUBSCRIBE\r\n"] {
        let (texte, _) = dire(&mut session, commande);
        assert!(texte.contains("BAD"), "{commande:?} : {texte}");
        assert!(texte.contains("expects a mailbox name"), "{texte}");
    }
    // Avant l'authentification, il n'y a pas de compte à abonner.
    let mut vierge = nouvelle(true);
    let (avant, _) = dire(&mut vierge, b"a001 SUBSCRIBE INBOX\r\n");
    assert!(
        avant.contains("BAD Command is not allowed before authentication"),
        "{avant}"
    );
}

/// **`INBOX` S'ÉCRIT COMME LE CLIENT VEUT** (§5.1), et ne fait qu'un abonnement.
#[test]
fn inbox_s_abonne_quelle_qu_en_soit_la_casse() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (pose, _) = dire(&mut session, b"a002 SUBSCRIBE inbox\r\n");
    assert_eq!(pose, "a002 OK SUBSCRIBE completed\r\n");
    let (filtre, _) = dire(&mut session, b"a003 LIST (SUBSCRIBED) \"\" *\r\n");
    assert_eq!(
        filtre,
        "* LIST (\\Subscribed \\HasNoChildren) \"/\" \"INBOX\"\r\n\
         a003 OK LIST completed\r\n"
    );
    // Et se désabonner sous une autre casse retire bien le même abonnement.
    dire(&mut session, b"a004 UNSUBSCRIBE INBOX\r\n");
    let (vide, _) = dire(&mut session, b"a005 LIST (SUBSCRIBED) \"\" *\r\n");
    assert_eq!(vide, "a005 OK LIST completed\r\n");
}

/// **UN MOTIF VIDE DEMANDE LE SÉPARATEUR**, et rien d'autre (§6.3.9).
#[test]
fn un_motif_vide_demande_le_separateur() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 LIST \"\" \"\"\r\n");
    assert_eq!(
        texte,
        "* LIST (\\Noselect) \"/\" \"\"\r\n\
         a002 OK LIST completed\r\n"
    );
}

/// **UNE BOÎTE QUI RÉPOND À DEUX MOTIFS NE SE REND QU'UNE FOIS.**
#[test]
fn plusieurs_motifs_ne_rendent_pas_deux_fois_la_meme_boite() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 LIST \"\" (\"INBOX\" \"IN*\")\r\n");
    assert_eq!(
        texte,
        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n\
         a002 OK LIST completed\r\n"
    );
    // Deux motifs qui désignent des boîtes différentes en rendent deux.
    let (deux, _) = dire(&mut session, b"a003 LIST \"\" (\"INBOX\" \"Archives\")\r\n");
    assert!(deux.contains("\"INBOX\""), "{deux}");
    assert!(deux.contains("\"Archives\""), "{deux}");
    // Et aucun motif ne demande rien.
    let (rien, _) = dire(&mut session, b"a004 LIST \"\" ()\r\n");
    assert_eq!(rien, "a004 OK LIST completed\r\n");
}

/// Une option de `LIST` qu'on ne sert pas est une faute, pas un silence.
#[test]
fn une_option_de_list_qu_on_ne_sert_pas_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [
        &b"a002 LIST (RECURSIVEMATCH) \"\" *\r\n"[..],
        b"a003 LIST \"\" * RETURN (STATUS (RECENT))\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD LIST arguments are not well formed"),
            "{commande:?} : {texte}"
        );
    }
    // `CHILDREN` est admis sans rien changer : la réponse le porte déjà.
    let (avec, _) = dire(&mut session, b"a004 LIST \"\" * RETURN (CHILDREN)\r\n");
    assert!(
        avec.contains("* LIST (\\HasNoChildren) \"/\" \"INBOX\""),
        "{avec}"
    );
}

/// **LA RÉPONSE PORTE CE QUI A ÉTÉ DEMANDÉ**, dans l'ordre où on l'a demandé
/// (§7.3.3). Rendre toujours les mêmes trois est commode, et faux.
#[test]
fn status_rend_ce_qu_on_lui_demande_et_dans_l_ordre() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    // La boîte d'épreuve : trois messages, dont un `\Seen`, de 100, 200 et 300
    // octets.
    let (texte, _) = dire(&mut session, b"a002 STATUS INBOX (UNSEEN SIZE DELETED)\r\n");
    assert_eq!(
        texte,
        "* STATUS \"INBOX\" (UNSEEN 2 SIZE 600 DELETED 0)\r\n\
         a002 OK STATUS completed\r\n"
    );

    // Un seul élément ne rend que celui-là.
    let (seul, _) = dire(&mut session, b"a003 STATUS INBOX (UIDNEXT)\r\n");
    assert_eq!(
        seul,
        "* STATUS \"INBOX\" (UIDNEXT 31)\r\n\
         a003 OK STATUS completed\r\n"
    );

    // Et `\Deleted` se compte : on en marque un.
    dire(&mut session, b"a004 SELECT INBOX\r\n");
    ecouler(&mut session, b"a005 STORE 1 +FLAGS (\\Deleted)\r\n");
    let (marque, _) = dire(&mut session, b"a006 STATUS INBOX (DELETED UNSEEN)\r\n");
    assert_eq!(
        marque,
        "* STATUS \"INBOX\" (DELETED 1 UNSEEN 2)\r\n\
         a006 OK STATUS completed\r\n"
    );
}

/// **UN NOM CITÉ PORTE DES ESPACES**, et la liste commence après son guillemet.
#[test]
fn status_lit_un_nom_cite_avant_sa_liste() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 STATUS \"INBOX\" (MESSAGES)\r\n");
    assert_eq!(
        texte,
        "* STATUS \"INBOX\" (MESSAGES 3)\r\n\
         a002 OK STATUS completed\r\n"
    );
    // Un nom à espace n'existe pas dans la boîte d'épreuve, mais il doit être LU
    // comme un nom, et non coupé en deux.
    let (espace, _) = dire(
        &mut session,
        b"a003 STATUS \"Sent Messages\" (MESSAGES)\r\n",
    );
    assert!(espace.starts_with("a003 NO [NONEXISTENT]"), "{espace}");
}

/// Ce qui n'a pas la forme de §6.3.11 est une faute.
#[test]
fn une_liste_de_status_mal_formee_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    for commande in [
        // Pas de liste du tout.
        &b"a002 STATUS INBOX\r\n"[..],
        // Une liste vide : §9 en veut au moins un élément.
        b"a003 STATUS INBOX ()\r\n",
        // Un mot qui n'est pas un élément — `RECENT` a disparu de rev2.
        b"a004 STATUS INBOX (RECENT)\r\n",
        b"a005 STATUS INBOX (TAILLE)\r\n",
        // Une parenthèse qui ne se ferme pas.
        b"a006 STATUS INBOX (MESSAGES\r\n",
        // Rien du tout.
        b"a007 STATUS\r\n",
        // Un guillemet qui ne se ferme pas.
        b"a008 STATUS \"INBOX (MESSAGES)\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD STATUS expects a mailbox name and items"),
            "{commande:?} : {texte}"
        );
    }
}

/// **`RETURN (STATUS (…))` REND UN `STATUS` PAR BOÎTE** (§6.3.9.7) : c'est une
/// commande là où il en fallait vingt.
#[test]
fn list_rend_le_status_de_chaque_boite_quand_on_le_demande() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(
        &mut session,
        b"a002 LIST \"\" INBOX RETURN (STATUS (MESSAGES UNSEEN))\r\n",
    );
    assert_eq!(
        texte,
        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n\
         * STATUS \"INBOX\" (MESSAGES 3 UNSEEN 2)\r\n\
         a002 OK LIST completed\r\n"
    );

    // **UNE BOÎTE LISTÉE QUE LE MAGASIN N'OUVRE PAS N'A PAS DE `STATUS`** non
    // plus : celle-ci se nomme et ne s'ouvre pas — un autre outil a pu la
    // retirer entre la liste et la question. On ne rend alors que sa ligne de
    // liste, sans zéros qu'on prendrait pour une boîte vide.
    dire(&mut session, b"a003 CREATE Fugace\r\n");
    let (toutes, _) = dire(
        &mut session,
        b"a004 LIST \"\" Fugace RETURN (STATUS (MESSAGES))\r\n",
    );
    assert_eq!(
        toutes,
        "* LIST (\\HasNoChildren) \"/\" \"Fugace\"\r\n\
         a004 OK LIST completed\r\n"
    );

    // Sans l'option, aucune ligne de `STATUS`.
    let (sans, _) = dire(&mut session, b"a005 LIST \"\" INBOX\r\n");
    assert!(!sans.contains("STATUS"), "{sans}");

    // **UNE BOÎTE QU'ON NE PEUT PAS OUVRIR N'A PAS DE `STATUS`** : `Archives` se
    // vide en gardant son nom, et l'interroger rendrait des zéros qu'on
    // prendrait pour une boîte vide.
    dire(&mut session, b"a006 DELETE Archives\r\n");
    let (videe, _) = dire(
        &mut session,
        b"a007 LIST \"\" Archives RETURN (STATUS (MESSAGES))\r\n",
    );
    assert_eq!(
        videe,
        "* LIST (\\Noselect \\HasChildren) \"/\" \"Archives\"\r\n\
         a007 OK LIST completed\r\n"
    );
}

/// La boîte SÉLECTIONNÉE se recense sans se rouvrir, dans `LIST` comme dans
/// `STATUS` : un magasin qui verrouille se heurterait à son propre verrou.
#[test]
fn list_recense_la_boite_ouverte_sans_la_rouvrir() {
    let mut session = selectionnee();
    let (texte, _) = dire(
        &mut session,
        b"a003 LIST \"\" INBOX RETURN (STATUS (MESSAGES))\r\n",
    );
    assert!(texte.contains("* STATUS \"INBOX\" (MESSAGES 3)"), "{texte}");
    assert_eq!(session.state(), State::Selected);
}

// ── LES OPTIONS DE RETOUR D'UNE RECHERCHE (§6.4.4) ──────────────────────────

/// **QUATRE FAÇONS DE RÉPONDRE À LA MÊME QUESTION.** Rendre la liste à qui a
/// demandé un compte, c'est envoyer des milliers de numéros pour qu'il en garde
/// un.
#[test]
fn une_recherche_rend_ce_qu_on_lui_demande() {
    let mut session = selectionnee();
    // Sans option, c'est la liste — comme avant.
    let tout = ecouler(&mut session, b"a003 SEARCH ALL\r\n");
    assert_eq!(
        tout,
        "* ESEARCH (TAG \"a003\") ALL 1:3\r\na003 OK SEARCH completed\r\n"
    );
    // `()` aussi, ce que §6.4.4 dit en toutes lettres.
    let vide = ecouler(&mut session, b"a004 SEARCH RETURN () ALL\r\n");
    assert_eq!(
        vide,
        "* ESEARCH (TAG \"a004\") ALL 1:3\r\na004 OK SEARCH completed\r\n"
    );

    let compte = ecouler(&mut session, b"a005 SEARCH RETURN (COUNT) ALL\r\n");
    assert_eq!(
        compte,
        "* ESEARCH (TAG \"a005\") COUNT 3\r\na005 OK SEARCH completed\r\n"
    );

    let bornes = ecouler(&mut session, b"a006 SEARCH RETURN (MIN MAX) ALL\r\n");
    assert_eq!(
        bornes,
        "* ESEARCH (TAG \"a006\") MIN 1 MAX 3\r\na006 OK SEARCH completed\r\n"
    );

    // Les quatre ensemble, et dans l'ordre de §7.3.4 : MIN, MAX, ALL, COUNT —
    // ici COUNT avant ALL, parce que ce qui se compte s'écrit avant ce qui
    // s'écoule.
    let toutes = ecouler(
        &mut session,
        b"a007 SEARCH RETURN (MIN MAX COUNT ALL) ALL\r\n",
    );
    assert_eq!(
        toutes,
        "* ESEARCH (TAG \"a007\") MIN 1 MAX 3 COUNT 3 ALL 1:3\r\n\
         a007 OK SEARCH completed\r\n"
    );

    // `UID SEARCH` rend des UID, `MIN` et `MAX` compris.
    let uids = ecouler(&mut session, b"a008 UID SEARCH RETURN (MIN MAX) ALL\r\n");
    assert_eq!(
        uids,
        "* ESEARCH (TAG \"a008\") UID MIN 10 MAX 30\r\n\
         a008 OK UID SEARCH completed\r\n"
    );
}

/// **UNE RECHERCHE SANS RÉSULTAT N'A NI `MIN` NI `MAX`** (§6.4.4), mais elle a
/// un `COUNT` : un compte nul est un renseignement, pas une absence.
#[test]
fn une_recherche_sans_resultat_omet_les_bornes_mais_pas_le_compte() {
    let mut session = selectionnee();
    let rien = ecouler(
        &mut session,
        b"a003 SEARCH RETURN (MIN MAX COUNT) DRAFT\r\n",
    );
    assert_eq!(
        rien,
        "* ESEARCH (TAG \"a003\") COUNT 0\r\na003 OK SEARCH completed\r\n"
    );
    // Et sans rien de demandé non plus, la ligne reste : §6.4.4 veut qu'elle
    // soit envoyée même vide.
    let liste = ecouler(&mut session, b"a004 SEARCH RETURN (ALL) DRAFT\r\n");
    assert_eq!(
        liste,
        "* ESEARCH (TAG \"a004\")\r\na004 OK SEARCH completed\r\n"
    );
}

/// Une option de retour qu'on ne sert pas est un `BAD` (§6.4.4), pas un silence.
#[test]
fn une_option_de_retour_inconnue_est_une_faute() {
    let mut session = selectionnee();
    for commande in [
        &b"a003 SEARCH RETURN (RELEVANCY) ALL\r\n"[..],
        b"a004 SEARCH RETURN MIN ALL\r\n",
        b"a005 SEARCH RETURN (MIN ALL\r\n",
    ] {
        let (texte, _) = dire(&mut session, commande);
        assert!(
            texte.contains("BAD SEARCH result options are malformed"),
            "{commande:?} : {texte}"
        );
    }
}

// ── `SAVE` ET LE MARQUEUR `$` (§6.4.4.1) ────────────────────────────────────

/// **`SAVE` RETIENT, `$` DÉSIGNE** : le client cherche une fois, et agit sur le
/// résultat sans le renvoyer.
#[test]
fn une_recherche_retenue_se_designe_par_le_marqueur() {
    let mut session = selectionnee();
    // `SAVE` SEUL NE FAIT RIEN ÉCRIRE : §6.4.4 veut qu'il supprime alors la
    // réponse `ESEARCH`.
    let sauve = ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) SEEN\r\n");
    assert_eq!(sauve, "a003 OK SEARCH completed\r\n");

    // Le message 2 est le seul `\Seen` : `$` le désigne.
    let lu = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(lu, "* 2 FETCH (UID 20)\r\na004 OK FETCH completed\r\n");

    // ET DANS L'AUTRE SENS AUSSI : posé par un `SEARCH`, employé par un
    // `UID FETCH`. §6.4.4.1 exige que le serveur traduise.
    let par_uid = ecouler(&mut session, b"a005 UID FETCH $ (FLAGS)\r\n");
    assert_eq!(
        par_uid,
        "* 2 FETCH (UID 20 FLAGS (\\Seen))\r\na005 OK UID FETCH completed\r\n"
    );
}

/// **CE QU'ON RETIENT EST EN UID**, et c'est ce qui rend §6.4.4.1 vrai sans
/// code : un message effacé cesse de correspondre, au lieu d'être remplacé par
/// son voisin.
#[test]
fn le_resultat_retenu_ne_suit_pas_la_renumerotation() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) ALL\r\n");
    // On efface le premier : les rangs 2 et 3 descendent à 1 et 2.
    ecouler(&mut session, b"a004 STORE 1 +FLAGS (\\Deleted)\r\n");
    ecouler(&mut session, b"a005 EXPUNGE\r\n");
    // `$` désigne toujours les MÊMES messages, par leurs UID.
    let reste = ecouler(&mut session, b"a006 FETCH $ (UID)\r\n");
    assert_eq!(
        reste,
        "* 1 FETCH (UID 20)\r\n* 2 FETCH (UID 30)\r\n\
         a006 OK FETCH completed\r\n"
    );
}

/// **UN RÉSULTAT VIDE EST UN RÉSULTAT** (§6.4.4.1), et non une absence : les
/// commandes qui l'emploient réussissent sans rien désigner.
#[test]
fn un_resultat_retenu_vide_ne_designe_rien_sans_faute() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) DRAFT\r\n");
    let rien = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(rien, "a004 OK FETCH completed\r\n");
    // Sans aucune recherche non plus : la session part avec la liste vide.
    let mut neuve = selectionnee();
    let vierge = ecouler(&mut neuve, b"a003 FETCH $ (UID)\r\n");
    assert_eq!(vierge, "a003 OK FETCH completed\r\n");
}

/// **UN `SELECT` REMET LE RÉSULTAT À ZÉRO** (§6.4.4.1) : ce qu'on avait retenu
/// parlait de la boîte qu'on vient de fermer.
#[test]
fn ouvrir_une_boite_oublie_le_resultat_retenu() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) ALL\r\n");
    dire(&mut session, b"a004 SELECT INBOX\r\n");
    let apres = ecouler(&mut session, b"a005 FETCH $ (UID)\r\n");
    assert_eq!(apres, "a005 OK FETCH completed\r\n");
}

/// **Table 4 de §6.4.4.1** : `SAVE` avec `MIN` et/ou `MAX` seuls retient CES
/// bornes, et non toute la liste.
#[test]
fn save_avec_les_bornes_ne_retient_que_les_bornes() {
    let mut session = selectionnee();
    let borne = ecouler(&mut session, b"a003 SEARCH RETURN (SAVE MIN) ALL\r\n");
    assert_eq!(
        borne,
        "* ESEARCH (TAG \"a003\") MIN 1\r\na003 OK SEARCH completed\r\n"
    );
    let seul = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(seul, "* 1 FETCH (UID 10)\r\na004 OK FETCH completed\r\n");

    // `SAVE MIN MAX` en retient deux.
    ecouler(&mut session, b"a005 SEARCH RETURN (SAVE MIN MAX) ALL\r\n");
    let deux = ecouler(&mut session, b"a006 FETCH $ (UID)\r\n");
    assert_eq!(
        deux,
        "* 1 FETCH (UID 10)\r\n* 3 FETCH (UID 30)\r\n\
         a006 OK FETCH completed\r\n"
    );

    // Avec `COUNT` ou `ALL`, c'est toute la liste — Table 4 encore.
    ecouler(&mut session, b"a007 SEARCH RETURN (SAVE MIN COUNT) ALL\r\n");
    let tout = ecouler(&mut session, b"a008 FETCH $ (UID)\r\n");
    assert_eq!(
        tout,
        "* 1 FETCH (UID 10)\r\n* 2 FETCH (UID 20)\r\n* 3 FETCH (UID 30)\r\n\
         a008 OK FETCH completed\r\n"
    );

    // Et `SAVE MIN` sur une recherche d'un seul message ne le retient qu'une
    // fois, même avec `MAX` : les deux bornes s'y confondent.
    ecouler(&mut session, b"a009 SEARCH RETURN (SAVE MIN MAX) SEEN\r\n");
    let une = ecouler(&mut session, b"a010 FETCH $ (UID)\r\n");
    assert_eq!(une, "* 2 FETCH (UID 20)\r\na010 OK FETCH completed\r\n");
}

/// Le marqueur vaut pour toutes les commandes qui prennent un ensemble.
#[test]
fn le_marqueur_vaut_pour_toutes_les_commandes_d_ensemble() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) SEEN\r\n");

    // `STORE`.
    let ecrit = ecouler(&mut session, b"a004 STORE $ +FLAGS (\\Flagged)\r\n");
    assert_eq!(
        ecrit,
        "* 2 FETCH (FLAGS (\\Seen \\Flagged))\r\na004 OK STORE completed\r\n"
    );

    // `COPY`.
    let copie = dire(&mut session, b"a005 COPY $ INBOX\r\n").0;
    assert!(copie.contains("a005 OK"), "{copie}");

    // `EXPUNGE` par UID, qui n'efface que ce qui est marqué.
    ecouler(&mut session, b"a006 STORE $ +FLAGS (\\Deleted)\r\n");
    let efface = ecouler(&mut session, b"a007 UID EXPUNGE $\r\n");
    assert_eq!(efface, "* 2 EXPUNGE\r\na007 OK UID EXPUNGE completed\r\n");
}

/// `MOVE $` déplace ce que la recherche a retenu.
#[test]
fn le_marqueur_vaut_aussi_pour_un_deplacement() {
    let mut session = selectionnee();
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) SEEN\r\n");
    let deplace = ecouler(&mut session, b"a004 MOVE $ INBOX\r\n");
    assert!(deplace.contains("* 2 EXPUNGE"), "{deplace}");
    assert!(deplace.contains("a004 OK MOVE completed"), "{deplace}");
}

/// **DES UID QUI SE SUIVENT SE COMPRIMENT EN PLAGE.** `1:1000` fait six octets
/// là où mille nombres n'en tiendraient dans aucun tampon borné.
#[test]
fn un_resultat_retenu_se_comprime_en_plages() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Suite\r\n");
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) ALL\r\n");
    // Les UID 5, 6 et 7 se suivent : le marqueur les désigne tous les trois.
    let tout = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(
        tout,
        "* 1 FETCH (UID 5)\r\n* 2 FETCH (UID 6)\r\n* 3 FETCH (UID 7)\r\n\
         a004 OK FETCH completed\r\n"
    );
}

/// **CE QUI DÉBORDE EST ABANDONNÉ, PAS TRONQUÉ** : un ensemble tronqué
/// désignerait d'autres messages que ceux qu'on a trouvés, ce qui est pire que
/// de n'en désigner aucun.
#[test]
fn un_resultat_retenu_trop_morcele_est_abandonne() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 SELECT Foisonnante\r\n");
    ecouler(&mut session, b"a003 SEARCH RETURN (SAVE) ALL\r\n");
    // Quatre cents UID espacés ne se comprimant en aucune plage, leur texte
    // dépasse ce qu'une session retient. Le marqueur ne désigne donc rien — et
    // la commande réussit quand même.
    let rien = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(rien, "a004 OK FETCH completed\r\n");
}

/// **`SAVE` SUR UNE RECHERCHE SANS RÉSULTAT RETIENT LA LISTE VIDE**, bornes
/// comprises : il n'y a pas de minimum d'un ensemble vide.
#[test]
fn save_avec_une_borne_sur_rien_retient_le_vide() {
    let mut session = selectionnee();
    let rien = ecouler(&mut session, b"a003 SEARCH RETURN (SAVE MIN) DRAFT\r\n");
    assert_eq!(
        rien,
        "* ESEARCH (TAG \"a003\")\r\na003 OK SEARCH completed\r\n"
    );
    let apres = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(apres, "a004 OK FETCH completed\r\n");
}

/// `SAVE MAX` seul retient le dernier, et rien d'autre (Table 4 de §6.4.4.1).
#[test]
fn save_avec_le_maximum_seul_ne_retient_que_lui() {
    let mut session = selectionnee();
    let borne = ecouler(&mut session, b"a003 SEARCH RETURN (SAVE MAX) ALL\r\n");
    assert_eq!(
        borne,
        "* ESEARCH (TAG \"a003\") MAX 3\r\na003 OK SEARCH completed\r\n"
    );
    let seul = ecouler(&mut session, b"a004 FETCH $ (UID)\r\n");
    assert_eq!(seul, "* 3 FETCH (UID 30)\r\na004 OK FETCH completed\r\n");
}

/// **UN MESSAGE DISPARU NE COMPTE POUR RIEN** dans un `STATUS` : une relève
/// concurrente peut l'avoir effacé, et il ne pèse plus.
#[test]
fn un_message_disparu_ne_compte_pas_dans_le_status() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    // `Trouee` en annonce trois et n'en rend que deux.
    let (texte, _) = dire(
        &mut session,
        b"a002 STATUS Trouee (MESSAGES UNSEEN SIZE)\r\n",
    );
    assert_eq!(
        texte,
        "* STATUS \"Trouee\" (MESSAGES 3 UNSEEN 2 SIZE 20)\r\n\
         a002 OK STATUS completed\r\n"
    );
}

/// Un nom que la réponse ne saurait pas citer n'est pas un nom de boîte, et
/// `STATUS` le dit comme les autres commandes.
#[test]
fn un_nom_de_status_qu_on_ne_saurait_pas_citer_est_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 STATUS a\\b (MESSAGES)\r\n");
    assert!(
        texte.contains("BAD STATUS expects a mailbox name and items"),
        "{texte}"
    );
}

/// **`SENTBEFORE` NE COMPARE PAS LA MÊME DATE QUE `BEFORE`.** Le premier lit le
/// champ `Date:` du message, le second sa date d'arrivée.
#[test]
fn les_criteres_d_ecriture_ne_sont_pas_ceux_d_arrivee() {
    let mut session = selectionnee();
    // Le message 1 dit avoir été écrit le 15 janvier 2026 ; il est arrivé le
    // 29 août 2026, comme les deux autres.
    let ecrit = ecouler(&mut session, b"a003 SEARCH SENTBEFORE 1-Feb-2026\r\n");
    assert_eq!(
        ecrit,
        "* ESEARCH (TAG \"a003\") ALL 1\r\na003 OK SEARCH completed\r\n"
    );
    let arrive = ecouler(&mut session, b"a004 SEARCH BEFORE 1-Feb-2026\r\n");
    assert_eq!(
        arrive,
        "* ESEARCH (TAG \"a004\")\r\na004 OK SEARCH completed\r\n"
    );

    // `SENTON` et `SENTSINCE` lisent la même date.
    let le = ecouler(&mut session, b"a005 SEARCH SENTON 15-Jan-2026\r\n");
    assert_eq!(
        le,
        "* ESEARCH (TAG \"a005\") ALL 1\r\na005 OK SEARCH completed\r\n"
    );
    let depuis = ecouler(&mut session, b"a006 SEARCH SENTSINCE 15-Jan-2026\r\n");
    assert_eq!(
        depuis,
        "* ESEARCH (TAG \"a006\") ALL 1\r\na006 OK SEARCH completed\r\n"
    );

    // **LES MESSAGES SANS `Date:` LISIBLE NE CORRESPONDENT À AUCUN** : les deux
    // autres n'en portent pas, et ne paraissent nulle part ci-dessus.
    let rien = ecouler(&mut session, b"a007 SEARCH SENTSINCE 1-Jan-1970\r\n");
    assert_eq!(
        rien,
        "* ESEARCH (TAG \"a007\") ALL 1\r\na007 OK SEARCH completed\r\n"
    );
}

// ── LES MOTS-CLEFS ──────────────────────────────────────────────────────────

/// **LES CINQ MOTS-CLEFS S'ANNONCENT, SE POSENT ET SE CHERCHENT.**
#[test]
fn les_mots_clefs_se_posent_et_se_cherchent() {
    let mut session = selectionnee();
    let pose = ecouler(&mut session, b"a003 STORE 1 +FLAGS ($Junk $Phishing)\r\n");
    assert_eq!(
        pose,
        "* 1 FETCH (FLAGS ($Junk $Phishing))\r\na003 OK STORE completed\r\n"
    );

    // `KEYWORD` les retrouve, `UNKEYWORD` désigne les autres.
    let trouve = ecouler(&mut session, b"a004 SEARCH KEYWORD $Junk\r\n");
    assert_eq!(
        trouve,
        "* ESEARCH (TAG \"a004\") ALL 1\r\na004 OK SEARCH completed\r\n"
    );
    let autres = ecouler(&mut session, b"a005 SEARCH UNKEYWORD $Junk\r\n");
    assert_eq!(
        autres,
        "* ESEARCH (TAG \"a005\") ALL 2:3\r\na005 OK SEARCH completed\r\n"
    );

    // Ils se retirent comme les autres.
    let retire = ecouler(&mut session, b"a006 STORE 1 -FLAGS ($Junk)\r\n");
    assert_eq!(
        retire,
        "* 1 FETCH (FLAGS ($Phishing))\r\na006 OK STORE completed\r\n"
    );
}

/// **UN MOT-CLEF QU'ON NE SERT PAS SE REFUSE**, et le dit — plutôt que de
/// répondre `OK` à une étiquette qu'on perdrait.
#[test]
fn un_mot_clef_qu_on_ne_sert_pas_se_refuse_en_le_disant() {
    let mut session = selectionnee();
    let (refus, _) = dire(&mut session, b"a003 STORE 1 +FLAGS ($Inconnu)\r\n");
    assert_eq!(refus, "a003 NO [CANNOT] This flag cannot be stored\r\n");

    let (cherche, _) = dire(&mut session, b"a004 SEARCH KEYWORD $Inconnu\r\n");
    assert!(
        cherche.contains("NO [CANNOT] This search key is not served yet"),
        "{cherche}"
    );
}

/// `PERMANENTFLAGS` N'ANNONCE PAS `\*` : `\*` promet qu'on accepte tout mot-clef
/// nouveau, et cette promesse-là, on ne la tient pas.
#[test]
fn les_mots_clefs_survivent_mais_l_ensemble_est_ferme() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (texte, _) = dire(&mut session, b"a002 SELECT INBOX\r\n");
    assert!(
        texte.contains(
            "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \
             $MDNSent $Forwarded $Junk $NonJunk $Phishing)\r\n"
        ),
        "{texte}"
    );
    assert!(!texte.contains("\\*"), "{texte}");
}

// ── LES ATTRIBUTS D'USAGE (RFC 6154) ────────────────────────────────────────

/// **UN `CREATE` DÉSIGNE, ET LE `LIST` LE RAPPORTE.**
///
/// Ce serveur ne désigne aucune boîte de son cru : c'est le client qui dit à
/// quoi la sienne servira, et le magasin qui retient. Sans cet aller-retour, un
/// client qui range un brouillon ne sait pas où le mettre — « Drafts »,
/// « Brouillons » et « Entwürfe » ne se devinent pas.
#[test]
fn un_usage_designe_se_rapporte_dans_le_list() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (fait, _) = dire(&mut session, b"a002 CREATE Brouillons (USE (\\Drafts))\r\n");
    assert!(fait.contains("a002 OK"), "{fait}");

    let (tout, _) = dire(&mut session, b"a003 LIST \"\" *\r\n");
    assert!(
        tout.contains("* LIST (\\Drafts \\HasNoChildren) \"/\" \"Brouillons\"\r\n"),
        "l'usage doit être écrit sur la ligne de la boîte : {tout}"
    );
    // **ET SUR ELLE SEULE** : une boîte ordinaire n'en porte aucun.
    assert!(
        tout.contains("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n"),
        "{tout}"
    );
}

/// **LES USAGES S'ÉCRIVENT TOUJOURS, ET NON SUR DEMANDE.**
///
/// §5.2 de RFC 6154 ne définit qu'une option de SÉLECTION — il n'y a pas de
/// `RETURN (SPECIAL-USE)`. Un client qui devrait redemander ce qu'il reçoit déjà
/// ferait un aller-retour pour rien.
#[test]
fn le_filtre_special_use_ne_rend_que_les_boites_designees() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Brouillons (USE (\\Drafts))\r\n");
    dire(&mut session, b"a003 CREATE Ordinaire\r\n");

    let (filtre, _) = dire(&mut session, b"a004 LIST (SPECIAL-USE) \"\" *\r\n");
    assert!(filtre.contains("\"Brouillons\""), "{filtre}");
    assert!(
        !filtre.contains("\"Ordinaire\"") && !filtre.contains("\"INBOX\""),
        "le filtre doit écarter ce qui ne porte aucun usage : {filtre}"
    );
    assert_eq!(filtre.matches("* LIST").count(), 1, "{filtre}");
}

/// **LES DEUX FILTRES SE CUMULENT** (§5.2) : demander les deux demande les
/// boîtes qui sont l'une ET l'autre, et non leur réunion.
#[test]
fn les_deux_filtres_de_list_se_cumulent() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Brouillons (USE (\\Drafts))\r\n");
    dire(&mut session, b"a003 CREATE Envoyes (USE (\\Sent))\r\n");
    dire(&mut session, b"a004 SUBSCRIBE Brouillons\r\n");

    let (deux, _) = dire(
        &mut session,
        b"a005 LIST (SUBSCRIBED SPECIAL-USE) \"\" *\r\n",
    );
    assert!(
        deux.contains("* LIST (\\Subscribed \\Drafts \\HasNoChildren) \"/\" \"Brouillons\"\r\n"),
        "{deux}"
    );
    assert_eq!(
        deux.matches("* LIST").count(),
        1,
        "`Envoyes` porte un usage mais n'est pas abonnée : {deux}"
    );
}

/// **UN USAGE NE VAUT QUE POUR UNE BOÎTE** (§3), et le refus dit que c'est
/// l'USAGE qu'on refuse — pas le nom.
#[test]
fn un_usage_deja_pris_se_refuse_par_useattr() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    dire(&mut session, b"a002 CREATE Brouillons (USE (\\Drafts))\r\n");

    let (refus, _) = dire(&mut session, b"a003 CREATE Autre (USE (\\Drafts))\r\n");
    assert!(refus.contains("a003 NO [USEATTR]"), "{refus}");

    // **ET LE MÊME NOM SANS L'USAGE PASSE** : c'est ce que `[USEATTR]` promet
    // au client, et il faut que ce soit vrai.
    let (sans, _) = dire(&mut session, b"a004 CREATE Autre\r\n");
    assert!(sans.contains("a004 OK"), "{sans}");
}

/// **UN ATTRIBUT BIEN ÉCRIT QU'ON NE SERT PAS SE DIT `NO [USEATTR]`**, et une
/// faute de grammaire se dit `BAD`. Les confondre enverrait relire sa syntaxe
/// un client qui l'a bien écrite.
#[test]
fn un_attribut_non_servi_ne_se_dit_pas_comme_une_faute() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");

    for (tag, commande) in [
        (b"a002", &b"a002 CREATE Tout (USE (\\All))\r\n"[..]),
        (b"a003", b"a003 CREATE Marques (USE (\\Flagged))\r\n"),
    ] {
        let (refus, _) = dire(&mut session, commande);
        assert!(
            refus.contains(&std::format!(
                "{} NO [USEATTR]",
                std::string::String::from_utf8_lossy(tag)
            )),
            "{refus}"
        );
    }

    for (tag, commande) in [
        (b"a004", &b"a004 CREATE X (USE (Drafts))\r\n"[..]),
        (b"a005", b"a005 CREATE Y (USAGE (\\Drafts))\r\n"),
        (b"a006", b"a006 CREATE Z (USE ())\r\n"),
        (b"a007", b"a007 CREATE W (USE (\\Drafts)) (X (1))\r\n"),
    ] {
        let (faute, _) = dire(&mut session, commande);
        assert!(
            faute.contains(&std::format!(
                "{} BAD",
                std::string::String::from_utf8_lossy(tag)
            )),
            "{faute}"
        );
    }
}

/// **UN NOM DE BOÎTE A LE DROIT DE PORTER UNE PARENTHÈSE**, et le paramètre se
/// lit quand même : c'est le lecteur d'arguments qui dit où le nom finit, et non
/// une recherche de la première parenthèse.
#[test]
fn un_nom_a_parenthese_ne_trompe_pas_le_parametre() {
    let mut session = nouvelle(true);
    dire(&mut session, b"a001 LOGIN jean ouvre-toi\r\n");
    let (fait, _) = dire(
        &mut session,
        b"a002 CREATE \"Compte (perso)\" (USE (\\Sent))\r\n",
    );
    assert!(fait.contains("a002 OK"), "{fait}");

    let (tout, _) = dire(&mut session, b"a003 LIST (SPECIAL-USE) \"\" *\r\n");
    assert!(
        tout.contains("* LIST (\\Sent \\HasNoChildren) \"/\" \"Compte (perso)\"\r\n"),
        "{tout}"
    );
}
