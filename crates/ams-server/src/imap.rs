//! Les boîtes, vues par le service IMAP.
//!
//! # Ce que ce module ajoute à ce que POP3 savait déjà
//!
//! POP3 ouvre UNE boîte, celle du compte, et n'en sort pas. IMAP en nomme
//! plusieurs, et il faut donc décider ce qu'un nom de boîte désigne. **Ce
//! serveur en a une par compte, et elle s'appelle `INBOX`** — le nom que la
//! RFC 9051 §5.1 réserve précisément pour cela.
//!
//! Créer des dossiers demanderait `CREATE`, un endroit où les mettre, et une
//! règle pour ce qu'un nom de dossier a le droit d'être ; rien de tout cela
//! n'est écrit, et prétendre en avoir plusieurs en attendant ferait mentir
//! `LIST`.
//!
//! # AUCUN CHEMIN N'EST CONSTRUIT À PARTIR D'UN NOM DE BOÎTE
//!
//! Le nom vient du client. `INBOX` est comparé à une constante, et la boîte
//! qu'il désigne est celle que la table des comptes a déjà ouverte au
//! démarrage. Un nom qui n'est pas `INBOX` n'ouvre rien — il ne devient jamais
//! un morceau de chemin, et il n'y a donc aucune traversée de répertoire à
//! empêcher.
//!
//! # IMAP NE VERROUILLE PAS, ET C'EST LE NOM DU FICHIER QUI FAIT FOI
//!
//! POP3 prend le verrou exclusif de la boîte, et RFC 1939 §3 le lui demande :
//! ses numéros de message ne doivent pas bouger de toute la session. Une session
//! IMAP, elle, dure des heures. Lui donner le même verrou reviendrait à
//! interdire toute relève POP3 pendant ces heures — et, plus bêtement encore, à
//! s'interdire à lui-même : `STATUS INBOX` sur une boîte déjà sélectionnée
//! heurtait son propre verrou et répondait qu'elle n'existe pas. Il prend donc
//! une [`MailboxView`], qui relève sans verrouiller.
//!
//! Ce qui remplace le verrou n'est pas rien : **le nom du fichier fait foi**. Il
//! porte les drapeaux, et on le relit à l'instant d'écrire — pour un `STORE`
//! comme pour un `EXPUNGE`. C'est ce qui permet à deux sessions de marquer la
//! même boîte sans se perdre l'une l'autre, et surtout de **ne jamais effacer un
//! message dont la marque a été retirée entre-temps** : un courrier perdu ne se
//! retrouve pas.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ams_index::{MessageName, Uid};
use ams_mime::BodySpan;
use ams_proto_imap::{Flags, PartWhat, SearchScope, StoreMode};
use ams_session::imap::{
    BinarySize, Creation, Deletion, Deposit, Listing, Mailbox, Mailboxes, MessageInfo, Renaming,
    Subscription,
};
use ams_store::{Incoming, MailboxView, Maildir, fresh_uid_validity};

/// Ce qu'on lit d'un en-tête pour en composer l'enveloppe.
///
/// **Aucune RFC ne le borne.** Au-delà, l'enveloppe est composée de ce qu'on a
/// lu : un en-tête de plus de soixante-quatre kibioctets n'est pas un message
/// qu'un humain a écrit, et le lire en entier offrirait à qui l'envoie le coût
/// de son parcours.
const ENTETE_MAX: usize = 64 * 1024;

/// Ce qu'une enveloppe composée occupe au plus.
const ENVELOPPE_MAX: usize = 128 * 1024;

/// Ce qu'une structure composée occupe au plus.
///
/// Elle est bornée par le nombre de parties qu'`ams-mime` décrit, pas par la
/// taille du message : une structure ne grandit pas avec les pièces jointes,
/// seulement avec leur nombre.
const STRUCTURE_MAX: usize = 128 * 1024;

/// Ce qu'un choix de champs composé occupe au plus.
///
/// Il ne peut pas dépasser l'en-tête dont il est tiré, plus la ligne vide qui le
/// termine.
const CHOIX_MAX: usize = ENTETE_MAX + 2;

/// Par combien d'octets à la fois le message passe devant le balayeur.
///
/// **C'est ce que la structure coûte en mémoire, et rien de plus** : le message
/// ne séjourne pas, il défile. Un message d'un gibioctet et un message de mille
/// octets tiennent dans la même fenêtre.
const FENETRE: usize = 64 * 1024;

/// Le seul nom de boîte que ce serveur connaisse (RFC 9051 §5.1).
const INBOX: &[u8] = b"INBOX";

/// Où les abonnements d'un compte s'écrivent, dans sa racine.
///
/// # POURQUOI UN FICHIER DE TEXTE, ICI, ALORS QUE LA CONFIGURATION EST BINAIRE
///
/// La configuration est binaire parce qu'elle a un SCHÉMA — des champs, des
/// types, une compatibilité à tenir d'une version à l'autre. Une liste
/// d'abonnements n'a rien de tout cela : c'est une suite de noms de boîtes, et
/// un nom de boîte est déjà de l'ASCII imprimable sans `LF` (§5.1 tel que ce
/// serveur le restreint). Une ligne par nom est donc une écriture qui ne peut
/// pas être ambiguë, et que l'administrateur peut lire sans outil.
const ABONNEMENTS: &str = "ams-abonnements";

/// Combien d'abonnements un compte peut porter.
///
/// Ce n'est pas une limite du protocole : c'est celle du travail qu'un `LIST`
/// fait, et de la place que le cache occupe par compte connecté.
const ABONNEMENTS_MAX: usize = 256;

/// Ce que le fichier d'abonnements peut peser, au plus.
///
/// [`ABONNEMENTS_MAX`] noms de [`MAILBOX_NAME_MAX`](ams_proto_imap::MAILBOX_NAME_MAX)
/// octets, plus leur fin de ligne. **On lit une borne, pas un fichier** : ce
/// fichier vit dans la racine du compte, et rien ne garantit que personne n'y a
/// écrit autre chose.
const ABONNEMENTS_OCTETS_MAX: u64 = 64 * 1024;

/// La même fenêtre, écrite en `u64`.
///
/// Un littéral plutôt qu'une conversion : `usize` vers `u64` n'est pas gratuit
/// sur toute cible, et le workspace refuse les conversions muettes.
const FENETRE_64: u64 = 64 * 1024;

/// Ce qu'un nom d'encodage occupe au plus.
///
/// `quoted-printable` en fait seize ; le double laisse de la place à un nom
/// qu'on ne connaîtra pas, et que l'on refusera.
const ENCODAGE_MAX: usize = 32;

/// Ce qu'on lit au plus d'une partie pour y chercher.
///
/// **Aucune RFC ne le borne.** Chercher dans une pièce jointe de vingt
/// mébioctets coûterait à ce serveur ce qu'un client peut demander autant de
/// fois qu'il veut. Un mébioctet de texte est un livre ; au-delà, on ne cherche
/// pas, et le serveur le dit au démarrage plutôt que de le laisser deviner.
const RECHERCHE_MAX: u64 = 1024 * 1024;

/// Lit un intervalle d'un fichier, borné.
fn lire(chemin: &Path, debut: u64, combien: usize) -> Option<Vec<u8>> {
    let mut octets = std::vec![0_u8; combien];
    let mut fichier = std::fs::File::open(chemin).ok()?;
    fichier.seek(SeekFrom::Start(debut)).ok()?;
    fichier.read_exact(&mut octets).ok()?;
    Some(octets)
}

/// L'en-tête d'un message, borné.
fn entete_de(chemin: &Path) -> Option<Vec<u8>> {
    let fin = fin_de_l_entete(chemin).unwrap_or(0);
    let combien = usize::try_from(fin).unwrap_or(usize::MAX).min(ENTETE_MAX);
    lire(chemin, 0, combien)
}

/// `cherche` figure-t-il dans un champ nommé ?
///
/// # ON CHERCHE DANS LE TEXTE, PAS DANS LES OCTETS
///
/// Un `SEARCH SUBJECT "facture"` doit trouver un sujet écrit
/// `=?utf-8?B?ZmFjdHVyZQ==?=` : répondre « non » serait un mensonge exact. C'est
/// l'inverse de ce que rend une `ENVELOPE`, et pour la même raison — rendre et
/// chercher ne demandent pas la même chose.
fn dans_un_champ(chemin: &Path, champ: &[u8], cherche: &[u8]) -> bool {
    let Some(entete) = entete_de(chemin) else {
        return false;
    };
    let Ok(message) = ams_mime::Message::parse(&entete, &ams_mime::Limits::DEFAULT) else {
        return false;
    };
    let mut decode = std::vec![0_u8; ams_mime::decoded_max(entete.len())];
    for lu in message.fields() {
        if !lu.name_is(champ) {
            continue;
        }
        // UN TEXTE VIDE DEMANDE QUE LE CHAMP EXISTE (§6.4.4), et il existe.
        if cherche.is_empty() {
            return true;
        }
        let Ok(ecrits) = ams_mime::decode_encoded_words(lu.raw_value(), &mut decode) else {
            continue;
        };
        if contient_sans_casse(decode.get(..ecrits).unwrap_or_default(), cherche) {
            return true;
        }
    }
    false
}

/// `cherche` figure-t-il quelque part dans l'en-tête, noms de champs compris ?
fn dans_l_entete_entier(chemin: &Path, cherche: &[u8]) -> bool {
    let Some(entete) = entete_de(chemin) else {
        return false;
    };
    let mut decode = std::vec![0_u8; ams_mime::decoded_max(entete.len())];
    let Ok(ecrits) = ams_mime::decode_encoded_words(&entete, &mut decode) else {
        return false;
    };
    contient_sans_casse(decode.get(..ecrits).unwrap_or_default(), cherche)
}

/// `cherche` figure-t-il dans le corps d'une partie de texte ?
///
/// # ON NE CHERCHE QUE DANS DU TEXTE
///
/// Une pièce jointe binaire ne se cherche pas par son texte : ce qu'on y
/// trouverait ne serait pas ce que le client a demandé. C'est aussi ce que font
/// les serveurs qui indexent, et pour la même raison.
fn dans_le_corps(chemin: &Path, cherche: &[u8]) -> bool {
    let Some(balayeur) = balayer(chemin) else {
        return false;
    };
    for rang in 0..balayeur.part_count() {
        let Some(partie) = balayeur.part(rang).filter(|partie| partie.text) else {
            continue;
        };
        let combien = usize::try_from(partie.end.saturating_sub(partie.start).min(RECHERCHE_MAX))
            .unwrap_or(usize::MAX);
        let Some(brut) = lire(chemin, partie.start, combien) else {
            continue;
        };
        let mut decode = std::vec![0_u8; ams_mime::decoded_max(combien).max(1)];
        let Ok(ecrits) = ams_mime::decode_transfer(partie.encoding, &brut, &mut decode) else {
            continue;
        };
        if contient_sans_casse(decode.get(..ecrits).unwrap_or_default(), cherche) {
            return true;
        }
    }
    false
}

/// `aiguille` figure-t-elle dans `botte`, à la casse près ?
///
/// La casse ne compte pas (§6.4.4) — **pour l'ASCII**. Replier les majuscules
/// d'un alphabet quelconque demande des tables de caractères que ce serveur n'a
/// pas, et prétendre le faire à moitié serait pire que de le dire.
fn contient_sans_casse(botte: &[u8], aiguille: &[u8]) -> bool {
    if aiguille.is_empty() {
        return true;
    }
    botte.windows(aiguille.len()).any(|fenetre| {
        fenetre
            .iter()
            .zip(aiguille)
            .all(|(vu, cherche)| vu.eq_ignore_ascii_case(cherche))
    })
}

/// Écoule un texte déjà composé : `out.len()` octets au plus, depuis `offset`.
fn ecouler(texte: &[u8], offset: u64, out: &mut [u8]) -> usize {
    let reste = texte
        .get(usize::try_from(offset).unwrap_or(usize::MAX)..)
        .unwrap_or_default();
    let voulu = reste.len().min(out.len());
    for (place, octet) in out.iter_mut().zip(reste.get(..voulu).unwrap_or_default()) {
        *place = *octet;
    }
    voulu
}

/// Fait défiler un message devant le balayeur, et rend ce qu'il en a retenu.
///
/// Rend `None` si le fichier ne se lit pas.
fn balayer(chemin: &Path) -> Option<Box<ams_mime::BodyScanner>> {
    let mut fichier = std::fs::File::open(chemin).ok()?;
    // LE BALAYEUR EST GROS, ET IL VA SUR LE TAS. Une vingtaine de kibioctets sur
    // la pile d'un fil qui en sert d'autres n'est pas une dépense qu'on veut
    // laisser à la profondeur d'appel.
    let mut balayeur = Box::new(ams_mime::BodyScanner::new(&ams_mime::Limits::DEFAULT));
    let mut fenetre = std::vec![0_u8; FENETRE];
    loop {
        let lus = fichier.read(&mut fenetre).ok()?;
        if lus == 0 {
            break;
        }
        balayeur.push(fenetre.get(..lus).unwrap_or_default());
    }
    balayeur.finish();
    Some(balayeur)
}

/// Une boîte relevée, vue par IMAP.
pub struct BoiteImap {
    vue: MailboxView,
    /// Ce que le répertoire portait au dernier regard.
    ///
    /// # DEUX `stat` PLUTÔT QU'UN PARCOURS
    ///
    /// Un client qui `IDLE` fait poser la question toutes les cinq secondes. La
    /// poser en relisant le répertoire coûterait, pour une boîte de dix mille
    /// messages, dix mille entrées à chaque fois et pour chaque session. Les
    /// dates de `new/` et `cur/` disent en deux appels qu'il n'y a rien de neuf,
    /// et c'est la réponse dans l'immense majorité des cas.
    vu: Empreinte,
    /// La boîte elle-même, pour ce qui s'écrit : une COPIE y dépose un message
    /// neuf, et l'UID vient de son compteur.
    maildir: Arc<Maildir>,
    uid_validity: u32,
    /// Les drapeaux, un par message, lus à l'ouverture depuis les noms de
    /// fichiers. Les relire à chaque `FETCH` rouvrirait le répertoire.
    drapeaux: Vec<Flags>,
    /// Les dates d'arrivée, une par message.
    dates: Vec<u64>,
    /// Le chemin COURANT de chaque message.
    ///
    /// # Pourquoi il ne suffit pas de garder celui de l'instantané
    ///
    /// Dans un Maildir, les drapeaux vivent DANS LE NOM DU FICHIER : les écrire,
    /// c'est renommer. Le chemin relevé à l'ouverture cesse donc d'être valide
    /// au premier `STORE` — le nôtre comme celui d'une autre session.
    chemins: Vec<PathBuf>,
}

/// Ce qu'on retient d'un répertoire pour savoir s'il a bougé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Empreinte {
    /// La date de `new/` : le courrier qui arrive s'y pose.
    neuf: Option<std::time::SystemTime>,
    /// Celle de `cur/` : ce qui a été adopté, ou renommé par un `STORE`.
    courant: Option<std::time::SystemTime>,
}

/// Relève l'empreinte des deux répertoires d'un Maildir.
fn empreinte_du_maildir(maildir: &Maildir) -> Empreinte {
    let date = |quoi: &str| {
        std::fs::metadata(maildir.root().join(quoi))
            .ok()
            .and_then(|etat| etat.modified().ok())
    };
    Empreinte {
        neuf: date("new"),
        courant: date("cur"),
    }
}

impl BoiteImap {
    /// Compose le choix de champs d'un message, ou dit qu'il n'y en a pas.
    fn choisir(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        let chemin = self.chemins.get(self.rang(sequence)?)?;
        // UN CHOIX PORTE SUR UN EN-TÊTE, et lequel dépend du chemin : celui du
        // message, ou celui du message qu'une partie encapsule. `HEADER.FIELDS`
        // sur une partie qui ne porte pas de message ne désigne rien, et
        // `span` le dit.
        let (debut, fin) = match path.is_empty() {
            true => (0, fin_de_l_entete(chemin).unwrap_or(0)),
            false => balayer(chemin)?.span(path, BodySpan::Header)?,
        };
        let combien = usize::try_from(fin.saturating_sub(debut))
            .unwrap_or(usize::MAX)
            .min(ENTETE_MAX);
        let mut entete = std::vec![0_u8; combien];
        let mut fichier = std::fs::File::open(chemin).ok()?;
        fichier.seek(SeekFrom::Start(debut)).ok()?;
        // `read_exact` ÉCHOUE SI LE MESSAGE A RÉTRÉCI, et c'est ce qu'on veut :
        // un en-tête tronqué composerait un choix qui n'est pas celui du
        // message.
        fichier.read_exact(&mut entete).ok()?;
        ams_mime::write_header_fields(&entete, names, except, out, &ams_mime::Limits::DEFAULT).ok()
    }

    fn rang(&self, sequence: u32) -> Option<usize> {
        let rang = usize::try_from(sequence.checked_sub(1)?).ok()?;
        (rang < self.vue.messages().len()).then_some(rang)
    }
}

impl Mailbox for BoiteImap {
    fn exists(&self) -> u32 {
        u32::try_from(self.vue.messages().len()).unwrap_or(u32::MAX)
    }

    fn uid_validity(&self) -> u32 {
        self.uid_validity
    }

    fn uid_next(&self) -> u32 {
        // ON DEMANDE À LA BOÎTE, PAS À L'INSTANTANÉ. Le dernier message plus un
        // serait faux dès qu'un message a été effacé : `UIDNEXT` redescendrait,
        // et un client qui l'a retenu croirait pouvoir attendre un numéro déjà
        // servi. §2.3.1.1 veut que le prochain UID ne recule jamais, et c'est
        // le compteur du Maildir qui le sait.
        self.maildir.next_uid().value()
    }

    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let rang = self.rang(sequence)?;
        let message = self.vue.messages().get(rang)?;
        Some(MessageInfo {
            uid: message.uid.value(),
            size: message.size,
            flags: self.drapeaux.get(rang).copied().unwrap_or_default(),
            internal_date: self.dates.get(rang).copied().unwrap_or(0),
        })
    }

    fn header_octets(&self, sequence: u32) -> u64 {
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let (Some(chemin), Some(message)) = (self.chemins.get(rang), self.vue.messages().get(rang))
        else {
            return 0;
        };
        fin_de_l_entete(chemin).unwrap_or(message.size)
    }

    fn envelope(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        // L'EN-TÊTE SE RELIT À CHAQUE MORCEAU, et c'est un choix. Le retenir
        // entre deux appels demanderait un état par session et par message ;
        // le relire coûte une lecture de quelques kibioctets, bornée, sur une
        // commande qu'un client n'émet qu'une fois par message affiché.
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return 0;
        };
        let fin = fin_de_l_entete(chemin).unwrap_or(0);
        let combien = usize::try_from(fin).unwrap_or(usize::MAX).min(ENTETE_MAX);
        let mut entete = std::vec![0_u8; combien];
        if let Ok(mut fichier) = std::fs::File::open(chemin) {
            let _ = fichier.read_exact(&mut entete);
        }

        let mut compose = std::vec![0_u8; ENVELOPPE_MAX];
        // UNE ENVELOPPE QU'ON NE SAIT PAS COMPOSER RESTE UNE ENVELOPPE. Rendre
        // zéro octet couperait la réponse au milieu d'un élément, et le client
        // lirait la suite comme autre chose. Dix `NIL` disent « je ne sais
        // rien » dans une forme que la grammaire admet.
        const RIEN: &[u8] = b"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
        let texte =
            match ams_mime::write_envelope(&entete, &mut compose, &ams_mime::Limits::DEFAULT) {
                Ok(ecrits) => compose.get(..ecrits).unwrap_or(RIEN),
                Err(_) => RIEN,
            };
        ecouler(texte, offset, out)
    }

    fn body_structure(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        // LE MESSAGE SE RELIT À CHAQUE MORCEAU, comme l'en-tête pour l'enveloppe
        // — mais ici la relecture porte sur tout le message, et non sur quelques
        // kibioctets. C'est le prix d'un état par session en moins, et il reste
        // rare : une structure tient presque toujours dans un seul morceau de
        // réponse, donc en un seul passage.
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return 0;
        };
        let mut compose = std::vec![0_u8; STRUCTURE_MAX];
        // UNE STRUCTURE QU'ON NE SAIT PAS COMPOSER RESTE UNE STRUCTURE. Rendre
        // zéro octet couperait la réponse au milieu d'un élément, et le client
        // lirait la suite comme autre chose. Le corps simple et vide de la RFC
        // 2045 dit « je ne sais rien » dans une forme que la grammaire admet.
        const RIEN: &[u8] =
            b"(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 0 0 NIL NIL NIL NIL)";
        let texte = match balayer(chemin).and_then(|vu| vu.write(&mut compose).ok()) {
            Some(ecrits) => compose.get(..ecrits).unwrap_or(RIEN),
            None => RIEN,
        };
        ecouler(texte, offset, out)
    }

    fn part_span(&self, sequence: u32, path: &[u32], what: PartWhat) -> Option<(u64, u64)> {
        // MÊME PRIX QU'UNE STRUCTURE : trouver une partie, c'est retrouver les
        // frontières, donc lire le message. La session ne le demande que pour
        // l'élément qu'elle est sur le point d'écrire.
        let chemin = self.chemins.get(self.rang(sequence)?)?;
        balayer(chemin)?.span(
            path,
            match what {
                PartWhat::Content => BodySpan::Content,
                PartWhat::Mime => BodySpan::Mime,
                PartWhat::Header => BodySpan::Header,
                PartWhat::Text => BodySpan::Text,
                // UN CHOIX N'EST PAS UN INTERVALLE : il se compose, et passe par
                // `header_fields`. Le demander ici serait demander où se trouve
                // une sélection, ce qui n'a pas de lieu.
                PartWhat::HeaderFields { .. } => return None,
            },
        )
    }

    fn refresh(&mut self) -> u32 {
        // RIEN N'A BOUGÉ : deux `stat`, et l'on s'arrête là.
        let maintenant = empreinte_du_maildir(&self.maildir);
        if maintenant == self.vu {
            return self.exists();
        }
        self.vu = maintenant;
        let Ok(vue) = MailboxView::open(&self.maildir) else {
            return self.exists();
        };
        // ON N'AJOUTE, ON NE RETIRE PAS : les rangs qu'un client a retenus
        // doivent rester valides, et retirer RENUMÉROTE tout ce qui suit.
        //
        // **LE NOUVEAU RELEVÉ DOIT DONC COMMENCER PAR L'ANCIEN**, UID pour UID.
        // S'il ne le fait pas, c'est qu'un message a disparu au milieu : on se
        // tait, et le client gardera les rangs qu'il connaît jusqu'à sa
        // prochaine ouverture. Le dire renuméroterait chez lui.
        let connus = self.vue.messages().len();
        let prefixe = vue.messages().len() >= connus
            && vue
                .messages()
                .iter()
                .zip(self.vue.messages())
                .all(|(neuf, ancien)| neuf.uid == ancien.uid);
        if !prefixe {
            return self.exists();
        }
        for message in vue.messages().iter().skip(connus) {
            self.drapeaux.push(drapeaux_de(&message.path));
            self.dates.push(date_de(&message.path));
            self.chemins.push(message.path.clone());
        }
        self.vue = vue;
        self.exists()
    }

    fn binary_size(&self, sequence: u32, path: &[u32]) -> BinarySize {
        let Some(rang) = self.rang(sequence) else {
            return BinarySize::Absent;
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return BinarySize::Absent;
        };
        let Some(balayeur) = balayer(chemin) else {
            return BinarySize::Absent;
        };
        let Some(partie) = balayeur.part_of(path) else {
            return BinarySize::Absent;
        };
        // ON COMPTE EN DÉCODANT, PAR FENÊTRES. La taille décodée ne se déduit
        // pas de celle du fichier : le pliage, les blancs et les coupures molles
        // ne rendent aucun octet. Une passe, et une seule, par demande.
        let mut sortie = std::vec![0_u8; FENETRE];
        let mut total = 0_u64;
        let mut vu = 0_u64;
        while partie.start.saturating_add(vu) < partie.end {
            let reste = partie.end.saturating_sub(partie.start).saturating_sub(vu);
            let combien = usize::try_from(reste.min(FENETRE_64)).unwrap_or(FENETRE);
            let Some(brut) = lire(chemin, partie.start.saturating_add(vu), combien) else {
                return BinarySize::Absent;
            };
            let dernier = partie
                .start
                .saturating_add(vu)
                .saturating_add(u64::try_from(combien).unwrap_or(0))
                >= partie.end;
            match ams_mime::decode_chunk(partie.encoding, &brut, dernier, &mut sortie) {
                Err(_) => return BinarySize::UnknownEncoding,
                // Rien n'avance : ce qui reste ne porte aucun groupe complet, et
                // n'en portera pas davantage à la fenêtre suivante.
                Ok((0, _)) => break,
                Ok((lus, ecrits)) => {
                    total = total.saturating_add(u64::try_from(ecrits).unwrap_or(0));
                    vu = vu.saturating_add(u64::try_from(lus).unwrap_or(0));
                }
            }
        }
        BinarySize::Octets(total)
    }

    fn binary(&self, sequence: u32, path: &[u32], raw: u64, out: &mut [u8]) -> (u64, usize) {
        let Some(rang) = self.rang(sequence) else {
            return (0, 0);
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return (0, 0);
        };
        let Some(partie) = balayer(chemin).and_then(|vu| {
            vu.part_of(path).map(|partie| {
                (partie.start, partie.end, {
                    let mut nom = [0_u8; ENCODAGE_MAX];
                    let voulu = partie.encoding.len().min(ENCODAGE_MAX);
                    for (place, octet) in nom.iter_mut().zip(partie.encoding) {
                        *place = *octet;
                    }
                    (nom, voulu)
                })
            })
        }) else {
            return (0, 0);
        };
        let (debut, fin, (nom, voulu)) = partie;
        let ou = debut.saturating_add(raw);
        if ou >= fin {
            return (0, 0);
        }
        let combien = usize::try_from(fin.saturating_sub(ou).min(FENETRE_64)).unwrap_or(FENETRE);
        let Some(brut) = lire(chemin, ou, combien) else {
            return (0, 0);
        };
        let encodage = nom.get(..voulu).unwrap_or_default();
        // LE DERNIER MORCEAU SE SAIT ICI, ET NULLE PART AILLEURS : c'est le
        // magasin qui connaît la fin de la partie, et le remplissage du base64
        // rend son dernier groupe partiel.
        let dernier = ou.saturating_add(u64::try_from(combien).unwrap_or(0)) >= fin;
        match ams_mime::decode_chunk(encodage, &brut, dernier, out) {
            Ok((lus, ecrits)) => (u64::try_from(lus).unwrap_or(0), ecrits),
            // L'encodage a déjà été éprouvé par `binary_size` : s'il résiste
            // ici, la demande a déjà été refusée, et rendre zéro conclut.
            Err(_) => (0, 0),
        }
    }

    fn sent_day(&self, sequence: u32) -> Option<u64> {
        let rang = self.rang(sequence)?;
        let chemin = self.chemins.get(rang)?;
        let entete = entete_de(chemin)?;
        let message = ams_mime::Message::parse(&entete, &ams_mime::Limits::DEFAULT).ok()?;
        // **LE PREMIER `Date:` GAGNE.** §3.6 de RFC 5322 n'en admet qu'un ; un
        // message qui en porte deux est mal formé, et prendre le dernier
        // laisserait un expéditeur choisir laquelle des deux dates le serveur
        // retiendra.
        message
            .fields()
            .find(|champ| champ.name_is(b"date"))
            .and_then(|champ| ams_mime::read_day(champ.raw_value()))
    }

    fn contains(&self, sequence: u32, scope: SearchScope, field: &[u8], needle: &[u8]) -> bool {
        let Some(rang) = self.rang(sequence) else {
            return false;
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return false;
        };
        match scope {
            SearchScope::Header => dans_un_champ(chemin, field, needle),
            SearchScope::Body => dans_le_corps(chemin, needle),
            // §6.4.4 : `TEXT` couvre l'en-tête ET le corps.
            SearchScope::Text => {
                dans_l_entete_entier(chemin, needle) || dans_le_corps(chemin, needle)
            }
        }
    }

    fn header_fields_len(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
    ) -> Option<u64> {
        let mut compose = std::vec![0_u8; CHOIX_MAX];
        let ecrits = self.choisir(sequence, path, names, except, &mut compose)?;
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
        // LE CHOIX SE RECOMPOSE À CHAQUE MORCEAU, comme l'enveloppe : le retenir
        // entre deux appels demanderait un état par session et par message, et
        // le recomposer coûte une lecture d'en-tête, bornée.
        let mut compose = std::vec![0_u8; CHOIX_MAX];
        let Some(ecrits) = self.choisir(sequence, path, names, except, &mut compose) else {
            return 0;
        };
        ecouler(compose.get(..ecrits).unwrap_or_default(), offset, out)
    }

    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return 0;
        };
        // ON ROUVRE LE FICHIER À CHAQUE MORCEAU, plutôt que de garder un
        // descripteur par message : une table de descripteurs épuisée arrête le
        // serveur entier, et une ouverture coûte moins que cela. Ce qu'on ne
        // refait PAS, c'est chercher le message — l'instantané le tient.
        let Ok(mut fichier) = std::fs::File::open(chemin) else {
            return 0;
        };
        if fichier.seek(SeekFrom::Start(offset)).is_err() {
            return 0;
        }
        fichier.read(out).unwrap_or(0)
    }

    fn permanent_flags(&self) -> Flags {
        // `\Deleted` N'EST PAS DE LA LISTE, ET C'EST VOULU. Le poser n'aurait de
        // sens que si quelque chose l'honorait : §6.4.2 veut qu'un `CLOSE`
        // efface les messages qui le portent, et rien n'efface encore. Un client
        // qui marque son courrier pour la corbeille et le retrouve intact au
        // relevé suivant a été trompé ; mieux vaut lui dire non tout de suite.
        Flags::SEEN
            .with(Flags::ANSWERED)
            .with(Flags::FLAGGED)
            .with(Flags::DELETED)
            .with(Flags::DRAFT)
    }

    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32> {
        // AUCUN CHEMIN N'EST CONSTRUIT À PARTIR D'UN NOM DE BOÎTE, ici non plus :
        // le nom est comparé à une constante, et la seule destination possible
        // est la boîte qu'on tient déjà.
        if !mailbox.eq_ignore_ascii_case(INBOX) {
            return None;
        }
        let rang = self.rang(sequence)?;
        let chemin = self.chemins.get(rang)?.clone();
        let drapeaux = self.drapeaux.get(rang).copied().unwrap_or_default();

        // ON ÉCRIT DANS `tmp/`, PUIS ON RENOMME. C'est la danse que Maildir
        // impose, et `Incoming` la connaît : tant que le message n'est pas
        // validé, personne ne le voit.
        let mut source = std::fs::File::open(&chemin).ok()?;
        let mut entrant = self.maildir.deliver().ok()?;
        let mut tampon = [0_u8; 8192];
        loop {
            let lus = source.read(&mut tampon).ok()?;
            if lus == 0 {
                break;
            }
            if entrant
                .write(tampon.get(..lus).unwrap_or_default())
                .is_err()
            {
                entrant.abort();
                return None;
            }
        }
        // §6.4.7 : les drapeaux du message d'origine sont préservés — en UN
        // renommage, pour qu'aucun client ne voie la copie sans eux.
        let uid = if drapeaux == Flags::NONE {
            entrant.commit().ok()?
        } else {
            entrant.commit_with_flags(drapeaux_maildir(drapeaux)).ok()?
        };
        Some(uid.value())
    }

    fn undo_copies(&mut self, mailbox: &[u8], premier: u32, dernier: u32) {
        if !mailbox.eq_ignore_ascii_case(INBOX) {
            return;
        }
        // On ne défait QUE ce qu'on vient de faire : les UID de la plage sont
        // ceux que `deliver` vient d'attribuer, et personne d'autre ne les a.
        for sous in ["new", "cur"] {
            let Ok(entrees) = std::fs::read_dir(self.maildir.root().join(sous)) else {
                continue;
            };
            for entree in entrees.flatten() {
                let nom = entree.file_name();
                let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
                    continue;
                };
                let Some(uid) = lu.uid() else {
                    continue;
                };
                if uid.value() >= premier && uid.value() <= dernier {
                    let _ = std::fs::remove_file(entree.path());
                }
            }
        }
    }

    fn remove(&mut self, sequence: u32) -> bool {
        let Some(rang) = self.rang(sequence) else {
            return false;
        };
        // RETIRER NE RELIT PAS LA MARQUE, et c'est toute la différence avec
        // `expunge` : il n'y a pas de marque à relire. Le message vient d'être
        // copié, à l'instant, et le client a demandé qu'il ne reste pas ici.
        // On le cherche quand même par son UID si son nom a changé — un
        // renommage concurrent ne doit pas laisser un doublon derrière un `MOVE`.
        for _ in 0..3_u32 {
            let Some(chemin) = self.chemins.get(rang).cloned() else {
                return false;
            };
            match std::fs::remove_file(&chemin) {
                Ok(()) => {
                    self.oublier(rang);
                    return true;
                }
                Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                    let uid = chemin
                        .file_name()
                        .and_then(|nom| MessageName::parse(nom.as_bytes()).ok())
                        .and_then(|lu| lu.uid());
                    match uid.and_then(|uid| retrouver(self.vue.root(), uid)) {
                        Some(actuel) => {
                            self.poser_le_chemin(rang, actuel);
                            continue;
                        }
                        None => break,
                    }
                }
                Err(_) => return false,
            }
        }
        // Introuvable sous son UID : il est bien parti, ce qui est ce qu'on
        // voulait.
        self.oublier(rang);
        true
    }

    fn expunge(&mut self, sequence: u32) -> bool {
        let Some(rang) = self.rang(sequence) else {
            return false;
        };
        // TROIS TENTATIVES, comme pour `store_flags` : chaque échec vient d'un
        // renommage concurrent, et trois de suite ne sont plus une course.
        for _ in 0..3_u32 {
            let Some(chemin) = self.chemins.get(rang).cloned() else {
                return false;
            };
            let Some(lu) = chemin
                .file_name()
                .and_then(|nom| MessageName::parse(nom.as_bytes()).ok())
            else {
                return false;
            };

            // ON NE VÉRIFIE PAS QU'ON PEUT EFFACER, ON VÉRIFIE QU'ON DOIT.
            //
            // La session demande d'effacer ce que SON instantané dit marqué
            // `\Deleted` — un instantané pris à l'ouverture, il y a peut-être
            // des heures. Entre-temps, une autre session a pu retirer la
            // marque. Effacer sur cette croyance-là, c'est perdre du courrier
            // que personne n'a demandé de perdre, et un courrier perdu ne se
            // retrouve pas. On relit donc le nom, qui porte les lettres.
            if !lu.flags().contains(ams_index::Flags::TRASHED) {
                // Deux causes possibles, et elles ne se valent pas : ou bien la
                // marque a vraiment été retirée, ou bien c'est NOTRE nom qui est
                // périmé. Le disque tranche.
                if chemin.symlink_metadata().is_ok() {
                    return false;
                }
                match lu.uid().and_then(|uid| retrouver(self.vue.root(), uid)) {
                    Some(actuel) => {
                        self.poser_le_chemin(rang, actuel);
                        continue;
                    }
                    None => break,
                }
            }

            match std::fs::remove_file(&chemin) {
                Ok(()) => {
                    self.oublier(rang);
                    return true;
                }
                // `NotFound` NE VEUT PAS DIRE « DÉJÀ PARTI ». Dans un Maildir,
                // un message qu'on ne trouve plus sous son nom a le plus souvent
                // simplement changé de nom — quelqu'un a écrit ses drapeaux. Le
                // prendre pour une disparition ferait oublier de la boîte un
                // message bien vivant, et pire : on l'aurait « effacé » sur la
                // foi de lettres lues dans un nom qui n'existe plus. Constaté
                // sur le binaire, en retirant la marque sous ses pieds.
                Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                    match lu.uid().and_then(|uid| retrouver(self.vue.root(), uid)) {
                        Some(actuel) => {
                            self.poser_le_chemin(rang, actuel);
                            continue;
                        }
                        None => break,
                    }
                }
                Err(_) => return false,
            }
        }
        // Introuvable sous son UID : celui-là est bien parti, et le client
        // demandait justement qu'il n'y soit plus.
        self.oublier(rang);
        true
    }

    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags> {
        let rang = self.rang(sequence)?;
        // TROIS TENTATIVES, ET PAS UNE BOUCLE SANS FIN. Chaque échec vient d'un
        // renommage concurrent ; s'il s'en produit trois de suite pendant qu'on
        // écrit une ligne, ce n'est plus une course, c'est un autre programme qui
        // remue la boîte, et insister ne fera que l'accompagner.
        for _ in 0..3_u32 {
            let chemin = self.chemins.get(rang)?.clone();
            let nom = chemin.file_name()?.as_bytes();
            let lu = MessageName::parse(nom).ok()?;
            // ON PART DE CE QU'ON VIENT DE LIRE, PAS DE CE QU'ON CROYAIT SAVOIR.
            // Les drapeaux sont relus dans le nom du fichier à l'instant où l'on
            // écrit : deux `+FLAGS` concurrents se composent alors, au lieu que
            // le second efface ce que le premier venait de poser. Un `FLAGS` nu,
            // lui, écrase — mais c'est ce que le client a demandé.
            let voulus = maildir_apres(lu.flags(), mode, flags);
            if voulus == lu.flags() && lu.has_info() {
                // RIEN À ÉCRIRE — ENCORE FAUT-IL QUE CE « RIEN » PORTE SUR UN
                // FICHIER QUI EXISTE. Les drapeaux qu'on vient de lire sont
                // ceux d'un NOM, et ce nom peut être celui que quelqu'un a
                // renommé pendant qu'on le tenait : croire qu'il n'y a rien à
                // faire reviendrait alors à répondre `OK` sans avoir rien écrit,
                // ce qui est exactement le mensonge qu'un `STORE` ne doit pas
                // faire. Constaté sur le binaire : un message renommé sous nos
                // pieds recevait `* 2 FETCH (FLAGS (\Seen \Flagged))` et un
                // `OK`, pendant que le fichier gardait ses anciennes lettres.
                if chemin.symlink_metadata().is_ok() {
                    return Some(drapeaux_imap(voulus));
                }
                *self.chemins.get_mut(rang)? = retrouver(self.vue.root(), lu.uid()?)?;
                continue;
            }
            let cible = self.vue.root().join("cur").join(nom_avec(nom, voulus));
            if std::fs::rename(&chemin, &cible).is_ok() {
                *self.chemins.get_mut(rang)? = cible;
                let nouveaux = drapeaux_imap(voulus);
                if let Some(place) = self.drapeaux.get_mut(rang) {
                    *place = nouveaux;
                }
                return Some(nouveaux);
            }
            // Le renommage a échoué : le message a bougé sous nos pieds. On le
            // retrouve par son UID — le seul identifiant qui survive à un
            // changement de drapeaux — et l'on recommence sur son nom actuel.
            *self.chemins.get_mut(rang)? = retrouver(self.vue.root(), lu.uid()?)?;
        }
        None
    }
}

/// Où finit le bloc d'en-tête, ligne vide comprise.
///
/// # On lit par morceaux, et l'on s'arrête
///
/// Un message dont on ne trouverait pas la ligne vide n'a pas d'en-tête — c'est
/// un fichier que quelqu'un a déposé là. On rend alors `None`, et l'appelant
/// prend le message entier : mieux vaut rendre trop que de prétendre découper ce
/// qu'on n'a pas su lire.
fn fin_de_l_entete(chemin: &std::path::Path) -> Option<u64> {
    let mut fichier = std::fs::File::open(chemin).ok()?;
    let mut tampon = [0_u8; 8192];
    let mut lus_en_tout = 0_u64;
    // Trois octets de recouvrement : la ligne vide peut être à cheval sur deux
    // morceaux, et la chercher morceau par morceau sans recouvrement la
    // manquerait une fois sur deux mille.
    let mut queue = [0_u8; 3];
    let mut queue_len = 0_usize;
    loop {
        let lus = fichier.read(&mut tampon).ok()?;
        if lus == 0 {
            return None;
        }
        let mut fenetre = Vec::with_capacity(queue_len.saturating_add(lus));
        fenetre.extend_from_slice(queue.get(..queue_len).unwrap_or_default());
        fenetre.extend_from_slice(tampon.get(..lus).unwrap_or_default());
        if let Some(rang) = fenetre
            .windows(4)
            .position(|fenetre| fenetre == b"\r\n\r\n")
        {
            let avant = lus_en_tout.saturating_sub(queue_len as u64);
            return Some(avant.saturating_add(rang as u64).saturating_add(4));
        }
        lus_en_tout = lus_en_tout.saturating_add(lus as u64);
        let reste = fenetre.len().min(3);
        queue_len = reste;
        queue.get_mut(..reste).unwrap_or_default().copy_from_slice(
            fenetre
                .get(fenetre.len().saturating_sub(reste)..)
                .unwrap_or_default(),
        );
    }
}

/// Les boîtes du serveur, telles qu'IMAP les ouvre.
pub struct BoitesImap {
    /// La boîte d'arrivée de chaque compte, ouverte au démarrage.
    boites: Arc<BTreeMap<String, Arc<Maildir>>>,
    /// Le nom d'hôte, qui entre dans les noms de fichiers Maildir.
    hote: Vec<u8>,
    /// Les dossiers déjà ouverts, par compte et par nom.
    ///
    /// # POURQUOI UN CACHE, ET POURQUOI IL EST BORNÉ PAR CE QUI EXISTE
    ///
    /// Ouvrir un Maildir relit son index, adopte les messages sans UID et
    /// réécrit l'index : le refaire à chaque `LIST` ou chaque `SELECT`
    /// coûterait un parcours de répertoire par commande. Le cache ne grandit
    /// que d'une entrée par dossier RÉELLEMENT créé — un client ne peut donc
    /// pas le faire enfler en nommant des boîtes au hasard.
    dossiers: std::sync::Mutex<BTreeMap<(String, String), Arc<Maildir>>>,
    /// Les abonnements de chaque compte, tels qu'on les a lus.
    ///
    /// # POURQUOI UN CACHE, ET CE QU'IL COÛTE QUAND RIEN NE CHANGE
    ///
    /// Un `LIST` pose la question « suis-je abonné ? » une fois par boîte. La
    /// poser en relisant le fichier ferait une lecture par boîte listée, pour
    /// une réponse qui est la même à chaque fois. La date du fichier suffit à
    /// savoir qu'elle n'a pas changé : un `stat` par question, et aucune lecture
    /// tant que personne n'a écrit.
    ///
    /// **C'EST AUSSI CE QUI ORDONNE LES ÉCRITURES.** Deux sessions du même
    /// compte qui s'abonnent en même temps liraient la même liste et
    /// s'écraseraient l'une l'autre ; ce verrou-ci les met en file. Il ne dit
    /// rien de DEUX SERVEURS sur le même magasin — mais deux serveurs sur le
    /// même magasin se disputent bien davantage que ce fichier.
    abonnes: std::sync::Mutex<BTreeMap<String, Abonnements>>,
}

/// Les abonnements d'un compte, et la date du fichier qui les porte.
#[derive(Debug, Clone, Default)]
struct Abonnements {
    /// Ce que le fichier portait au dernier regard, ou `None` s'il n'y en avait
    /// pas — un compte qui ne s'est jamais abonné n'a pas de fichier.
    vu: Option<std::time::SystemTime>,
    /// Les noms, triés et sans doublon.
    noms: Arc<Vec<Vec<u8>>>,
}

impl BoitesImap {
    /// Monte le service à partir des boîtes déjà ouvertes par le serveur.
    #[must_use]
    pub fn new(boites: Arc<BTreeMap<String, Arc<Maildir>>>, hote: &[u8]) -> Self {
        Self {
            boites,
            hote: hote.to_vec(),
            dossiers: std::sync::Mutex::new(BTreeMap::new()),
            abonnes: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// La racine de la boîte d'arrivée d'un compte.
    fn racine(&self, user: &[u8]) -> Option<PathBuf> {
        let nom = core::str::from_utf8(user).ok()?;
        Some(self.boites.get(nom)?.root().to_path_buf())
    }

    /// Le répertoire d'un dossier, à la façon de Maildir++.
    ///
    /// # C'EST ICI QU'UN NOM DE CLIENT DEVIENT UN CHEMIN
    ///
    /// Et c'est pourquoi la règle est vérifiée UNE SECONDE FOIS, alors que la
    /// session l'a déjà appliquée : c'est ce code-ci qui touche le système de
    /// fichiers, et une vérification faite ailleurs est une vérification qu'on
    /// ne voit pas en lisant l'endroit qui en dépend. Elle ne coûte rien, et
    /// elle survivra à un appelant qui l'oublierait.
    ///
    /// `Archives/2026` devient `.Archives.2026` DANS la racine du compte : un
    /// seul niveau de répertoires, comme Maildir++ le veut, et donc aucun
    /// chemin composé de plusieurs morceaux venus du client.
    fn chemin_du_dossier(&self, user: &[u8], name: &[u8]) -> Option<PathBuf> {
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        if !ams_proto_imap::mailbox_name_is_safe(name) {
            return None;
        }
        let racine = self.racine(user)?;
        let mut repertoire = std::vec::Vec::with_capacity(name.len().saturating_add(1));
        repertoire.push(b'.');
        for octet in name {
            repertoire.push(if *octet == b'/' { b'.' } else { *octet });
        }
        // Le nom composé ne porte ni `/` ni `..` : la vérification l'a exclu, et
        // la transcription ne peut pas en introduire.
        Some(racine.join(std::ffi::OsString::from_vec(repertoire)))
    }

    /// La boîte d'un compte : `INBOX`, ou un dossier qui existe déjà.
    fn maildir(&self, user: &[u8], name: &[u8]) -> Option<Arc<Maildir>> {
        if name.eq_ignore_ascii_case(INBOX) {
            let nom = core::str::from_utf8(user).ok()?;
            return self.boites.get(nom).map(Arc::clone);
        }
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        let clef = (
            core::str::from_utf8(user).ok()?.to_owned(),
            core::str::from_utf8(name).ok()?.to_owned(),
        );
        let mut ouverts = self.dossiers.lock().ok()?;
        if let Some(deja) = ouverts.get(&clef) {
            return Some(Arc::clone(deja));
        }
        let chemin = self.chemin_du_dossier(user, name)?;
        // ON N'OUVRE QUE CE QUI EXISTE. `Maildir::open` crée l'arborescence
        // qu'on lui nomme : l'appeler sans regarder ferait de chaque `SELECT`
        // sur une faute de frappe une boîte de plus.
        // ON N'OUVRE QUE CE QUI EST UNE BOÎTE. Un répertoire sans `cur/` est un
        // nom que §6.3.5 a laissé derrière un effacement : l'ouvrir le
        // ressusciterait, puisque `Maildir::open` recrée ce qui manque.
        if !chemin.is_dir() || !Self::selectionnable(&chemin) {
            return None;
        }
        let boite = Arc::new(Maildir::open(&chemin, &self.hote, fresh_uid_validity()).ok()?);
        ouverts.insert(clef, Arc::clone(&boite));
        Some(boite)
    }

    /// Oublie les boîtes ouvertes d'un compte à partir d'un nom, filles
    /// comprises.
    fn oublier_les_ouverts(&self, user: &[u8], depuis: &[u8]) {
        let (Ok(compte), Ok(nom)) = (core::str::from_utf8(user), core::str::from_utf8(depuis))
        else {
            return;
        };
        if let Ok(mut ouverts) = self.dossiers.lock() {
            ouverts.retain(|(c, boite), _| {
                c != compte || (boite != nom && !boite.starts_with(&std::format!("{nom}/")))
            });
        }
    }

    /// §6.3.6 : renommer `INBOX` DÉPLACE SON COURRIER et la laisse en place.
    ///
    /// Elle n'est pas une boîte comme une autre : c'est le seul endroit où le
    /// courrier arrive, et un compte qui la perdrait ne recevrait plus rien. On
    /// crée donc la destination, on y déplace les messages un à un, et l'arrivée
    /// reste — vide.
    fn vider_l_arrivee(&self, user: &[u8], to: &[u8], cible: &std::path::Path) -> Renaming {
        let Some(arrivee) = self.racine(user) else {
            return Renaming::Absente;
        };
        if self.create(user, to) == Creation::Refusee {
            return Renaming::Refusee;
        }
        for sous in ["cur", "new"] {
            let Ok(entrees) = std::fs::read_dir(arrivee.join(sous)) else {
                continue;
            };
            for entree in entrees.flatten() {
                // Un déplacement dans le même système de fichiers est un
                // renommage : le message ne passe jamais par la mémoire, et il
                // n'existe à aucun instant en deux exemplaires.
                let _ = std::fs::rename(entree.path(), cible.join(sous).join(entree.file_name()));
            }
        }
        // ON GARDE L'INDEX DE L'ARRIVÉE, et c'est essentiel. Il porte le
        // prochain UID à servir, et son `UIDVALIDITY` NE CHANGE PAS : la retirer
        // ferait repartir les UID de un après un redémarrage, sous la même
        // validité — c'est-à-dire réattribuer des numéros déjà donnés, ce que
        // §2.3.1.1 interdit. Un index qui compte des messages partis n'est pas
        // un problème : le parcours dit ce qui EST, l'index seulement ce qui A
        // ÉTÉ, et `reconcile` les confronte dans cet ordre.
        Renaming::Faite
    }

    /// Cette boîte est-elle ouvrable ?
    ///
    /// # UN RÉPERTOIRE SANS `cur/` N'EST PAS UNE BOÎTE
    ///
    /// §6.3.5 : une boîte effacée qui avait des filles garde son nom sans son
    /// courrier. Sur le disque, cela se dit sans marqueur : le répertoire reste,
    /// et ses trois sous-répertoires Maildir s'en vont. Un nom qui n'a plus de
    /// `cur/` est donc `\Noselect`, et il le RESTE tant qu'un `CREATE` ne le
    /// refait pas — ce que §6.3.4 autorise expressément.
    fn selectionnable(chemin: &std::path::Path) -> bool {
        chemin.join("cur").is_dir()
    }

    /// Le fichier d'abonnements d'un compte.
    fn fichier_des_abonnements(&self, user: &[u8]) -> Option<PathBuf> {
        Some(self.racine(user)?.join(ABONNEMENTS))
    }

    /// Les abonnements d'un compte, relus seulement si le fichier a bougé.
    fn abonnements(&self, user: &[u8]) -> Arc<Vec<Vec<u8>>> {
        let vide = || Arc::new(std::vec::Vec::new());
        let (Some(chemin), Ok(compte)) = (
            self.fichier_des_abonnements(user),
            core::str::from_utf8(user),
        ) else {
            return vide();
        };
        // LA DATE D'ABORD : c'est la réponse dans l'immense majorité des cas, et
        // elle ne lit rien.
        let date = std::fs::metadata(&chemin)
            .ok()
            .and_then(|etat| etat.modified().ok());
        let Ok(mut cache) = self.abonnes.lock() else {
            return vide();
        };
        if let Some(connu) = cache.get(compte).filter(|connu| connu.vu == date) {
            return Arc::clone(&connu.noms);
        }
        let noms = Arc::new(lire_les_abonnements(&chemin));
        cache.insert(
            compte.to_string(),
            Abonnements {
                vu: date,
                noms: Arc::clone(&noms),
            },
        );
        noms
    }

    /// Réécrit le fichier d'abonnements d'un compte.
    ///
    /// # ON ÉCRIT À CÔTÉ, PUIS ON RENOMME
    ///
    /// Écrire par-dessus laisserait, le temps de l'écriture, un fichier tronqué
    /// que `LIST` pourrait lire : le client verrait alors la moitié de ses
    /// abonnements. Le renommage est atomique — un lecteur voit l'ancienne liste
    /// ou la nouvelle, jamais un entre-deux.
    fn ecrire_les_abonnements(&self, user: &[u8], noms: &[Vec<u8>]) -> bool {
        let (Some(chemin), Ok(compte)) = (
            self.fichier_des_abonnements(user),
            core::str::from_utf8(user),
        ) else {
            return false;
        };
        let mut texte = std::vec::Vec::new();
        for nom in noms {
            texte.extend_from_slice(nom);
            texte.push(b'\n');
        }
        let provisoire = chemin.with_extension("tmp");
        if std::fs::write(&provisoire, &texte).is_err() {
            return false;
        }
        if std::fs::rename(&provisoire, &chemin).is_err() {
            // Ce qu'on n'a pas pu poser, on l'enlève : un fichier provisoire
            // laissé là resterait à jamais.
            let _ = std::fs::remove_file(&provisoire);
            return false;
        }
        // LE CACHE DOIT SUIVRE, ET IMMÉDIATEMENT : la session qui vient
        // d'écrire va lister, et deux écritures dans la même seconde peuvent
        // porter la même date sur un système de fichiers qui ne compte pas plus
        // fin. S'en remettre à la date ferait relire l'ancienne liste.
        if let Ok(mut cache) = self.abonnes.lock() {
            let date = std::fs::metadata(&chemin)
                .ok()
                .and_then(|etat| etat.modified().ok());
            cache.insert(
                compte.to_string(),
                Abonnements {
                    vu: date,
                    noms: Arc::new(noms.to_vec()),
                },
            );
        }
        true
    }

    /// Le nom sous lequel un abonnement s'inscrit.
    ///
    /// `INBOX` s'écrit comme le client veut (§5.1) et désigne toujours la même
    /// boîte : on l'inscrit sous une seule écriture, faute de quoi `inbox` et
    /// `INBOX` feraient deux abonnements pour une boîte.
    fn nom_abonne(name: &[u8]) -> Vec<u8> {
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        if name.eq_ignore_ascii_case(INBOX) {
            return INBOX.to_vec();
        }
        name.to_vec()
    }

    /// Les dossiers d'un compte, par ordre de nom.
    fn dossiers_de(&self, user: &[u8]) -> Vec<Vec<u8>> {
        let mut noms = std::vec![INBOX.to_vec()];
        let Some(racine) = self.racine(user) else {
            return noms;
        };
        let Ok(entrees) = std::fs::read_dir(&racine) else {
            return noms;
        };
        let mut dossiers = std::vec::Vec::new();
        for entree in entrees.flatten() {
            if !entree.path().is_dir() {
                continue;
            }
            let nom = entree.file_name();
            let Some(reste) = nom.as_bytes().strip_prefix(b".") else {
                continue;
            };
            // ON NE REND QUE CE QU'ON SAURAIT RELIRE. Un répertoire déposé là
            // par autre chose que nous — un point d'accueil, un `.git` — n'a pas
            // à devenir une boîte que le client croira sienne.
            let imap: Vec<u8> = reste
                .iter()
                .map(|octet| if *octet == b'.' { b'/' } else { *octet })
                .collect();
            if ams_proto_imap::mailbox_name_is_safe(&imap) {
                dossiers.push(imap);
            }
        }
        dossiers.sort_unstable();
        noms.extend(dossiers);
        noms
    }
}

/// Relit un fichier d'abonnements.
///
/// **ON LIT UNE BORNE, PAS UN FICHIER** : celui-ci vit dans la racine du compte,
/// et rien ne garantit que personne n'y a écrit autre chose. Ce qui dépasse est
/// ignoré, et ce qui n'est pas un nom de boîte servable aussi — un nom qu'on ne
/// saurait pas ouvrir n'a rien à faire dans la liste qu'on rend au client.
fn lire_les_abonnements(chemin: &Path) -> Vec<Vec<u8>> {
    let mut noms = std::vec::Vec::new();
    let Ok(fichier) = std::fs::File::open(chemin) else {
        return noms;
    };
    let mut texte = std::vec::Vec::new();
    if std::io::Read::read_to_end(
        &mut std::io::Read::take(fichier, ABONNEMENTS_OCTETS_MAX),
        &mut texte,
    )
    .is_err()
    {
        return noms;
    }
    for ligne in texte.split(|octet| *octet == b'\n') {
        let nom = ligne.trim_ascii();
        if nom.is_empty() || noms.len() >= ABONNEMENTS_MAX {
            continue;
        }
        if nom.eq_ignore_ascii_case(INBOX) {
            noms.push(INBOX.to_vec());
            continue;
        }
        if ams_proto_imap::mailbox_name_is_safe(nom) {
            noms.push(nom.to_vec());
        }
    }
    noms.sort_unstable();
    noms.dedup();
    noms
}

/// Un message en cours de dépôt, vu par IMAP.
///
/// Ce n'est qu'une [`Incoming`] : la danse Maildir — écrire dans `tmp/`,
/// synchroniser, renommer — est la même qu'une remise SMTP, et il n'y a aucune
/// raison d'en avoir deux.
pub struct DepotImap {
    entrant: Option<Incoming>,
}

impl Deposit for DepotImap {
    fn write(&mut self, chunk: &[u8]) -> bool {
        let Some(entrant) = self.entrant.as_mut() else {
            return false;
        };
        entrant.write(chunk).is_ok()
    }

    fn commit(mut self, flags: Flags, date: Option<u64>) -> Option<u32> {
        let entrant = self.entrant.take()?;
        let quand = date.map(|secondes| {
            std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_secs(secondes))
                .unwrap_or(std::time::UNIX_EPOCH)
        });
        // Sans drapeaux ET sans date, c'est une arrivée ordinaire : elle va dans
        // `new/`, là où Maildir met ce qu'on n'a pas encore vu.
        let uid = if flags == Flags::NONE && quand.is_none() {
            entrant.commit().ok()?
        } else {
            entrant.commit_with(drapeaux_maildir(flags), quand).ok()?
        };
        Some(uid.value())
    }

    fn abort(mut self) {
        // On parcourt une tranche plutôt que de tester une option : un dépôt
        // ouvert n'est pas une condition, c'est une chose qu'on a ou qu'on n'a
        // pas. Ici il faut le CONSOMMER, d'où le `take` puis le `if let` — et
        // le « et sinon » est bien atteignable : un dépôt abandonné deux fois.
        if let Some(entrant) = self.entrant.take() {
            entrant.abort();
        }
    }
}

impl Mailboxes for BoitesImap {
    type Open = BoiteImap;
    type Deposit = DepotImap;

    fn append(&self, user: &[u8], name: &[u8]) -> Option<DepotImap> {
        let maildir = self.maildir(user, name)?;
        Some(DepotImap {
            entrant: Some(maildir.deliver().ok()?),
        })
    }

    fn subscribe(&self, user: &[u8], name: &[u8]) -> Subscription {
        let nom = Self::nom_abonne(name);
        // ON VALIDE À L'ABONNEMENT : accepter un abonnement à une boîte qui n'a
        // jamais existé rendrait au client une liste où figure un nom qu'il ne
        // pourra pas ouvrir.
        if !self.dossiers_de(user).contains(&nom) {
            return Subscription::Absente;
        }
        let mut noms = (*self.abonnements(user)).clone();
        // §6.3.7 : se réabonner n'est pas une faute. Rien à écrire, et l'état
        // demandé est déjà celui qu'on a.
        if noms.contains(&nom) {
            return Subscription::Faite;
        }
        if noms.len() >= ABONNEMENTS_MAX {
            return Subscription::Refusee;
        }
        noms.push(nom);
        noms.sort_unstable();
        match self.ecrire_les_abonnements(user, &noms) {
            true => Subscription::Faite,
            false => Subscription::Refusee,
        }
    }

    fn unsubscribe(&self, user: &[u8], name: &[u8]) -> Subscription {
        // **AUCUNE VÉRIFICATION D'EXISTENCE ICI**, et c'est le point de §6.3.8 :
        // se désabonner d'une boîte disparue est exactement ce qu'un client fait
        // pour se débarrasser d'un abonnement orphelin. Le refuser l'y
        // enfermerait.
        let nom = Self::nom_abonne(name);
        let mut noms = (*self.abonnements(user)).clone();
        let avant = noms.len();
        noms.retain(|autre| *autre != nom);
        if noms.len() == avant {
            // Se désabonner de ce à quoi l'on n'est pas abonné n'est pas une
            // faute : l'état demandé est déjà celui qu'on a.
            return Subscription::Faite;
        }
        match self.ecrire_les_abonnements(user, &noms) {
            true => Subscription::Faite,
            false => Subscription::Refusee,
        }
    }

    fn is_subscribed(&self, user: &[u8], name: &[u8]) -> bool {
        let nom = Self::nom_abonne(name);
        self.abonnements(user).contains(&nom)
    }

    fn orphan<'n>(&self, user: &[u8], index: usize, out: &'n mut [u8]) -> Option<&'n [u8]> {
        let existantes = self.dossiers_de(user);
        let abonnements = self.abonnements(user);
        let nom = abonnements
            .iter()
            .filter(|nom| !existantes.contains(nom))
            .nth(index)?;
        let longueur = nom.len().min(out.len());
        let place = out.get_mut(..longueur)?;
        place.copy_from_slice(nom.get(..longueur)?);
        Some(place)
    }

    fn name<'n>(&self, user: &[u8], index: usize, out: &'n mut [u8]) -> Option<Listing<'n>> {
        // Le compte d'abord : sans lui, il n'y a pas de boîte à nommer.
        let compte = core::str::from_utf8(user).ok()?;
        self.boites.get(compte)?;
        let noms = self.dossiers_de(user);
        let nom = noms.get(index)?;
        let selectable = nom.as_slice() == INBOX
            || self
                .chemin_du_dossier(user, nom)
                .is_some_and(|chemin| Self::selectionnable(&chemin));
        // UNE FILLE EST UNE BOÎTE DONT LE NOM COMMENCE PAR LE NÔTRE, SUIVI DU
        // SÉPARATEUR. On les cherche dans la liste qu'on tient déjà : ouvrir le
        // système de fichiers une seconde fois pour la même question coûterait un
        // parcours de répertoire par boîte listée.
        let has_children = noms.iter().any(|autre| {
            autre
                .get(..nom.len())
                .is_some_and(|debut| debut == nom.as_slice())
                && autre.get(nom.len()).copied() == Some(b'/')
        });
        let longueur = nom.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        Some(Listing {
            name: out.get(..longueur)?,
            selectable,
            has_children,
        })
    }

    fn rename(&self, user: &[u8], from: &[u8], to: &[u8]) -> Renaming {
        let from = ams_proto_imap::mailbox_name_trimmed(from);
        let to = ams_proto_imap::mailbox_name_trimmed(to);
        if to.eq_ignore_ascii_case(INBOX) || !ams_proto_imap::mailbox_name_is_safe(to) {
            return Renaming::Refusee;
        }
        let Some(cible) = self.chemin_du_dossier(user, to) else {
            return Renaming::Refusee;
        };
        if cible.exists() {
            return Renaming::DejaLa;
        }
        // La boîte d'arrivée est un cas à part : elle ne se déplace pas.
        if from.eq_ignore_ascii_case(INBOX) {
            return self.vider_l_arrivee(user, to, &cible);
        }

        let Some(source) = self.chemin_du_dossier(user, from) else {
            return Renaming::Refusee;
        };
        if !source.is_dir() {
            return Renaming::Absente;
        }

        // §6.3.6 : LES FILLES SUIVENT. On rassemble d'abord tout ce qui bouge,
        // et l'on vérifie que RIEN n'est déjà pris : renommer à moitié laisserait
        // des boîtes dont le chemin ne mène plus nulle part.
        let mut mouvements = std::vec::Vec::new();
        mouvements.push((source.clone(), cible.clone()));
        for autre in self.dossiers_de(user) {
            if autre.len() <= from.len()
                || !autre.starts_with(from)
                || autre.get(from.len()) != Some(&b'/')
            {
                continue;
            }
            let mut neuf = to.to_vec();
            neuf.extend_from_slice(autre.get(from.len()..).unwrap_or_default());
            let (Some(vieux), Some(neuf)) = (
                self.chemin_du_dossier(user, &autre),
                self.chemin_du_dossier(user, &neuf),
            ) else {
                return Renaming::Refusee;
            };
            if neuf.exists() {
                return Renaming::DejaLa;
            }
            mouvements.push((vieux, neuf));
        }

        // Les boîtes concernées cessent d'être ouvertes : un `Maildir` gardé en
        // cache écrirait son index dans un répertoire qui a changé de nom.
        self.oublier_les_ouverts(user, from);

        // ON DÉFAIT CE QU'ON A FAIT. Un renommage à moitié réussi laisserait la
        // mère sous un nom et ses filles sous l'autre, ce qu'aucun client ne
        // saurait démêler.
        let mut faits = std::vec::Vec::new();
        for (vieux, neuf) in &mouvements {
            if std::fs::rename(vieux, neuf).is_err() {
                for (vieux, neuf) in faits.iter().rev() {
                    let _ = std::fs::rename(neuf, vieux);
                }
                return Renaming::Refusee;
            }
            faits.push((vieux.clone(), neuf.clone()));
        }
        Renaming::Faite
    }

    fn delete(&self, user: &[u8], name: &[u8]) -> Deletion {
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        // §6.3.5 : `INBOX` ne s'efface pas. La session le dit déjà ; on ne s'y
        // fie pas, puisque c'est ici que des fichiers disparaîtraient.
        if name.eq_ignore_ascii_case(INBOX) {
            return Deletion::Refusee;
        }
        let Some(chemin) = self.chemin_du_dossier(user, name) else {
            return Deletion::Absente;
        };
        if !chemin.is_dir() || !Self::selectionnable(&chemin) {
            return Deletion::Absente;
        }
        // La boîte cesse d'être ouverte AVANT d'être effacée : un `Maildir`
        // gardé en cache écrirait son index dans un répertoire qui n'est plus.
        if let Ok(mut ouverts) = self.dossiers.lock()
            && let (Ok(compte), Ok(boite)) =
                (core::str::from_utf8(user), core::str::from_utf8(name))
        {
            ouverts.remove(&(compte.to_owned(), boite.to_owned()));
        }

        // §6.3.5 : UNE BOÎTE QUI A DES FILLES NE DISPARAÎT PAS. Son courrier
        // s'en va, son nom demeure — sans quoi ses filles n'auraient plus de
        // chemin par où être nommées.
        let a_des_filles = self.dossiers_de(user).iter().any(|autre| {
            autre.len() > name.len()
                && autre.starts_with(name)
                && autre.get(name.len()) == Some(&b'/')
        });
        for sous in ["cur", "new", "tmp"] {
            if std::fs::remove_dir_all(chemin.join(sous)).is_err() {
                return Deletion::Refusee;
            }
        }
        // L'index part avec le courrier : le garder ferait qu'une boîte recréée
        // sous le même nom reprendrait les UID de l'ancienne.
        let _ = std::fs::remove_file(chemin.join("ams-index.bin"));
        if a_des_filles {
            return Deletion::Videe;
        }
        if std::fs::remove_dir(&chemin).is_err() {
            // Le répertoire n'est pas vide : quelque chose y vit qui n'est pas à
            // nous. On a retiré le courrier, on ne retire pas le reste.
            return Deletion::Videe;
        }
        Deletion::Faite
    }

    fn create(&self, user: &[u8], name: &[u8]) -> Creation {
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        // §6.3.4 : `INBOX` existe toujours. La session le dit déjà ; on ne s'y
        // fie pas, puisque c'est ici qu'un répertoire naîtrait.
        if name.eq_ignore_ascii_case(INBOX) {
            return Creation::DejaLa;
        }
        let Some(chemin) = self.chemin_du_dossier(user, name) else {
            return Creation::Refusee;
        };
        // §6.3.4 : CRÉER SUR UN NOM `\Noselect` LE REND OUVRABLE. C'est
        // exactement ce que la RFC prévoit pour reprendre une boîte effacée qui
        // avait des filles.
        if chemin.is_dir() && Self::selectionnable(&chemin) {
            return Creation::DejaLa;
        }
        // §6.3.4 : CRÉER `A/B` CRÉE AUSSI `A`. En Maildir++ il n'y a qu'un
        // niveau de répertoires, et les parents sont donc des répertoires
        // frères — il faut les faire, sans quoi `LIST` montrerait une fille
        // sans sa mère.
        let mut parcouru = std::vec::Vec::new();
        for composant in name.split(|octet| *octet == b'/') {
            if !parcouru.is_empty() {
                parcouru.push(b'/');
            }
            parcouru.extend_from_slice(composant);
            let Some(chemin) = self.chemin_du_dossier(user, &parcouru) else {
                return Creation::Refusee;
            };
            if chemin.is_dir() && Self::selectionnable(&chemin) {
                continue;
            }
            if Maildir::open(&chemin, &self.hote, fresh_uid_validity()).is_err() {
                return Creation::Refusee;
            }
        }
        Creation::Faite
    }

    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open> {
        let maildir = self.maildir(user, name)?;
        let vue = MailboxView::open(&maildir).ok()?;
        let (drapeaux, dates) = vue
            .messages()
            .iter()
            .map(|message| (drapeaux_de(&message.path), date_de(&message.path)))
            .unzip();
        let chemins = vue
            .messages()
            .iter()
            .map(|message| message.path.clone())
            .collect();
        Some(BoiteImap {
            vue,
            maildir: Arc::clone(&maildir),
            uid_validity: maildir.uid_validity().value(),
            drapeaux,
            dates,
            chemins,
            vu: empreinte_du_maildir(&maildir),
        })
    }
}

impl BoiteImap {
    /// Note où vit désormais le message de rang `rang`.
    fn poser_le_chemin(&mut self, rang: usize, chemin: PathBuf) {
        if let Some(place) = self.chemins.get_mut(rang) {
            *place = chemin;
        }
    }

    /// Retire un message de l'instantané, et de tout ce qui le suit rang par
    /// rang. **Les quatre listes descendent ensemble** : en oublier une ferait
    /// lire les drapeaux d'un message dans ceux d'un autre.
    fn oublier(&mut self, rang: usize) {
        self.vue.forget(rang);
        for liste in [&mut self.chemins] {
            if rang < liste.len() {
                liste.remove(rang);
            }
        }
        if rang < self.drapeaux.len() {
            self.drapeaux.remove(rang);
        }
        if rang < self.dates.len() {
            self.dates.remove(rang);
        }
    }
}

/// Ce que deviennent les lettres Maildir d'un message après un `STORE`.
///
/// # `P` N'EST PAS DANS LE VOCABULAIRE D'IMAP, DONC IMAP NE PEUT PAS LE RETIRER
///
/// Maildir a six lettres, IMAP cinq drapeaux, et `P` (*passed*, transmis) n'a
/// pas d'équivalent. Un `FLAGS (\Seen)` demande « exactement `\Seen` » — mais
/// exactement dans le vocabulaire du client, qui ne sait pas dire `P`. Le lui
/// faire effacer serait lui prêter une intention qu'il ne pouvait pas former.
fn maildir_apres(actuels: ams_index::Flags, mode: StoreMode, demandes: Flags) -> ams_index::Flags {
    let demandes = drapeaux_maildir(demandes);
    match mode {
        StoreMode::Add => actuels.with(demandes),
        StoreMode::Remove => actuels.without(demandes),
        // Ce qu'IMAP ne sait pas nommer, il ne le remplace pas.
        StoreMode::Replace => {
            let hors_du_vocabulaire = actuels.contains(ams_index::Flags::PASSED);
            if hors_du_vocabulaire {
                demandes.with(ams_index::Flags::PASSED)
            } else {
                demandes
            }
        }
    }
}

/// Le nom d'un message, avec d'autres lettres.
///
/// **On recopie tout ce qui précède le `:`**, champs étrangers compris : un
/// autre outil a pu y poser le sien, et le recomposer à partir de ce qu'on en
/// comprend lui ferait perdre ce qu'il y avait mis.
fn nom_avec(nom: &[u8], drapeaux: ams_index::Flags) -> std::ffi::OsString {
    let unique = nom.split(|octet| *octet == b':').next().unwrap_or_default();
    let mut lettres = [0_u8; ams_index::Flags::MAX_OCTETS];
    let ecrites = drapeaux.write_into(&mut lettres);
    let mut compose = Vec::with_capacity(unique.len().saturating_add(3).saturating_add(ecrites));
    compose.extend_from_slice(unique);
    compose.extend_from_slice(b":2,");
    compose.extend_from_slice(lettres.get(..ecrites).unwrap_or_default());
    std::ffi::OsString::from_vec(compose)
}

/// Retrouve un message par son UID, quand son nom a changé sous nos pieds.
fn retrouver(racine: &std::path::Path, uid: Uid) -> Option<PathBuf> {
    for sous in ["cur", "new"] {
        let Ok(entrees) = std::fs::read_dir(racine.join(sous)) else {
            continue;
        };
        for entree in entrees.flatten() {
            let nom = entree.file_name();
            let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
                continue;
            };
            if lu.uid() == Some(uid) {
                return Some(entree.path());
            }
        }
    }
    None
}

/// Les lettres Maildir d'un jeu de drapeaux IMAP.
fn drapeaux_maildir(drapeaux: Flags) -> ams_index::Flags {
    let mut maildir = ams_index::Flags::NONE;
    for (present, lettre) in [
        (drapeaux.contains(Flags::SEEN), ams_index::Flags::SEEN),
        (
            drapeaux.contains(Flags::ANSWERED),
            ams_index::Flags::REPLIED,
        ),
        (drapeaux.contains(Flags::FLAGGED), ams_index::Flags::FLAGGED),
        (drapeaux.contains(Flags::DELETED), ams_index::Flags::TRASHED),
        (drapeaux.contains(Flags::DRAFT), ams_index::Flags::DRAFT),
    ] {
        if present {
            maildir = maildir.with(lettre);
        }
    }
    maildir
}

/// Les drapeaux IMAP d'un jeu de lettres Maildir.
fn drapeaux_imap(maildir: ams_index::Flags) -> Flags {
    let mut drapeaux = Flags::NONE;
    // LES LETTRES DE MAILDIR NE SONT PAS LES DRAPEAUX D'IMAP, et la
    // correspondance n'est pas totale : `P` (transmis) n'a pas d'équivalent, et
    // `T` (trashed) est ce qu'IMAP appelle `\Deleted`.
    for (present, drapeau) in [
        (maildir.contains(ams_index::Flags::SEEN), Flags::SEEN),
        (maildir.contains(ams_index::Flags::REPLIED), Flags::ANSWERED),
        (maildir.contains(ams_index::Flags::FLAGGED), Flags::FLAGGED),
        (maildir.contains(ams_index::Flags::TRASHED), Flags::DELETED),
        (maildir.contains(ams_index::Flags::DRAFT), Flags::DRAFT),
    ] {
        if present {
            drapeaux = drapeaux.with(drapeau);
        }
    }
    drapeaux
}

/// Les drapeaux d'un message, lus dans son nom de fichier.
fn drapeaux_de(chemin: &std::path::Path) -> Flags {
    let Some(nom) = chemin.file_name().and_then(|brut| brut.to_str()) else {
        return Flags::NONE;
    };
    let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
        return Flags::NONE;
    };
    drapeaux_imap(lu.flags())
}

/// La date d'arrivée d'un message : celle du fichier.
///
/// **Ce n'est pas la date du message** : `INTERNALDATE` dit quand il est arrivé
/// ici, et c'est bien ce que la date de modification du fichier raconte.
fn date_de(chemin: &std::path::Path) -> u64 {
    std::fs::metadata(chemin)
        .and_then(|donnees| donnees.modified())
        .ok()
        .and_then(|instant| instant.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |ecoule| ecoule.as_secs())
}
