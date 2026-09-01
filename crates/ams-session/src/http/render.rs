// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les représentations des ressources : **ce que l'API rend, et rien de plus**.
//!
//! # LE MAGASIN LIT, CE MODULE ÉCRIT
//!
//! Rien ici n'ouvre un fichier. L'appelant a lu la boîte — c'est son travail, et
//! il a le droit d'attendre — puis il passe ce qu'il a lu sous une forme que
//! cette crate sait rendre. La séparation n'est pas une élégance : c'est ce qui
//! permet à ces représentations d'être éprouvées exhaustivement, sans disque et
//! sans horloge (C1).
//!
//! # UN UID N'EST PAS UN RANG, ET C'EST LA DÉCISION PRINCIPALE
//!
//! IMAP a deux façons de désigner un message : son numéro de séquence — sa place
//! dans la boîte — et son UID. Le premier CHANGE quand un message est effacé :
//! le message numéro 4 d'hier est le numéro 3 d'aujourd'hui.
//!
//! Une API où l'on agit par requêtes séparées ne peut pas s'en servir. Un client
//! qui lirait la liste, puis effacerait « le troisième », effacerait un autre
//! message si une livraison ou un effacement s'est glissé entre les deux appels.
//! **Cette API ne connaît donc que des UID**, et le mot « rang » n'y apparaît
//! nulle part.
//!
//! # ET UN UID NE VAUT QUE SOUS SON `uidvalidity`
//!
//! §2.3.1.1 de RFC 9051 : quand une boîte ne peut plus garantir la stabilité de
//! ses UID, elle change d'`UIDVALIDITY`, et tous les UID connus deviennent
//! caducs. Une réponse qui ne le porterait pas laisserait un client agir sur des
//! identifiants qui ne désignent plus rien — ou, pire, qui désignent autre chose.
//!
//! C'est pourquoi il accompagne **toute** représentation qui porte un UID.
//!
//! # LES DATES SONT DES NOMBRES
//!
//! Des secondes depuis l'époque, et non une chaîne. Un nombre n'a qu'une
//! écriture ; une date en a autant que de fuseaux, de décalages et de conventions
//! de secondes intercalaires — et deux logiciels qui l'écrivent différemment ne
//! trient plus pareil. Le client la met en forme, puisque c'est lui qui sait pour
//! qui.

use ams_api::{Error, Event, Json, Reader, Reason, Str};
use ams_proto_imap::Flags;

/// Ce qu'un nom de drapeau peut faire de long, une fois décodé.
///
/// Le plus long qu'on serve — `$Forwarded` — en fait dix. Trente-deux laissent
/// de la marge sans retenir ce qu'un client choisirait.
const NOM_OCTETS_MAX: usize = 32;

/// Combien de drapeaux une modification peut nommer.
///
/// Dix, comme le vocabulaire d'`ams-proto-imap` : on ne sait pas en écrire
/// d'autres, donc on n'en lit pas d'autres.
pub const FLAGS_MAX: usize = 10;

/// Une boîte, telle que l'API la rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxRow<'a> {
    /// Son nom.
    pub name: &'a str,
    /// Combien de messages elle porte.
    pub messages: u32,
    /// Combien ne sont pas lus.
    pub unseen: u32,
    /// L'UID que portera le prochain message.
    pub uid_next: u32,
    /// Sous quel `uidvalidity` ces UID valent (§2.3.1.1 de RFC 9051).
    pub uid_validity: u32,
}

/// Un message, tel que l'API le rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageRow<'a> {
    /// Son identifiant durable.
    pub uid: u32,
    /// Sa taille en octets, telle qu'elle est stockée.
    pub size: u64,
    /// Ses drapeaux.
    pub flags: Flags,
    /// Quand il est arrivé, en secondes depuis l'époque.
    pub received: u64,
    /// Son sujet, décodé — ou `None` s'il n'en porte pas.
    ///
    /// **LE VIDE ET L'ABSENCE NE SONT PAS LA MÊME CHOSE** : un sujet vide s'écrit
    /// `""`, un message sans sujet `null`. Les confondre ferait croire à un
    /// client qu'un message a un sujet vide alors qu'il n'en a pas.
    pub subject: Option<&'a str>,
    /// Son expéditeur, décodé.
    pub from: Option<&'a str>,
}

/// Écrit la liste des boîtes.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_mailboxes<'o>(
    boites: &[MailboxRow<'_>],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("mailboxes")?;
    json.begin_array()?;
    for boite in boites {
        ecrire_une_boite(&mut json, boite)?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Écrit une boîte seule.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_mailbox<'o>(boite: &MailboxRow<'_>, sortie: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    ecrire_une_boite(&mut json, boite)?;
    json.finish()
}

/// Le corps d'une boîte.
fn ecrire_une_boite(json: &mut Json<'_>, boite: &MailboxRow<'_>) -> Result<(), Error> {
    json.begin_object()?;
    json.field_str("name", boite.name)?;
    json.field_u64("messages", u64::from(boite.messages))?;
    json.field_u64("unseen", u64::from(boite.unseen))?;
    json.field_u64("uidNext", u64::from(boite.uid_next))?;
    // **IL ACCOMPAGNE TOUT CE QUI PORTE UN UID** (§2.3.1.1 de RFC 9051).
    json.field_u64("uidValidity", u64::from(boite.uid_validity))?;
    json.end_object()
}

/// Un compte, tel que l'administration le rend.
///
/// # L'EMPREINTE N'EST PAS ICI, ET NE PEUT PAS Y ÊTRE
///
/// §3.2 de RFC 9110 : une représentation dit l'état d'une ressource. Celle d'un
/// compte ne porte donc **aucun secret** — le mot de passe est une ressource à
/// part, qui ne se lit pas. La séparation n'est pas un choix de présentation :
/// c'est ce qui rend impossible de fuir une empreinte en lisant un compte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountRow<'a> {
    /// Son nom, tel qu'il s'authentifie.
    pub login: &'a str,
    /// Les adresses d'enveloppe qui lui arrivent.
    ///
    /// **VIDE EST LICITE** : un compte qui peut se connecter sans rien recevoir
    /// est un compte de soumission, et c'est une situation réelle.
    pub addresses: &'a [&'a str],
}

/// Un bannissement en cours (C8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanRow<'a> {
    /// L'adresse du préfixe puni, **sans sa longueur**.
    ///
    /// C'est aussi ce qu'on écrit pour le lever : une longueur dans le chemin
    /// ferait deux segments d'un seul (§3.3 de RFC 3986), et le routage y verrait
    /// une autre ressource.
    pub source: &'a str,
    /// Combien de bits le préfixe couvre (C8).
    ///
    /// **SANS ELLE, LA SOURCE EST UNE DEMI-VÉRITÉ** : « 2001:db8:: » ne dit pas
    /// qu'un `/64` entier est puni, et un exploitant croirait n'avoir banni
    /// qu'une machine.
    pub prefix: u8,
    /// Combien de secondes il reste à courir.
    ///
    /// **DU TEMPS RESTANT, ET NON UNE DATE** : l'horloge du garde compte depuis
    /// l'ouverture du serveur et n'a de sens que pour lui. Un exploitant, lui,
    /// veut savoir combien de temps il reste.
    pub seconds: u64,
}

/// Écrit la liste des comptes.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_accounts<'o>(
    comptes: &[AccountRow<'_>],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("accounts")?;
    json.begin_array()?;
    for compte in comptes {
        ecrire_un_compte(&mut json, compte)?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Écrit un compte seul.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_account<'o>(compte: &AccountRow<'_>, sortie: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    ecrire_un_compte(&mut json, compte)?;
    json.finish()
}

/// Le corps d'un compte.
fn ecrire_un_compte(json: &mut Json<'_>, compte: &AccountRow<'_>) -> Result<(), Error> {
    json.begin_object()?;
    json.field_str("login", compte.login)?;
    json.key("addresses")?;
    json.begin_array()?;
    for adresse in compte.addresses {
        json.string(adresse)?;
    }
    json.end_array()?;
    json.end_object()
}

/// Écrit les domaines qu'on héberge.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_domains<'o>(domaines: &[&str], sortie: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("domains")?;
    json.begin_array()?;
    for domaine in domaines {
        json.string(domaine)?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Écrit les bannissements en cours.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_bans<'o>(bans: &[BanRow<'_>], sortie: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("bans")?;
    json.begin_array()?;
    for ban in bans {
        json.begin_object()?;
        json.field_str("source", ban.source)?;
        json.field_u64("prefixBits", u64::from(ban.prefix))?;
        json.field_u64("secondsRemaining", ban.seconds)?;
        json.end_object()?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Écrit une page de messages.
///
/// `suivant` est l'UID par lequel la page suivante commence, ou `None` quand il
/// n'y en a pas.
///
/// # LA PAGINATION EST PAR UID, ET NON PAR DÉCALAGE
///
/// Une page repérée par « les vingt suivants à partir du rang 40 » se déplace
/// dès qu'un message arrive ou disparaît : le client voit deux fois le même
/// message, ou en saute un, sans jamais s'en apercevoir.
///
/// Un curseur sur l'UID ne bouge pas : il désigne un message, et les messages
/// que la boîte a perdus ne se réinsèrent pas avant lui.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_messages<'o>(
    messages: &[MessageRow<'_>],
    uid_validity: u32,
    suivant: Option<u32>,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_u64("uidValidity", u64::from(uid_validity))?;
    json.key("messages")?;
    json.begin_array()?;
    for message in messages {
        ecrire_un_message(&mut json, message)?;
    }
    json.end_array()?;
    json.key("next")?;
    match suivant {
        Some(uid) => json.number(u64::from(uid))?,
        // **`null` PLUTÔT QUE L'ABSENCE DU CHAMP** : un client qui cherche
        // `next` doit trouver une réponse, et non avoir à distinguer « il n'y a
        // plus rien » de « ce serveur ne pagine pas ».
        None => json.null()?,
    }
    json.end_object()?;
    json.finish()
}

/// Écrit un message seul.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_message<'o>(
    message: &MessageRow<'_>,
    uid_validity: u32,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_u64("uidValidity", u64::from(uid_validity))?;
    json.key("message")?;
    ecrire_un_message(&mut json, message)?;
    json.end_object()?;
    json.finish()
}

/// Le corps d'un message.
fn ecrire_un_message(json: &mut Json<'_>, message: &MessageRow<'_>) -> Result<(), Error> {
    json.begin_object()?;
    json.field_u64("uid", u64::from(message.uid))?;
    json.field_u64("size", message.size)?;
    // **UNE DATE EST UN NOMBRE** : le client la met en forme, puisque c'est lui
    // qui sait pour qui.
    json.field_u64("received", message.received)?;
    json.key("subject")?;
    ecrire_un_texte_facultatif(json, message.subject)?;
    json.key("from")?;
    ecrire_un_texte_facultatif(json, message.from)?;
    json.key("flags")?;
    json.begin_array()?;
    for nom in noms_des_drapeaux(message.flags) {
        json.string(nom)?;
    }
    json.end_array()?;
    json.end_object()
}

/// Écrit un texte, ou `null` s'il n'y en a pas.
fn ecrire_un_texte_facultatif(json: &mut Json<'_>, texte: Option<&str>) -> Result<(), Error> {
    match texte {
        Some(valeur) => json.string(valeur),
        None => json.null(),
    }
}

/// Écrit la santé du serveur.
///
/// # ELLE NE DIT QUE « OUI »
///
/// Pas de version, pas de date de construction, pas de nom de machine. Ce serait
/// un champ `server` sous un autre nom — et cette ressource-ci est justement
/// celle qu'un balayage interroge en premier.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_health(sortie: &mut [u8]) -> Result<&[u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("status", "ok")?;
    json.end_object()?;
    json.finish()
}

/// Écrit des compteurs.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_metrics<'o>(
    compteurs: &[(&str, u64)],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    for (nom, valeur) in compteurs {
        json.field_u64(nom, *valeur)?;
    }
    json.end_object()?;
    json.finish()
}

/// Ce qu'un corps de compte a dit.
///
/// # UNE SEULE LECTURE POUR QUATRE RESSOURCES
///
/// Créer un compte, le remplacer, changer son secret, changer ses adresses : ce
/// sont quatre corps de même grammaire, dont chacun n'emploie qu'une partie.
/// Quatre lecteurs auraient donné quatre façons de lire la même chose, et le
/// jour où l'une changerait, les trois autres ne le sauraient pas.
///
/// **C'EST L'APPELANT QUI EXIGE**, et il doit refuser ce qu'il n'emploie pas :
/// un `PUT` sur le secret qui accepterait un champ `addresses` en silence ferait
/// croire au client qu'on a changé ses adresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountBody<'c, 's> {
    /// Le nom, s'il est donné.
    pub login: Option<&'c str>,
    /// Le secret, tel qu'il a été déséchappé dans le tampon prêté.
    pub password: Option<&'s str>,
    /// Combien d'adresses ont été écrites dans la tranche prêtée.
    ///
    /// **`None` EST L'ABSENCE DU CHAMP, `Some(0)` UNE LISTE VIDE** : l'un ne
    /// touche pas aux adresses, l'autre les efface toutes. Les confondre ferait
    /// perdre à un compte ses adresses parce qu'on changeait son mot de passe.
    pub addresses: Option<usize>,
}

/// Lit un corps de compte.
///
/// `secret` reçoit le mot de passe déséchappé ; `vers` reçoit les adresses, qui
/// pointent dans `corps`.
///
/// # POURQUOI LE SECRET SE DÉSÉCHAPPE ET PAS LES ADRESSES
///
/// Un mot de passe a le droit de porter un guillemet ou une barre oblique
/// inverse — c'est même souhaitable —, et JSON les écrit alors échappés. Une
/// adresse ou un nom de compte qui aurait besoin d'être échappé ne serait pas une
/// adresse ni un nom que ce serveur accepte : les refuser ici est plus honnête
/// que de les déséchapper pour les refuser deux lignes plus loin.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] : un champ qu'on ne connaît pas, un champ répété, une
/// valeur du mauvais type, une chaîne échappée là où l'on n'en accepte pas, ou
/// plus d'adresses que la tranche n'en tient — **on refuse plutôt que de
/// tronquer**.
pub fn read_account_body<'c, 's>(
    corps: &'c [u8],
    secret: &'s mut [u8],
    vers: &mut [&'c str],
) -> Result<AccountBody<'c, 's>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut login = None;
    let mut adresses: Option<usize> = None;
    // **LA CHAÎNE, ET NON SA LONGUEUR** : elle emprunte le corps, qui vit plus
    // longtemps que la boucle. La déséchapper ici obligerait à prêter le tampon à
    // chaque tour, puis à retrouver après coup ce qu'on y avait écrit — deux
    // gardes qu'aucune entrée ne peut faire échouer.
    let mut secret_dit: Option<Str<'c>> = None;
    // Quel champ on est en train de lire : 1 login, 2 password, 3 addresses.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("login"), clef.is("password"), clef.is("addresses")) {
                    (true, _, _) if login.is_none() => 1,
                    (_, true, _) if secret_dit.is_none() => 2,
                    (_, _, true) if adresses.is_none() => 3,
                    // Un champ inconnu, ou répété. **RÉPÉTÉ EST AUSSI GRAVE** :
                    // rien ne dit lequel des deux le client voulait.
                    _ => return Err(mauvais),
                };
            }
            Some(Event::ArrayStart) if quel == 3 => adresses = Some(0),
            Some(Event::Text(texte)) => match quel {
                1 => login = Some(texte.as_plain().ok_or(mauvais)?),
                2 => secret_dit = Some(texte),
                3 => {
                    let combien = adresses.ok_or(mauvais)?;
                    let place = vers.get_mut(combien).ok_or(mauvais)?;
                    *place = texte.as_plain().ok_or(mauvais)?;
                    adresses = Some(combien.saturating_add(1));
                }
                _ => return Err(mauvais),
            },
            Some(Event::ObjectStart | Event::ObjectEnd | Event::ArrayEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }

    // **UNE SEULE FOIS, ET APRÈS LA BOUCLE** : un `password` répété est déjà
    // refusé, donc il n'y a jamais deux chaînes à déséchapper.
    let password = match secret_dit {
        Some(texte) => Some(texte.unescape(secret).map_err(|_| mauvais)?),
        None => None,
    };
    Ok(AccountBody {
        login,
        password,
        addresses: adresses,
    })
}

/// Ce qu'une modification de drapeaux demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagPatch {
    /// Ceux à poser.
    pub add: Flags,
    /// Ceux à ôter.
    pub remove: Flags,
}

impl Default for FlagPatch {
    fn default() -> Self {
        Self::VIDE
    }
}

impl FlagPatch {
    /// Une modification qui ne demande rien.
    pub const VIDE: Self = Self {
        add: Flags::NONE,
        remove: Flags::NONE,
    };
}

/// Lit une modification de drapeaux.
///
/// Le corps attendu est `{"add":["\\Seen"],"remove":["\\Flagged"]}` — les deux
/// champs sont facultatifs, mais l'un des deux au moins doit être là.
///
/// # ON N'ÉCRIT PAS « TOUS LES DRAPEAUX SONT MAINTENANT CEUX-CI »
///
/// Un remplacement complet écrase ce qu'un autre client vient de poser : deux
/// fenêtres ouvertes sur la même boîte se défont mutuellement, et personne ne
/// voit passer le conflit. Poser et ôter, en revanche, ne touchent que ce qu'on
/// nomme.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps qui n'est pas cela, ou qui nomme un
/// drapeau qu'on ne sait pas écrire.
pub fn read_flag_patch(corps: &[u8]) -> Result<FlagPatch, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut patch = FlagPatch::default();
    let mut vus = 0_u32;
    // `Some(true)` pour `add`, `Some(false)` pour `remove`.
    let mut lequel = None;
    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                lequel = match (clef.is("add"), clef.is("remove")) {
                    (true, _) => Some(true),
                    (_, true) => Some(false),
                    // **UN CHAMP QU'ON NE CONNAÎT PAS SE REFUSE ICI**, et non
                    // s'ignore : sur une MODIFICATION, ignorer un champ ferait
                    // croire au client qu'on a fait ce qu'il demandait.
                    _ => return Err(mauvais),
                };
                vus = vus.saturating_add(1);
            }
            Some(Event::Text(texte)) => {
                // **UN NOM DE DRAPEAU EST TOUJOURS ÉCHAPPÉ**, et ce n'est pas un
                // cas rare : cinq des dix commencent par une barre oblique
                // inverse, qu'aucun JSON ne peut écrire nue. Se contenter des
                // chaînes non échappées aurait refusé `\Seen`, c'est-à-dire le
                // drapeau le plus employé de tous.
                //
                // Défaut écrit, puis trouvé par le premier essai qui a nommé un
                // drapeau système.
                let mut place = [0_u8; NOM_OCTETS_MAX];
                let nom = match texte.as_plain() {
                    Some(clair) => clair,
                    None => texte.unescape(&mut place).map_err(|_| mauvais)?,
                };
                let drapeau = Flags::parse_one(nom.as_bytes()).ok_or(mauvais)?;
                match lequel {
                    Some(true) => patch.add = patch.add.with(drapeau),
                    Some(false) => patch.remove = patch.remove.with(drapeau),
                    None => return Err(mauvais),
                }
            }
            Some(Event::ObjectStart | Event::ArrayStart | Event::ArrayEnd | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    if vus == 0 {
        return Err(mauvais);
    }
    // **POSER ET ÔTER LE MÊME DRAPEAU N'A PAS DE SENS**, et choisir lequel
    // l'emporte serait inventer une règle que le client ne connaît pas.
    if patch.add.contains(patch.remove) && patch.remove != Flags::NONE {
        return Err(mauvais);
    }
    match patch.add == Flags::NONE && patch.remove == Flags::NONE {
        true => Err(mauvais),
        false => Ok(patch),
    }
}

/// Les noms des drapeaux posés, dans l'ordre stable d'`ams-proto-imap`.
///
/// **CE SONT LES NOMS D'IMAP, ET NON DES NOMS INVENTÉS.** Deux vocabulaires pour
/// la même chose finiraient par diverger, et un client qui parle les deux ne
/// saurait plus lequel croire — alors que c'est le même serveur, et souvent la
/// même boîte, qu'il regarde par deux fenêtres.
fn noms_des_drapeaux(flags: Flags) -> impl Iterator<Item = &'static str> {
    const NOMS: [(Flags, &str); FLAGS_MAX] = [
        (Flags::SEEN, "\\Seen"),
        (Flags::ANSWERED, "\\Answered"),
        (Flags::FLAGGED, "\\Flagged"),
        (Flags::DELETED, "\\Deleted"),
        (Flags::DRAFT, "\\Draft"),
        (Flags::MDN_SENT, "$MDNSent"),
        (Flags::FORWARDED, "$Forwarded"),
        (Flags::JUNK, "$Junk"),
        (Flags::NON_JUNK, "$NonJunk"),
        (Flags::PHISHING, "$Phishing"),
    ];
    NOMS.into_iter()
        .filter(move |(bit, _)| flags.contains(*bit))
        .map(|(_, nom)| nom)
}

#[cfg(test)]
mod tests;
