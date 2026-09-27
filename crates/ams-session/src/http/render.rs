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
    /// Le dernier point du journal des changements, **quand on l'a tenu**.
    ///
    /// C'est le curseur à partir duquel un client demande les deltas : il le
    /// prend AVANT sa lecture complète de la boîte, pour ne rien manquer de ce
    /// qui change pendant. `None` dans la liste des boîtes, où réconcilier
    /// chacune coûterait une relecture par boîte — le champ n'est alors pas
    /// écrit.
    pub highest_modseq: Option<u64>,
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
    if let Some(modseq) = boite.highest_modseq {
        json.field_u64("highestModseq", modseq)?;
    }
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

/// Ce qu'une demande de défi dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeRequest<'a> {
    /// Le compte dont on veut ouvrir une session.
    pub login: &'a str,
    /// L'appareil qui prétend tenir la clef.
    pub device: &'a str,
    /// Ce que l'appelant compte faire de ce défi : ouvrir une session, ou
    /// approuver un appairage.
    ///
    /// **IL NE CHANGE PAS LE DÉFI**, seulement le RÔLE que le serveur annonce —
    /// et donc le condensat que l'appareil signera. Un défi reste un défi ; ce
    /// qui distingue les deux gestes est la signature, pas le scellé.
    ///
    /// Absent, c'est une session : c'est le geste courant, et celui que tout
    /// client fait au moins une fois.
    pub appairage: bool,
}

/// Lit une demande de défi.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps qu'on ne sait pas lire, un champ
/// inconnu, ou un champ échappé.
pub fn read_challenge_request(corps: &[u8]) -> Result<ChallengeRequest<'_>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut login = None;
    let mut device = None;
    let mut appairage = false;
    // Quel champ on lit : 1 `login`, 2 `deviceId`, 3 `purpose`.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("login"), clef.is("deviceId"), clef.is("purpose")) {
                    (true, _, _) => 1,
                    (_, true, _) => 2,
                    (_, _, true) => 3,
                    _ => return Err(mauvais),
                };
            }
            Some(Event::Text(texte)) => {
                let clair = texte.as_plain().ok_or(mauvais)?;
                match quel {
                    1 => login = Some(clair),
                    2 => device = Some(clair),
                    // **UN USAGE INCONNU SE REFUSE**, plutôt que de retomber en
                    // silence sur la session : un client qui écrirait `pairing`
                    // obtiendrait sinon un défi de session, signerait le mauvais
                    // condensat, et chercherait sa faute dans la cryptographie.
                    3 => appairage = usage_d_appairage(clair).ok_or(mauvais)?,
                    _ => return Err(mauvais),
                }
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    Ok(ChallengeRequest {
        login: login.ok_or(mauvais)?,
        device: device.ok_or(mauvais)?,
        appairage,
    })
}

/// L'usage que nomme ce mot, s'il en nomme un.
///
/// **DEUX MOTS, ET PAS D'AUTRES.** Les écrire ici plutôt que chez l'appelant
/// garde le vocabulaire là où il est lu.
fn usage_d_appairage(mot: &str) -> Option<bool> {
    match mot {
        "session" => Some(false),
        "pairing" => Some(true),
        _ => None,
    }
}

/// Écrit un défi fraîchement émis.
///
/// # CE QU'IL FAUT POUR LE SIGNER EST DIT AVEC LUI
///
/// Le client doit signer le condensat d'une suite qui porte un **rôle** et le
/// **domaine du serveur** — et non le défi nu. Les rendre ici lui évite de les
/// deviner, et évite surtout que cinq applications natives les devinent
/// différemment.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_challenge<'o>(
    challenge: &str,
    role: &str,
    domaine: &str,
    expires_in: u64,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("challenge", challenge)?;
    json.field_str("role", role)?;
    json.field_str("serverIdentity", domaine)?;
    // **UNE DURÉE, ET NON UNE DATE.** Une date obligerait le client à comparer
    // son horloge à la nôtre ; une durée lui dit seulement combien de temps il
    // lui reste pour obtenir une empreinte de son propriétaire.
    json.field_u64("expiresInSeconds", expires_in)?;
    json.end_object()?;
    json.finish()
}

/// Ce qu'une réponse à un défi dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRequest<'a> {
    /// Le défi tel qu'il a été rendu.
    pub challenge: &'a str,
    /// La signature, en base64url : `r ‖ s`, soixante-quatre octets.
    pub signature: &'a str,
}

/// Lit une réponse à un défi.
///
/// # Errors
///
/// [`Reason::BadJsonBody`].
pub fn read_session_request(corps: &[u8]) -> Result<SessionRequest<'_>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut challenge = None;
    let mut signature = None;
    // Quel champ on lit : 1 `challenge`, 2 `signature`.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("challenge"), clef.is("signature")) {
                    (true, _) => 1,
                    (_, true) => 2,
                    _ => return Err(mauvais),
                };
            }
            Some(Event::Text(texte)) => {
                let clair = texte.as_plain().ok_or(mauvais)?;
                match quel {
                    1 => challenge = Some(clair),
                    2 => signature = Some(clair),
                    _ => return Err(mauvais),
                }
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    Ok(SessionRequest {
        challenge: challenge.ok_or(mauvais)?,
        signature: signature.ok_or(mauvais)?,
    })
}

/// Ce qu'une demande d'appairage dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingRequest<'a> {
    /// Le défi que l'appareil APPROBATEUR a obtenu.
    ///
    /// **C'EST LUI QUI DIT QUI APPROUVE** : le compte et l'appareil y sont
    /// scellés, et le corps n'a donc pas à les répéter — deux écritures d'une
    /// même chose finiraient par ne plus dire la même.
    pub challenge: &'a str,
    /// Sa signature, sous le rôle d'appairage.
    pub signature: &'a str,
    /// La clef publique du NOUVEL appareil, en base64url.
    pub public_key: &'a str,
    /// Le nom que son propriétaire lui donne. Peut être vide.
    pub name: &'a str,
}

/// Lit une demande d'appairage.
///
/// # LE NOM N'EST PAS DÉSÉCHAPPÉ ICI
///
/// Contrairement à l'enrôlement par invitation, cette lecture a lieu dans une
/// caisse qui alloue : l'appelant range le nom tel quel, et ce sont les mêmes
/// échappements qu'il verrait. **Ce lecteur les refuse donc**, comme il refuse
/// ceux du défi et de la clef — l'appelant qui voudrait les admettre devra
/// déséchapper là où il range.
///
/// # Errors
///
/// [`Reason::BadJsonBody`].
pub fn read_pairing_request(corps: &[u8]) -> Result<PairingRequest<'_>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut challenge = None;
    let mut signature = None;
    let mut public_key = None;
    let mut name = "";
    // Quel champ : 1 `challenge`, 2 `signature`, 3 `publicKey`, 4 `name`.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (
                    clef.is("challenge"),
                    clef.is("signature"),
                    clef.is("publicKey"),
                    clef.is("name"),
                ) {
                    (true, _, _, _) => 1,
                    (_, true, _, _) => 2,
                    (_, _, true, _) => 3,
                    (_, _, _, true) => 4,
                    _ => return Err(mauvais),
                };
            }
            Some(Event::Text(texte)) => {
                let clair = texte.as_plain().ok_or(mauvais)?;
                match quel {
                    1 => challenge = Some(clair),
                    2 => signature = Some(clair),
                    3 => public_key = Some(clair),
                    4 => name = clair,
                    _ => return Err(mauvais),
                }
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    Ok(PairingRequest {
        challenge: challenge.ok_or(mauvais)?,
        signature: signature.ok_or(mauvais)?,
        public_key: public_key.ok_or(mauvais)?,
        name,
    })
}

/// Ce qu'une demande d'invitation dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvitationRequest<'a> {
    /// Le compte à inviter.
    pub login: &'a str,
    /// Combien de minutes elle vaudra, ou `None` pour la durée par défaut.
    pub minutes: Option<u64>,
}

/// Lit une demande d'invitation.
///
/// # LE NOM N'EST PAS DÉSÉCHAPPÉ, ET C'EST SANS CONSÉQUENCE
///
/// `check_login` refuse de toute façon tout ce qu'un échappement pourrait
/// porter : un nom de compte devient un nom de répertoire, et son alphabet est
/// borné bien en deçà de ce que JSON sait écrire.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps qu'on ne sait pas lire, un champ
/// inconnu, un nom échappé, ou une durée qui n'est pas un entier positif.
pub fn read_invitation_request(corps: &[u8]) -> Result<InvitationRequest<'_>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut login = None;
    let mut minutes = None;
    // Quel champ on lit : 1 `login`, 2 `minutes`.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("login"), clef.is("minutes")) {
                    (true, _) => 1,
                    (_, true) => 2,
                    _ => return Err(mauvais),
                };
            }
            Some(Event::Text(texte)) => match quel {
                1 => login = Some(texte.as_plain().ok_or(mauvais)?),
                _ => return Err(mauvais),
            },
            Some(Event::Number(nombre)) => match quel {
                2 => minutes = Some(nombre.as_u64().ok_or(mauvais)?),
                _ => return Err(mauvais),
            },
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    Ok(InvitationRequest {
        login: login.ok_or(mauvais)?,
        minutes,
    })
}

/// Écrit une invitation fraîchement frappée.
///
/// # LE COMPTE Y FIGURE, BIEN QU'IL SOIT DANS LE SCEAU
///
/// L'exploitant qui la frappe relaie souvent DEUX choses à son utilisateur : le
/// texte à coller, et le compte auquel il correspond. Les rendre ensemble lui
/// évite de les rapprocher lui-même — et de se tromper le jour où il en frappe
/// trois d'affilée.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_invitation<'o>(
    invitation: &str,
    login: &str,
    expires_at: u64,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("invitation", invitation)?;
    json.field_str("login", login)?;
    // **EN SECONDES, COMME PARTOUT CE QUI SORT** : les microsecondes sont une
    // unité interne, et les rendre obligerait chaque client à savoir laquelle
    // des deux il lit.
    json.field_u64("expiresAt", expires_at)?;
    json.end_object()?;
    json.finish()
}

/// Écrit ce qu'un enrôlement réussi rend.
///
/// # LES ADRESSES SONT LÀ POUR QUE L'APPLICATION SE CONFIGURE
///
/// C'est la seule réponse que reçoit un client qui n'a encore rien : sans elles,
/// il faudrait un second appel, et il n'a pas encore de jeton pour le faire.
///
/// **ELLES SONT LUES MAINTENANT, ET NON SCELLÉES DANS L'INVITATION** : un
/// administrateur qui corrige une adresse entre l'invitation et l'enrôlement
/// verrait sinon l'application se configurer avec l'ancienne.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_enrolled<'o>(
    id: &str,
    login: &str,
    addresses: &[&str],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("id", id)?;
    json.field_str("login", login)?;
    json.key("addresses")?;
    json.begin_array()?;
    for adresse in addresses {
        json.string(adresse)?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Un appareil enrôlé, tel qu'on le montre à son propriétaire.
///
/// # LA CLEF PUBLIQUE N'Y EST PAS, ET CE N'EST PAS PAR PRUDENCE
///
/// Elle est publique ; la rendre ne coûterait rien en secret. Mais soixante-cinq
/// octets de base64 dans une liste n'apprennent rien à un humain qui cherche
/// lequel de ses trois téléphones révoquer. **Ce qui lui servirait est une
/// empreinte courte**, et elle viendra avec l'enrôlement croisé, où elle a un
/// rôle : confirmer de visu l'appareil qu'on ajoute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRow<'a> {
    /// Ce qui le désigne, et ce qu'on écrit pour le révoquer.
    pub id: &'a str,
    /// Le nom que son propriétaire lui a donné. Peut être vide.
    pub name: &'a str,
    /// Quand il a été enrôlé, en secondes depuis l'époque.
    pub enrolled: u64,
    /// Quand il a ouvert une session pour la dernière fois, **ou zéro s'il ne
    /// l'a jamais fait**.
    ///
    /// Le champ est écrit dans les deux cas. L'omettre obligerait chaque client
    /// à distinguer « absent » de « zéro », et les deux moitiés de cette
    /// distinction finiraient par diverger.
    pub last_seen: u64,
    /// Le canal de son abonnement aux notifications (`apns`, `fcm`,
    /// `webpush`), ou `None` s'il n'est pas abonné.
    ///
    /// **LE CANAL, PAS LE JETON** : savoir lequel de ses appareils sonne est
    /// utile à l'utilisateur ; l'adresse où il sonne ne l'est pas.
    pub push: Option<&'a str>,
}

/// Écrit la liste des appareils d'un compte.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_devices<'o>(
    appareils: &[DeviceRow<'_>],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("devices")?;
    json.begin_array()?;
    for appareil in appareils {
        json.begin_object()?;
        json.field_str("id", appareil.id)?;
        json.field_str("name", appareil.name)?;
        json.field_u64("enrolledAt", appareil.enrolled)?;
        json.field_u64("lastSeenAt", appareil.last_seen)?;
        json.key("push")?;
        ecrire_un_texte_facultatif(&mut json, appareil.push)?;
        json.end_object()?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Un abonnement aux notifications, tel qu'un client le demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushRequest<'a> {
    /// Le canal nommé : `apns`, `fcm` ou `webpush`. Non vérifié ici.
    pub channel: &'a str,
    /// Le jeton APNs ou FCM, ou l'URL Web Push — déséchappé.
    pub token: &'a str,
    /// La clef publique Web Push, décodée de base64url.
    pub key: Option<[u8; PUSH_KEY_OCTETS]>,
    /// Le secret d'authentification Web Push, décodé de base64url.
    pub auth: Option<[u8; PUSH_AUTH_OCTETS]>,
}

/// Une clef publique P-256 non compressée : soixante-cinq octets.
pub const PUSH_KEY_OCTETS: usize = 65;

/// Le secret d'authentification de Web Push : seize octets (§3.2 de RFC 8291).
pub const PUSH_AUTH_OCTETS: usize = 16;

/// Lit le corps de `PUT /v1/me/push`.
///
/// ```json
/// {"channel": "apns", "token": "a1b2…"}
/// {"channel": "webpush", "endpoint": "https://…",
///  "keys": {"p256dh": "BN…", "auth": "q1…"}, "expirationTime": null}
/// ```
///
/// # LA FORME DU NAVIGATEUR, TELLE QUELLE
///
/// Pour Web Push, c'est ce que `PushSubscription.toJSON()` rend, plus le canal :
/// un client web n'a rien à reconstruire. `endpoint` et `token` sont deux noms
/// du même champ ; `expirationTime` se lit et s'ignore.
///
/// **ICI, LA FORME ; LA RÈGLE EST AILLEURS** : ce lecteur ne dit pas si le canal
/// existe ni si l'URL est acceptable — c'est `ams_config::Push::new`, la même
/// porte que pour le fichier relu.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps illisible, un champ inconnu ou
/// répété, un canal ou un jeton absent, un jeton plus long que `jeton`, une
/// clef ou un secret qui ne se décode pas à sa longueur exacte.
pub fn read_push_request<'n>(
    corps: &'n [u8],
    jeton: &'n mut [u8],
) -> Result<PushRequest<'n>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let (mut canal, mut brut, mut cle, mut auth) = (None, None, None, None);
    let (mut profondeur, mut quel, mut cles_vues, mut expiration_vue) = (0_u8, 0_u8, false, false);
    loop {
        let evenement = lecteur.read().map_err(|_| mauvais)?;
        match (evenement, profondeur, quel) {
            (None, _, _) => break,
            (Some(Event::ObjectStart), 0, _) => profondeur = 1,
            // `keys` s'ouvre, et rien d'autre ne s'imbrique.
            (Some(Event::ObjectStart), 1, 3) => {
                profondeur = 2;
                quel = 0;
            }
            (Some(Event::ObjectEnd), _, 0) => profondeur = profondeur.saturating_sub(1),
            (Some(Event::Key(clef)), 1, 0) => {
                quel = match clef {
                    _ if clef.is("channel") && canal.is_none() => 1,
                    _ if (clef.is("token") || clef.is("endpoint")) && brut.is_none() => 2,
                    _ if clef.is("keys") && !cles_vues => {
                        cles_vues = true;
                        3
                    }
                    _ if clef.is("expirationTime") && !expiration_vue => {
                        expiration_vue = true;
                        4
                    }
                    _ => return Err(mauvais),
                };
            }
            (Some(Event::Key(clef)), 2, 0) => {
                quel = match clef {
                    _ if clef.is("p256dh") && cle.is_none() => 5,
                    _ if clef.is("auth") && auth.is_none() => 6,
                    _ => return Err(mauvais),
                };
            }
            (Some(Event::Text(texte)), _, 1) => {
                canal = Some(texte.as_plain().ok_or(mauvais)?);
                quel = 0;
            }
            (Some(Event::Text(texte)), _, 2) => {
                brut = Some(texte);
                quel = 0;
            }
            (Some(Event::Text(texte)), _, 5) => {
                let mut place = [0_u8; PUSH_KEY_OCTETS];
                cle = Some(decoder_exactement(texte, &mut place).ok_or(mauvais)?);
                quel = 0;
            }
            (Some(Event::Text(texte)), _, 6) => {
                let mut place = [0_u8; PUSH_AUTH_OCTETS];
                auth = Some(decoder_exactement(texte, &mut place).ok_or(mauvais)?);
                quel = 0;
            }
            (Some(Event::Null | Event::Number(_)), _, 4) => quel = 0,
            _ => return Err(mauvais),
        }
    }
    let channel = canal.ok_or(mauvais)?;
    let token = brut.ok_or(mauvais)?.unescape(jeton).map_err(|_| mauvais)?;
    Ok(PushRequest {
        channel,
        token,
        key: cle,
        auth,
    })
}

/// Décode du base64url dans `place`, à sa longueur EXACTE : ni plus court, ni
/// plus long — un octet de plus ne tiendrait pas, un de moins resterait à zéro.
fn decoder_exactement<const N: usize>(texte: Str<'_>, place: &mut [u8; N]) -> Option<[u8; N]> {
    let brut = texte.as_plain()?;
    let lu = ams_api::decode_base64url(brut.as_bytes(), place).ok()?;
    (lu.len() == N).then_some(*place)
}

/// Écrit l'abonnement de l'appareil qui appelle : `{"push": {"channel": …,
/// "since": …}, "vapidKey": …}`, `"push": null` s'il n'en a pas.
///
/// `vapidKey` est la clef publique VAPID du serveur, en base64url — ce qu'une
/// application web donne au navigateur pour s'abonner (`applicationServerKey`)
/// —, ou `null` si le serveur n'en a pas : Web Push n'est alors pas servi.
///
/// **NI LE JETON NI LES CLEFS NE REVIENNENT** : le client les a, et un jeton
/// qu'on relirait par l'API est un jeton qu'un jeton d'accès volé suffirait à
/// apprendre.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_push<'o>(
    abonnement: Option<(&str, u64)>,
    vapid: Option<&str>,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("push")?;
    match abonnement {
        Some((canal, depuis)) => {
            json.begin_object()?;
            json.field_str("channel", canal)?;
            json.field_u64("since", depuis)?;
            json.end_object()?;
        }
        None => json.null()?,
    }
    json.key("vapidKey")?;
    ecrire_un_texte_facultatif(&mut json, vapid)?;
    json.end_object()?;
    json.finish()
}

/// Lit le corps de `POST /v1/me/app-passwords` : `{"name": "…"}`, et rien
/// d'autre.
///
/// **LE NOM SE DÉSÉCHAPPE** dans `place` : un client qui écrit « Thunderbird —
/// bureau » par une bibliothèque JSON ordinaire l'enverra sous la forme
/// `\u2014`, et le refuser serait refuser la plupart des clients. Un nom plus
/// long que `place` se refuse.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps illisible, un champ inconnu, un nom
/// absent, vide, ou plus long que `place`.
pub fn read_app_password_request<'p>(corps: &[u8], place: &'p mut [u8]) -> Result<&'p str, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut nom = None;
    let mut est_le_nom = false;
    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                if !clef.is("name") {
                    return Err(mauvais);
                }
                est_le_nom = true;
            }
            Some(Event::Text(texte)) if est_le_nom && nom.is_none() => nom = Some(texte),
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    let clair = nom.ok_or(mauvais)?.unescape(place).map_err(|_| mauvais)?;
    if clair.is_empty() {
        return Err(mauvais);
    }
    Ok(clair)
}

/// Une ligne de la liste des mots de passe applicatifs d'un compte.
#[derive(Debug, Clone, Copy)]
pub struct AppPasswordRow<'a> {
    /// Ce qui le désigne, et ce qu'on écrit pour le révoquer.
    pub id: &'a str,
    /// Le nom que son propriétaire lui a donné.
    pub name: &'a str,
    /// Quand il a été créé, en secondes depuis l'époque.
    pub created: u64,
    /// Quand il a servi pour la dernière fois — à l'heure près —, **ou zéro
    /// s'il n'a jamais servi**. Écrit dans les deux cas, comme pour un appareil.
    pub last_used: u64,
}

/// Écrit la liste des mots de passe applicatifs d'un compte — **sans aucun
/// secret** : le serveur n'en a que les condensats, et ne les rend pas non plus.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_app_passwords<'o>(
    lignes: &[AppPasswordRow<'_>],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("appPasswords")?;
    json.begin_array()?;
    for ligne in lignes {
        json.begin_object()?;
        json.field_str("id", ligne.id)?;
        json.field_str("name", ligne.name)?;
        json.field_u64("createdAt", ligne.created)?;
        json.field_u64("lastUsedAt", ligne.last_used)?;
        json.end_object()?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Écrit un mot de passe applicatif fraîchement créé, **secret compris** —
/// c'est la seule fois qu'il sort du serveur.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_app_password_created<'o>(
    ligne: &AppPasswordRow<'_>,
    mot_de_passe: &str,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("id", ligne.id)?;
    json.field_str("name", ligne.name)?;
    json.field_u64("createdAt", ligne.created)?;
    json.field_str("password", mot_de_passe)?;
    json.end_object()?;
    json.finish()
}

/// Une ligne d'une liste de délégations : un compte, et les droits qu'elle
/// porte, par leur nom.
#[derive(Debug, Clone, Copy)]
pub struct DelegationRow<'a> {
    /// Le compte de l'autre côté : le délégué dans la liste d'un titulaire, le
    /// titulaire dans la liste de qui appelle.
    pub login: &'a str,
    /// Les droits : `read`, `write`, `send`.
    pub rights: &'a [&'a str],
}

/// Écrit une liste de délégations sous la clé `cle`, chaque compte sous le
/// champ `champ` — `{"delegates":[{"login":…}]}` pour l'administration,
/// `{"delegations":[{"account":…}]}` pour qui appelle.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_delegations<'o>(
    cle: &str,
    champ: &str,
    lignes: &[DelegationRow<'_>],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key(cle)?;
    json.begin_array()?;
    for ligne in lignes {
        json.begin_object()?;
        json.field_str(champ, ligne.login)?;
        json.key("rights")?;
        json.begin_array()?;
        for droit in ligne.rights {
            json.string(droit)?;
        }
        json.end_array()?;
        json.end_object()?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Lit le corps d'une délégation : `{"rights":["read","write"]}`.
///
/// Rend les noms, **sans les juger** — c'est le serveur qui sait lesquels sont
/// des droits. Au plus trois, sans doublon, et au moins un : une délégation sans
/// droit ne délègue rien.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps illisible, un champ inconnu, un nom
/// échappé, plus de trois noms, un doublon, ou aucun.
pub fn read_rights_request(corps: &[u8]) -> Result<([&str; 3], usize), Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut noms = [""; 3];
    let mut combien = 0_usize;
    let mut dans_le_tableau = false;
    let mut vu_la_cle = false;
    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) if clef.is("rights") && !vu_la_cle => vu_la_cle = true,
            Some(Event::ArrayStart) if vu_la_cle && !dans_le_tableau => dans_le_tableau = true,
            Some(Event::ArrayEnd) if dans_le_tableau => dans_le_tableau = false,
            Some(Event::Text(texte)) if dans_le_tableau => {
                let nom = texte.as_plain().ok_or(mauvais)?;
                if noms.iter().take(combien).any(|connu| *connu == nom) {
                    return Err(mauvais);
                }
                let place = noms.get_mut(combien).ok_or(mauvais)?;
                *place = nom;
                combien = combien.saturating_add(1);
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    if combien == 0 {
        return Err(mauvais);
    }
    Ok((noms, combien))
}

/// Combien d'UID une copie ou un déplacement nomme au plus.
///
/// **UNE BORNE, PAS UNE PAGE** : ranger une sélection de deux cent cinquante-six
/// messages en une requête suffit à toute interface, et la réponse — deux UID
/// par message — tient dans le tampon de sortie.
pub const TRANSFER_UIDS_MAX: usize = 256;

/// Une demande de copie ou de déplacement : `{"to":"Archives","uids":[1,2]}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRequest<'n> {
    /// La boîte de destination, DÉSÉCHAPPÉE — `Envoy\u00e9s` est `Envoyés`.
    pub to: &'n str,
    /// Les UID, dans l'ordre où ils ont été écrits.
    pub uids: [u32; TRANSFER_UIDS_MAX],
    /// Combien de `uids` valent.
    pub count: usize,
}

impl TransferRequest<'_> {
    /// Les UID demandés.
    #[must_use]
    pub fn uids(&self) -> &[u32] {
        self.uids.get(..self.count).unwrap_or_default()
    }
}

/// Lit une demande de copie ou de déplacement.
///
/// # LA DESTINATION SE DÉSÉCHAPPE, AU LIEU DE SE REFUSER
///
/// Les noms de boîte portent des accents, et bien des bibliothèques JSON les
/// échappent d'office — `json.dumps` de Python écrit `Envoy\u00e9s`. Les
/// refuser écarterait ces clients pour une écriture équivalente. `nom` reçoit
/// la forme décodée.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps illisible, un champ inconnu ou
/// répété, une destination absente ou vide, un UID nul, négatif ou au-delà de
/// 2³² − 1, un doublon, aucun UID ou plus de [`TRANSFER_UIDS_MAX`] — ou une
/// destination trop longue pour `nom`.
pub fn read_transfer_request<'n>(
    corps: &[u8],
    nom: &'n mut [u8],
) -> Result<TransferRequest<'n>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut destination: Option<Str<'_>> = None;
    let mut uids = [0_u32; TRANSFER_UIDS_MAX];
    let mut combien = 0_usize;
    // Le champ qu'on lit : 1 `to`, 2 `uids`.
    let mut quel = 0_u8;
    let mut vus = (false, false);
    let mut dans_le_tableau = false;
    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("to"), clef.is("uids"), vus) {
                    (true, _, (false, _)) => 1,
                    (_, true, (_, false)) => 2,
                    _ => return Err(mauvais),
                };
                vus = (vus.0 || quel == 1, vus.1 || quel == 2);
            }
            Some(Event::Text(texte)) if quel == 1 => destination = Some(texte),
            Some(Event::ArrayStart) if quel == 2 && !dans_le_tableau => dans_le_tableau = true,
            Some(Event::ArrayEnd) if dans_le_tableau => dans_le_tableau = false,
            Some(Event::Number(nombre)) if dans_le_tableau => {
                let uid = nombre
                    .as_u64()
                    .and_then(|valeur| u32::try_from(valeur).ok())
                    .filter(|valeur| *valeur != 0)
                    .ok_or(mauvais)?;
                if uids.iter().take(combien).any(|connu| *connu == uid) {
                    return Err(mauvais);
                }
                let place = uids.get_mut(combien).ok_or(mauvais)?;
                *place = uid;
                combien = combien.saturating_add(1);
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    let to = destination
        .ok_or(mauvais)?
        .unescape(nom)
        .map_err(|_| mauvais)?;
    if to.is_empty() || combien == 0 {
        return Err(mauvais);
    }
    Ok(TransferRequest {
        to,
        uids,
        count: combien,
    })
}

/// Écrit l'issue d'une copie ou d'un déplacement :
/// `{"uidValidity":7,"uids":[{"from":1,"to":57}],"missing":[4]}`.
///
/// **LES ABSENTS SE DISENT** : un UID qui n'est plus dans la source — effacé
/// ailleurs entre-temps — n'est pas une faute (§6.4.7 de RFC 9051 le tait de
/// même), mais le client qui l'a nommé doit savoir qu'il n'a rien copié.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_transfer<'o>(
    uid_validity: u32,
    faits: &[(u32, u32)],
    absents: &[u32],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_u64("uidValidity", u64::from(uid_validity))?;
    json.key("uids")?;
    json.begin_array()?;
    for (de, vers) in faits {
        json.begin_object()?;
        json.field_u64("from", u64::from(*de))?;
        json.field_u64("to", u64::from(*vers))?;
        json.end_object()?;
    }
    json.end_array()?;
    json.key("missing")?;
    json.begin_array()?;
    for absent in absents {
        json.number(u64::from(*absent))?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// La déclaration d'une pièce jointe : `{"name":"facture.pdf",
/// "type":"application/pdf","size":123456}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentRequest<'n> {
    /// Le nom du fichier, DÉSÉCHAPPÉ — comme la destination d'une copie.
    pub name: &'n str,
    /// Son type, `type/sous-type`, tel qu'écrit.
    pub media: &'n str,
    /// Sa taille entière, en octets. Jamais nulle.
    pub size: u64,
}

/// Ce type de média se lit-il `type/sous-type`, en jetons de RFC 2045 ?
///
/// **IL FINIRA DANS UN EN-TÊTE MIME** : ce qui n'est pas un jeton — un
/// guillemet, un point-virgule, un retour à la ligne — y ouvrirait un paramètre
/// ou un champ que personne n'a demandé.
fn type_de_media_sur(media: &str) -> bool {
    let jeton = |partie: &str| {
        !partie.is_empty()
            && partie
                .bytes()
                .all(|octet| octet.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&octet))
    };
    media.len() <= 127
        && media
            .split_once('/')
            .is_some_and(|(genre, sorte)| jeton(genre) && jeton(sorte))
}

/// Lit la déclaration d'une pièce jointe.
///
/// Le nom se déséchappe dans `nom` ; il ne peut être ni vide, ni porter un
/// octet de contrôle — il finira dans un en-tête.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps illisible, un champ inconnu, répété ou
/// absent, un nom vide ou trop long pour `nom`, un octet de contrôle dans le
/// nom, un type qui n'est pas `type/sous-type` en jetons, ou une taille nulle.
pub fn read_attachment_request<'n>(
    corps: &'n [u8],
    nom: &'n mut [u8],
) -> Result<AttachmentRequest<'n>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let (mut brut, mut media, mut taille) = (None, None, None);
    // Le champ qu'on lit : 1 `name`, 2 `type`, 3 `size`.
    let mut quel = 0_u8;
    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("name"), clef.is("type"), clef.is("size")) {
                    (true, _, _) if brut.is_none() => 1,
                    (_, true, _) if media.is_none() => 2,
                    (_, _, true) if taille.is_none() => 3,
                    _ => return Err(mauvais),
                };
            }
            Some(Event::Text(texte)) if quel == 1 => brut = Some(texte),
            Some(Event::Text(texte)) if quel == 2 => {
                media = Some(texte.as_plain().ok_or(mauvais)?);
            }
            Some(Event::Number(nombre)) if quel == 3 => {
                taille = Some(
                    nombre
                        .as_u64()
                        .filter(|octets| *octets > 0)
                        .ok_or(mauvais)?,
                );
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    let media = media
        .filter(|media| type_de_media_sur(media))
        .ok_or(mauvais)?;
    let size = taille.ok_or(mauvais)?;
    let name = brut.ok_or(mauvais)?.unescape(nom).map_err(|_| mauvais)?;
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(mauvais);
    }
    Ok(AttachmentRequest { name, media, size })
}

/// Lit une demande de rangement : `{"mailbox":"Brouillons"}`, le nom
/// déséchappé dans `nom`.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] pour un corps illisible, un champ inconnu ou
/// répété, ou une boîte absente, vide ou trop longue pour `nom`.
pub fn read_store_request<'n>(corps: &[u8], nom: &'n mut [u8]) -> Result<&'n str, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut boite: Option<Str<'_>> = None;
    let mut vu = false;
    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) if clef.is("mailbox") && !vu => vu = true,
            Some(Event::Text(texte)) if vu && boite.is_none() => boite = Some(texte),
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    let nom = boite.ok_or(mauvais)?.unescape(nom).map_err(|_| mauvais)?;
    if nom.is_empty() {
        return Err(mauvais);
    }
    Ok(nom)
}

/// L'état d'une pièce jointe, tel que le brouillon le rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentRow<'a> {
    /// Son numéro dans le brouillon.
    pub piece: u64,
    /// Son nom.
    pub name: &'a str,
    /// Son type.
    pub media: &'a str,
    /// Sa taille entière.
    pub size: u64,
    /// Les portées reçues, bornes comprises et sans chevauchement.
    pub received: &'a [(u64, u64)],
}

/// Écrit une pièce jointe dans un objet déjà ouvert.
fn ecrire_une_piece(json: &mut Json<'_>, piece: &AttachmentRow<'_>) -> Result<(), Error> {
    json.begin_object()?;
    json.field_u64("attachment", piece.piece)?;
    json.field_str("name", piece.name)?;
    json.field_str("type", piece.media)?;
    json.field_u64("size", piece.size)?;
    json.key("received")?;
    json.begin_array()?;
    let mut recu = 0_u64;
    for (debut, fin) in piece.received {
        json.begin_array()?;
        json.number(*debut)?;
        json.number(*fin)?;
        json.end_array()?;
        recu = recu.saturating_add(fin.saturating_sub(*debut).saturating_add(1));
    }
    json.end_array()?;
    // **COMPLÈTE SE DIT**, plutôt que de laisser le client sommer des portées :
    // c'est la seule question qu'il se pose avant d'envoyer.
    json.field_bool("complete", recu == piece.size)?;
    json.end_object()
}

/// Écrit l'état d'une pièce jointe seule — la réponse à un morceau.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_attachment<'o>(
    piece: &AttachmentRow<'_>,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    ecrire_une_piece(&mut json, piece)?;
    json.finish()
}

/// Écrit un brouillon : `{"id":…,"expiresAt":…,"attachments":[…]}`.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_draft<'o>(
    id: &str,
    expires_at: u64,
    pieces: &[AttachmentRow<'_>],
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("id", id)?;
    json.field_u64("expiresAt", expires_at)?;
    json.key("attachments")?;
    json.begin_array()?;
    for piece in pieces {
        ecrire_une_piece(&mut json, piece)?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
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

/// Écrit ce qui a changé dans une boîte depuis un point.
///
/// `changed` porte les messages arrivés OU dont les drapeaux ont bougé, en
/// entier — le client distingue les deux : il connaît l'UID ou non.
/// `vanished` porte les UID disparus. `modseq` est le curseur à renvoyer en
/// `since` ; `more` dit qu'il faut le faire tout de suite.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_changes<'o>(
    changes: &[MessageRow<'_>],
    disparus: &[u32],
    uid_validity: u32,
    modseq: u64,
    more: bool,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_u64("uidValidity", u64::from(uid_validity))?;
    json.field_u64("modseq", modseq)?;
    json.key("more")?;
    json.boolean(more)?;
    json.key("changed")?;
    json.begin_array()?;
    for message in changes {
        ecrire_un_message(&mut json, message)?;
    }
    json.end_array()?;
    json.key("vanished")?;
    json.begin_array()?;
    for uid in disparus {
        json.number(u64::from(*uid))?;
    }
    json.end_array()?;
    json.end_object()?;
    json.finish()
}

/// Écrit un message seul, son enveloppe lue dans `entete`, et sa structure.
///
/// `entete` est le bloc d'en-tête du message ; `structure`, le balayeur qui a
/// lu le message entier. `None` écrit `null` — c'est ce que l'appelant rend
/// quand la représentation entière ne tient pas dans la réponse : le message
/// reste servi, et le client sait qu'il lui manque quelque chose au lieu de
/// croire qu'il n'y a rien.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn write_message<'o>(
    message: &MessageRow<'_>,
    entete: Option<&[u8]>,
    structure: Option<&ams_mime::BodyScanner>,
    uid_validity: u32,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_u64("uidValidity", u64::from(uid_validity))?;
    json.key("message")?;
    json.begin_object()?;
    ecrire_les_champs(&mut json, message)?;
    json.key("envelope")?;
    match entete {
        Some(entete) => ecrire_l_enveloppe(&mut json, entete)?,
        None => json.null()?,
    }
    json.key("structure")?;
    match structure {
        Some(balayeur) => ecrire_la_structure(&mut json, balayeur)?,
        None => json.null()?,
    }
    json.end_object()?;
    json.end_object()?;
    json.finish()
}

/// Combien d'éléments au plus par liste de l'enveloppe.
///
/// **Aucune RFC ne le borne.** Un message envoyé à une liste de diffusion peut
/// nommer mille destinataires dans son `To:`, et une réponse doit tenir dans son
/// tampon. Au-delà, `complete` le dit.
pub const ENVELOPE_LIST_MAX: usize = 100;

/// Ce qu'un nom d'affichage peut occuper, avant décodage.
///
/// Mille octets : la RFC 5322 §2.1.1 borne une ligne à 998, et un nom plus long
/// est plié sur plusieurs — ce qu'aucun client n'afficherait entier.
const NOM_MAX: usize = 1000;

/// Ce qu'une adresse peut occuper. §4.5.3.1.3 de RFC 5321 borne un chemin à
/// 256 octets ; celui qui en écrit plus n'écrit pas une adresse qu'un serveur
/// accepterait.
const ADRESSE_MAX: usize = 256;

/// L'enveloppe, lue et DÉCODÉE pour un client qui l'affiche.
///
/// # CE N'EST PAS L'`ENVELOPE` D'IMAP, ET C'EST VOULU
///
/// IMAP rend le texte de l'en-tête tel quel, et c'est la règle pour un client
/// IMAP. Un client REST veut le sens : les noms décodés, la date en instant, les
/// identifiants sans chevrons. Et ce qui est absent est `null` — IMAP remplace
/// un `Sender:` absent par le `From:`, ce qui ferait croire ici que le message
/// en porte un.
///
/// # CE QU'ON NE SAIT PAS RENDRE NE SE REND PAS, ET `complete` LE DIT
///
/// Une liste coupée à [`ENVELOPE_LIST_MAX`], une adresse qui n'est pas de
/// l'UTF-8 ou qui ne tient pas : `complete` vaut `false`. Un client qui répond
/// à tous doit savoir qu'il n'a pas « tous ».
fn ecrire_l_enveloppe(json: &mut Json<'_>, entete: &[u8]) -> Result<(), Error> {
    let Ok(lu) = ams_mime::Message::parse(entete, &ams_mime::Limits::DEFAULT) else {
        // UN EN-TÊTE ILLISIBLE N'A PAS D'ENVELOPPE : l'inventer vide ferait
        // croire à un message sans expéditeur.
        return json.null();
    };
    // LE PREMIER CHAMP DE CE NOM, comme partout dans ce dépôt : prendre le
    // dernier laisserait qui a fabriqué le message choisir lequel on montre.
    let champ = |nom: &[u8]| {
        lu.fields()
            .find(|champ| champ.name_is(nom))
            .map(|champ| champ.raw_value())
    };
    let mut complet = true;
    json.begin_object()?;
    let date = champ(b"date").and_then(ams_mime::read_date_time);
    json.key("date")?;
    match date {
        Some(date) => json.number(date.epoch_seconds)?,
        None => json.null()?,
    }
    json.key("dateZone")?;
    match date {
        Some(date) => json.string(core::str::from_utf8(&date.zone()).unwrap_or_default())?,
        None => json.null()?,
    }
    for (cle, nom) in [
        ("from", &b"from"[..]),
        ("sender", b"sender"),
        ("replyTo", b"reply-to"),
        ("to", b"to"),
        ("cc", b"cc"),
        ("bcc", b"bcc"),
    ] {
        json.key(cle)?;
        match champ(nom) {
            Some(valeur) => complet &= ecrire_les_adresses(json, valeur)?,
            None => json.null()?,
        }
    }
    json.key("messageId")?;
    let identifiant = champ(b"message-id")
        .and_then(|valeur| ams_mime::message_ids(valeur).next())
        .and_then(|octets| core::str::from_utf8(octets).ok());
    ecrire_un_texte_facultatif(json, identifiant)?;
    for (cle, nom) in [
        ("inReplyTo", &b"in-reply-to"[..]),
        ("references", b"references"),
    ] {
        json.key(cle)?;
        match champ(nom) {
            Some(valeur) => complet &= ecrire_les_identifiants(json, valeur)?,
            None => json.null()?,
        }
    }
    json.field_bool("complete", complet)?;
    json.end_object()
}

/// Ce qu'une valeur de paramètre peut occuper, avant et après décodage.
///
/// L'en-tête d'une partie est retenu sur deux kibioctets au plus par le
/// balayeur : un paramètre n'en occupe jamais davantage, et sa conversion en
/// UTF-8 au plus le double.
const PARAMETRE_MAX: usize = 2 * 1024;

/// Ce qu'un `type/sous-type` peut occuper. Au-delà, ce n'est plus un type que
/// quiconque saurait lire, et l'on écrit `application/octet-stream`, comme la
/// RFC 2049 §2 le demande de ce qu'on ne sait pas interpréter.
const TYPE_MAX: usize = 128;

/// L'arbre des parties, tel qu'un client le parcourt pour afficher le corps et
/// lister les pièces jointes.
///
/// # LE CHEMIN EST CELUI QUE `…/parts/{p}` SERT
///
/// Il vient du balayeur, qui numérote comme §6.4.5 de RFC 9051 : un chemin lu
/// ici désigne la même partie, servie là. Un `multipart` à la racine d'un
/// message n'a pas de chemin à lui — `"part": null` —, ses filles si.
///
/// # LES NOMS SONT DÉCODÉS, ET RESTENT CE QUE L'EXPÉDITEUR A ÉCRIT
///
/// `filename` de la disposition d'abord, `name` du type ensuite ; RFC 2231 et
/// RFC 2047 défaits. Un nom de fichier est un texte choisi par un inconnu :
/// `../../.bashrc` est un nom valable ici, et c'est au client de ne jamais s'en
/// servir comme d'un chemin.
fn ecrire_la_structure(json: &mut Json<'_>, balayeur: &ams_mime::BodyScanner) -> Result<(), Error> {
    let mut travail = [0_u8; PARAMETRE_MAX];
    let mut valeur = [0_u8; PARAMETRE_MAX * 2];
    // Ce qui a été ouvert à chaque profondeur porte-t-il des `parts` ?
    let mut conteneurs = [false; ams_mime::STRUCTURE_PARTS_MAX];
    let mut profondeur = 0_usize;
    let mut faute = None;
    let fini = balayeur.walk(&mut |pas| {
        let ecrit = match pas {
            ams_mime::StructureStep::Enter { index, path } => {
                // `walk` ne rend que des rangs de la table, qui se décrivent
                // toujours : `map_or` évite une branche qu'aucun message ne
                // prendrait.
                let conteneur = balayeur.describe(index).map_or(Ok(false), |partie| {
                    ecrire_une_partie(json, &partie, path, &mut travail, &mut valeur)
                });
                conteneur.map(|conteneur| {
                    conteneurs
                        .get_mut(profondeur)
                        .into_iter()
                        .for_each(|place| *place = conteneur);
                    profondeur = profondeur.saturating_add(1);
                })
            }
            ams_mime::StructureStep::Leave => {
                profondeur = profondeur.saturating_sub(1);
                let conteneur = conteneurs.get(profondeur).copied().unwrap_or_default();
                fermer_une_partie(json, conteneur)
            }
        };
        match ecrit {
            Ok(()) => true,
            Err(erreur) => {
                faute = Some(erreur);
                false
            }
        }
    });
    // `walk` ne s'arrête que si l'écriture a échoué, et la faute le dit.
    let _ = fini;
    faute.map_or(Ok(()), Err)
}

/// Ouvre une partie et écrit ce qu'elle est. Rend si elle porte des `parts`,
/// laissées ouvertes pour ses filles.
fn ecrire_une_partie(
    json: &mut Json<'_>,
    partie: &ams_mime::PartHeader<'_>,
    chemin: Option<&[u32]>,
    travail: &mut [u8],
    valeur: &mut [u8],
) -> Result<bool, Error> {
    json.begin_object()?;
    json.key("part")?;
    let mut place = [0_u8; ams_mime::STRUCTURE_PARTS_MAX * 4];
    ecrire_un_texte_facultatif(
        json,
        chemin.map(|chemin| ecrire_le_chemin(chemin, &mut place)),
    )?;
    let mut genre = [0_u8; TYPE_MAX];
    json.field_str("type", ecrire_le_type(partie, &mut genre))?;
    let conteneur = partie.kind != ams_mime::PartKind::Leaf;
    if partie.kind != ams_mime::PartKind::Multipart {
        if partie.kind == ams_mime::PartKind::Leaf {
            json.key("charset")?;
            let longueur = longueur_decodee(partie.type_params, b"charset", travail, valeur);
            ecrire_un_texte_facultatif(json, longueur.and_then(|n| texte_de(valeur, n)))?;
        }
        json.key("name")?;
        // `filename` d'abord (RFC 2183), `name` ensuite : le second est
        // l'usage ancien, que les deux écrivent souvent.
        let longueur = longueur_decodee(partie.disposition_params, b"filename", travail, valeur)
            .or_else(|| longueur_decodee(partie.type_params, b"name", travail, valeur));
        ecrire_un_texte_facultatif(json, longueur.and_then(|n| texte_de(valeur, n)))?;
        json.key("disposition")?;
        let mut disposition = [0_u8; TYPE_MAX];
        ecrire_un_texte_facultatif(json, en_minuscules(partie.disposition, &mut disposition))?;
        if partie.kind == ams_mime::PartKind::Leaf {
            json.key("cid")?;
            let cid = partie
                .content_id
                .and_then(|brut| ams_mime::message_ids(brut).next())
                .and_then(|octets| core::str::from_utf8(octets).ok());
            ecrire_un_texte_facultatif(json, cid)?;
            let mut encodage = [0_u8; TYPE_MAX];
            json.field_str(
                "encoding",
                en_minuscules(partie.encoding, &mut encodage).unwrap_or("7bit"),
            )?;
        }
        json.field_u64("size", partie.size)?;
    }
    if conteneur {
        json.key("parts")?;
        json.begin_array()?;
    }
    Ok(conteneur)
}

/// Ferme une partie, et ses `parts` s'il y en a.
fn fermer_une_partie(json: &mut Json<'_>, conteneur: bool) -> Result<(), Error> {
    if conteneur {
        json.end_array()?;
    }
    json.end_object()
}

/// Ce qu'occupe, dans `valeur`, le paramètre `nom` décodé — s'il est là.
fn longueur_decodee(
    params: &[u8],
    nom: &[u8],
    travail: &mut [u8],
    valeur: &mut [u8],
) -> Option<usize> {
    ams_mime::write_parameter(params, nom, travail, valeur)
        .ok()
        .flatten()
}

/// Les `longueur` premiers octets de `valeur`, s'ils sont un texte non vide.
fn texte_de(valeur: &[u8], longueur: usize) -> Option<&str> {
    valeur
        .get(..longueur)
        .and_then(|octets| core::str::from_utf8(octets).ok())
        .filter(|texte| !texte.is_empty())
}

/// Ce que le `Content-Type` d'une partie servie peut occuper.
pub const PART_MEDIA_MAX: usize = 256;

/// Ce que le `Content-Disposition` d'une partie servie peut occuper. Un nom
/// qui n'y tiendrait pas n'est pas dit — la partie reste `attachment`.
pub const PART_DISPOSITION_MAX: usize = 2 * 1024;

/// Ce qu'un `charset` peut occuper pour être redit. Les noms de l'IANA en font
/// moins de quarante.
const JEU_MAX: usize = 40;

/// Le `Content-Type` d'une partie servie : son type, et son jeu si c'est du
/// texte.
///
/// # CE QUI VIENT DU MESSAGE SE FILTRE AVANT D'ÊTRE REDIT
///
/// C'est un champ d'en-tête HTTP que l'expéditeur remplirait : le type est fait
/// de jetons MIME, et le `charset` n'est redit que s'il n'est fait que de
/// lettres, de chiffres et de `-_.:+`. Autrement, le texte part sans jeu — le
/// client sait qu'il ne sait pas, au lieu de lire un jeu inventé.
#[must_use]
pub fn write_part_media<'o>(partie: &ams_mime::PartHeader<'_>, sortie: &'o mut [u8]) -> &'o str {
    let mut genre = [0_u8; TYPE_MAX];
    let mut jeu = [0_u8; JEU_MAX];
    let mut travail = [0_u8; PARAMETRE_MAX];
    let mut valeur = [0_u8; PARAMETRE_MAX * 2];
    let texte = partie.media_type.eq_ignore_ascii_case(b"text");
    let charset = longueur_decodee(partie.type_params, b"charset", &mut travail, &mut valeur)
        .and_then(|n| valeur.get(..n))
        .filter(|octets| {
            texte
                && octets.iter().all(|o| {
                    o.is_ascii_alphanumeric() || matches!(*o, b'-' | b'_' | b'.' | b':' | b'+')
                })
        })
        .and_then(|octets| en_minuscules(octets, &mut jeu));
    let mut plume = Plume::neuve(sortie);
    plume.mettre(ecrire_le_type(partie, &mut genre).as_bytes());
    if let Some(charset) = charset {
        plume.mettre(b"; charset=");
        plume.mettre(charset.as_bytes());
    }
    plume.texte()
}

/// Le `Content-Disposition` d'une partie servie : TOUJOURS `attachment`, et
/// son nom de fichier sous les deux formes de la RFC 6266.
///
/// - `filename="…"` en ASCII, pour les lecteurs anciens : ce qui n'y tient pas
///   devient `_`, un guillemet ou une barre aussi ;
/// - `filename*=UTF-8''…` pour les autres, chaque octet hors des caractères
///   admis écrit `%XX` (§3.2.1 de RFC 8187).
///
/// **`attachment` MÊME POUR UNE PARTIE `inline`** : c'est un navigateur qu'on
/// empêche ici d'afficher chez nous ce qu'un inconnu a écrit. La disposition
/// que le message déclare est dans la structure, pour le client.
#[must_use]
pub fn write_part_disposition<'o>(
    partie: &ams_mime::PartHeader<'_>,
    sortie: &'o mut [u8],
) -> &'o str {
    let mut travail = [0_u8; PARAMETRE_MAX];
    let mut valeur = [0_u8; PARAMETRE_MAX * 2];
    let longueur = longueur_decodee(
        partie.disposition_params,
        b"filename",
        &mut travail,
        &mut valeur,
    )
    .or_else(|| longueur_decodee(partie.type_params, b"name", &mut travail, &mut valeur));
    let nom = longueur.and_then(|n| texte_de(&valeur, n));
    let mut plume = Plume::neuve(sortie);
    plume.mettre(b"attachment");
    if let Some(nom) = nom {
        let marque = plume.ecrits;
        plume.mettre(b"; filename=\"");
        for caractere in nom.chars() {
            let octet = u8::try_from(caractere)
                .ok()
                .filter(|o| (b' '..=b'~').contains(o) && !matches!(*o, b'"' | b'\\'))
                .unwrap_or(b'_');
            plume.mettre(&[octet]);
        }
        plume.mettre(b"\"; filename*=UTF-8''");
        for octet in nom.bytes() {
            if octet.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&octet) {
                plume.mettre(&[octet]);
            } else {
                const HEXA: &[u8; 16] = b"0123456789ABCDEF";
                let haut = HEXA.get(usize::from(octet >> 4)).copied().unwrap_or(b'0');
                let bas = HEXA.get(usize::from(octet & 0x0F)).copied().unwrap_or(b'0');
                plume.mettre(&[b'%', haut, bas]);
            }
        }
        // UN NOM QUI NE TIENT PAS N'EST PAS DIT À MOITIÉ : la moitié d'un nom
        // de fichier est le nom d'un autre fichier.
        if !plume.entier {
            plume.ecrits = marque;
            plume.entier = true;
        }
    }
    plume.texte()
}

/// De quoi écrire un champ d'en-tête dans un tampon fixe, et savoir s'il a
/// tenu.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
    /// Tout ce qu'on a mis a tenu.
    entier: bool,
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self {
            out,
            ecrits: 0,
            entier: true,
        }
    }

    /// Met `octets` à la suite, si tout tient ; sinon ne met rien, et le
    /// retient.
    fn mettre(&mut self, octets: &[u8]) {
        let fin = self.ecrits.saturating_add(octets.len());
        match self.out.get_mut(self.ecrits..fin).filter(|_| self.entier) {
            Some(place) => {
                place.copy_from_slice(octets);
                self.ecrits = fin;
            }
            None => self.entier = false,
        }
    }

    /// Ce qui a été écrit. Des octets ASCII, et des caractères UTF-8 entiers.
    fn texte(self) -> &'a str {
        let Self { out, ecrits, .. } = self;
        core::str::from_utf8(out.get(..ecrits).unwrap_or_default()).unwrap_or_default()
    }
}

/// `1.2.3`.
fn ecrire_le_chemin<'p>(chemin: &[u32], place: &'p mut [u8]) -> &'p str {
    let octets = chemin.iter().enumerate().flat_map(|(rang, numero)| {
        (rang > 0)
            .then_some(b'.')
            .into_iter()
            .chain(chiffres_de(*numero))
    });
    // LA PLACE SUFFIT TOUJOURS — un chemin compte au plus autant de numéros
    // que la table de parties, et chacun deux chiffres —, et `zip` s'arrête de
    // lui-même là où elle finirait.
    let mut ecrits = 0_usize;
    for (case, octet) in place.iter_mut().zip(octets) {
        *case = octet;
        ecrits = ecrits.saturating_add(1);
    }
    core::str::from_utf8(place.get(..ecrits).unwrap_or_default()).unwrap_or_default()
}

/// Les chiffres décimaux d'un nombre, sans zéro en tête.
fn chiffres_de(nombre: u32) -> impl Iterator<Item = u8> {
    const PUISSANCES: [u32; 10] = [
        1_000_000_000,
        100_000_000,
        10_000_000,
        1_000_000,
        100_000,
        10_000,
        1_000,
        100,
        10,
        1,
    ];
    let debut = PUISSANCES
        .iter()
        .position(|puissance| nombre >= *puissance)
        .unwrap_or(9);
    PUISSANCES.into_iter().skip(debut).map(move |puissance| {
        let chiffre = nombre.checked_div(puissance).unwrap_or(0) % 10;
        b'0'.wrapping_add(u8::try_from(chiffre).unwrap_or(0))
    })
}

/// `type/sous-type`, en minuscules.
fn ecrire_le_type<'g>(partie: &ams_mime::PartHeader<'_>, place: &'g mut [u8]) -> &'g str {
    const INCONNU: &str = "application/octet-stream";
    let longueur = partie
        .media_type
        .len()
        .saturating_add(1)
        .saturating_add(partie.subtype.len());
    let Some(cible) = place.get_mut(..longueur) else {
        return INCONNU;
    };
    let octets = partie.media_type.iter().chain(b"/").chain(partie.subtype);
    for (case, octet) in cible.iter_mut().zip(octets) {
        *case = octet.to_ascii_lowercase();
    }
    // Des jetons MIME : de l'ASCII imprimable (RFC 2045 §5.1).
    core::str::from_utf8(cible).unwrap_or(INCONNU)
}

/// Un jeton en minuscules, ou `None` s'il est vide ou ne tient pas.
fn en_minuscules<'m>(jeton: &[u8], place: &'m mut [u8]) -> Option<&'m str> {
    let cible = place.get_mut(..jeton.len()).filter(|_| !jeton.is_empty())?;
    for (case, octet) in cible.iter_mut().zip(jeton) {
        *case = octet.to_ascii_lowercase();
    }
    core::str::from_utf8(cible).ok()
}

/// Écrit une liste d'adresses, `{"name": …, "email": …}` chacune. Rend si elle
/// est complète.
fn ecrire_les_adresses(json: &mut Json<'_>, valeur: &[u8]) -> Result<bool, Error> {
    let mut travail = [0_u8; NOM_MAX];
    let mut nom = [0_u8; NOM_MAX * 2];
    let mut adresse = [0_u8; ADRESSE_MAX];
    let mut complet = true;
    let mut rendues = 0_usize;
    json.begin_array()?;
    for une in ams_mime::named_addresses(valeur) {
        if rendues == ENVELOPE_LIST_MAX {
            complet = false;
            break;
        }
        // UNE ADRESSE QU'ON NE PEUT PAS RENDRE ENTIÈRE NE SE REND PAS : la
        // moitié d'une adresse est l'adresse de quelqu'un d'autre.
        let courriel = ams_mime::write_addr_spec(une.address, &mut adresse)
            .ok()
            .and_then(|ecrits| adresse.get(..ecrits))
            .and_then(|octets| core::str::from_utf8(octets).ok())
            .filter(|texte| !texte.is_empty());
        let Some(courriel) = courriel else {
            complet = false;
            continue;
        };
        // UN NOM QU'ON NE SAIT PAS RENDRE VAUT `null` : le nom n'engage à rien,
        // l'adresse reste juste.
        let affiche = ams_mime::write_display_name(une.name, &mut travail, &mut nom)
            .ok()
            .and_then(|ecrits| nom.get(..ecrits))
            .and_then(|octets| core::str::from_utf8(octets).ok())
            .filter(|texte| !texte.is_empty());
        json.begin_object()?;
        json.key("name")?;
        ecrire_un_texte_facultatif(json, affiche)?;
        json.field_str("email", courriel)?;
        json.end_object()?;
        rendues = rendues.saturating_add(1);
    }
    json.end_array()?;
    Ok(complet)
}

/// Écrit une liste d'identifiants de message. Rend si elle est complète.
///
/// # LE PREMIER ET LES DERNIERS
///
/// Au-delà de [`ENVELOPE_LIST_MAX`], on garde le premier — la racine du fil —
/// et les plus récents, dont le parent direct : c'est ce qu'un client emploie
/// pour ranger un message dans son fil. Garder les premiers perdrait justement
/// le parent.
fn ecrire_les_identifiants(json: &mut Json<'_>, valeur: &[u8]) -> Result<bool, Error> {
    let total = ams_mime::message_ids(valeur).count();
    let sautes = total.saturating_sub(ENVELOPE_LIST_MAX);
    json.begin_array()?;
    for (rang, identifiant) in ams_mime::message_ids(valeur).enumerate() {
        if rang != 0 && rang <= sautes {
            continue;
        }
        // Un identifiant est de l'ASCII imprimable : `message_ids` l'a vérifié.
        json.string(core::str::from_utf8(identifiant).unwrap_or_default())?;
    }
    json.end_array()?;
    Ok(sautes == 0)
}

/// Le corps d'un message, tel qu'une liste le rend.
fn ecrire_un_message(json: &mut Json<'_>, message: &MessageRow<'_>) -> Result<(), Error> {
    json.begin_object()?;
    ecrire_les_champs(json, message)?;
    json.end_object()
}

/// Les champs qu'un message porte dans toutes ses représentations.
fn ecrire_les_champs(json: &mut Json<'_>, message: &MessageRow<'_>) -> Result<(), Error> {
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
    json.end_array()
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

/// Ce qu'une recherche demande.
///
/// # LES CRITÈRES SE COMBINENT PAR « ET », ET IL N'Y A PAS D'AUTRE FAÇON
///
/// §6.4.4 de RFC 9051 admet `OR` et `NOT` ; cette ressource ne les sert pas. Un
/// langage d'expression en JSON demanderait un arbre, une profondeur bornée et sa
/// propre grammaire — c'est-à-dire un second langage de recherche à côté de celui
/// d'IMAP, qui le sert déjà. **Ce qui manque le dit** plutôt que de le laisser
/// deviner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SearchCriteria<'a> {
    /// `\Seen` : posé, ôté, ou indifférent.
    pub seen: Option<bool>,
    /// `\Answered`.
    pub answered: Option<bool>,
    /// `\Flagged`.
    pub flagged: Option<bool>,
    /// `\Deleted`.
    pub deleted: Option<bool>,
    /// `\Draft`.
    pub draft: Option<bool>,
    /// Un texte cherché dans le champ `From:`.
    pub from: Option<&'a str>,
    /// Dans le champ `To:`.
    pub to: Option<&'a str>,
    /// Dans le champ `Subject:`.
    pub subject: Option<&'a str>,
    /// Dans le corps.
    pub body: Option<&'a str>,
    /// Dans l'en-tête ET le corps (§6.4.4).
    pub text: Option<&'a str>,
}

impl SearchCriteria<'_> {
    /// Cette recherche demande-t-elle quelque chose ?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.seen.is_none()
            && self.answered.is_none()
            && self.flagged.is_none()
            && self.deleted.is_none()
            && self.draft.is_none()
            && self.from.is_none()
            && self.to.is_none()
            && self.subject.is_none()
            && self.body.is_none()
            && self.text.is_none()
    }
}

/// Lit les critères d'une recherche.
///
/// # LES TEXTES NE SE DÉSÉCHAPPENT PAS
///
/// Un critère qui aurait besoin d'être échappé en JSON porte un guillemet, une
/// barre oblique inverse ou une commande — et ce serveur ne les cherche pas. Le
/// refuser ici est plus honnête que de le déséchapper pour ne rien trouver.
///
/// **Tout le reste passe tel quel**, accents compris : du texte non ASCII s'écrit
/// directement en JSON (§8.1 de RFC 8259) et n'a pas besoin d'échappement.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] : un champ qu'on ne connaît pas, un champ répété, une
/// valeur du mauvais type, ou une chaîne échappée.
pub fn read_search_criteria(corps: &[u8]) -> Result<SearchCriteria<'_>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut vu = SearchCriteria::default();
    // Le champ en cours : 1..=5 les drapeaux, 6..=10 les textes.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                let noms: [(&str, u8); 10] = [
                    ("seen", 1),
                    ("answered", 2),
                    ("flagged", 3),
                    ("deleted", 4),
                    ("draft", 5),
                    ("from", 6),
                    ("to", 7),
                    ("subject", 8),
                    ("body", 9),
                    ("text", 10),
                ];
                // **UNE CLEF RÉPÉTÉE NE PEUT PAS ARRIVER ICI** : `Reader` la
                // refuse déjà, parce que §4 de RFC 8259 dit seulement « SHOULD be
                // unique » et que chaque analyseur en fait ce qu'il veut. Une
                // garde de plus serait un chemin qu'aucun corps ne peut emprunter.
                let trouve = noms.iter().find(|(nom, _)| clef.is(nom));
                let (_, rang) = trouve.ok_or(mauvais)?;
                quel = *rang;
            }
            Some(Event::Bool(valeur)) => match quel {
                1 => vu.seen = Some(valeur),
                2 => vu.answered = Some(valeur),
                3 => vu.flagged = Some(valeur),
                4 => vu.deleted = Some(valeur),
                5 => vu.draft = Some(valeur),
                _ => return Err(mauvais),
            },
            Some(Event::Text(texte)) => {
                let clair = texte.as_plain().ok_or(mauvais)?;
                match quel {
                    6 => vu.from = Some(clair),
                    7 => vu.to = Some(clair),
                    8 => vu.subject = Some(clair),
                    9 => vu.body = Some(clair),
                    10 => vu.text = Some(clair),
                    _ => return Err(mauvais),
                }
            }
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }
    Ok(vu)
}

/// Écrit le résultat d'une recherche.
///
/// # DES UID, ET NON DES RANGS
///
/// Un rang change dès qu'un message disparaît de la boîte ; un UID ne change
/// jamais tant que `uidValidity` ne bouge pas (§2.3.1.1 de RFC 9051). Rendre des
/// rangs ferait désigner au client, une seconde plus tard, d'autres messages que
/// ceux qu'il a trouvés.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_search<'o>(
    uids: &[u32],
    uid_validity: u32,
    complet: bool,
    sortie: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.key("uids")?;
    json.begin_array()?;
    for uid in uids {
        json.number(u64::from(*uid))?;
    }
    json.end_array()?;
    json.field_u64("uidValidity", u64::from(uid_validity))?;
    // **DIRE QUE LA LISTE EST TRONQUÉE, ET NON LA TRONQUER EN SILENCE** : un
    // client qui croirait avoir tous les résultats agirait sur une moitié.
    json.field_bool("complete", complet)?;
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
                // **RÉPÉTÉ NE PEUT PAS ARRIVER ICI** : `Reader` refuse déjà une
                // clef en double (§4 de RFC 8259 ne dit que « SHOULD be
                // unique »). Il ne reste donc que le champ inconnu à refuser.
                quel = match (clef.is("login"), clef.is("password"), clef.is("addresses")) {
                    (true, _, _) => 1,
                    (_, true, _) => 2,
                    (_, _, true) => 3,
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

/// Ce qu'un changement de son propre secret demande.
///
/// **LES DEUX SONT OBLIGATOIRES**, et c'est toute la sécurité de la route. Le
/// jeton dit de QUI il s'agit ; le mot de passe actuel dit que c'est bien LUI
/// qui tient le clavier. Sans le second, un jeton volé — dans un journal
/// d'intermédiaire, dans une sauvegarde de navigateur — permettrait de changer
/// le secret, et donc de verrouiller le propriétaire hors de sa boîte pour de
/// bon. Un vol de jeton, qui expire, deviendrait un vol de compte, qui n'expire
/// pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnPasswordBody<'a> {
    /// Le secret actuel, déséchappé dans le premier tampon prêté.
    pub current: &'a str,
    /// Le secret voulu, déséchappé dans le second.
    pub new: &'a str,
}

/// Lit un corps de changement de son propre secret.
///
/// Le corps attendu est `{"current_password": "…", "password": "…"}`, et **rien
/// d'autre** : ni `login` — le jeton le dit —, ni `addresses`, qu'un client
/// croirait avoir changées.
///
/// # DEUX TAMPONS, ET NON UN SEUL PARTAGÉ
///
/// Les deux chaînes se déséchappent, et les deux doivent survivre jusqu'à la
/// comparaison. Les écrire dans un même tampon obligerait à retenir où finit la
/// première — une longueur de plus à ne pas se tromper, pour rien.
///
/// # Errors
///
/// [`Reason::BadJsonBody`] : un champ inconnu, un champ manquant, une valeur du
/// mauvais type, ou un secret plus long que le tampon prêté.
pub fn read_own_password_body<'a>(
    corps: &[u8],
    actuel: &'a mut [u8],
    neuf: &'a mut [u8],
) -> Result<OwnPasswordBody<'a>, Error> {
    let mauvais = Error::new(Reason::BadJsonBody);
    let mut lecteur = Reader::new(corps);
    let mut dit_actuel: Option<Str<'_>> = None;
    let mut dit_neuf: Option<Str<'_>> = None;
    // Quel champ on lit : 1 `current_password`, 2 `password`.
    let mut quel = 0_u8;

    loop {
        match lecteur.read().map_err(|_| mauvais)? {
            None => break,
            Some(Event::Key(clef)) => {
                quel = match (clef.is("current_password"), clef.is("password")) {
                    (true, _) => 1,
                    (_, true) => 2,
                    _ => return Err(mauvais),
                };
            }
            Some(Event::Text(texte)) => match quel {
                1 => dit_actuel = Some(texte),
                2 => dit_neuf = Some(texte),
                _ => return Err(mauvais),
            },
            Some(Event::ObjectStart | Event::ObjectEnd) => {}
            Some(_) => return Err(mauvais),
        }
    }

    // **L'ABSENCE EST UN REFUS**, et non un champ laissé tel quel : il n'y a pas
    // de « changer le secret sans dire lequel ».
    let (Some(dit_actuel), Some(dit_neuf)) = (dit_actuel, dit_neuf) else {
        return Err(mauvais);
    };
    Ok(OwnPasswordBody {
        current: dit_actuel.unescape(actuel).map_err(|_| mauvais)?,
        new: dit_neuf.unescape(neuf).map_err(|_| mauvais)?,
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

/// Écrit l'UID d'un message qu'on vient de ranger.
///
/// **UN `201` DOIT DIRE CE QU'IL A CRÉÉ.** Un corps vide obligerait le client à
/// relire la boîte entière pour retrouver ce qu'il venait d'y mettre — et à le
/// deviner, si deux messages sont arrivés entre-temps.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_uid_cree(uid: u32, sortie: &mut [u8]) -> Result<&[u8], Error> {
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_u64("uid", u64::from(uid))?;
    json.end_object()?;
    json.finish()
}
